"""HTTP & AWS SigV4 Traffic Parser for Live Proxy Capture.

Normalizes live intercepted requests (both AWS API calls and generic Cloud Web
Application HTTP requests) into structured metadata + CloudTrail-compatible JSON
so static Sigma rules and Dynamic Behavioral rules evaluate them uniformly.
"""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Mapping
from urllib.parse import parse_qs, urlsplit

from identity_shield.clouds.redaction import (
    REDACTED,
    is_sensitive_key as _is_sensitive_key,
    redact_mapping as _redact_value,
    redact_query_string as _redact_query_string,
    redact_text,
)

ISO = "%Y-%m-%dT%H:%M:%SZ"

_SIGV4_CRED_RE = re.compile(
    r"Credential=([^/\s,]+)/(\d{8})/([^/\s]+)/([^/\s]+)/aws4_request"
)


def parse_sigv4_auth(auth_header: str) -> dict[str, str]:
    match = _SIGV4_CRED_RE.search(auth_header or "")
    if not match:
        return {}
    return {
        "access_key": match.group(1),
        "date": match.group(2),
        "region": match.group(3),
        "service": match.group(4),
    }


def _infer_aws_service(host: str, target: str, sigv4_service: str) -> str:
    if sigv4_service:
        return sigv4_service.lower()
    if target and "." in target:
        prefix = target.split(".", 1)[0].lower()
        return prefix.removeprefix("aws")
    host_l = (host or "").lower()
    for svc in ("iam", "sts", "ec2", "s3", "secretsmanager", "kms", "rds", "lambda", "cloudtrail", "sqs", "ssm"):
        if host_l.startswith(f"{svc}.") or f".{svc}." in host_l:
            return svc
    return "http_app"


def _infer_operation(
    *,
    method: str,
    path: str,
    query_params: Mapping[str, list[str]],
    body_params: Mapping[str, Any],
    headers: Mapping[str, str],
    service: str,
) -> tuple[str, str]:
    """Return `(operation, traffic_kind)`."""
    target = headers.get("x-amz-target", "")
    if target and "." in target:
        return target.split(".", 1)[1], "aws_api"

    action = (
        (query_params.get("Action") or [None])[0]
        or body_params.get("Action")
    )
    if action:
        return str(action), "aws_api"

    if service == "s3" or headers.get("x-amz-content-sha256"):
        clean_path = path.lstrip("/")
        if not clean_path:
            return "ListBuckets", "aws_api"
        parts = clean_path.split("/", 1)
        if len(parts) == 1 or not parts[1]:
            return ("HeadBucket" if method == "HEAD" else "ListBucket"), "aws_api"
        if method == "PUT":
            return "PutObject", "aws_api"
        if method == "DELETE":
            return "DeleteObject", "aws_api"
        return "GetObject", "aws_api"

    if service != "http_app":
        return f"{method}:{path or '/'}", "aws_api"

    # Generic Cloud Web Application route
    clean = path.split("?", 1)[0] or "/"
    return f"{method} {clean}", "http_app"


def _extract_principal(headers: Mapping[str, str], sigv4: Mapping[str, str], client_ip: str) -> str:
    if sigv4.get("access_key"):
        return sigv4["access_key"]
    custom_user = headers.get("x-identity-user") or headers.get("x-user")
    if custom_user:
        return str(custom_user)
    auth = headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        token = auth[7:].strip()
        digest = hashlib.sha256(token.encode("utf-8")).hexdigest()[:10]
        return f"bearer:{digest}"
    api_key = headers.get("x-api-key")
    if api_key:
        digest = hashlib.sha256(api_key.encode("utf-8")).hexdigest()[:10]
        return f"apikey:{digest}"
    return f"ip:{client_ip or 'unknown'}"


def parse_request(
    *,
    method: str,
    url_or_path: str,
    headers: Mapping[str, str],
    body: bytes = b"",
    client_ip: str = "127.0.0.1",
    target_host_override: str | None = None,
    timestamp: str | None = None,
) -> dict[str, Any]:
    """Classify and normalize an intercepted HTTP, AWS, GCP, or Azure API request."""
    from identity_shield.clouds.registry import parse_cloud_http_request

    lower_headers = {str(k).lower(): str(v) for k, v in headers.items()}
    split = urlsplit(url_or_path)
    path = split.path or "/"
    query_params = parse_qs(split.query)

    target_host = target_host_override or split.netloc or lower_headers.get("host", "")
    body_text = body.decode("utf-8", errors="replace") if body else ""
    content_type = lower_headers.get("content-type", "").lower()

    body_params: dict[str, Any] = {}
    if ("application/x-www-form-urlencoded" in content_type or (not content_type and "Action=" in body_text)) and body_text:
        for k, vals in parse_qs(body_text).items():
            body_params[k] = vals[0] if len(vals) == 1 else vals
    elif "json" in content_type and body_text:
        try:
            parsed = json.loads(body_text)
            if isinstance(parsed, Mapping):
                body_params = dict(parsed)
        except json.JSONDecodeError:
            body_params = {"_raw": body_text[:500]}

    sigv4 = parse_sigv4_auth(lower_headers.get("authorization", ""))
    classification, canonical = parse_cloud_http_request(
        method=method,
        url_or_path=url_or_path,
        headers=headers,
        body_params=body_params,
        sigv4=sigv4,
        target_host=target_host,
        client_ip=client_ip,
        body=body,
        timestamp=timestamp,
    )

    safe_query = _redact_query_string(split.query)

    if canonical is not None:
        event_obj = canonical.to_sigma_event()
        params_src = canonical.request_metadata.get("params") or {}
        req_hash = canonical.event_id
        # Scrub real 20-char access key / OAuth secrets from flat principal column while keeping short test labels intact
        safe_principal = redact_text(str(canonical.principal or ""))
        return {
            "proxy_event_id": f"px-{req_hash[:16]}",
            "timestamp": canonical.event_time,
            "cloud_provider": canonical.cloud_provider,
            "account_scope": canonical.account_scope,
            "traffic_type": classification.traffic_type,
            "traffic_kind": classification.legacy_traffic_kind,
            "classification_confidence": classification.confidence,
            "classification_reason": classification.reason,
            "client_ip": client_ip,
            "principal": safe_principal,
            "method": method.upper(),
            "target_host": target_host,
            "path": path + (f"?{safe_query}" if safe_query else ""),
            "service": canonical.service,
            "operation": canonical.operation,
            "user_agent": canonical.user_agent,
            "aws_region": canonical.region,
            "params_json": json.dumps(params_src, sort_keys=True),
            "event_obj": event_obj,
            "event_json": json.dumps(event_obj, sort_keys=True),
            "canonical_event": canonical.to_dict(),
        }

    # Generic Cloud Web Application / ambiguous request path
    operation, _ = _infer_operation(
        method=method.upper(),
        path=path,
        query_params=query_params,
        body_params=body_params,
        headers=lower_headers,
        service="http_app",
    )
    region = lower_headers.get("x-aws-region") or "eu-west-1"
    user_agent = lower_headers.get("user-agent", "unknown")
    principal = _extract_principal(lower_headers, sigv4, client_ip)
    ts = timestamp or datetime.now(timezone.utc).strftime(ISO)

    merged_params: dict[str, Any] = {}
    for k, vals in query_params.items():
        if k not in {"Action", "Version"}:
            val = vals[0] if len(vals) == 1 else vals
            merged_params[k] = "[REDACTED]" if _is_sensitive_key(k) else _redact_value(val)
    for k, v in body_params.items():
        if k not in {"Action", "Version"}:
            merged_params[k] = "[REDACTED]" if _is_sensitive_key(k) else _redact_value(v)

    req_hash = hashlib.sha256(
        f"{ts}|{principal}|{method}|{target_host}|{path}|{operation}|{len(body)}|{uuid.uuid4().hex}".encode("utf-8")
    ).hexdigest()

    event_obj = {
        "cloudProvider": classification.cloud_provider,
        "eventVersion": "1.09",
        "eventID": req_hash[:32],
        "eventTime": ts,
        "eventSource": target_host or "cloud.webapp.local",
        "eventName": operation,
        "awsRegion": region,
        "sourceIPAddress": client_ip,
        "userAgent": user_agent,
        "userIdentity": {
            "type": "WebIdentityUser",
            "principalId": principal,
            "arn": f"arn:identity:webapp::user/{principal}",
            "accessKeyId": None,
        },
        "requestParameters": merged_params,
        "httpRequest": {
            "method": method.upper(),
            "host": target_host,
            "path": path,
            "query": safe_query,
        },
        "proxyCaptured": True,
    }

    return {
        "proxy_event_id": f"px-{req_hash[:16]}",
        "timestamp": ts,
        "cloud_provider": classification.cloud_provider,
        "account_scope": "",
        "traffic_type": classification.traffic_type,
        "traffic_kind": classification.legacy_traffic_kind,
        "classification_confidence": classification.confidence,
        "classification_reason": classification.reason,
        "client_ip": client_ip,
        "principal": principal,
        "method": method.upper(),
        "target_host": target_host,
        "path": path + (f"?{safe_query}" if safe_query else ""),
        "service": classification.detected_service or "http_app",
        "operation": operation,
        "user_agent": user_agent,
        "aws_region": region,
        "params_json": json.dumps(merged_params, sort_keys=True),
        "event_obj": event_obj,
        "event_json": json.dumps(event_obj, sort_keys=True),
    }


def parse_connect_tunnel(
    *,
    authority: str,
    headers: Mapping[str, str],
    client_ip: str = "127.0.0.1",
    timestamp: str | None = None,
) -> dict[str, Any]:
    """Normalize an HTTPS CONNECT tunnel request using metadata-only inspection."""
    from identity_shield.clouds.classifier import classify_traffic

    raw_auth = str(authority or "").strip()
    if raw_auth.startswith("["):
        end_bracket = raw_auth.find("]")
        if end_bracket != -1:
            host = raw_auth[1:end_bracket]
            rest = raw_auth[end_bracket + 1 :]
            port = rest[1:] if rest.startswith(":") else ""
        else:
            host, _, port = raw_auth.partition(":")
    elif raw_auth.count(":") == 1:
        host, _, port = raw_auth.partition(":")
    elif ":" in raw_auth:
        host, port = raw_auth, ""
    else:
        host, port = raw_auth, ""
    lower_headers = {str(k).lower(): str(v) for k, v in headers.items()}
    classification = classify_traffic(
        method="CONNECT",
        url_or_path=authority,
        headers=lower_headers,
        host_override=host,
        is_connect=True,
    )
    parts = host.lower().split(".")
    service = classification.detected_service or "https_tunnel"
    region = parts[1] if "amazonaws.com" in host.lower() and len(parts) >= 4 else "global"
    user_agent = lower_headers.get("user-agent", "tls-client")
    ts = timestamp or datetime.now(timezone.utc).strftime(ISO)
    principal = f"ip:{client_ip}"
    digest = hashlib.sha256(f"{ts}|{client_ip}|{authority}|{uuid.uuid4().hex}".encode("utf-8")).hexdigest()

    event_obj = {
        "cloudProvider": classification.cloud_provider,
        "eventVersion": "1.09",
        "eventID": digest[:32],
        "eventTime": ts,
        "eventSource": host,
        "eventName": "TlsConnectTunnel",
        "awsRegion": region,
        "sourceIPAddress": client_ip,
        "userAgent": user_agent,
        "userIdentity": {"type": "TunnelClient", "principalId": principal},
        "requestParameters": {"host": host, "port": port or "443", "tunnel_metadata_only": True},
        "proxyCaptured": True,
    }
    return {
        "proxy_event_id": f"px-{digest[:16]}",
        "timestamp": ts,
        "cloud_provider": classification.cloud_provider,
        "account_scope": "",
        "traffic_type": "connect_tunnel",
        "traffic_kind": "connect_tunnel",
        "classification_confidence": classification.confidence,
        "classification_reason": classification.reason,
        "client_ip": client_ip,
        "principal": principal,
        "method": "CONNECT",
        "target_host": host,
        "path": authority,
        "service": service,
        "operation": f"CONNECT:{classification.cloud_provider}:{service}",
        "user_agent": user_agent,
        "aws_region": region,
        "params_json": json.dumps({"host": host, "port": port or "443", "metadata_only": True}),
        "event_obj": event_obj,
        "event_json": json.dumps(event_obj, sort_keys=True),
    }
