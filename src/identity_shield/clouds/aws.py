"""AWS CloudTrail audit log & HTTP API adapter preserving all existing behavior."""

from __future__ import annotations

import importlib.util
import shutil
import uuid
from datetime import datetime, timezone
from typing import Any, Mapping
from urllib.parse import parse_qs, urlsplit

from identity_shield.clouds.models import CanonicalEvent, ProviderCapabilities, deterministic_event_id
from identity_shield.clouds.redaction import redact_headers, redact_mapping, redact_query_string
from identity_shield.detect.parser import extract_events as extract_cloudtrail_events
from identity_shield.detect.parser import normalize_time

ISO = "%Y-%m-%dT%H:%M:%SZ"


def capabilities() -> ProviderCapabilities:
    return ProviderCapabilities(
        provider="aws",
        display_name="Amazon Web Services (AWS)",
        audit_log_formats=("cloudtrail", "cloudtrail_s3_records"),
        proxy_api_inspection=True,
        connect_metadata_only=True,
        synthetic_variants=True,
        live_sdk_available=importlib.util.find_spec("boto3") is not None,
        supported_factors=(
            "identity_context",
            "network_origin",
            "client_tool",
            "timing",
            "api_form",
        ),
        unsupported_notes=(
            "HTTPS CONNECT without TLS interception records destination metadata only.",
            "IMDS T1552.005 logs downstream STS/EC2 calls rather than local 169.254.169.254 fetch.",
        ),
    )


def extract_events(payload: Any) -> list[dict[str, Any]]:
    return extract_cloudtrail_events(payload)


def is_aws_audit_event(item: Mapping[str, Any]) -> bool:
    if not isinstance(item, Mapping):
        return False
    source = str(item.get("eventSource") or "")
    return (
        "eventVersion" in item
        or "awsRegion" in item
        or source.endswith(".amazonaws.com")
        or ("eventName" in item and "userIdentity" in item)
    )


def normalize_audit_event(event: Mapping[str, Any]) -> CanonicalEvent:
    identity = event.get("userIdentity") if isinstance(event.get("userIdentity"), Mapping) else {}
    req_params = event.get("requestParameters") if isinstance(event.get("requestParameters"), Mapping) else {}
    source = str(event.get("eventSource") or "aws.amazonaws.com")
    service = source.split(".", 1)[0].lower() if "." in source else source.lower()
    operation = str(event.get("eventName") or "UnknownEvent")
    principal = str(
        identity.get("arn")
        or identity.get("principalId")
        or identity.get("userName")
        or identity.get("accessKeyId")
        or "unknown"
    )
    principal_type = str(identity.get("type") or "Unknown")
    account_scope = str(
        event.get("recipientAccountId")
        or identity.get("accountId")
        or ""
    )
    err = str(event.get("errorCode") or "").strip()
    if err in {"AccessDenied", "UnauthorizedOperation", "Client.UnauthorizedOperation"}:
        outcome = "denied"
    elif err:
        outcome = "error"
    else:
        outcome = "success"

    resource = str(
        req_params.get("bucketName")
        or req_params.get("userName")
        or req_params.get("roleName")
        or req_params.get("roleArn")
        or req_params.get("instanceId")
        or req_params.get("secretId")
        or ""
    )
    if not resource and isinstance(event.get("resources"), list) and event["resources"]:
        first_res = event["resources"][0]
        if isinstance(first_res, Mapping):
            resource = str(first_res.get("ARN") or first_res.get("accountId") or "")

    event_time = normalize_time(event.get("eventTime"))
    event_id = str(event.get("eventID") or "") or deterministic_event_id("aws", event)
    sanitized = redact_mapping(dict(event))

    return CanonicalEvent(
        event_id=event_id,
        event_time=event_time,
        cloud_provider="aws",
        source_type="cloudtrail",
        account_scope=account_scope,
        service=service,
        operation=operation,
        principal=principal,
        principal_type=principal_type,
        source_ip=str(event.get("sourceIPAddress") or ""),
        user_agent=str(event.get("userAgent") or ""),
        resource=resource,
        region=str(event.get("awsRegion") or ""),
        outcome=outcome,
        authentication_context={
            "user_identity_type": principal_type,
            "mfa_authenticated": ((identity.get("sessionContext") or {}).get("attributes") or {}).get("mfaAuthenticated")
            if isinstance(identity.get("sessionContext"), Mapping)
            else None,
            "invoked_by": identity.get("invokedBy"),
        },
        request_metadata={
            "event_source": source,
            "error_code": err or None,
            "read_only": event.get("readOnly"),
        },
        raw=sanitized if isinstance(sanitized, dict) else {},
    )


def parse_http_event(
    *,
    method: str,
    url_or_path: str,
    headers: Mapping[str, str],
    body_params: Mapping[str, Any],
    sigv4: Mapping[str, str],
    target_host: str,
    client_ip: str,
    timestamp: str | None = None,
) -> CanonicalEvent:
    split = urlsplit(url_or_path)
    path = split.path or "/"
    query_params = parse_qs(split.query)
    lower_headers = {str(k).lower(): str(v) for k, v in headers.items()}

    target_hdr = lower_headers.get("x-amz-target", "")
    service = sigv4.get("service", "").lower()
    if not service and target_hdr and "." in target_hdr:
        service = target_hdr.split(".", 1)[0].lower().removeprefix("aws")
    if not service:
        for cand in ("iam", "sts", "ec2", "s3", "secretsmanager", "kms", "rds", "lambda", "cloudtrail", "sqs", "ssm"):
            if target_host.lower().startswith(f"{cand}.") or f".{cand}." in target_host.lower():
                service = cand
                break
    if not service and (lower_headers.get("x-amz-content-sha256") or path.count("/") >= 1 and "s3" in target_host.lower()):
        service = "s3"
    service = service or "aws"

    action = (query_params.get("Action") or [None])[0] or body_params.get("Action")
    if target_hdr and "." in target_hdr:
        operation = target_hdr.split(".", 1)[1]
    elif action:
        operation = str(action)
    elif service == "s3" or lower_headers.get("x-amz-content-sha256"):
        clean = path.lstrip("/")
        if not clean:
            operation = "ListBuckets"
        elif "/" not in clean:
            operation = "HeadBucket" if method.upper() == "HEAD" else "ListBucket"
        elif method.upper() == "PUT":
            operation = "PutObject"
        elif method.upper() == "DELETE":
            operation = "DeleteObject"
        else:
            operation = "GetObject"
    else:
        operation = f"{method.upper()}:{path}"

    region = sigv4.get("region") or lower_headers.get("x-aws-region") or "eu-west-1"
    principal = sigv4.get("access_key") or f"ip:{client_ip}"
    principal_type = "IAMUser" if principal.startswith("AKIA") else ("AssumedRole" if principal.startswith("ASIA") else "WebIdentityUser")
    ts = timestamp or datetime.now(timezone.utc).strftime(ISO)

    merged_params = redact_mapping(dict(body_params))
    for k, vals in query_params.items():
        if k not in {"Action", "Version"}:
            merged_params[k] = redact_mapping(vals[0] if len(vals) == 1 else vals)

    if service == "s3" and path.strip("/"):
        seg = path.strip("/").split("/", 1)
        merged_params.setdefault("bucketName", seg[0])
        if len(seg) > 1:
            merged_params.setdefault("key", seg[1])

    resource = str(
        merged_params.get("bucketName")
        or merged_params.get("UserName")
        or merged_params.get("userName")
        or merged_params.get("RoleName")
        or merged_params.get("roleName")
        or ""
    )

    raw_event = {
        "eventVersion": "1.09",
        "eventTime": ts,
        "eventSource": f"{service}.amazonaws.com",
        "eventName": operation,
        "awsRegion": region,
        "sourceIPAddress": client_ip,
        "userAgent": lower_headers.get("user-agent", "unknown"),
        "userIdentity": {
            "type": principal_type,
            "principalId": principal,
            "arn": f"arn:aws:iam::proxy:user/{principal}",
            "accessKeyId": principal if principal.startswith(("AKIA", "ASIA")) else None,
        },
        "requestParameters": merged_params,
        "httpRequest": {
            "method": method.upper(),
            "host": target_host,
            "path": path,
            "query": redact_query_string(split.query),
            "headers": redact_headers(headers),
        },
        "proxyCaptured": True,
    }
    event_id = deterministic_event_id("awspx", {"ts": ts, "host": target_host, "op": operation, "principal": principal, "path": path, "nonce": uuid.uuid4().hex})
    raw_event["eventID"] = event_id

    return CanonicalEvent(
        event_id=event_id,
        event_time=ts,
        cloud_provider="aws",
        source_type="cloud_api",
        account_scope="",
        service=service,
        operation=operation,
        principal=principal,
        principal_type=principal_type,
        source_ip=client_ip,
        user_agent=lower_headers.get("user-agent", "unknown"),
        resource=resource,
        region=region,
        outcome="unknown",
        authentication_context={"scheme": "AWS4-HMAC-SHA256" if sigv4 else "custom"},
        request_metadata={"method": method.upper(), "host": target_host, "path": path, "params": merged_params},
        raw=raw_event,
    )
