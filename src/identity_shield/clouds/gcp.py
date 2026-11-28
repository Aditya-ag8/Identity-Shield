"""Google Cloud Platform (GCP) Cloud Audit Logs & REST API adapter."""

from __future__ import annotations

import importlib.util
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Mapping
from urllib.parse import urlsplit

from identity_shield.clouds.models import CanonicalEvent, ProviderCapabilities, deterministic_event_id
from identity_shield.clouds.redaction import redact_headers, redact_mapping, redact_query_string
from identity_shield.detect.parser import normalize_time

ISO = "%Y-%m-%dT%H:%M:%SZ"


def capabilities() -> ProviderCapabilities:
    return ProviderCapabilities(
        provider="gcp",
        display_name="Google Cloud Platform (GCP)",
        audit_log_formats=("gcp_admin_activity", "gcp_data_access", "gcp_system_event", "gcp_policy_denied"),
        proxy_api_inspection=True,
        connect_metadata_only=True,
        synthetic_variants=True,
        live_sdk_available=importlib.util.find_spec("google.cloud") is not None,
        supported_factors=(
            "identity_context",
            "network_origin",
            "client_tool",
            "timing",
            "api_form",
        ),
        unsupported_notes=(
            "Offline Audit Log normalization and synthetic 5-factor variants are built-in.",
            "Live GCP execution requires optional google-cloud-* SDKs / gcloud CLI and explicit project authorization.",
            "HTTPS CONNECT without TLS interception inspects destination metadata only; set CLOUDSDK_API_ENDPOINT_OVERRIDES_* for full L7 inspection.",
        ),
    )


def is_gcp_audit_event(item: Mapping[str, Any]) -> bool:
    if not isinstance(item, Mapping):
        return False
    if isinstance(item.get("protoPayload"), Mapping):
        payload_type = str(item["protoPayload"].get("@type") or "")
        if "AuditLog" in payload_type or "methodName" in item["protoPayload"]:
            return True
    log_name = str(item.get("logName") or "")
    return "cloudaudit.googleapis.com" in log_name


def extract_events(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        out: list[dict[str, Any]] = []
        for item in payload:
            out.extend(extract_events(item))
        return out
    if isinstance(payload, Mapping):
        if isinstance(payload.get("entries"), list):
            out = []
            for item in payload["entries"]:
                out.extend(extract_events(item))
            return out
        if isinstance(payload.get("Records"), list):
            out = []
            for item in payload["Records"]:
                if is_gcp_audit_event(item):
                    out.append(dict(item))
            return out
        if is_gcp_audit_event(payload):
            return [dict(payload)]
    return []


def _gcp_source_type(log_name: str, proto: Mapping[str, Any]) -> str:
    lower = log_name.lower()
    if "policy" in lower:
        return "gcp_policy_denied"
    if "data_access" in lower:
        return "gcp_data_access"
    if "system_event" in lower:
        return "gcp_system_event"
    if "activity" in lower:
        return "gcp_admin_activity"
    status_obj = proto.get("status") if isinstance(proto.get("status"), Mapping) else {}
    if status_obj.get("code") == 7:
        return "gcp_policy_denied"
    return "gcp_admin_activity"


def _project_from_resource(resource_obj: Mapping[str, Any], resource_name: str, log_name: str) -> str:
    labels = resource_obj.get("labels") if isinstance(resource_obj.get("labels"), Mapping) else {}
    if labels.get("project_id"):
        return str(labels["project_id"])
    for text in (resource_name, log_name):
        m = re.search(r"projects/([^/]+)", str(text or ""))
        if m:
            return m.group(1)
    return ""


def _scalar_text(val: Any) -> str:
    if isinstance(val, Mapping):
        for k in ("email", "value", "principalEmail", "principalSubject", "displayName", "name", "id"):
            if val.get(k) not in (None, ""):
                return str(val.get(k))
        return ""
    return str(val or "")


def normalize_audit_event(event: Mapping[str, Any]) -> CanonicalEvent:
    proto = event.get("protoPayload") if isinstance(event.get("protoPayload"), Mapping) else {}
    auth_info = proto.get("authenticationInfo") if isinstance(proto.get("authenticationInfo"), Mapping) else {}
    req_meta = proto.get("requestMetadata") if isinstance(proto.get("requestMetadata"), Mapping) else {}
    res_obj = event.get("resource") if isinstance(event.get("resource"), Mapping) else {}
    res_labels = res_obj.get("labels") if isinstance(res_obj.get("labels"), Mapping) else {}
    status_obj = proto.get("status") if isinstance(proto.get("status"), Mapping) else {}
    authz_list = proto.get("authorizationInfo") if isinstance(proto.get("authorizationInfo"), list) else []

    log_name = _scalar_text(event.get("logName"))
    service_name = _scalar_text(proto.get("serviceName")) or "googleapis.com"
    method_name = _scalar_text(proto.get("methodName")) or "UnknownGcpMethod"
    resource_name = _scalar_text(proto.get("resourceName"))
    principal = (
        _scalar_text(auth_info.get("principalEmail"))
        or _scalar_text(auth_info.get("principalSubject"))
        or _scalar_text(auth_info.get("serviceAccountKeyName"))
        or "unknown"
    )
    principal_type = (
        "ServiceAccount"
        if principal.endswith(".gserviceaccount.com") or auth_info.get("serviceAccountKeyName")
        else ("IAMUser" if "@" in principal else "Principal")
    )

    project_id = _project_from_resource(res_obj, resource_name, log_name)
    region = str(
        res_labels.get("location")
        or res_labels.get("zone")
        or res_labels.get("region")
        or "global"
    )
    source_ip = str(req_meta.get("callerIp") or "")
    user_agent = str(req_meta.get("callerSuppliedUserAgent") or "")

    # Determine outcome from status + authorizationInfo
    status_code = status_obj.get("code")
    denied_authz = any(isinstance(a, Mapping) and a.get("granted") is False for a in authz_list)
    if status_code == 7 or denied_authz or "policy" in log_name.lower():
        outcome = "denied"
    elif status_code not in (None, 0):
        outcome = "error"
    else:
        outcome = "success"

    ts = normalize_time(event.get("timestamp") or event.get("receiveTimestamp"))
    event_id = str(event.get("insertId") or "") or deterministic_event_id("gcp", event)
    source_type = _gcp_source_type(log_name, proto)
    sanitized = redact_mapping(dict(event))

    # Preserve native protoPayload alongside top-level canonical metadata cleanly
    return CanonicalEvent(
        event_id=event_id,
        event_time=ts,
        cloud_provider="gcp",
        source_type=source_type,
        account_scope=project_id,
        service=service_name,
        operation=method_name,
        principal=principal,
        principal_type=principal_type,
        source_ip=source_ip,
        user_agent=user_agent,
        resource=resource_name or str(res_labels.get("bucket_name") or ""),
        region=region,
        outcome=outcome,
        authentication_context={
            "principal_email": auth_info.get("principalEmail"),
            "service_account_key_name": auth_info.get("serviceAccountKeyName"),
            "authority_selector": auth_info.get("authoritySelector"),
        },
        request_metadata={
            "log_name": log_name,
            "severity": event.get("severity"),
            "authorization_info": redact_mapping(authz_list),
            "status_code": status_code,
        },
        raw=sanitized if isinstance(sanitized, dict) else {},
        extras={"resource_type": res_obj.get("type")},
    )


def _infer_gcp_http_operation(method: str, path: str, service: str) -> tuple[str, str]:
    m = method.upper()
    if "/serviceAccounts" in path and "/keys" in path and m == "POST":
        return "google.iam.admin.v1.CreateServiceAccountKey", "iam.googleapis.com"
    if ":setIamPolicy" in path:
        return (
            "google.cloud.resourcemanager.v3.Projects.SetIamPolicy" if "projects/" in path else "SetIamPolicy",
            f"{service}.googleapis.com" if "." not in service else service,
        )
    if path.startswith("/storage/v1/b/") or (service == "storage" and "/o" in path):
        if "/o/" in path and m == "GET":
            return "storage.objects.get", "storage.googleapis.com"
        if "/o" in path and m == "GET":
            return "storage.objects.list", "storage.googleapis.com"
        if m in {"POST", "PUT"}:
            return "storage.objects.create", "storage.googleapis.com"
        return "storage.buckets.get", "storage.googleapis.com"
    if ":access" in path and "secrets" in path:
        return "google.cloud.secretmanager.v1.SecretManagerService.AccessSecretVersion", "secretmanager.googleapis.com"
    if "/secrets" in path and m == "GET":
        return "google.cloud.secretmanager.v1.SecretManagerService.ListSecrets", "secretmanager.googleapis.com"
    if "/instances" in path and m == "GET":
        return "v1.compute.instances.list", "compute.googleapis.com"
    svc = f"{service}.googleapis.com" if service and "." not in service else (service or "googleapis.com")
    return f"{m}:{path}", svc


def parse_http_event(
    *,
    method: str,
    url_or_path: str,
    headers: Mapping[str, str],
    body_params: Mapping[str, Any],
    detected_service: str,
    target_host: str,
    client_ip: str,
    timestamp: str | None = None,
) -> CanonicalEvent:
    split = urlsplit(url_or_path)
    path = split.path or "/"
    lower_headers = {str(k).lower(): str(v) for k, v in headers.items()}

    service_short = detected_service or (target_host.split(".", 1)[0] if ".googleapis.com" in target_host else "gcp")
    method_name, service_fqdn = _infer_gcp_http_operation(method, path, service_short)
    m_proj = re.search(r"/projects/([^/]+)", path)
    project_id = lower_headers.get("x-goog-user-project") or (m_proj.group(1) if m_proj else "")
    principal = (
        lower_headers.get("x-identity-user")
        or lower_headers.get("x-goog-authenticated-user-email")
        or f"ip:{client_ip}"
    )
    user_agent = lower_headers.get("user-agent") or lower_headers.get("x-goog-api-client") or "unknown"
    ts = timestamp or datetime.now(timezone.utc).strftime(ISO)

    sanitized_params = redact_mapping(dict(body_params))
    raw_event = {
        "logName": f"projects/{project_id or 'proxy'}/logs/cloudaudit.googleapis.com%2Factivity",
        "timestamp": ts,
        "protoPayload": {
            "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
            "serviceName": service_fqdn,
            "methodName": method_name,
            "resourceName": path.lstrip("/"),
            "authenticationInfo": {"principalEmail": principal},
            "requestMetadata": {
                "callerIp": client_ip,
                "callerSuppliedUserAgent": user_agent,
            },
            "request": sanitized_params,
        },
        "resource": {"type": "audited_resource", "labels": {"project_id": project_id}},
        "httpRequest": {
            "method": method.upper(),
            "host": target_host,
            "path": path,
            "query": redact_query_string(split.query),
            "headers": redact_headers(headers),
        },
        "proxyCaptured": True,
    }
    event_id = deterministic_event_id("gcppx", {"ts": ts, "host": target_host, "method": method_name, "principal": principal, "path": path, "nonce": uuid.uuid4().hex})
    raw_event["insertId"] = event_id

    return CanonicalEvent(
        event_id=event_id,
        event_time=ts,
        cloud_provider="gcp",
        source_type="cloud_api",
        account_scope=project_id,
        service=service_fqdn,
        operation=method_name,
        principal=principal,
        principal_type="ServiceAccount" if ".gserviceaccount.com" in principal else "Principal",
        source_ip=client_ip,
        user_agent=user_agent,
        resource=path.lstrip("/"),
        region="global",
        outcome="unknown",
        authentication_context={
            "x_goog_user_project": project_id or None,
            "has_bearer_auth": lower_headers.get("authorization", "").lower().startswith("bearer "),
        },
        request_metadata={"method": method.upper(), "host": target_host, "path": path, "params": sanitized_params},
        raw=raw_event,
    )
