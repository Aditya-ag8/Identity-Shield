"""Microsoft Azure (Activity Logs, Entra Sign-In Logs, Entra Audit Logs & ARM/Graph API) adapter."""

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
        provider="azure",
        display_name="Microsoft Azure & Entra ID",
        audit_log_formats=("azure_activity", "entra_signin", "entra_audit"),
        proxy_api_inspection=True,
        connect_metadata_only=True,
        synthetic_variants=True,
        live_sdk_available=importlib.util.find_spec("azure") is not None,
        supported_factors=(
            "identity_context",
            "network_origin",
            "client_tool",
            "timing",
            "api_form",
        ),
        unsupported_notes=(
            "Offline Activity/Entra log normalization and synthetic 5-factor variants are built-in.",
            "Live Azure execution requires optional azure-* SDKs / az CLI and explicit subscription authorization.",
            "HTTPS CONNECT without TLS interception inspects destination metadata only.",
        ),
    )


def _azure_log_kind(item: Mapping[str, Any]) -> str | None:
    if not isinstance(item, Mapping):
        return None
    if "activityDisplayName" in item or "initiatedBy" in item or "targetResources" in item:
        return "entra_audit"
    if (
        "userPrincipalName" in item
        or "conditionalAccessStatus" in item
        or "clientAppUsed" in item
        or ("appId" in item and "status" in item and ("createdDateTime" in item or "ipAddress" in item))
    ):
        return "entra_signin"
    if (
        "operationName" in item
        or "resourceId" in item
        or (isinstance(item.get("properties"), Mapping) and "resourceId" in item["properties"])
        or str(item.get("category") or "") in {"Administrative", "Security", "Policy", "ServiceHealth"}
    ):
        return "azure_activity"
    return None


def is_azure_audit_event(item: Mapping[str, Any]) -> bool:
    return _azure_log_kind(item) is not None


def extract_events(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        out: list[dict[str, Any]] = []
        for item in payload:
            out.extend(extract_events(item))
        return out
    if isinstance(payload, Mapping):
        for key in ("value", "records"):
            items = payload.get(key)
            if isinstance(items, list):
                out = []
                for item in items:
                    out.extend(extract_events(item))
                return out
        if is_azure_audit_event(payload):
            return [dict(payload)]
    return []


def _extract_value(obj: Any) -> str:
    if isinstance(obj, Mapping):
        return str(
            obj.get("value")
            or obj.get("localizedValue")
            or obj.get("upn")
            or obj.get("userPrincipalName")
            or obj.get("email")
            or obj.get("displayName")
            or obj.get("id")
            or ""
        )
    return str(obj or "")


def _subscription_from_resource_id(resource_id: str) -> str:
    m = re.search(r"/subscriptions/([^/]+)", str(resource_id or ""), re.IGNORECASE)
    return m.group(1) if m else ""


def _normalize_activity_log(event: Mapping[str, Any]) -> CanonicalEvent:
    props = event.get("properties") if isinstance(event.get("properties"), Mapping) else {}
    claims = event.get("claims") if isinstance(event.get("claims"), Mapping) else (
        props.get("claims") if isinstance(props.get("claims"), Mapping) else {}
    )
    identity = event.get("identity") if isinstance(event.get("identity"), Mapping) else {}
    http_req = event.get("httpRequest") if isinstance(event.get("httpRequest"), Mapping) else {}

    op_name = _extract_value(event.get("operationName") or props.get("message") or "UnknownAzureOperation")
    resource_id = str(event.get("resourceId") or props.get("resourceId") or "")
    subscription_id = str(
        event.get("subscriptionId")
        or _subscription_from_resource_id(resource_id)
        or event.get("tenantId")
        or ""
    )
    tenant_id = str(event.get("tenantId") or claims.get("http://schemas.microsoft.com/identity/claims/tenantid") or "")
    raw_caller = event.get("caller")
    caller_str = _extract_value(raw_caller) if isinstance(raw_caller, Mapping) else str(raw_caller or "")
    caller = (
        caller_str
        or str(claims.get("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn") or "")
        or str(claims.get("appid") or "")
        or str((identity.get("authorization") or {}).get("scope") if isinstance(identity.get("authorization"), Mapping) else "")
        or "unknown"
    )
    principal_type = "ServicePrincipal" if (claims.get("appid") and "@" not in caller) else "AzurePrincipal"
    source_ip = str(event.get("callerIpAddress") or http_req.get("clientIpAddress") or "")
    user_agent = str(http_req.get("clientRequestId") or props.get("userAgent") or "")
    status_val = _extract_value(event.get("status") or event.get("activityStatus") or event.get("resultType") or "")
    sub_status = _extract_value(event.get("subStatus") or "")
    lower_status = f"{status_val} {sub_status}".lower()
    if any(k in lower_status for k in ("forbidden", "unauthorized", "denied", "403")):
        outcome = "denied"
    elif "fail" in lower_status or "error" in lower_status:
        outcome = "error"
    elif any(k in lower_status for k in ("succeed", "accept", "ok", "start")):
        outcome = "success"
    else:
        outcome = "unknown"

    provider_seg = ""
    m_prov = re.search(r"/providers/([^/]+)", resource_id, re.IGNORECASE)
    if m_prov:
        provider_seg = m_prov.group(1)
    elif "/" in op_name:
        provider_seg = op_name.split("/", 1)[0]

    ts = normalize_time(event.get("eventTimestamp") or event.get("time"))
    event_id = str(event.get("eventDataId") or event.get("id") or "") or deterministic_event_id("azact", event)
    sanitized = redact_mapping(dict(event))

    return CanonicalEvent(
        event_id=event_id,
        event_time=ts,
        cloud_provider="azure",
        source_type="azure_activity",
        account_scope=subscription_id or tenant_id,
        service=provider_seg or "Microsoft.Resources",
        operation=op_name,
        principal=caller,
        principal_type=principal_type,
        source_ip=source_ip,
        user_agent=user_agent,
        resource=resource_id,
        region=str(event.get("resourceLocation") or "global"),
        outcome=outcome,
        authentication_context={
            "tenant_id": tenant_id or None,
            "appid": claims.get("appid"),
            "object_id": claims.get("http://schemas.microsoft.com/identity/claims/objectidentifier"),
            "claims_present": sorted(str(k) for k in claims.keys())[:15],
        },
        request_metadata={
            "category": _extract_value(event.get("category")),
            "status": status_val or None,
            "sub_status": sub_status or None,
            "correlation_id": event.get("correlationId"),
        },
        raw=sanitized if isinstance(sanitized, dict) else {},
    )


def _normalize_entra_signin_log(event: Mapping[str, Any]) -> CanonicalEvent:
    status_obj = event.get("status") if isinstance(event.get("status"), Mapping) else {}
    location = event.get("location") if isinstance(event.get("location"), Mapping) else {}
    err_code = status_obj.get("errorCode")
    ca_status = str(event.get("conditionalAccessStatus") or "")

    if err_code in (None, 0):
        outcome = "success"
    elif "block" in ca_status.lower() or "denied" in str(status_obj.get("failureReason") or "").lower():
        outcome = "denied"
    else:
        outcome = "error"

    principal = (
        _extract_value(event.get("userPrincipalName"))
        or _extract_value(event.get("servicePrincipalName"))
        or _extract_value(event.get("userId"))
        or _extract_value(event.get("servicePrincipalId"))
        or _extract_value(event.get("appDisplayName"))
        or "unknown"
    )
    principal_type = "ServicePrincipal" if event.get("servicePrincipalId") and not event.get("userPrincipalName") else "EntraUser"
    tenant_id = _extract_value(event.get("tenantId") or event.get("homeTenantId"))
    ts = normalize_time(event.get("createdDateTime") or event.get("time"))
    event_id = str(event.get("id") or "") or deterministic_event_id("azsi", event)
    sanitized = redact_mapping(dict(event))

    return CanonicalEvent(
        event_id=event_id,
        event_time=ts,
        cloud_provider="azure",
        source_type="entra_signin",
        account_scope=tenant_id,
        service="Microsoft.EntraID",
        operation="UserSignIn" if principal_type == "EntraUser" else "ServicePrincipalSignIn",
        principal=principal,
        principal_type=principal_type,
        source_ip=str(event.get("ipAddress") or ""),
        user_agent=str(event.get("userAgent") or event.get("clientAppUsed") or ""),
        resource=str(event.get("resourceDisplayName") or event.get("resourceId") or "Microsoft Entra ID"),
        region=str(location.get("countryOrRegion") or "global"),
        outcome=outcome,
        authentication_context={
            "conditional_access_status": ca_status or None,
            "client_app_used": event.get("clientAppUsed"),
            "mfa_detail": redact_mapping(event.get("mfaDetail")) if event.get("mfaDetail") else None,
            "risk_level": event.get("riskLevelDuringSignIn") or event.get("riskLevelAggregated"),
        },
        request_metadata={
            "category": str(event.get("category") or "SignInLogs"),
            "app_display_name": event.get("appDisplayName"),
            "error_code": err_code,
            "failure_reason": status_obj.get("failureReason"),
        },
        raw=sanitized if isinstance(sanitized, dict) else {},
    )


def _normalize_entra_audit_log(event: Mapping[str, Any]) -> CanonicalEvent:
    initiated = event.get("initiatedBy") if isinstance(event.get("initiatedBy"), Mapping) else {}
    user_init = initiated.get("user") if isinstance(initiated.get("user"), Mapping) else {}
    app_init = initiated.get("app") if isinstance(initiated.get("app"), Mapping) else {}
    targets = event.get("targetResources") if isinstance(event.get("targetResources"), list) else []

    principal = (
        _extract_value(user_init.get("userPrincipalName"))
        or _extract_value(user_init.get("id"))
        or _extract_value(app_init.get("displayName"))
        or _extract_value(app_init.get("servicePrincipalId"))
        or "unknown"
    )
    principal_type = "ServicePrincipal" if app_init and not user_init else "EntraUser"
    first_target = targets[0] if targets and isinstance(targets[0], Mapping) else {}
    resource = (
        _extract_value(first_target.get("userPrincipalName"))
        or _extract_value(first_target.get("displayName"))
        or _extract_value(first_target.get("id"))
        or ""
    )

    result = _extract_value(event.get("result")).lower()
    if "fail" in result:
        outcome = "error"
    elif "denied" in _extract_value(event.get("resultReason")).lower():
        outcome = "denied"
    elif result == "success":
        outcome = "success"
    else:
        outcome = "unknown"

    tenant_id = _extract_value(event.get("tenantId"))
    ts = normalize_time(event.get("activityDateTime") or event.get("time"))
    event_id = _extract_value(event.get("id")) or deterministic_event_id("azau", event)
    sanitized = redact_mapping(dict(event))

    return CanonicalEvent(
        event_id=event_id,
        event_time=ts,
        cloud_provider="azure",
        source_type="entra_audit",
        account_scope=tenant_id,
        service="Microsoft.EntraID",
        operation=_extract_value(event.get("activityDisplayName")) or "EntraDirectoryAudit",
        principal=principal,
        principal_type=principal_type,
        source_ip=str(user_init.get("ipAddress") or ""),
        user_agent=str(event.get("loggedByService") or "Microsoft Entra ID"),
        resource=resource,
        region="global",
        outcome=outcome,
        authentication_context={"initiated_by": redact_mapping(initiated)},
        request_metadata={
            "category": str(event.get("category") or "AuditLogs"),
            "operation_type": event.get("operationType"),
            "result_reason": event.get("resultReason"),
        },
        raw=sanitized if isinstance(sanitized, dict) else {},
    )


def normalize_audit_event(event: Mapping[str, Any]) -> CanonicalEvent:
    kind = _azure_log_kind(event)
    if kind == "entra_signin":
        return _normalize_entra_signin_log(event)
    if kind == "entra_audit":
        return _normalize_entra_audit_log(event)
    return _normalize_activity_log(event)


def _infer_azure_http_operation(method: str, path: str, host: str) -> tuple[str, str]:
    m = method.upper()
    lower = path.lower()
    if "roleassignments" in lower:
        verb = "write" if m in {"PUT", "POST"} else ("delete" if m == "DELETE" else "read")
        return f"Microsoft.Authorization/roleAssignments/{verb}", "Microsoft.Authorization"
    if "serviceprincipals" in lower and ("addpassword" in lower or "addkey" in lower):
        return "Add service principal credentials", "Microsoft.EntraID"
    if ".vault.azure.net" in host.lower() and "/secrets" in lower:
        return ("SecretList" if m == "GET" and lower.rstrip("/").endswith("/secrets") else "SecretGet"), "Microsoft.KeyVault"
    if "/virtualmachines" in lower:
        return "Microsoft.Compute/virtualMachines/read" if m == "GET" else "Microsoft.Compute/virtualMachines/write", "Microsoft.Compute"
    if "graph.microsoft.com" in host.lower() and "/users" in lower:
        return "List users" if m == "GET" else "Update user", "Microsoft.EntraID"
    return f"{m}:{path}", host or "management.azure.com"


def parse_http_event(
    *,
    method: str,
    url_or_path: str,
    headers: Mapping[str, str],
    body_params: Mapping[str, Any],
    target_host: str,
    client_ip: str,
    timestamp: str | None = None,
) -> CanonicalEvent:
    split = urlsplit(url_or_path)
    path = split.path or "/"
    lower_headers = {str(k).lower(): str(v) for k, v in headers.items()}

    operation, service = _infer_azure_http_operation(method, path, target_host)
    sub_id = _subscription_from_resource_id(path)
    principal = lower_headers.get("x-identity-user") or lower_headers.get("x-ms-client-principal-name") or f"ip:{client_ip}"
    user_agent = lower_headers.get("user-agent") or "unknown"
    ts = timestamp or datetime.now(timezone.utc).strftime(ISO)
    sanitized_params = redact_mapping(dict(body_params))

    raw_event = {
        "time": ts,
        "eventTimestamp": ts,
        "operationName": {"value": operation, "localizedValue": operation},
        "category": {"value": "Administrative"},
        "caller": principal,
        "callerIpAddress": client_ip,
        "resourceId": path,
        "subscriptionId": sub_id,
        "httpRequest": {
            "method": method.upper(),
            "host": target_host,
            "path": path,
            "query": redact_query_string(split.query),
            "headers": redact_headers(headers),
            "clientIpAddress": client_ip,
        },
        "properties": {"params": sanitized_params, "userAgent": user_agent},
        "proxyCaptured": True,
    }
    event_id = deterministic_event_id("azpx", {"ts": ts, "host": target_host, "op": operation, "principal": principal, "path": path, "nonce": uuid.uuid4().hex})
    raw_event["eventDataId"] = event_id

    return CanonicalEvent(
        event_id=event_id,
        event_time=ts,
        cloud_provider="azure",
        source_type="cloud_api",
        account_scope=sub_id,
        service=service,
        operation=operation,
        principal=principal,
        principal_type="EntraUser" if "@" in principal else "ServicePrincipal",
        source_ip=client_ip,
        user_agent=user_agent,
        resource=path,
        region="global",
        outcome="unknown",
        authentication_context={
            "has_bearer_auth": lower_headers.get("authorization", "").lower().startswith("bearer "),
            "subscription_id": sub_id or None,
        },
        request_metadata={"method": method.upper(), "host": target_host, "path": path, "params": sanitized_params},
        raw=raw_event,
    )
