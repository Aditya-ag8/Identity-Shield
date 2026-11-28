"""Cloud provider registry & multi-cloud audit/HTTP routing helpers."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Mapping

from identity_shield.clouds import aws as aws_adapter
from identity_shield.clouds import azure as azure_adapter
from identity_shield.clouds import gcp as gcp_adapter
from identity_shield.clouds.classifier import classify_traffic
from identity_shield.clouds.models import CanonicalEvent, ClassificationResult, ProviderCapabilities


@dataclass(frozen=True)
class CloudProviderSpec:
    cloud_id: str
    capabilities_fn: Callable[[], ProviderCapabilities]
    extract_events_fn: Callable[[Any], list[dict[str, Any]]]
    normalize_audit_fn: Callable[[Mapping[str, Any]], CanonicalEvent]
    is_audit_event_fn: Callable[[Mapping[str, Any]], bool]


_REGISTRY: dict[str, CloudProviderSpec] = {
    "aws": CloudProviderSpec(
        cloud_id="aws",
        capabilities_fn=aws_adapter.capabilities,
        extract_events_fn=aws_adapter.extract_events,
        normalize_audit_fn=aws_adapter.normalize_audit_event,
        is_audit_event_fn=aws_adapter.is_aws_audit_event,
    ),
    "gcp": CloudProviderSpec(
        cloud_id="gcp",
        capabilities_fn=gcp_adapter.capabilities,
        extract_events_fn=gcp_adapter.extract_events,
        normalize_audit_fn=gcp_adapter.normalize_audit_event,
        is_audit_event_fn=gcp_adapter.is_gcp_audit_event,
    ),
    "azure": CloudProviderSpec(
        cloud_id="azure",
        capabilities_fn=azure_adapter.capabilities,
        extract_events_fn=azure_adapter.extract_events,
        normalize_audit_fn=azure_adapter.normalize_audit_event,
        is_audit_event_fn=azure_adapter.is_azure_audit_event,
    ),
}


def list_providers() -> tuple[str, ...]:
    return tuple(_REGISTRY.keys())


def register_provider(spec: CloudProviderSpec) -> CloudProviderSpec:
    """Register or override a custom cloud provider adapter dynamically."""
    key = str(spec.cloud_id or "").strip().lower()
    if not key:
        raise ValueError("cloud_id must be non-empty")
    _REGISTRY[key] = spec
    return spec


def get_provider(cloud_id: str) -> CloudProviderSpec:
    key = str(cloud_id or "").strip().lower()
    if key not in _REGISTRY:
        raise ValueError(f"Unsupported cloud provider {cloud_id!r}; expected one of {sorted(_REGISTRY)}")
    return _REGISTRY[key]


def list_provider_capabilities() -> list[dict[str, Any]]:
    return [spec.capabilities_fn().to_dict() for spec in _REGISTRY.values()]


def _iter_raw_candidates(payload: Any) -> list[Any]:
    if isinstance(payload, list):
        out: list[Any] = []
        for elem in payload:
            out.extend(_iter_raw_candidates(elem))
        return out
    if isinstance(payload, Mapping):
        for container_key in ("Records", "entries", "items", "value", "records"):
            sub = payload.get(container_key)
            if isinstance(sub, list):
                out = []
                for elem in sub:
                    out.extend(_iter_raw_candidates(elem))
                return out
        return [payload]
    return []


def extract_audit_events(payload: Any, *, cloud_provider: str | None = None) -> list[tuple[str, dict[str, Any]]]:
    """Extract raw audit items paired with their detected or forced cloud provider."""
    if cloud_provider and cloud_provider != "auto":
        spec = get_provider(cloud_provider)
        return [(spec.cloud_id, item) for item in spec.extract_events_fn(payload)]

    order = [cid for cid in ("gcp", "azure", "aws") if cid in _REGISTRY] + [
        cid for cid in _REGISTRY if cid not in {"gcp", "azure", "aws"}
    ]
    results: list[tuple[str, dict[str, Any]]] = []
    # Classify each candidate record independently so mixed-cloud batches never drop trailing providers.
    for candidate in _iter_raw_candidates(payload):
        for cid in order:
            spec = _REGISTRY[cid]
            extracted = spec.extract_events_fn(candidate)
            if extracted:
                for item in extracted:
                    results.append((cid, item))
                break
    return results


def detect_and_normalize_audit_payload(
    payload: Any,
    *,
    cloud_provider: str | None = None,
) -> list[CanonicalEvent]:
    """Normalize AWS CloudTrail, GCP Audit Logs, or Azure Activity/Entra payloads cleanly."""
    pairs = extract_audit_events(payload, cloud_provider=cloud_provider)
    normalized: list[CanonicalEvent] = []
    for cid, item in pairs:
        spec = get_provider(cid)
        evt = spec.normalize_audit_fn(item)
        evt.validate()
        normalized.append(evt)
    return normalized


def parse_cloud_http_request(
    *,
    method: str,
    url_or_path: str,
    headers: Mapping[str, str],
    body_params: Mapping[str, Any],
    sigv4: Mapping[str, str],
    target_host: str,
    client_ip: str,
    body: bytes = b"",
    timestamp: str | None = None,
) -> tuple[ClassificationResult, CanonicalEvent | None]:
    """Classify an HTTP request and dispatch to the matching cloud HTTP parser when applicable."""
    classification = classify_traffic(
        method=method,
        url_or_path=url_or_path,
        headers=headers,
        body=body,
        host_override=target_host or None,
        is_connect=False,
    )
    if classification.cloud_provider == "aws" and classification.traffic_type == "cloud_api":
        return (
            classification,
            aws_adapter.parse_http_event(
                method=method,
                url_or_path=url_or_path,
                headers=headers,
                body_params=body_params,
                sigv4=sigv4,
                target_host=target_host,
                client_ip=client_ip,
                timestamp=timestamp,
            ),
        )
    if classification.cloud_provider == "gcp" and classification.traffic_type == "cloud_api":
        return (
            classification,
            gcp_adapter.parse_http_event(
                method=method,
                url_or_path=url_or_path,
                headers=headers,
                body_params=body_params,
                detected_service=classification.detected_service,
                target_host=target_host,
                client_ip=client_ip,
                timestamp=timestamp,
            ),
        )
    if classification.cloud_provider == "azure" and classification.traffic_type == "cloud_api":
        return (
            classification,
            azure_adapter.parse_http_event(
                method=method,
                url_or_path=url_or_path,
                headers=headers,
                body_params=body_params,
                target_host=target_host,
                client_ip=client_ip,
                timestamp=timestamp,
            ),
        )
    return classification, None
