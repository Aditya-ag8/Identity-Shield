"""Canonical multi-cloud security contracts and provider capability descriptors."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Mapping

from identity_shield.clouds.redaction import redact_mapping

CANONICAL_SCHEMA_VERSION = "1.0"
CLOUD_PROVIDERS = ("aws", "gcp", "azure", "unknown")
TRAFFIC_TYPES = ("cloud_api", "http_app", "connect_tunnel")


@dataclass(frozen=True, slots=True)
class ClassificationResult:
    """Output of Stage-1 multi-signal cloud traffic classification."""

    cloud_provider: str
    traffic_type: str
    confidence: str  # high | medium | low
    reason: str
    destination_host: str
    detected_service: str = ""
    signals: tuple[str, ...] = ()
    conflicting_providers: tuple[str, ...] = ()

    @property
    def legacy_traffic_kind(self) -> str:
        """Backward-compatible proxy traffic_kind string preserving AWS/HTTP values."""
        if self.traffic_type == "connect_tunnel":
            return "connect_tunnel"
        if self.traffic_type == "cloud_api" and self.cloud_provider in {"aws", "gcp", "azure"}:
            return f"{self.cloud_provider}_api"
        return "http_app"

    def to_dict(self) -> dict[str, Any]:
        return {
            "cloud_provider": self.cloud_provider,
            "traffic_type": self.traffic_type,
            "legacy_traffic_kind": self.legacy_traffic_kind,
            "confidence": self.confidence,
            "reason": self.reason,
            "destination_host": self.destination_host,
            "detected_service": self.detected_service,
            "signals": list(self.signals),
            "conflicting_providers": list(self.conflicting_providers),
        }


@dataclass(frozen=True, slots=True)
class ProviderCapabilities:
    """Honest capability declaration per cloud provider."""

    provider: str
    display_name: str
    audit_log_formats: tuple[str, ...]
    proxy_api_inspection: bool
    connect_metadata_only: bool
    synthetic_variants: bool
    live_sdk_available: bool
    supported_factors: tuple[str, ...]
    unsupported_notes: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "display_name": self.display_name,
            "audit_log_formats": list(self.audit_log_formats),
            "proxy_api_inspection": self.proxy_api_inspection,
            "connect_metadata_only": self.connect_metadata_only,
            "synthetic_variants": self.synthetic_variants,
            "live_sdk_available": self.live_sdk_available,
            "supported_factors": list(self.supported_factors),
            "unsupported_notes": list(self.unsupported_notes),
        }


@dataclass(frozen=True, slots=True)
class CanonicalEvent:
    """Versioned canonical security event normalized across AWS, GCP, Azure, and HTTP."""

    event_id: str
    event_time: str
    cloud_provider: str
    source_type: str
    account_scope: str
    service: str
    operation: str
    principal: str
    principal_type: str
    source_ip: str
    user_agent: str
    resource: str
    region: str
    outcome: str
    authentication_context: Mapping[str, Any] = field(default_factory=dict)
    request_metadata: Mapping[str, Any] = field(default_factory=dict)
    raw: Mapping[str, Any] = field(default_factory=dict)
    schema_version: str = CANONICAL_SCHEMA_VERSION
    extras: Mapping[str, Any] = field(default_factory=dict)

    def profile_key(self) -> str:
        """Globally scoped behavioral profile key preventing cross-cloud collisions."""
        return f"{self.cloud_provider}:{self.account_scope}:{self.principal or 'unknown'}"

    def validate(self) -> None:
        if self.cloud_provider not in CLOUD_PROVIDERS:
            raise ValueError(f"Unsupported cloud_provider {self.cloud_provider!r}")
        if not self.event_id:
            raise ValueError("CanonicalEvent.event_id must be non-empty")
        if not self.event_time:
            raise ValueError("CanonicalEvent.event_time must be non-empty")
        if not self.schema_version:
            raise ValueError("CanonicalEvent.schema_version must be non-empty")

    def sanitized_raw(self) -> dict[str, Any]:
        redacted = redact_mapping(dict(self.raw))
        return redacted if isinstance(redacted, dict) else {"value": redacted}

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "event_id": self.event_id,
            "event_time": self.event_time,
            "cloud_provider": self.cloud_provider,
            "source_type": self.source_type,
            "account_scope": self.account_scope,
            "service": self.service,
            "operation": self.operation,
            "principal": self.principal,
            "principal_type": self.principal_type,
            "source_ip": self.source_ip,
            "user_agent": self.user_agent,
            "resource": self.resource,
            "region": self.region,
            "outcome": self.outcome,
            "authentication_context": redact_mapping(dict(self.authentication_context)),
            "request_metadata": redact_mapping(dict(self.request_metadata)),
            "extras": redact_mapping(dict(self.extras)),
            "raw": self.sanitized_raw(),
        }

    def to_sigma_event(self) -> dict[str, Any]:
        """Return an evaluation dict exposing both sanitized native fields and canonical aliases.

        Native AWS CloudTrail rules evaluate against existing keys identically; GCP/Azure
        and cross-cloud Sigma rules can match either native fields (`protoPayload.*`,
        `operationName`, `activityDisplayName`) or canonical keys (`cloudProvider`,
        `eventName`, `eventSource`, `sourceIPAddress`, `userAgent`).
        """
        doc = self.sanitized_raw()
        doc.setdefault("cloudProvider", self.cloud_provider)
        doc.setdefault("sourceType", self.source_type)
        doc.setdefault("accountScope", self.account_scope)
        doc.setdefault("eventID", self.event_id)
        doc.setdefault("eventTime", self.event_time)
        if self.cloud_provider == "aws":
            doc.setdefault("eventSource", f"{self.service}.amazonaws.com" if self.service else "aws")
        elif self.cloud_provider == "gcp":
            doc.setdefault("eventSource", self.service or "googleapis.com")
        elif self.cloud_provider == "azure":
            doc.setdefault("eventSource", self.service or "management.azure.com")
        else:
            doc.setdefault("eventSource", self.service or "http_app")
        doc.setdefault("eventName", self.operation)
        doc.setdefault("awsRegion", self.region)
        doc.setdefault("region", self.region)
        doc.setdefault("sourceIPAddress", self.source_ip)
        doc.setdefault("userAgent", self.user_agent)
        doc.setdefault("resource", self.resource)
        doc.setdefault("outcome", self.outcome)
        if "userIdentity" not in doc:
            doc["userIdentity"] = {
                "type": self.principal_type,
                "principalId": self.principal,
                "arn": self.principal,
            }
        return doc


def deterministic_event_id(prefix: str, payload: Mapping[str, Any]) -> str:
    canonical = json.dumps(redact_mapping(dict(payload)), sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    digest = hashlib.sha256(f"{prefix}|{canonical}".encode("utf-8")).hexdigest()[:28]
    return f"{prefix}-{digest}"
