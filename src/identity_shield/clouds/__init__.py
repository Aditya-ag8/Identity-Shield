"""Multi-cloud provider adapters, request classifier, and canonical event normalization."""

from .classifier import classify_traffic
from .models import (
    CANONICAL_SCHEMA_VERSION,
    CLOUD_PROVIDERS,
    TRAFFIC_TYPES,
    CanonicalEvent,
    ClassificationResult,
    ProviderCapabilities,
)
from .redaction import redact_headers, redact_mapping, redact_query_string, redact_text
from .registry import (
    CloudProviderSpec,
    detect_and_normalize_audit_payload,
    extract_audit_events,
    get_provider,
    list_provider_capabilities,
    list_providers,
    parse_cloud_http_request,
    register_provider,
)

__all__ = [
    "CANONICAL_SCHEMA_VERSION",
    "CLOUD_PROVIDERS",
    "CloudProviderSpec",
    "TRAFFIC_TYPES",
    "CanonicalEvent",
    "ClassificationResult",
    "ProviderCapabilities",
    "classify_traffic",
    "detect_and_normalize_audit_payload",
    "extract_audit_events",
    "get_provider",
    "list_provider_capabilities",
    "list_providers",
    "parse_cloud_http_request",
    "redact_headers",
    "redact_mapping",
    "redact_query_string",
    "redact_text",
    "register_provider",
]
