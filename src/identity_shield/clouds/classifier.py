"""Stage-1 Multi-Signal Cloud Traffic Classifier (`aws`, `gcp`, `azure`, `unknown`).

Separates cloud provider identity from traffic type (`cloud_api`, `http_app`,
`connect_tunnel`), handles conflicting signals safely, and never logs secrets.
"""

from __future__ import annotations

import re
from typing import Mapping
from urllib.parse import parse_qs, urlsplit

from identity_shield.clouds.models import ClassificationResult

_GCP_SERVICE_HOSTS = {
    "iam.googleapis.com": "iam",
    "iamcredentials.googleapis.com": "iamcredentials",
    "storage.googleapis.com": "storage",
    "compute.googleapis.com": "compute",
    "secretmanager.googleapis.com": "secretmanager",
    "cloudresourcemanager.googleapis.com": "cloudresourcemanager",
    "container.googleapis.com": "container",
    "cloudfunctions.googleapis.com": "cloudfunctions",
    "logging.googleapis.com": "logging",
    "sts.googleapis.com": "sts",
}

_AZURE_HOST_SERVICE = (
    ("management.azure.com", "arm"),
    ("graph.microsoft.com", "graph"),
    ("login.microsoftonline.com", "entra_auth"),
    (".vault.azure.net", "keyvault"),
    (".blob.core.windows.net", "storage_blob"),
    (".queue.core.windows.net", "storage_queue"),
    (".table.core.windows.net", "storage_table"),
    (".azurecr.io", "acr"),
)

_AWS_HOST_RE = re.compile(
    r"^(?:([a-z0-9-]+)\.)?(?:([a-z]{2}-[a-z]+-\d)\.)?(amazonaws\.com(?:\.cn)?|aws\.amazon\.com)$"
)
_GCP_HOST_RE = re.compile(r"^(?:([a-z0-9-]+)\.)?googleapis\.com$")


def _host_without_port(raw_host: str) -> str:
    cleaned = str(raw_host or "").strip().lower()
    if not cleaned:
        return ""
    if cleaned.startswith("["):
        return cleaned.split("]", 1)[0].lstrip("[")
    return cleaned.split(":", 1)[0]


def _aws_service_from_host(host: str) -> str:
    m = _AWS_HOST_RE.match(host)
    if not m or not m.group(1):
        return ""
    sub = m.group(1)
    if sub.startswith("s3"):
        return "s3"
    return sub


def classify_traffic(
    *,
    method: str = "GET",
    url_or_path: str = "/",
    headers: Mapping[str, str] | None = None,
    body: bytes = b"",
    host_override: str | None = None,
    is_connect: bool = False,
) -> ClassificationResult:
    """Classify incoming request into `(cloud_provider, traffic_type)` using multi-signal scoring."""
    lower_headers = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
    split = urlsplit(str(url_or_path or "/"))
    path = split.path or "/"
    query = parse_qs(split.query)

    raw_host = host_override or split.netloc or lower_headers.get("host") or (str(url_or_path) if is_connect else "")
    host = _host_without_port(raw_host)

    auth_scheme = lower_headers.get("authorization", "").strip()
    auth_lower = auth_scheme.lower()
    body_preview = ""
    if body:
        try:
            body_preview = body[:2048].decode("utf-8", errors="ignore")
        except Exception:
            body_preview = ""

    scores: dict[str, int] = {"aws": 0, "gcp": 0, "azure": 0}
    signals: dict[str, list[str]] = {"aws": [], "gcp": [], "azure": []}
    detected_services: dict[str, str] = {"aws": "", "gcp": "", "azure": ""}

    # --- 1. Host signals ---
    aws_host_svc = _aws_service_from_host(host)
    if aws_host_svc or host.endswith(".amazonaws.com") or host == "amazonaws.com":
        scores["aws"] += 6
        signals["aws"].append(f"host:{host}")
        detected_services["aws"] = aws_host_svc or "aws"

    if host in _GCP_SERVICE_HOSTS or host.endswith(".googleapis.com") or host.endswith(".pkg.dev"):
        scores["gcp"] += 6
        signals["gcp"].append(f"host:{host}")
        detected_services["gcp"] = _GCP_SERVICE_HOSTS.get(host) or host.split(".", 1)[0]

    for suffix_or_host, svc_name in _AZURE_HOST_SERVICE:
        if (suffix_or_host.startswith(".") and host.endswith(suffix_or_host)) or host == suffix_or_host:
            scores["azure"] += 6
            signals["azure"].append(f"host:{host}")
            detected_services["azure"] = svc_name
            break

    # --- 2. Header conventions (never reading/logging raw credential values) ---
    if auth_lower.startswith("aws4-hmac-sha256") and "aws4_request" in auth_lower:
        scores["aws"] += 5
        signals["aws"].append("auth:sigv4")
    if any(k.startswith("x-amz-") for k in lower_headers):
        scores["aws"] += 4
        signals["aws"].append("headers:x-amz-*")
    target = lower_headers.get("x-amz-target", "")
    if target:
        scores["aws"] += 3
        signals["aws"].append("header:x-amz-target")
        if "." in target and not detected_services["aws"]:
            detected_services["aws"] = target.split(".", 1)[0].lower().removeprefix("aws")

    if any(k.startswith("x-goog-") for k in lower_headers):
        scores["gcp"] += 5
        signals["gcp"].append("headers:x-goog-*")

    if any(k.startswith("x-ms-") for k in lower_headers) or "ocp-apim-subscription-key" in lower_headers:
        scores["azure"] += 5
        signals["azure"].append("headers:x-ms-*")

    # Non-secret User-Agent hints (weak auxiliary signal)
    ua_lower = lower_headers.get("user-agent", "").lower()
    if any(tok in ua_lower for tok in ("boto3/", "botocore/", "aws-cli/")):
        scores["aws"] += 2
        signals["aws"].append("ua:aws-sdk")
    if any(tok in ua_lower for tok in ("google-cloud-sdk", "gcloud/", "google-api-python-client")):
        scores["gcp"] += 2
        signals["gcp"].append("ua:gcp-sdk")
    if any(tok in ua_lower for tok in ("azsdk-python", "azure-cli", "azure-powershell")):
        scores["azure"] += 2
        signals["azure"].append("ua:azure-sdk")

    # --- 3. Path / Query / Request Shape signals ---
    if "Action" in query or ("Action=" in body_preview and "Version=" in body_preview):
        scores["aws"] += 3
        signals["aws"].append("shape:aws-query-action")

    if re.search(r"/(?:v1|v1beta\d*|v2)/projects/[^/]+", path) or path.startswith("/storage/v1/"):
        scores["gcp"] += 4
        signals["gcp"].append("path:gcp-resource-rest")
        if not detected_services["gcp"]:
            if "/storage/" in path:
                detected_services["gcp"] = "storage"
            elif "/serviceAccounts" in path or ":setIamPolicy" in path or ":getIamPolicy" in path:
                detected_services["gcp"] = "iam"
            elif "/secrets" in path:
                detected_services["gcp"] = "secretmanager"
            elif "/instances" in path:
                detected_services["gcp"] = "compute"

    if re.search(r"/subscriptions/[^/]+/(?:resourceGroups/[^/]+/)?providers/Microsoft\.", path, re.IGNORECASE):
        scores["azure"] += 5
        signals["azure"].append("path:azure-arm-provider")
        if not detected_services["azure"]:
            detected_services["azure"] = "arm"
    elif path.startswith("/v1.0/") and (host == "graph.microsoft.com" or any(k.startswith("x-ms-") for k in lower_headers)):
        scores["azure"] += 4
        signals["azure"].append("path:ms-graph")
        detected_services["azure"] = detected_services["azure"] or "graph"
    elif "api-version" in query and any(tok in host for tok in ("azure", "windows.net", "microsoft")):
        scores["azure"] += 3
        signals["azure"].append("query:azure-api-version")

    # --- 4. Resolve winner & detect conflicts cleanly ---
    active_providers = [p for p, s in scores.items() if s >= 3]
    ranked = sorted(scores.items(), key=lambda kv: kv[1], reverse=True)
    top_provider, top_score = ranked[0]
    second_provider, second_score = ranked[1]

    if top_score < 3:
        traffic_type = "connect_tunnel" if is_connect else "http_app"
        return ClassificationResult(
            cloud_provider="unknown",
            traffic_type=traffic_type,
            confidence="high" if top_score == 0 else "low",
            reason="No strong cloud provider endpoint or protocol markers; routed as generic traffic.",
            destination_host=host,
            detected_service="https_tunnel" if is_connect else "http_app",
            signals=tuple(sig for p in ("aws", "gcp", "azure") for sig in signals[p]),
        )

    conflicts: tuple[str, ...] = ()
    if len(active_providers) > 1 and second_score >= 3:
        conflicts = tuple(sorted(active_providers))
        # Strong host match breaks tie deterministically, otherwise stay conservative
        if top_score - second_score >= 4 and any(s.startswith("host:") for s in signals[top_provider]):
            confidence = "medium"
            reason = (
                f"Classified as {top_provider} from authoritative host despite conflicting signals "
                f"from {second_provider} ({', '.join(signals[second_provider])})."
            )
        else:
            return ClassificationResult(
                cloud_provider="unknown",
                traffic_type="connect_tunnel" if is_connect else "http_app",
                confidence="low",
                reason=f"Ambiguous conflicting cloud signals across {', '.join(conflicts)}.",
                destination_host=host,
                detected_service="https_tunnel" if is_connect else "http_app",
                signals=tuple(sig for p in conflicts for sig in signals[p]),
                conflicting_providers=conflicts,
            )
    else:
        confidence = "high" if top_score >= 6 else "medium"
        reason = f"Matched {top_provider} signals: {', '.join(signals[top_provider])}."

    traffic_type = "connect_tunnel" if is_connect else "cloud_api"
    return ClassificationResult(
        cloud_provider=top_provider,
        traffic_type=traffic_type,
        confidence=confidence,
        reason=reason,
        destination_host=host,
        detected_service=detected_services[top_provider] or top_provider,
        signals=tuple(signals[top_provider]),
        conflicting_providers=conflicts,
    )
