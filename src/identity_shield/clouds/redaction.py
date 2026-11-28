"""Centralized credential, bearer-token, and secret redaction across clouds."""

from __future__ import annotations

import re
from typing import Any, Mapping

REDACTED = "[REDACTED]"

_SENSITIVE_KEY_PARTS = (
    "authorization",
    "proxy-authorization",
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "x-api-key",
    "x-goog-api-key",
    "ocp-apim-subscription-key",
    "x-amz-security-token",
    "x-amz-signature",
    "x-goog-signature",
    "access_key",
    "secretaccesskey",
    "sessiontoken",
    "private_key",
    "credential",
    "cookie",
    "set-cookie",
    "jwt",
    "client_secret",
    "auth_code",
    "authorization_code",
    "sas",
)

# Sensitive single-word query parameter names (avoid stripping structured JSON keys like S3 `key` or gRPC `status.code`)
_EXACT_SENSITIVE_KEYS = frozenset({"pin", "ssn"})
_EXACT_SENSITIVE_QUERY_KEYS = frozenset(
    {
        "sig",
        "key",
        "code",
        "sv",
        "se",
        "sp",
        "sr",
    }
)

# Preserve non-secret resource identifier keys in cloud audit / CloudFox structures.
_SAFE_KEY_NAMES = frozenset(
    {
        "secrets",
        "secretname",
        "secretid",
        "secretarn",
        "secretversion",
        "serviceaccountkeyname",
        "token_type",
        "tokentype",
    }
)

_BEARER_VALUE_RE = re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{8,}", re.IGNORECASE)
_GCP_OAUTH_RE = re.compile(r"\bya29\.[A-Za-z0-9._-]{12,}\b")
_GCP_API_KEY_RE = re.compile(r"\bAIza[0-9A-Za-z_-]{16,45}\b")
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}\b")
_AWS_KEY_RE = re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")
_KV_SECRET_RE = re.compile(
    r"((?:^|[?&\s])(?:sig|signature|x-amz-signature|x-amz-security-token|x-goog-signature|access_token|refresh_token|id_token|client_secret|api_key|apikey|password|passwd)=)[^&\s;]+",
    re.IGNORECASE,
)
_BASIC_AUTH_RE = re.compile(r"\bBasic\s+[A-Za-z0-9+/=]{6,}", re.IGNORECASE)


def is_sensitive_key(key: str) -> bool:
    kl = str(key or "").strip().lower()
    if kl in _SAFE_KEY_NAMES:
        return False
    if kl in _EXACT_SENSITIVE_KEYS:
        return True
    return any(part in kl for part in _SENSITIVE_KEY_PARTS)


def redact_text(text: str) -> str:
    """Scrub bearer tokens, JWTs, OAuth/GCP API keys, SAS signatures, and AWS keys from strings."""
    if not text:
        return text
    cleaned = _BEARER_VALUE_RE.sub("Bearer [REDACTED]", text)
    cleaned = _BASIC_AUTH_RE.sub("Basic [REDACTED]", cleaned)
    cleaned = _GCP_OAUTH_RE.sub("[REDACTED_GCP_TOKEN]", cleaned)
    cleaned = _GCP_API_KEY_RE.sub("[REDACTED_GCP_API_KEY]", cleaned)
    cleaned = _JWT_RE.sub("[REDACTED_JWT]", cleaned)
    cleaned = _AWS_KEY_RE.sub("[REDACTED_AWS_KEY]", cleaned)
    cleaned = _KV_SECRET_RE.sub(r"\1[REDACTED]", cleaned)
    return cleaned


def redact_mapping(value: Any, *, _depth: int = 0) -> Any:
    """Recursively redact sensitive fields without mutating caller containers."""
    if _depth > 16:
        return REDACTED
    if isinstance(value, Mapping):
        out: dict[str, Any] = {}
        for k, v in value.items():
            key_str = str(k)
            if not isinstance(v, (Mapping, list, tuple)) and is_sensitive_key(key_str):
                out[key_str] = REDACTED
            else:
                out[key_str] = redact_mapping(v, _depth=_depth + 1)
        return out
    if isinstance(value, list):
        return [redact_mapping(item, _depth=_depth + 1) for item in value]
    if isinstance(value, tuple):
        return [redact_mapping(item, _depth=_depth + 1) for item in value]
    if isinstance(value, str):
        return redact_text(value)
    return value


def redact_headers(headers: Mapping[str, str]) -> dict[str, str]:
    """Return a header copy safe for logs, UI, and SQLite persistence."""
    sanitized: dict[str, str] = {}
    for k, v in headers.items():
        ks = str(k)
        vs = str(v)
        kl = ks.lower()
        if kl in {"authorization", "proxy-authorization", "cookie", "set-cookie", "x-api-key", "x-goog-api-key", "ocp-apim-subscription-key", "x-amz-security-token"}:
            # Preserve non-secret scheme label only (e.g. AWS4-HMAC-SHA256 / Bearer)
            scheme = vs.split(" ", 1)[0] if " " in vs and kl in {"authorization", "proxy-authorization"} else ""
            sanitized[ks] = f"{scheme} {REDACTED}".strip() if scheme in {"AWS4-HMAC-SHA256", "Bearer", "Basic"} else REDACTED
        elif is_sensitive_key(ks):
            sanitized[ks] = REDACTED
        else:
            sanitized[ks] = redact_text(vs)
    return sanitized


def redact_query_string(raw_query: str) -> str:
    if not raw_query:
        return ""
    parts: list[str] = []
    for seg in raw_query.split("&"):
        if "=" in seg:
            k, v = seg.split("=", 1)
            kl = k.strip().lower()
            parts.append(
                f"{k}={REDACTED}"
                if (is_sensitive_key(k) or kl in _EXACT_SENSITIVE_QUERY_KEYS)
                else f"{k}={redact_text(v)}"
            )
        else:
            parts.append(redact_text(seg))
    return "&".join(parts)
