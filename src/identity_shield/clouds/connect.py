"""Real Multi-Cloud Authentication, Scope Verification, Cloud SIEM Log Pulling & Resource Discovery.

Supports AWS, GCP, and Microsoft Azure / Entra ID across single-account/project/subscription
and whole-organization scopes without requiring heavy SDK dependencies or persisting secrets.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import shutil
import ssl
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Mapping

_SAFE_ID_RE = re.compile(r"^[A-Za-z0-9._:@/-]{1,200}$")
_SAFE_BUCKET_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{1,62}$")
_ISO_Z = "%Y-%m-%dT%H:%M:%SZ"

HttpFn = Callable[[str, str, Mapping[str, str], bytes | None], tuple[int, dict[str, Any]]]
RunnerFn = Callable[..., subprocess.CompletedProcess[str]]


def _sanitize_error(msg: str, secrets: tuple[str, ...] = ()) -> str:
    text = str(msg or "Unknown error")
    for s in secrets:
        if s and len(s) >= 6:
            text = text.replace(s, "[REDACTED]")
    text = re.sub(r"Bearer\s+[A-Za-z0-9._-]+", "Bearer [REDACTED]", text, flags=re.IGNORECASE)
    return text[:400]


def _default_https_json(
    method: str,
    url: str,
    headers: Mapping[str, str] | None = None,
    body: bytes | None = None,
    *,
    allow_imds: bool = False,
    timeout: int = 20,
) -> tuple[int, dict[str, Any]]:
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme == "http" and allow_imds and parsed.hostname == "169.254.169.254":
        pass
    elif parsed.scheme != "https" or not parsed.hostname:
        raise ValueError(f"Refusing non-HTTPS cloud endpoint: {url!r}")

    req = urllib.request.Request(url, data=body, method=method.upper())
    for k, v in (headers or {}).items():
        req.add_header(str(k), str(v))

    ctx = ssl.create_default_context() if parsed.scheme == "https" else None
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            raw = resp.read()
            txt = raw.decode("utf-8", errors="replace").strip()
            return int(resp.status), (json.loads(txt) if txt else {})
    except urllib.error.HTTPError as exc:
        err_raw = exc.read().decode("utf-8", errors="replace").strip() if exc.fp else ""
        try:
            err_obj = json.loads(err_raw) if err_raw else {}
        except json.JSONDecodeError:
            err_obj = {"error": err_raw[:300]}
        return int(exc.code), err_obj


_ORIG_DEFAULT_HTTPS_JSON = _default_https_json


def _default_https_bytes(
    method: str,
    url: str,
    headers: Mapping[str, str] | None = None,
    body: bytes | None = None,
    *,
    timeout: int = 25,
) -> tuple[int, str]:
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https" or not parsed.hostname:
        raise ValueError(f"Refusing non-HTTPS cloud endpoint: {url!r}")
    req = urllib.request.Request(url, data=body, method=method.upper())
    for k, v in (headers or {}).items():
        req.add_header(str(k), str(v))
    ctx = ssl.create_default_context()
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return int(resp.status), resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        err_raw = exc.read().decode("utf-8", errors="replace") if exc.fp else str(exc)
        return int(exc.code), err_raw[:400]


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _decode_jwt_claims(token: str) -> dict[str, Any]:
    parts = str(token or "").split(".")
    if len(parts) < 2:
        return {}
    seg = parts[1]
    seg += "=" * (-len(seg) % 4)
    try:
        decoded = base64.urlsafe_b64decode(seg.encode("ascii"))
        obj = json.loads(decoded.decode("utf-8", errors="replace"))
        return obj if isinstance(obj, dict) else {}
    except Exception:
        return {}


# ---------------------------------------------------------------------------
# Pure-Python RAM-Only PKCS#8 RSA Signing (Zero Temp Key Files on Disk)
# ---------------------------------------------------------------------------


def _read_der_tlv(buf: bytes, pos: int) -> tuple[int, bytes, int]:
    if pos >= len(buf):
        raise ValueError("Truncated ASN.1 DER structure")
    tag = buf[pos]
    pos += 1
    ln = buf[pos]
    pos += 1
    if ln & 0x80:
        nbytes = ln & 0x7F
        if nbytes == 0 or pos + nbytes > len(buf):
            raise ValueError("Invalid ASN.1 DER length")
        ln = int.from_bytes(buf[pos : pos + nbytes], "big")
        pos += nbytes
    if pos + ln > len(buf):
        raise ValueError("Truncated ASN.1 DER value")
    return tag, buf[pos : pos + ln], pos + ln


def _parse_rsa_pkcs8_pem(pem_text: str) -> tuple[int, int]:
    """Extract `(n, d)` from an unencrypted PKCS#8 or PKCS#1 RSA private key in RAM."""
    cleaned = str(pem_text or "").strip()
    is_pkcs1 = "BEGIN RSA PRIVATE KEY" in cleaned
    lines = [
        ln.strip()
        for ln in cleaned.splitlines()
        if ln.strip() and not ln.strip().startswith("-----")
    ]
    if not lines:
        raise ValueError("Missing PEM private_key material")
    der = base64.b64decode("".join(lines).encode("ascii"))

    if not is_pkcs1:
        tag, top, _ = _read_der_tlv(der, 0)
        if tag != 0x30:
            raise ValueError("Invalid PKCS#8 SEQUENCE")
        _, _, pos = _read_der_tlv(top, 0)  # version
        _, _, pos = _read_der_tlv(top, pos)  # PrivateKeyAlgorithmIdentifier
        tag_k, rsa_der, _ = _read_der_tlv(top, pos)  # privateKey OCTET STRING
        if tag_k != 0x04:
            raise ValueError("Unsupported PKCS#8 private key container")
    else:
        rsa_der = der

    tag_r, seq, _ = _read_der_tlv(rsa_der, 0)
    if tag_r != 0x30:
        raise ValueError("Invalid RSAPrivateKey SEQUENCE")
    ints: list[int] = []
    pos = 0
    for _ in range(4):  # version, n, e, d
        t_i, val_b, pos = _read_der_tlv(seq, pos)
        if t_i != 0x02:
            raise ValueError("Expected ASN.1 INTEGER in RSA private key")
        ints.append(int.from_bytes(val_b, "big"))
    return ints[1], ints[3]


def sign_rs256_jwt_in_memory(payload: Mapping[str, Any], private_key_pem: str, *, key_id: str = "") -> str:
    """Sign an RS256 JWT completely in RAM using PKCS#1 v1.5 SHA-256 padding."""
    header: dict[str, str] = {"alg": "RS256", "typ": "JWT"}
    if key_id:
        header["kid"] = key_id
    signing_input = (
        f"{_b64url(json.dumps(header, separators=(',', ':')).encode('utf-8'))}."
        f"{_b64url(json.dumps(dict(payload), separators=(',', ':')).encode('utf-8'))}"
    )

    try:
        from google.auth import crypt as g_crypt  # type: ignore

        signer = g_crypt.RSASigner.from_string(private_key_pem, key_id or None)
        sig = signer.sign(signing_input.encode("ascii"))
        return f"{signing_input}.{_b64url(sig)}"
    except Exception:
        pass

    n, d = _parse_rsa_pkcs8_pem(private_key_pem)
    k = (n.bit_length() + 7) // 8
    digest_info = bytes.fromhex("3031300d060960864801650304020105000420") + hashlib.sha256(signing_input.encode("ascii")).digest()
    ps_len = k - len(digest_info) - 3
    if ps_len < 8:
        raise ValueError("RSA key modulus too small for RS256 signing")
    em = b"\x00\x01" + (b"\xff" * ps_len) + b"\x00" + digest_info
    sig_int = pow(int.from_bytes(em, "big"), d, n)
    sig_bytes = sig_int.to_bytes(k, "big")
    return f"{signing_input}.{_b64url(sig_bytes)}"


# ---------------------------------------------------------------------------
# Local CLI Discovery (Safe, Optional — Zero Failure When CLIs Absent)
# ---------------------------------------------------------------------------


def list_local_gcp_configurations(runner_fn: RunnerFn | None = None) -> list[dict[str, Any]]:
    runner_fn = runner_fn or subprocess.run
    gcloud_bin = shutil.which("gcloud")
    if not gcloud_bin:
        return []
    try:
        proc = runner_fn(
            [gcloud_bin, "config", "configurations", "list", "--format=json"],
            capture_output=True,
            text=True,
            timeout=8,
        )
        if proc.returncode != 0 or not proc.stdout.strip():
            return []
        items = json.loads(proc.stdout)
        out: list[dict[str, Any]] = []
        for item in items if isinstance(items, list) else []:
            props = item.get("properties") if isinstance(item.get("properties"), Mapping) else {}
            core = props.get("core") if isinstance(props.get("core"), Mapping) else {}
            out.append(
                {
                    "name": str(item.get("name") or "default"),
                    "is_active": bool(item.get("is_active")),
                    "account": str(core.get("account") or ""),
                    "project": str(core.get("project") or ""),
                }
            )
        return out
    except Exception:
        return []


def list_local_azure_subscriptions(runner_fn: RunnerFn | None = None) -> list[dict[str, Any]]:
    runner_fn = runner_fn or subprocess.run
    az_bin = shutil.which("az")
    if not az_bin:
        return []
    try:
        proc = runner_fn(
            [az_bin, "account", "list", "--output", "json"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if proc.returncode != 0 or not proc.stdout.strip():
            return []
        items = json.loads(proc.stdout)
        out: list[dict[str, Any]] = []
        for item in items if isinstance(items, list) else []:
            out.append(
                {
                    "id": str(item.get("id") or ""),
                    "name": str(item.get("name") or ""),
                    "tenant_id": str(item.get("tenantId") or ""),
                    "is_default": bool(item.get("isDefault")),
                    "state": str(item.get("state") or "Enabled"),
                }
            )
        return out
    except Exception:
        return []


# ---------------------------------------------------------------------------
# GCP Connector & Verifier
# ---------------------------------------------------------------------------


def _obtain_gcp_adc_token(
    *,
    gcloud_config: str = "",
    runner_fn: RunnerFn | None = None,
) -> tuple[str, dict[str, Any]]:
    runner_fn = runner_fn or subprocess.run
    # 1. Try google-auth ADC if installed and no named gcloud configuration was requested
    if not gcloud_config:
        try:
            import google.auth  # type: ignore
            from google.auth.transport.requests import Request  # type: ignore

            creds, adc_proj = google.auth.default(scopes=["https://www.googleapis.com/auth/cloud-platform"])
            creds.refresh(Request())
            if getattr(creds, "token", None):
                return str(creds.token), {
                    "provider_method": "google_auth_adc",
                    "project_id": str(adc_proj or ""),
                    "principal": str(getattr(creds, "service_account_email", "") or ""),
                }
        except Exception:
            pass

    # 2. Fall back to local gcloud CLI
    gcloud_bin = shutil.which("gcloud")
    if not gcloud_bin:
        raise ValueError(
            "gcloud CLI / Application Default Credentials unavailable. "
            "Install gcloud CLI and run 'gcloud auth login' or choose Service Account JSON / OAuth Token."
        )
    cmd = [gcloud_bin, "auth", "print-access-token"]
    if gcloud_config:
        if not _SAFE_ID_RE.match(gcloud_config):
            raise ValueError("Invalid gcloud configuration name")
        cmd.append(f"--configuration={gcloud_config}")
    proc = runner_fn(cmd, capture_output=True, text=True, timeout=12)
    token = (proc.stdout or "").strip() if proc.returncode == 0 else ""
    if not token:
        # Try ADC token fallback
        adc_proc = runner_fn([gcloud_bin, "auth", "application-default", "print-access-token"], capture_output=True, text=True, timeout=12)
        token = (adc_proc.stdout or "").strip() if adc_proc.returncode == 0 else ""
    if not token:
        raise ValueError(f"Unable to get GCP access token from gcloud: {_sanitize_error(proc.stderr or adc_proc.stderr)}")

    proj_proc = runner_fn([gcloud_bin, "config", "get-value", "project"], capture_output=True, text=True, timeout=8)
    acct_proc = runner_fn([gcloud_bin, "config", "get-value", "account"], capture_output=True, text=True, timeout=8)
    return token, {
        "provider_method": "gcloud_cli",
        "project_id": (proj_proc.stdout or "").strip() if proj_proc.returncode == 0 else "",
        "principal": (acct_proc.stdout or "").strip() if acct_proc.returncode == 0 else "",
    }


def verify_and_connect_gcp(
    payload: Mapping[str, Any],
    *,
    http_fn: HttpFn | None = None,
    runner_fn: RunnerFn | None = None,
) -> dict[str, Any]:
    """Authenticate and verify GCP single-project or organization scope in RAM only."""
    http_fn = http_fn or _default_https_json
    runner_fn = runner_fn or subprocess.run
    auth_mode = str(payload.get("auth_mode") or "gcloud_adc").strip().lower()
    scope = str(payload.get("scope") or "single_project").strip().lower()
    if scope not in {"single_project", "organization"}:
        raise ValueError("GCP scope must be 'single_project' or 'organization'")

    project_id = str(payload.get("project_id") or "").strip()
    org_id = str(payload.get("organization_id") or "").strip()
    service_account = str(payload.get("service_account") or "").strip()
    region = str(payload.get("region") or "us-central1").strip() or "us-central1"
    gcloud_config = str(payload.get("gcloud_config") or "").strip()

    for label, val in (("project_id", project_id), ("organization_id", org_id), ("service_account", service_account)):
        if val and not _SAFE_ID_RE.match(val):
            raise ValueError(f"Invalid {label}: {val!r}")

    secret_values: list[str] = []
    token = ""
    meta: dict[str, Any] = {}

    if auth_mode == "gcloud_adc":
        token, meta = _obtain_gcp_adc_token(gcloud_config=gcloud_config, runner_fn=runner_fn)
        project_id = project_id or meta.get("project_id", "")

    elif auth_mode == "impersonate_sa":
        if not service_account:
            raise ValueError("Target Service Account email is required for impersonation")
        base_token = str(payload.get("base_token") or "").strip()
        if not base_token:
            base_token, meta = _obtain_gcp_adc_token(gcloud_config=gcloud_config, runner_fn=runner_fn)
            project_id = project_id or meta.get("project_id", "")
        secret_values.append(base_token)
        imp_url = f"https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/{urllib.parse.quote(service_account)}:generateAccessToken"
        req_body = json.dumps({"scope": ["https://www.googleapis.com/auth/cloud-platform"], "lifetime": "3600s"}).encode("utf-8")
        st, resp = http_fn(
            "POST",
            imp_url,
            {"Authorization": f"Bearer {base_token}", "Content-Type": "application/json"},
            req_body,
        )
        if st >= 400 or not resp.get("accessToken"):
            raise ValueError(f"GCP SA impersonation failed ({st}): {_sanitize_error(json.dumps(resp), tuple(secret_values))}")
        token = str(resp["accessToken"])
        meta = {"provider_method": "iamcredentials_impersonate", "principal": service_account, "expire_time": resp.get("expireTime")}

    elif auth_mode == "service_account_json":
        raw_sa = payload.get("service_account_json")
        if isinstance(raw_sa, Mapping):
            sa_obj = dict(raw_sa)
        else:
            try:
                sa_obj = json.loads(str(raw_sa or ""))
            except json.JSONDecodeError as exc:
                raise ValueError("Invalid GCP Service Account JSON payload") from exc
        if not isinstance(sa_obj, dict) or not sa_obj.get("client_email") or not sa_obj.get("private_key"):
            raise ValueError("Service Account JSON must include client_email and private_key")
        sa_email = str(sa_obj["client_email"])
        priv_key = str(sa_obj["private_key"])
        secret_values.append(priv_key)
        token_uri = str(sa_obj.get("token_uri") or "https://oauth2.googleapis.com/token")
        now = int(time.time())
        assertion = sign_rs256_jwt_in_memory(
            {
                "iss": sa_email,
                "sub": sa_email,
                "scope": "https://www.googleapis.com/auth/cloud-platform",
                "aud": token_uri,
                "iat": now,
                "exp": now + 3600,
            },
            priv_key,
            key_id=str(sa_obj.get("private_key_id") or ""),
        )
        form = urllib.parse.urlencode(
            {"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer", "assertion": assertion}
        ).encode("utf-8")
        st, resp = http_fn("POST", token_uri, {"Content-Type": "application/x-www-form-urlencoded"}, form)
        if st >= 400 or not resp.get("access_token"):
            raise ValueError(f"GCP Service Account token exchange failed ({st}): {_sanitize_error(json.dumps(resp), tuple(secret_values))}")
        token = str(resp["access_token"])
        project_id = project_id or str(sa_obj.get("project_id") or "")
        service_account = sa_email
        meta = {"provider_method": "service_account_jwt_ram", "principal": sa_email}

    elif auth_mode == "workload_identity":
        oidc_token = str(payload.get("subject_token") or "").strip()
        audience = str(payload.get("audience") or "").strip()
        if not oidc_token or not audience:
            raise ValueError("Audience (WIF provider resource) and OIDC subject_token are required")
        secret_values.append(oidc_token)
        form = urllib.parse.urlencode(
            {
                "grantType": "urn:ietf:params:oauth:grant-type:token-exchange",
                "audience": audience,
                "scope": "https://www.googleapis.com/auth/cloud-platform",
                "requestedTokenType": "urn:ietf:params:oauth:token-type:access_token",
                "subjectToken": oidc_token,
                "subjectTokenType": "urn:ietf:params:oauth:token-type:jwt",
            }
        ).encode("utf-8")
        st, resp = http_fn("POST", "https://sts.googleapis.com/v1/token", {"Content-Type": "application/x-www-form-urlencoded"}, form)
        if st >= 400 or not resp.get("access_token"):
            raise ValueError(f"GCP Workload Identity STS exchange failed ({st}): {_sanitize_error(json.dumps(resp), tuple(secret_values))}")
        token = str(resp["access_token"])
        meta = {"provider_method": "workload_identity_sts"}

    elif auth_mode == "in_memory_token":
        token = str(payload.get("access_token") or "").strip()
        if not token:
            raise ValueError("GCP OAuth access_token is required")
        meta = {"provider_method": "in_memory_token"}
    else:
        raise ValueError(f"Unsupported GCP auth_mode: {auth_mode!r}")

    secret_values.append(token)
    auth_hdr = {"Authorization": f"Bearer {token}"}

    # Verify token live
    st_ti, ti = http_fn(
        "POST",
        "https://oauth2.googleapis.com/tokeninfo",
        {"Content-Type": "application/x-www-form-urlencoded"},
        urllib.parse.urlencode({"access_token": token}).encode("utf-8"),
    )
    if st_ti >= 400 or ("error" in ti and not ti.get("email")):
        raise ValueError(f"GCP token verification failed ({st_ti}): {_sanitize_error(json.dumps(ti), tuple(secret_values))}")

    verified_email = str(ti.get("email") or service_account or meta.get("principal") or "gcp-principal")
    projects: list[dict[str, Any]] = []
    orgs: list[dict[str, Any]] = []

    if project_id:
        st_p, p_obj = http_fn("GET", f"https://cloudresourcemanager.googleapis.com/v1/projects/{urllib.parse.quote(project_id)}", auth_hdr, None)
        if st_p >= 400:
            raise ValueError(f"Cannot verify GCP project {project_id!r} ({st_p}): {_sanitize_error(json.dumps(p_obj), tuple(secret_values))}")
        projects.append({"project_id": p_obj.get("projectId", project_id), "name": p_obj.get("name", project_id), "state": p_obj.get("lifecycleState", "ACTIVE")})
    else:
        st_lp, lp_obj = http_fn("GET", "https://cloudresourcemanager.googleapis.com/v1/projects?pageSize=25", auth_hdr, None)
        if st_lp < 400:
            for item in lp_obj.get("projects") or []:
                projects.append({"project_id": item.get("projectId"), "name": item.get("name"), "state": item.get("lifecycleState")})
            if projects and not project_id:
                project_id = str(projects[0]["project_id"] or "")

    if scope == "organization":
        if org_id:
            clean_org = org_id.replace("organizations/", "")
            st_o, o_obj = http_fn("GET", f"https://cloudresourcemanager.googleapis.com/v1/organizations/{urllib.parse.quote(clean_org)}", auth_hdr, None)
            if st_o >= 400:
                raise ValueError(f"Cannot verify GCP organization {clean_org!r} ({st_o}): {_sanitize_error(json.dumps(o_obj), tuple(secret_values))}")
            orgs.append({"organization_id": clean_org, "display_name": o_obj.get("displayName", clean_org)})
            org_id = clean_org
        else:
            st_so, so_obj = http_fn("POST", "https://cloudresourcemanager.googleapis.com/v1/organizations:search", {**auth_hdr, "Content-Type": "application/json"}, b"{}")
            if st_so < 400:
                for o in so_obj.get("organizations") or []:
                    oid = str(o.get("name") or "").replace("organizations/", "")
                    orgs.append({"organization_id": oid, "display_name": o.get("displayName", oid)})
                if orgs:
                    org_id = orgs[0]["organization_id"]

    return {
        "access_token": token,
        "descriptor": {
            "auth_mode": auth_mode,
            "project_id": project_id,
            "organization_id": org_id,
            "service_account": service_account or (verified_email if verified_email.endswith(".gserviceaccount.com") else ""),
            "region": region,
            "scope": scope,
            "gcloud_config": gcloud_config,
        },
        "identity": {
            "principal": verified_email,
            "project_id": project_id,
            "organization_id": org_id,
            "scope": scope,
            "effective_scope": "GCP Organization" if scope == "organization" else "Single Project",
            "verified_via": meta.get("provider_method") or auth_mode,
            "projects_accessible": len(projects),
            "organizations_accessible": len(orgs),
            "projects": projects[:15],
            "organizations": orgs[:10],
            "token_scopes": str(ti.get("scope") or "").split(),
            "expires_in": ti.get("expires_in"),
        },
    }


# ---------------------------------------------------------------------------
# Azure & Microsoft Entra ID Connector & Verifier
# ---------------------------------------------------------------------------


def _obtain_az_cli_tokens(
    *,
    subscription_id: str = "",
    runner_fn: RunnerFn | None = None,
) -> tuple[str, str, dict[str, Any]]:
    runner_fn = runner_fn or subprocess.run
    az_bin = shutil.which("az")
    if not az_bin:
        raise ValueError(
            "Azure CLI ('az') not found on PATH. Install Azure CLI and run 'az login', "
            "or choose Entra Service Principal / OIDC / Bearer Token."
        )
    cmd_arm = [az_bin, "account", "get-access-token", "--resource", "https://management.azure.com/", "--output", "json"]
    if subscription_id:
        if not _SAFE_ID_RE.match(subscription_id):
            raise ValueError("Invalid subscription_id")
        cmd_arm.extend(["--subscription", subscription_id])
    proc = runner_fn(cmd_arm, capture_output=True, text=True, timeout=15)
    if proc.returncode != 0 or not proc.stdout.strip():
        raise ValueError(f"Azure CLI token lookup failed: {_sanitize_error(proc.stderr or proc.stdout)}")
    arm_obj = json.loads(proc.stdout)
    arm_token = str(arm_obj.get("accessToken") or "")
    if not arm_token:
        raise ValueError("Azure CLI returned empty ARM access token")

    graph_token = ""
    try:
        proc_g = runner_fn(
            [az_bin, "account", "get-access-token", "--resource-type", "ms-graph", "--output", "json"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if proc_g.returncode == 0 and proc_g.stdout.strip():
            graph_token = str(json.loads(proc_g.stdout).get("accessToken") or "")
    except Exception:
        pass

    acct_info: dict[str, Any] = {}
    try:
        proc_a = runner_fn([az_bin, "account", "show", "--output", "json"], capture_output=True, text=True, timeout=8)
        if proc_a.returncode == 0 and proc_a.stdout.strip():
            acct_info = json.loads(proc_a.stdout)
    except Exception:
        pass

    return arm_token, graph_token, {
        "tenant_id": str(arm_obj.get("tenant") or acct_info.get("tenantId") or ""),
        "subscription_id": str(arm_obj.get("subscription") or acct_info.get("id") or subscription_id or ""),
        "subscription_name": str(acct_info.get("name") or ""),
        "user": str(((acct_info.get("user") or {}).get("name")) or ""),
    }


def _entra_oauth_token(
    *,
    tenant_id: str,
    client_id: str,
    scope_url: str,
    client_secret: str = "",
    federated_token: str = "",
    http_fn: HttpFn,
) -> str:
    if not _SAFE_ID_RE.match(tenant_id) or not _SAFE_ID_RE.match(client_id):
        raise ValueError("Invalid tenant_id or client_id")
    token_url = f"https://login.microsoftonline.com/{urllib.parse.quote(tenant_id)}/oauth2/v2.0/token"
    form_data: dict[str, str] = {
        "client_id": client_id,
        "scope": scope_url,
        "grant_type": "client_credentials",
    }
    secrets: list[str] = []
    if client_secret:
        form_data["client_secret"] = client_secret
        secrets.append(client_secret)
    elif federated_token:
        form_data["client_assertion_type"] = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
        form_data["client_assertion"] = federated_token
        secrets.append(federated_token)
    else:
        raise ValueError("Provide client_secret or federated_token for Entra authentication")

    st, resp = http_fn(
        "POST",
        token_url,
        {"Content-Type": "application/x-www-form-urlencoded"},
        urllib.parse.urlencode(form_data).encode("utf-8"),
    )
    if st >= 400 or not resp.get("access_token"):
        raise ValueError(f"Azure Entra token request failed ({st}): {_sanitize_error(json.dumps(resp), tuple(secrets))}")
    return str(resp["access_token"])


def verify_and_connect_azure(
    payload: Mapping[str, Any],
    *,
    http_fn: HttpFn | None = None,
    runner_fn: RunnerFn | None = None,
) -> dict[str, Any]:
    """Authenticate and verify Azure single-subscription or whole-tenant/org scope in RAM."""
    http_fn = http_fn or _default_https_json
    runner_fn = runner_fn or subprocess.run
    auth_mode = str(payload.get("auth_mode") or "az_cli").strip().lower()
    scope = str(payload.get("scope") or "single_subscription").strip().lower()
    if scope not in {"single_subscription", "organization"}:
        raise ValueError("Azure scope must be 'single_subscription' or 'organization'")

    tenant_id = str(payload.get("tenant_id") or "").strip()
    subscription_id = str(payload.get("subscription_id") or "").strip()
    mg_id = str(payload.get("management_group_id") or "").strip()
    client_id = str(payload.get("client_id") or "").strip()
    location = str(payload.get("location") or "eastus").strip() or "eastus"

    for label, val in (("tenant_id", tenant_id), ("subscription_id", subscription_id), ("management_group_id", mg_id), ("client_id", client_id)):
        if val and not _SAFE_ID_RE.match(val):
            raise ValueError(f"Invalid {label}: {val!r}")

    arm_token = ""
    graph_token = ""
    meta: dict[str, Any] = {}
    secrets: list[str] = []

    if auth_mode == "az_cli":
        arm_token, graph_token, meta = _obtain_az_cli_tokens(subscription_id=subscription_id, runner_fn=runner_fn)
        tenant_id = tenant_id or meta.get("tenant_id", "")
        subscription_id = subscription_id or meta.get("subscription_id", "")

    elif auth_mode == "service_principal":
        c_secret = str(payload.get("client_secret") or "").strip()
        if not tenant_id or not client_id or not c_secret:
            raise ValueError("tenant_id, client_id, and client_secret are required for Service Principal auth")
        secrets.append(c_secret)
        arm_token = _entra_oauth_token(
            tenant_id=tenant_id,
            client_id=client_id,
            scope_url="https://management.azure.com/.default",
            client_secret=c_secret,
            http_fn=http_fn,
        )
        try:
            graph_token = _entra_oauth_token(
                tenant_id=tenant_id,
                client_id=client_id,
                scope_url="https://graph.microsoft.com/.default",
                client_secret=c_secret,
                http_fn=http_fn,
            )
        except Exception:
            graph_token = ""

    elif auth_mode == "oidc_federated":
        fed_tok = str(payload.get("federated_token") or "").strip()
        if not tenant_id or not client_id or not fed_tok:
            raise ValueError("tenant_id, client_id, and federated_token are required for OIDC Federated auth")
        secrets.append(fed_tok)
        arm_token = _entra_oauth_token(
            tenant_id=tenant_id,
            client_id=client_id,
            scope_url="https://management.azure.com/.default",
            federated_token=fed_tok,
            http_fn=http_fn,
        )

    elif auth_mode == "managed_identity":
        mi_url = "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
        if client_id:
            mi_url += f"&client_id={urllib.parse.quote(client_id)}"
        try:
            if http_fn is _ORIG_DEFAULT_HTTPS_JSON:
                st_mi, mi_resp = _ORIG_DEFAULT_HTTPS_JSON("GET", mi_url, {"Metadata": "true"}, None, allow_imds=True, timeout=6)
            else:
                st_mi, mi_resp = http_fn("GET", mi_url, {"Metadata": "true"}, None)
        except Exception as exc:
            raise ValueError(f"Azure Managed Identity endpoint unreachable (are you running inside Azure?): {exc}") from exc
        if st_mi >= 400 or not mi_resp.get("access_token"):
            raise ValueError(f"Azure Managed Identity token failed ({st_mi}): {_sanitize_error(json.dumps(mi_resp), tuple(secrets))}")
        arm_token = str(mi_resp["access_token"])

    elif auth_mode == "in_memory_token":
        arm_token = str(payload.get("access_token") or "").strip()
        graph_token = str(payload.get("graph_token") or "").strip()
        if not arm_token:
            raise ValueError("Azure ARM access_token is required")
    else:
        raise ValueError(f"Unsupported Azure auth_mode: {auth_mode!r}")

    secrets.extend([arm_token, graph_token])
    claims = _decode_jwt_claims(arm_token)
    tenant_id = tenant_id or str(claims.get("tid") or "")
    principal = str(claims.get("upn") or claims.get("preferred_username") or claims.get("appid") or claims.get("oid") or meta.get("user") or "azure-principal")

    arm_hdr = {"Authorization": f"Bearer {arm_token}"}
    subscriptions: list[dict[str, Any]] = []
    management_groups: list[dict[str, Any]] = []

    if subscription_id and scope == "single_subscription":
        st_sub, sub_obj = http_fn(
            "GET",
            f"https://management.azure.com/subscriptions/{urllib.parse.quote(subscription_id)}?api-version=2022-12-01",
            arm_hdr,
            None,
        )
        if st_sub >= 400:
            raise ValueError(f"Cannot verify Azure subscription {subscription_id!r} ({st_sub}): {_sanitize_error(json.dumps(sub_obj), tuple(secrets))}")
        subscriptions.append(
            {
                "subscription_id": sub_obj.get("subscriptionId", subscription_id),
                "display_name": sub_obj.get("displayName", subscription_id),
                "tenant_id": sub_obj.get("tenantId", tenant_id),
                "state": sub_obj.get("state", "Enabled"),
            }
        )
        tenant_id = tenant_id or str(sub_obj.get("tenantId") or "")
    else:
        st_ls, ls_obj = http_fn("GET", "https://management.azure.com/subscriptions?api-version=2022-12-01", arm_hdr, None)
        if st_ls >= 400:
            raise ValueError(f"Cannot list Azure subscriptions ({st_ls}): {_sanitize_error(json.dumps(ls_obj), tuple(secrets))}")
        for s in ls_obj.get("value") or []:
            subscriptions.append(
                {
                    "subscription_id": s.get("subscriptionId"),
                    "display_name": s.get("displayName"),
                    "tenant_id": s.get("tenantId"),
                    "state": s.get("state"),
                }
            )
            if not tenant_id and s.get("tenantId"):
                tenant_id = str(s["tenantId"])
        if subscriptions and not subscription_id:
            subscription_id = str(subscriptions[0].get("subscription_id") or "")

    if scope == "organization":
        st_mg, mg_obj = http_fn(
            "GET",
            "https://management.azure.com/providers/Microsoft.Management/managementGroups?api-version=2020-05-01",
            arm_hdr,
            None,
        )
        if st_mg < 400:
            for mg in mg_obj.get("value") or []:
                props = mg.get("properties") if isinstance(mg.get("properties"), Mapping) else {}
                management_groups.append(
                    {
                        "id": mg.get("name"),
                        "display_name": props.get("displayName") or mg.get("name"),
                    }
                )
            if management_groups and not mg_id:
                mg_id = str(management_groups[0].get("id") or "")

    return {
        "access_token": arm_token,
        "graph_token": graph_token,
        "descriptor": {
            "auth_mode": auth_mode,
            "tenant_id": tenant_id,
            "subscription_id": subscription_id,
            "management_group_id": mg_id,
            "client_id": client_id or str(claims.get("appid") or ""),
            "location": location,
            "scope": scope,
        },
        "identity": {
            "principal": principal,
            "tenant_id": tenant_id,
            "subscription_id": subscription_id,
            "management_group_id": mg_id,
            "scope": scope,
            "effective_scope": "Entra Tenant / Management Group Organization" if scope == "organization" else "Single Subscription",
            "subscriptions_accessible": len(subscriptions),
            "management_groups_accessible": len(management_groups),
            "subscriptions": subscriptions[:15],
            "management_groups": management_groups[:10],
            "has_graph_token": bool(graph_token),
        },
    }


# ---------------------------------------------------------------------------
# Multi-Cloud Onboarding Scripts & Templates (AWS / GCP / Azure)
# ---------------------------------------------------------------------------


def multicloud_onboarding_templates() -> dict[str, Any]:
    """Return least-privilege single-user & organization setup commands/templates for AWS, GCP & Azure."""
    return {
        "gcp-single": {
            "cloud": "gcp",
            "scope": "single_project",
            "files": {
                "gcp-single-project-setup.sh": (
                    "# 1. Authenticate locally OR grant a dedicated Cloud SIEM / audit service account\n"
                    "gcloud auth application-default login\n"
                    "export GCP_PROJECT_ID=\"my-gcp-project\"\n"
                    "gcloud config set project \"$GCP_PROJECT_ID\"\n\n"
                    "# Optional least-privilege SA for read-only SIEM log pull & asset census:\n"
                    "gcloud iam service-accounts create identity-shield-siem \\\n"
                    "  --display-name=\"Identity Shield Cloud SIEM\"\n"
                    "for ROLE in roles/logging.viewer roles/iam.securityReviewer roles/browser; do\n"
                    "  gcloud projects add-iam-policy-binding \"$GCP_PROJECT_ID\" \\\n"
                    "    --member=\"serviceAccount:identity-shield-siem@$GCP_PROJECT_ID.iam.gserviceaccount.com\" \\\n"
                    "    --role=\"$ROLE\"\n"
                    "done\n"
                )
            },
        },
        "gcp-organization": {
            "cloud": "gcp",
            "scope": "organization",
            "files": {
                "gcp-organization-setup.sh": (
                    "# Organization-wide Cloud Audit SIEM & Asset Inventory permissions:\n"
                    "export GCP_ORG_ID=\"123456789012\"\n"
                    "export SA=\"serviceAccount:identity-shield-siem@security-proj.iam.gserviceaccount.com\"\n\n"
                    "for ROLE in roles/logging.viewer roles/logging.privateLogViewer roles/iam.securityReviewer roles/resourcemanager.organizationViewer; do\n"
                    "  gcloud organizations add-iam-policy-binding \"$GCP_ORG_ID\" \\\n"
                    "    --member=\"$SA\" \\\n"
                    "    --role=\"$ROLE\"\n"
                    "done\n"
                )
            },
        },
        "azure-single": {
            "cloud": "azure",
            "scope": "single_subscription",
            "files": {
                "azure-single-subscription-setup.sh": (
                    "# 1. Local interactive login OR dedicated Read-Only SIEM Service Principal\n"
                    "az login\n"
                    "export AZ_SUB_ID=\"00000000-0000-0000-0000-000000000000\"\n"
                    "az account set --subscription \"$AZ_SUB_ID\"\n\n"
                    "# Optional Service Principal scoped to single subscription:\n"
                    "az ad sp create-for-rbac --name \"identity-shield-siem\" \\\n"
                    "  --role \"Reader\" \\\n"
                    "  --scopes \"/subscriptions/$AZ_SUB_ID\"\n"
                )
            },
        },
        "azure-organization": {
            "cloud": "azure",
            "scope": "organization",
            "files": {
                "azure-tenant-org-setup.sh": (
                    "# Tenant / Management Group wide Cloud SIEM permissions:\n"
                    "export TENANT_ID=\"00000000-0000-0000-0000-000000000000\"\n"
                    "export MG_ID=\"org-root-mg\"\n\n"
                    "az ad sp create-for-rbac --name \"identity-shield-org-siem\" \\\n"
                    "  --role \"Reader\" \\\n"
                    "  --scopes \"/providers/Microsoft.Management/managementGroups/$MG_ID\"\n\n"
                    "# Grant Microsoft Graph Application permission 'AuditLog.Read.All' in Entra Admin Center\n"
                    "# to ingest Entra ID Sign-In & Directory Audit logs across the entire organization.\n"
                )
            },
        },
    }


# ---------------------------------------------------------------------------
# Cloud-Only SIEM Pullers & Read-Only Resource Census (AWS / GCP / Azure)
# ---------------------------------------------------------------------------


def pull_gcp_audit_logs(
    *,
    access_token: str,
    project_id: str = "",
    organization_id: str = "",
    scope: str = "single_project",
    hours: int = 24,
    limit: int = 100,
    http_fn: HttpFn | None = None,
) -> list[dict[str, Any]]:
    http_fn = http_fn or _default_https_json
    if not access_token:
        raise ValueError("Connect GCP first before pulling Cloud Audit Logs")
    resource_names: list[str] = []
    if scope == "organization" and organization_id:
        resource_names.append(f"organizations/{organization_id.replace('organizations/', '')}")
    elif project_id:
        resource_names.append(f"projects/{project_id}")
    else:
        raise ValueError("Provide a GCP project_id (or organization_id for org scope) to query Cloud Logging")

    since_ts = (datetime.now(timezone.utc) - timedelta(hours=max(1, min(int(hours), 168)))).strftime(_ISO_Z)
    req_payload = {
        "resourceNames": resource_names,
        "filter": f'logName:"cloudaudit.googleapis.com" AND timestamp >= "{since_ts}"',
        "orderBy": "timestamp desc",
        "pageSize": max(1, min(int(limit), 200)),
    }
    st, resp = http_fn(
        "POST",
        "https://logging.googleapis.com/v2/entries:list",
        {"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"},
        json.dumps(req_payload).encode("utf-8"),
    )
    if st >= 400:
        raise ValueError(f"GCP Cloud Logging entries:list failed ({st}): {_sanitize_error(json.dumps(resp), (access_token,))}")
    return [dict(e) for e in (resp.get("entries") or []) if isinstance(e, Mapping)]


def pull_azure_siem_logs(
    *,
    arm_token: str,
    graph_token: str = "",
    subscription_id: str = "",
    subscription_ids: list[str] | None = None,
    hours: int = 24,
    limit: int = 100,
    http_fn: HttpFn | None = None,
) -> list[dict[str, Any]]:
    http_fn = http_fn or _default_https_json
    if not arm_token:
        raise ValueError("Connect Azure first before pulling Activity & Entra Logs")
    targets = list(subscription_ids or ([subscription_id] if subscription_id else []))
    if not targets and not graph_token:
        raise ValueError("Provide an Azure subscription_id (or Graph token) to pull logs")

    since_ts = (datetime.now(timezone.utc) - timedelta(hours=max(1, min(int(hours), 168)))).strftime(_ISO_Z)
    collected: list[dict[str, Any]] = []
    cap = max(1, min(int(limit), 200))

    for sub_id in targets[:5]:
        if len(collected) >= cap:
            break
        filt = urllib.parse.quote(f"eventTimestamp ge '{since_ts}'")
        url = (
            f"https://management.azure.com/subscriptions/{urllib.parse.quote(sub_id)}"
            f"/providers/Microsoft.Insights/eventtypes/management/values?api-version=2015-04-01&$filter={filt}"
        )
        st, resp = http_fn("GET", url, {"Authorization": f"Bearer {arm_token}"}, None)
        if st >= 400:
            raise ValueError(f"Azure Activity Logs pull failed ({st}): {_sanitize_error(json.dumps(resp), (arm_token,))}")
        for ev in resp.get("value") or []:
            if isinstance(ev, Mapping):
                collected.append(dict(ev))
                if len(collected) >= cap:
                    break

    if graph_token and len(collected) < cap:
        g_hdr = {"Authorization": f"Bearer {graph_token}"}
        for path in ("auditLogs/directoryAudits", "auditLogs/signIns"):
            if len(collected) >= cap:
                break
            st_g, g_resp = http_fn("GET", f"https://graph.microsoft.com/v1.0/{path}?$top=50", g_hdr, None)
            if st_g < 400:
                for ev in g_resp.get("value") or []:
                    if isinstance(ev, Mapping):
                        item = dict(ev)
                        item.setdefault("category", "AuditLogs" if "directoryAudits" in path else "SignInLogs")
                        collected.append(item)
                        if len(collected) >= cap:
                            break
    return collected


def collect_gcp_census(
    *,
    access_token: str,
    project_id: str,
    http_fn: HttpFn | None = None,
) -> dict[str, Any]:
    http_fn = http_fn or _default_https_json
    if not access_token or not project_id:
        raise ValueError("Connected GCP token and project_id required for live GCP census")
    hdr = {"Authorization": f"Bearer {access_token}"}
    inv: dict[str, Any] = {
        "cloud_provider": "gcp",
        "account_scope": project_id,
        "projects": [project_id],
        "service_accounts": [],
        "buckets": [],
        "secrets": [],
        "instances": [],
        "errors": [],
    }
    queries = (
        ("service_accounts", f"https://iam.googleapis.com/v1/projects/{urllib.parse.quote(project_id)}/serviceAccounts?pageSize=50", "accounts", "email"),
        ("buckets", f"https://storage.googleapis.com/storage/v1/b?project={urllib.parse.quote(project_id)}&maxResults=50", "items", "name"),
        ("secrets", f"https://secretmanager.googleapis.com/v1/projects/{urllib.parse.quote(project_id)}/secrets?pageSize=50", "secrets", "name"),
    )
    for field_name, url, list_key, name_key in queries:
        try:
            st, data = http_fn("GET", url, hdr, None)
            if st < 400:
                inv[field_name] = [str(item.get(name_key) or "") for item in (data.get(list_key) or []) if isinstance(item, Mapping) and item.get(name_key)]
            else:
                inv["errors"].append(f"{field_name}: HTTP {st}")
        except Exception as exc:
            inv["errors"].append(f"{field_name}: {_sanitize_error(str(exc), (access_token,))}")
    inv["resources"] = {
        "buckets": list(inv["buckets"]),
        "secrets": list(inv["secrets"]),
        "identities": list(inv["service_accounts"]),
        "compute": list(inv["instances"]),
    }
    return inv


def collect_azure_census(
    *,
    arm_token: str,
    subscription_id: str,
    tenant_id: str = "",
    http_fn: HttpFn | None = None,
) -> dict[str, Any]:
    http_fn = http_fn or _default_https_json
    if not arm_token or not subscription_id:
        raise ValueError("Connected Azure token and subscription_id required for live Azure census")
    hdr = {"Authorization": f"Bearer {arm_token}"}
    inv: dict[str, Any] = {
        "cloud_provider": "azure",
        "account_scope": tenant_id or subscription_id,
        "subscription_id": subscription_id,
        "resource_groups": [],
        "key_vaults": [],
        "storage_accounts": [],
        "vms": [],
        "errors": [],
    }
    queries = (
        ("resource_groups", f"https://management.azure.com/subscriptions/{urllib.parse.quote(subscription_id)}/resourcegroups?api-version=2021-04-01"),
        ("key_vaults", f"https://management.azure.com/subscriptions/{urllib.parse.quote(subscription_id)}/providers/Microsoft.KeyVault/vaults?api-version=2022-07-01"),
        ("storage_accounts", f"https://management.azure.com/subscriptions/{urllib.parse.quote(subscription_id)}/providers/Microsoft.Storage/storageAccounts?api-version=2023-01-01"),
        ("vms", f"https://management.azure.com/subscriptions/{urllib.parse.quote(subscription_id)}/providers/Microsoft.Compute/virtualMachines?api-version=2023-09-01"),
    )
    for field_name, url in queries:
        try:
            st, data = http_fn("GET", url, hdr, None)
            if st < 400:
                inv[field_name] = [str(item.get("name") or item.get("id") or "") for item in (data.get("value") or []) if isinstance(item, Mapping)]
            else:
                inv["errors"].append(f"{field_name}: HTTP {st}")
        except Exception as exc:
            inv["errors"].append(f"{field_name}: {_sanitize_error(str(exc), (arm_token,))}")
    inv["resources"] = {
        "buckets": list(inv["storage_accounts"]),
        "secrets": list(inv["key_vaults"]),
        "identities": [],
        "compute": list(inv["vms"]),
    }
    return inv


def upload_archive_gcs(
    *,
    access_token: str,
    bucket: str,
    object_name: str,
    content: bytes,
    bytes_fn: Callable[..., tuple[int, str]] | None = None,
) -> dict[str, Any]:
    bytes_fn = bytes_fn or _default_https_bytes
    clean_bucket = str(bucket or "").strip()
    if not _SAFE_BUCKET_RE.match(clean_bucket):
        raise ValueError("Invalid GCS bucket name")
    clean_obj = object_name.lstrip("/")
    url = f"https://storage.googleapis.com/upload/storage/v1/b/{urllib.parse.quote(clean_bucket)}/o?uploadType=media&name={urllib.parse.quote(clean_obj)}"
    st, msg = bytes_fn(
        "POST",
        url,
        {"Authorization": f"Bearer {access_token}", "Content-Type": "application/x-ndjson"},
        content,
    )
    if st >= 400:
        raise ValueError(f"GCS telemetry upload failed ({st}): {_sanitize_error(msg, (access_token,))}")
    return {"archived": True, "provider": "gcp", "bucket": clean_bucket, "object": clean_obj, "uri": f"gs://{clean_bucket}/{clean_obj}"}


def upload_archive_azure_blob(
    *,
    arm_or_storage_token: str,
    storage_account: str,
    container: str,
    blob_name: str,
    content: bytes,
    bytes_fn: Callable[..., tuple[int, str]] | None = None,
) -> dict[str, Any]:
    bytes_fn = bytes_fn or _default_https_bytes
    if not re.match(r"^[a-z0-9]{3,24}$", str(storage_account or "").strip()):
        raise ValueError("Invalid Azure storage account name (3-24 lowercase alphanumeric)")
    if not re.match(r"^[a-z0-9][a-z0-9-]{2,62}$", str(container or "").strip()):
        raise ValueError("Invalid Azure Blob container name")
    clean_blob = blob_name.lstrip("/")
    url = f"https://{storage_account}.blob.core.windows.net/{container}/{urllib.parse.quote(clean_blob)}"
    st, msg = bytes_fn(
        "PUT",
        url,
        {
            "Authorization": f"Bearer {arm_or_storage_token}",
            "x-ms-blob-type": "BlockBlob",
            "x-ms-version": "2020-10-02",
            "Content-Type": "application/x-ndjson",
        },
        content,
    )
    if st >= 400:
        raise ValueError(f"Azure Blob telemetry upload failed ({st}): {_sanitize_error(msg, (arm_or_storage_token,))}")
    return {"archived": True, "provider": "azure", "container": container, "blob": clean_blob, "uri": url}
