"""Optional zero-overhead adapters for external OSS tools (CloudFox, Pacu, Stratus).

Design invariants:
- No third-party tool installation is required; absence never slows startup or tests.
- All CLI invocations use shell=False and strict identifier allowlists.
- Pacu is strictly constrained to a small read-only reconnaissance allowlist.
- Imported CloudFox JSON inventories are size-bounded and secret-redacted.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

MAX_CLOUDFOX_BYTES = 2 * 1024 * 1024  # 2 MiB hard limit for imported recon JSON
MAX_ITEMS_PER_CATEGORY = 200

ALLOWED_PACU_MODULES: frozenset[str] = frozenset(
    {
        "iam__enum_permissions",
        "iam__enum_users_roles_customers_policies",
        "ec2__enum",
        "s3__enum",
    }
)

_SAFE_TOKEN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_ACCESS_KEY_RE = re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")
_SENSITIVE_KEY_WORDS = (
    "secret_key",
    "secretaccesskey",
    "secretstring",
    "secretbinary",
    "client_secret",
    "token",
    "password",
    "passwd",
    "private_key",
    "access_key",
    "credential",
    "authorization",
    "api_key",
    "apikey",
)
_SAFE_IDENTIFIER_KEYS = frozenset({"secrets", "secretname", "secretid", "secretarn", "secretsmanager"})

_TOOL_CATALOG: tuple[dict[str, str], ...] = (
    {
        "id": "stratus",
        "name": "Stratus Red Team",
        "binary": "stratus",
        "role": "Live AWS attack simulation",
        "install_hint": "Optional: install Stratus binary for live sandbox trials.",
    },
    {
        "id": "cloudfox",
        "name": "CloudFox",
        "binary": "cloudfox",
        "role": "AWS resource & path enumeration",
        "install_hint": "Optional: run CloudFox offline or import its JSON inventory below.",
    },
    {
        "id": "pacu",
        "name": "Pacu (Read-Only Recon)",
        "binary": "pacu",
        "role": "Allowlisted permission enumeration",
        "install_hint": "Optional: only read-only enum modules are permitted.",
    },
    {
        "id": "terraform",
        "name": "Terraform",
        "binary": "terraform",
        "role": "Provision / clean up Stratus resources",
        "install_hint": "Optional: required only when warming up Stratus live labs.",
    },
    {
        "id": "mitmdump",
        "name": "mitmproxy",
        "binary": "mitmdump",
        "role": "Optional upstream TLS proxy",
        "install_hint": "Optional: built-in Identity Shield proxy works standalone.",
    },
    {
        "id": "gcloud",
        "name": "Google Cloud CLI (gcloud)",
        "binary": "gcloud",
        "role": "Optional live GCP authentication & enumeration",
        "install_hint": "Optional: offline GCP audit log parsing and synthetic simulation work without gcloud.",
    },
    {
        "id": "az",
        "name": "Azure CLI (az)",
        "binary": "az",
        "role": "Optional live Azure / Entra authentication & enumeration",
        "install_hint": "Optional: offline Azure/Entra normalization and synthetic simulation work without az.",
    },
    {
        "id": "scout",
        "name": "ScoutSuite",
        "binary": "scout",
        "role": "Optional AWS/GCP/Azure configuration posture scanner",
        "install_hint": "Optional: paste or import ScoutSuite multi-cloud JSON exports offline.",
    },
)


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _validate_safe_identifier(value: str | None, field: str) -> str | None:
    if value is None:
        return None
    cleaned = str(value).strip()
    if not cleaned:
        return None
    if not _SAFE_TOKEN_RE.match(cleaned):
        raise ValueError(
            f"Invalid {field}: must start with alphanumeric and contain only [A-Za-z0-9._-] (max 64 chars)."
        )
    return cleaned


def _redact_secrets(value: Any) -> Any:
    """Recursively redact credential-looking scalar fields and AWS access key patterns."""
    if isinstance(value, dict):
        sanitized: dict[str, Any] = {}
        for k, v in value.items():
            key_lower = str(k).lower()
            if (
                not isinstance(v, (dict, list))
                and key_lower not in _SAFE_IDENTIFIER_KEYS
                and any(word in key_lower for word in _SENSITIVE_KEY_WORDS)
            ):
                sanitized[str(k)] = "<redacted>"
            else:
                sanitized[str(k)] = _redact_secrets(v)
        return sanitized
    if isinstance(value, list):
        return [_redact_secrets(item) for item in value[:MAX_ITEMS_PER_CATEGORY]]
    if isinstance(value, str):
        return _ACCESS_KEY_RE.sub("<redacted-aws-key>", value)[:512]
    return value


def get_external_tools_status(which_fn: Callable[[str], str | None] = shutil.which) -> dict[str, Any]:
    """Return instant PATH availability of optional security tools without spawning binaries."""
    tools: list[dict[str, Any]] = []
    installed_count = 0
    for spec in _TOOL_CATALOG:
        resolved = which_fn(spec["binary"])
        installed = bool(resolved)
        if installed:
            installed_count += 1
        tools.append(
            {
                "id": spec["id"],
                "name": spec["name"],
                "binary": spec["binary"],
                "role": spec["role"],
                "installed": installed,
                "path": resolved if installed else None,
                "install_hint": spec["install_hint"],
            }
        )
    return {
        "tools": tools,
        "installed_count": installed_count,
        "total": len(tools),
        "lazy_mode": True,
        "allowed_pacu_modules": sorted(ALLOWED_PACU_MODULES),
        "checked_at": _utc_now(),
    }


def _extract_names(items: Any, keys: tuple[str, ...]) -> list[str]:
    if not isinstance(items, list):
        return []
    out: list[str] = []
    seen: set[str] = set()
    for raw in items[:MAX_ITEMS_PER_CATEGORY]:
        candidate = ""
        if isinstance(raw, str):
            candidate = raw.strip()
        elif isinstance(raw, dict):
            for k in keys:
                val = raw.get(k)
                if isinstance(val, str) and val.strip():
                    candidate = val.strip()
                    break
        if candidate and candidate not in seen:
            seen.add(candidate)
            out.append(candidate[:160])
    return out


def parse_cloudfox_inventory(raw_data: str | bytes | dict[str, Any] | list[Any]) -> dict[str, Any]:
    """Parse and normalize a bounded CloudFox / AWS recon JSON payload.

    Supports structured inventory dicts (`buckets`, `iam_users`, `iam_roles`,
    `ec2_instances`, `lambdas`, `secrets`, `sqs_queues`) as well as list exports
    of CloudFox table rows carrying `Service`/`Name`/`Arn`/`BucketName`/`InstanceId`.
    """
    if isinstance(raw_data, bytes):
        if len(raw_data) > MAX_CLOUDFOX_BYTES:
            raise ValueError(f"CloudFox payload exceeds {MAX_CLOUDFOX_BYTES // (1024 * 1024)} MiB limit.")
        raw_text = raw_data.decode("utf-8")
    elif isinstance(raw_data, str):
        raw_bytes = raw_data.encode("utf-8")
        if len(raw_bytes) > MAX_CLOUDFOX_BYTES:
            raise ValueError(f"CloudFox payload exceeds {MAX_CLOUDFOX_BYTES // (1024 * 1024)} MiB limit.")
        raw_text = raw_data
    else:
        raw_text = ""

    if raw_text:
        try:
            payload = json.loads(raw_text)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid CloudFox JSON payload: {exc.msg}") from exc
    else:
        encoded = json.dumps(raw_data).encode("utf-8")
        if len(encoded) > MAX_CLOUDFOX_BYTES:
            raise ValueError(f"CloudFox payload exceeds {MAX_CLOUDFOX_BYTES // (1024 * 1024)} MiB limit.")
        payload = raw_data

    payload = _redact_secrets(payload)

    buckets: list[str] = []
    iam_users: list[str] = []
    iam_roles: list[str] = []
    ec2_instances: list[str] = []
    lambdas: list[str] = []
    secrets: list[str] = []
    sqs_queues: list[str] = []

    if isinstance(payload, dict):
        # Accept optional nested wrapper {"resources": {...}} or {"inventory": {...}}
        root = payload.get("resources") if isinstance(payload.get("resources"), dict) else payload
        buckets = _extract_names(
            root.get("buckets") or root.get("s3_buckets") or root.get("s3"),
            ("BucketName", "bucket", "Name", "name", "Arn", "arn"),
        )
        iam_users = _extract_names(
            root.get("iam_users") or root.get("users"),
            ("UserName", "user", "Name", "name", "Arn", "arn"),
        )
        iam_roles = _extract_names(
            root.get("iam_roles") or root.get("roles"),
            ("RoleName", "role", "Name", "name", "Arn", "arn"),
        )
        ec2_instances = _extract_names(
            root.get("ec2_instances") or root.get("instances") or root.get("ec2"),
            ("InstanceId", "instance_id", "Name", "name", "Id", "id"),
        )
        lambdas = _extract_names(
            root.get("lambdas") or root.get("lambda_functions") or root.get("functions"),
            ("FunctionName", "function", "Name", "name", "Arn", "arn"),
        )
        secrets = _extract_names(
            root.get("secrets") or root.get("secretsmanager"),
            ("SecretName", "SecretId", "Name", "name", "Arn", "arn"),
        )
        sqs_queues = _extract_names(
            root.get("sqs_queues") or root.get("queues") or root.get("sqs"),
            ("QueueUrl", "QueueName", "Name", "name", "Arn", "arn"),
        )
        rows = root.get("rows") or root.get("findings") or root.get("endpoints")
        if isinstance(rows, list):
            payload = rows

    if isinstance(payload, list):
        for row in payload[: MAX_ITEMS_PER_CATEGORY * 2]:
            if not isinstance(row, dict):
                continue
            service = str(row.get("Service") or row.get("service") or row.get("Type") or "").lower()
            arn = str(row.get("Arn") or row.get("arn") or "")
            name = str(
                row.get("Name")
                or row.get("name")
                or row.get("BucketName")
                or row.get("InstanceId")
                or row.get("RoleName")
                or row.get("UserName")
                or row.get("FunctionName")
                or row.get("QueueUrl")
                or row.get("Resource")
                or arn
            ).strip()
            if not name:
                continue
            lower_all = f"{service} {arn} {name}".lower()
            if "s3" in lower_all or row.get("BucketName"):
                if name not in buckets:
                    buckets.append(name[:160])
            elif "instance" in lower_all or name.startswith("i-"):
                if name not in ec2_instances:
                    ec2_instances.append(name[:160])
            elif ":role/" in lower_all or "role" in service or row.get("RoleName"):
                if name not in iam_roles:
                    iam_roles.append(name[:160])
            elif ":user/" in lower_all or "user" in service or row.get("UserName"):
                if name not in iam_users:
                    iam_users.append(name[:160])
            elif "lambda" in lower_all or row.get("FunctionName"):
                if name not in lambdas:
                    lambdas.append(name[:160])
            elif "secret" in lower_all:
                if name not in secrets:
                    secrets.append(name[:160])
            elif "sqs" in lower_all or "queue" in lower_all:
                if name not in sqs_queues:
                    sqs_queues.append(name[:160])

    resources = {
        "buckets": buckets[:MAX_ITEMS_PER_CATEGORY],
        "iam_users": iam_users[:MAX_ITEMS_PER_CATEGORY],
        "iam_roles": iam_roles[:MAX_ITEMS_PER_CATEGORY],
        "ec2_instances": ec2_instances[:MAX_ITEMS_PER_CATEGORY],
        "lambdas": lambdas[:MAX_ITEMS_PER_CATEGORY],
        "secrets": secrets[:MAX_ITEMS_PER_CATEGORY],
        "sqs_queues": sqs_queues[:MAX_ITEMS_PER_CATEGORY],
    }
    counts = {key: len(val) for key, val in resources.items()}
    total_resources = sum(counts.values())
    if total_resources == 0:
        raise ValueError(
            "No recognized AWS/CloudFox resources found in JSON (expected buckets, iam_users, iam_roles, ec2_instances, lambdas, secrets, sqs_queues, or row objects)."
        )

    suggested_bindings: dict[str, str] = {}
    if resources["buckets"]:
        suggested_bindings["data_bucket"] = resources["buckets"][0]
    if resources["iam_users"]:
        suggested_bindings["test_user_name"] = resources["iam_users"][0].split("/")[-1]
    if resources["iam_roles"]:
        suggested_bindings["admin_role_name"] = resources["iam_roles"][0].split("/")[-1]
    if resources["ec2_instances"]:
        suggested_bindings["instance_id"] = resources["ec2_instances"][0]
    if resources["sqs_queues"]:
        suggested_bindings["queue_url"] = resources["sqs_queues"][0]

    return {
        "source": "cloudfox",
        "imported_at": _utc_now(),
        "total_resources": total_resources,
        "counts": counts,
        "resources": resources,
        "suggested_bindings": suggested_bindings,
    }


def load_cloudfox_inventory_file(path_str: str, *, base_dir: Path | None = None) -> dict[str, Any]:
    """Safely load and parse a CloudFox JSON file from disk with traversal and size guards."""
    raw = str(path_str or "").strip()
    if not raw:
        raise ValueError("File path is required.")
    if ".." in Path(raw).parts:
        raise ValueError("Path traversal ('..') is not allowed.")
    candidate = Path(raw)
    if base_dir is not None:
        base_resolved = base_dir.resolve()
        target = (base_resolved / candidate).resolve() if not candidate.is_absolute() else candidate.resolve()
        if not target.is_relative_to(base_resolved):
            raise ValueError("Path must stay within the allowed workspace/data directory.")
    else:
        target = candidate.resolve()
    if target.suffix.lower() != ".json":
        raise ValueError("Only .json files are allowed for CloudFox inventory import.")
    if not target.is_file():
        raise FileNotFoundError(f"CloudFox inventory file not found: {target}")
    size = target.stat().st_size
    if size > MAX_CLOUDFOX_BYTES:
        raise ValueError(f"CloudFox JSON file exceeds {MAX_CLOUDFOX_BYTES // (1024 * 1024)} MiB limit.")
    return parse_cloudfox_inventory(target.read_bytes())


def _is_local_proxy_url(proxy_url: str | None) -> bool:
    if not proxy_url:
        return False
    lower = proxy_url.strip().lower()
    return lower.startswith(("http://127.0.0.1:", "http://localhost:"))


def run_cloudfox_recon(
    *,
    profile: str | None = None,
    region: str | None = None,
    which_fn: Callable[[str], str | None] = shutil.which,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> dict[str, Any]:
    """Run CloudFox lazily if installed; otherwise return instant non-fatal status."""
    safe_profile = _validate_safe_identifier(profile, "profile")
    safe_region = _validate_safe_identifier(region, "region")
    exe = which_fn("cloudfox")
    if not exe:
        return {
            "ok": False,
            "installed": False,
            "tool": "cloudfox",
            "error": "CloudFox CLI is not installed in PATH. Paste or import a CloudFox JSON export instead.",
        }
    cmd = [exe, "aws", "--output", "json", "inventory"]
    if safe_profile:
        cmd.extend(["--profile", safe_profile])
    if safe_region:
        cmd.extend(["--region", safe_region])

    proc = runner(cmd, shell=False, capture_output=True, text=True, timeout=90)
    if proc.returncode != 0:
        return {
            "ok": False,
            "installed": True,
            "tool": "cloudfox",
            "returncode": proc.returncode,
            "error": (proc.stderr or proc.stdout or "CloudFox execution failed").strip()[:400],
        }
    inventory = parse_cloudfox_inventory(proc.stdout)
    return {"ok": True, "installed": True, "tool": "cloudfox", "inventory": inventory}


def run_pacu_recon(
    module_name: str,
    *,
    profile: str | None = None,
    session_name: str = "identity_shield_recon",
    proxy_url: str | None = None,
    which_fn: Callable[[str], str | None] = shutil.which,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> dict[str, Any]:
    """Execute an allowlisted read-only Pacu reconnaissance module if Pacu is installed.

    Destructive or privilege-escalation Pacu modules are rejected unconditionally.
    """
    clean_module = str(module_name or "").strip()
    if clean_module not in ALLOWED_PACU_MODULES:
        raise ValueError(
            f"Pacu module '{clean_module}' is not allowed. Permitted read-only modules: {', '.join(sorted(ALLOWED_PACU_MODULES))}."
        )
    safe_session = _validate_safe_identifier(session_name, "session_name") or "identity_shield_recon"
    safe_profile = _validate_safe_identifier(profile, "profile")

    exe = which_fn("pacu")
    if not exe:
        return {
            "ok": False,
            "installed": False,
            "tool": "pacu",
            "module": clean_module,
            "error": "Pacu CLI is not installed in PATH. Built-in Boto3/Proxy/Closed-Loop tests work without Pacu.",
        }

    cmd = [exe, "--session", safe_session, "--exec", "--module-name", clean_module]
    if safe_profile:
        cmd.extend(["--set-aws-keys", safe_profile])

    env = dict(os.environ)
    if proxy_url and _is_local_proxy_url(proxy_url):
        env["HTTP_PROXY"] = proxy_url.strip()
        env["HTTPS_PROXY"] = proxy_url.strip()

    proc = runner(cmd, shell=False, capture_output=True, text=True, timeout=60, env=env)
    return {
        "ok": proc.returncode == 0,
        "installed": True,
        "tool": "pacu",
        "module": clean_module,
        "returncode": proc.returncode,
        "stdout": _redact_secrets(proc.stdout or "")[:2000],
        "stderr": _redact_secrets(proc.stderr or "")[:600],
    }


def parse_scoutsuite_inventory(raw_data: str | bytes | dict[str, Any]) -> dict[str, Any]:
    """Parse a bounded multi-cloud ScoutSuite / resource inventory JSON export (AWS, GCP, Azure)."""
    if isinstance(raw_data, bytes):
        if len(raw_data) > MAX_CLOUDFOX_BYTES:
            raise ValueError(f"Recon JSON exceeds {MAX_CLOUDFOX_BYTES // (1024 * 1024)} MiB limit.")
        payload = json.loads(raw_data.decode("utf-8"))
    elif isinstance(raw_data, str):
        if len(raw_data.encode("utf-8")) > MAX_CLOUDFOX_BYTES:
            raise ValueError(f"Recon JSON exceeds {MAX_CLOUDFOX_BYTES // (1024 * 1024)} MiB limit.")
        payload = json.loads(raw_data)
    else:
        payload = raw_data

    if not isinstance(payload, dict):
        raise ValueError("Multi-cloud inventory JSON must be an object.")
    payload = _redact_secrets(payload)

    provider_code = str(payload.get("provider_code") or payload.get("cloud_provider") or "aws").lower()
    if provider_code not in {"aws", "gcp", "azure"}:
        provider_code = "aws"
    account_scope = str(payload.get("account_id") or payload.get("project_id") or payload.get("subscription_id") or "")

    # Extract resources uniformly from ScoutSuite `services` tree or simplified keys
    buckets: list[str] = _extract_names(payload.get("buckets"), ("name", "id", "BucketName"))
    identities: list[str] = _extract_names(
        payload.get("service_accounts") or payload.get("iam_roles") or payload.get("principals"),
        ("email", "name", "id", "RoleName", "UserName"),
    )
    secrets: list[str] = _extract_names(payload.get("secrets") or payload.get("keyvaults"), ("name", "id", "SecretName"))
    compute: list[str] = _extract_names(payload.get("instances") or payload.get("vms"), ("name", "id", "InstanceId"))

    services = payload.get("services")
    if isinstance(services, dict):
        for svc_name, svc_data in services.items():
            if not isinstance(svc_data, dict):
                continue
            sl = str(svc_name).lower()
            for bucket_map_key in ("buckets", "storageaccounts", "containers"):
                b_obj = svc_data.get(bucket_map_key)
                if isinstance(b_obj, dict):
                    buckets.extend(str(k)[:160] for k in list(b_obj.keys())[:MAX_ITEMS_PER_CATEGORY])
            for id_key in ("service_accounts", "users", "roles", "service_principals"):
                i_obj = svc_data.get(id_key)
                if isinstance(i_obj, dict):
                    identities.extend(str(k)[:160] for k in list(i_obj.keys())[:MAX_ITEMS_PER_CATEGORY])
            for sec_key in ("secrets", "vaults", "keyvaults"):
                s_obj = svc_data.get(sec_key)
                if isinstance(s_obj, dict):
                    secrets.extend(str(k)[:160] for k in list(s_obj.keys())[:MAX_ITEMS_PER_CATEGORY])
            for vm_key in ("instances", "vms", "virtual_machines"):
                v_obj = svc_data.get(vm_key)
                if isinstance(v_obj, dict):
                    compute.extend(str(k)[:160] for k in list(v_obj.keys())[:MAX_ITEMS_PER_CATEGORY])

    buckets = list(dict.fromkeys(buckets))[:MAX_ITEMS_PER_CATEGORY]
    identities = list(dict.fromkeys(identities))[:MAX_ITEMS_PER_CATEGORY]
    secrets = list(dict.fromkeys(secrets))[:MAX_ITEMS_PER_CATEGORY]
    compute = list(dict.fromkeys(compute))[:MAX_ITEMS_PER_CATEGORY]
    total = len(buckets) + len(identities) + len(secrets) + len(compute)
    if total == 0:
        raise ValueError("No recognized AWS/GCP/Azure resources found in ScoutSuite/recon JSON.")

    return {
        "source": "scoutsuite",
        "cloud_provider": provider_code,
        "account_scope": account_scope,
        "imported_at": _utc_now(),
        "total_resources": total,
        "counts": {
            "buckets": len(buckets),
            "identities": len(identities),
            "secrets": len(secrets),
            "compute": len(compute),
        },
        "resources": {
            "buckets": buckets,
            "identities": identities,
            "secrets": secrets,
            "compute": compute,
        },
    }
