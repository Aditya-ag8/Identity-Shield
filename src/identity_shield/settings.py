"""Central configuration, threshold guardrails, resource bindings, and attack overrides.

Shared by both the CLI and the Web Control Plane API so every setting,
threshold, resource binding, and custom attack behaves identically regardless
of which interface the operator uses.

Security invariant: permanent or temporary AWS secret keys / session tokens are
held strictly in process memory (``RuntimeSessionStore``) and are NEVER written
to SQLite or JSON configuration files on disk.
"""

from __future__ import annotations

import copy
import json
import os
import re
import threading
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Mapping

from identity_shield import config

_TECHNIQUE_RE = re.compile(r"^T\d{4}(?:\.[A-Za-z0-9_]{1,16})?$")
_RULE_STEM_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,80}$")
_LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}


def validate_rule_stem(name: str) -> str:
    """Ensure a Sigma rule filename maps strictly inside the rules directory."""
    raw = str(name or "").strip()
    if not raw or "/" in raw or "\\" in raw or ".." in raw or "\x00" in raw:
        raise ValueError(f"Invalid rule filename {name!r}")
    stem = Path(raw).stem
    if not _RULE_STEM_RE.fullmatch(stem):
        raise ValueError(f"Unsafe rule filename {name!r}; use alphanumerics, '-', '_', or '.'")
    return stem


@dataclass
class ThresholdConfig:
    """Operational cost, SLA, and detection quality-gate thresholds."""

    budget_usd: float = 50.0
    budget_alert_emails: list[str] = field(default_factory=list)
    enable_data_events: bool = False
    enable_instance: bool = False
    log_retention_days: int = 30
    allowed_regions: list[str] = field(default_factory=lambda: ["eu-west-1", "us-east-1", "us-west-2"])
    min_detection_rate: float = 0.80
    max_evasion_rate: float = 0.20
    max_false_alarm_rate: float = 0.05
    max_ingest_lag_ms: int = 300_000
    collector_timeout_seconds: int = 120
    max_delivery_lag_minutes: int = 15

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any] | None) -> "ThresholdConfig":
        if not data:
            return cls()
        defaults = cls()
        regions = data.get("allowed_regions")
        if isinstance(regions, list) and regions:
            allowed_regions = [str(r).strip() for r in regions if str(r).strip()]
        else:
            allowed_regions = list(defaults.allowed_regions)
        emails = data.get("budget_alert_emails")
        budget_emails = (
            [str(e).strip() for e in emails if str(e).strip()]
            if isinstance(emails, list)
            else []
        )
        return cls(
            budget_usd=float(data.get("budget_usd", defaults.budget_usd)),
            budget_alert_emails=budget_emails,
            enable_data_events=bool(data.get("enable_data_events", defaults.enable_data_events)),
            enable_instance=bool(data.get("enable_instance", defaults.enable_instance)),
            log_retention_days=int(data.get("log_retention_days", defaults.log_retention_days)),
            allowed_regions=allowed_regions,
            min_detection_rate=float(data.get("min_detection_rate", defaults.min_detection_rate)),
            max_evasion_rate=float(data.get("max_evasion_rate", defaults.max_evasion_rate)),
            max_false_alarm_rate=float(data.get("max_false_alarm_rate", defaults.max_false_alarm_rate)),
            max_ingest_lag_ms=int(data.get("max_ingest_lag_ms", defaults.max_ingest_lag_ms)),
            collector_timeout_seconds=int(
                data.get("collector_timeout_seconds", defaults.collector_timeout_seconds)
            ),
            max_delivery_lag_minutes=int(
                data.get("max_delivery_lag_minutes", defaults.max_delivery_lag_minutes)
            ),
        )


@dataclass
class ResourceBinding:
    """Bound target AWS, GCP, and Azure resources for live simulation & SIEM collection."""

    # AWS targets
    lab_name: str = "identity-shield"
    region: str = "eu-west-1"
    data_bucket: str = "is-lab-crown-jewels"
    data_key: str = "finance/q4.csv"
    trail_name: str = "identity-shield-trail"
    queue_url: str = ""
    test_user_name: str = "is-test-user"
    admin_role_name: str = "is-admin-role"
    instance_id: str = ""
    # GCP targets
    gcp_project_id: str = ""
    gcp_region: str = "us-central1"
    gcp_bucket: str = ""
    gcp_object_key: str = "finance/q4.csv"
    gcp_secret_name: str = ""
    gcp_service_account: str = ""
    gcp_log_sink: str = "identity-shield-audit-sink"
    # Azure targets
    azure_subscription_id: str = ""
    azure_location: str = "eastus"
    azure_resource_group: str = "rg-identity-shield-lab"
    azure_key_vault: str = ""
    azure_secret_name: str = "lab-secret"
    azure_storage_account: str = ""
    azure_vm_name: str = ""
    azure_spn_id: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any] | None) -> "ResourceBinding":
        if not data:
            return cls()
        defaults = cls()
        return cls(
            lab_name=str(data.get("lab_name") or defaults.lab_name),
            region=str(data.get("region") or defaults.region),
            data_bucket=str(data.get("data_bucket") or defaults.data_bucket),
            data_key=str(data.get("data_key") or defaults.data_key),
            trail_name=str(data.get("trail_name") or defaults.trail_name),
            queue_url=str(data.get("queue_url") or ""),
            test_user_name=str(data.get("test_user_name") or defaults.test_user_name),
            admin_role_name=str(data.get("admin_role_name") or defaults.admin_role_name),
            instance_id=str(data.get("instance_id") or ""),
            gcp_project_id=str(data.get("gcp_project_id") or ""),
            gcp_region=str(data.get("gcp_region") or defaults.gcp_region),
            gcp_bucket=str(data.get("gcp_bucket") or ""),
            gcp_object_key=str(data.get("gcp_object_key") or defaults.gcp_object_key),
            gcp_secret_name=str(data.get("gcp_secret_name") or ""),
            gcp_service_account=str(data.get("gcp_service_account") or ""),
            gcp_log_sink=str(data.get("gcp_log_sink") or defaults.gcp_log_sink),
            azure_subscription_id=str(data.get("azure_subscription_id") or ""),
            azure_location=str(data.get("azure_location") or defaults.azure_location),
            azure_resource_group=str(data.get("azure_resource_group") or defaults.azure_resource_group),
            azure_key_vault=str(data.get("azure_key_vault") or ""),
            azure_secret_name=str(data.get("azure_secret_name") or defaults.azure_secret_name),
            azure_storage_account=str(data.get("azure_storage_account") or ""),
            azure_vm_name=str(data.get("azure_vm_name") or ""),
            azure_spn_id=str(data.get("azure_spn_id") or ""),
        )


@dataclass
class ConnectionDescriptor:
    """Non-secret metadata describing how the workspace connects to AWS."""

    auth_mode: str = "profile"  # profile | assume_role | in_memory
    profile_name: str = "lab"
    role_arn: str = ""
    external_id: str = ""
    session_name: str = "identity-shield-session"
    region: str = "eu-west-1"
    scope: str = "single_account"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any] | None) -> "ConnectionDescriptor":
        if not data:
            return cls()
        defaults = cls()
        return cls(
            auth_mode=str(data.get("auth_mode") or defaults.auth_mode),
            profile_name=str(data.get("profile_name") if data.get("profile_name") is not None else defaults.profile_name),
            role_arn=str(data.get("role_arn") or ""),
            external_id=str(data.get("external_id") or ""),
            session_name=str(data.get("session_name") or defaults.session_name),
            region=str(data.get("region") or defaults.region),
            scope=str(data.get("scope") or defaults.scope),
        )


@dataclass
class GcpConnectionDescriptor:
    """Non-secret metadata describing how the workspace connects to GCP."""

    auth_mode: str = "gcloud_adc"  # gcloud_adc | impersonate_sa | service_account_json | workload_identity | in_memory_token
    project_id: str = ""
    organization_id: str = ""
    service_account: str = ""
    region: str = "us-central1"
    scope: str = "single_project"  # single_project | organization
    gcloud_config: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any] | None) -> "GcpConnectionDescriptor":
        if not data:
            return cls()
        defaults = cls()
        return cls(
            auth_mode=str(data.get("auth_mode") or defaults.auth_mode),
            project_id=str(data.get("project_id") or ""),
            organization_id=str(data.get("organization_id") or ""),
            service_account=str(data.get("service_account") or ""),
            region=str(data.get("region") or defaults.region),
            scope=str(data.get("scope") or defaults.scope),
            gcloud_config=str(data.get("gcloud_config") or ""),
        )


@dataclass
class AzureConnectionDescriptor:
    """Non-secret metadata describing how the workspace connects to Microsoft Azure / Entra ID."""

    auth_mode: str = "az_cli"  # az_cli | service_principal | oidc_federated | managed_identity | in_memory_token
    tenant_id: str = ""
    subscription_id: str = ""
    management_group_id: str = ""
    client_id: str = ""
    location: str = "eastus"
    scope: str = "single_subscription"  # single_subscription | organization

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any] | None) -> "AzureConnectionDescriptor":
        if not data:
            return cls()
        defaults = cls()
        return cls(
            auth_mode=str(data.get("auth_mode") or defaults.auth_mode),
            tenant_id=str(data.get("tenant_id") or ""),
            subscription_id=str(data.get("subscription_id") or ""),
            management_group_id=str(data.get("management_group_id") or ""),
            client_id=str(data.get("client_id") or ""),
            location=str(data.get("location") or defaults.location),
            scope=str(data.get("scope") or defaults.scope),
        )


@dataclass
class ProxyConfig:
    """Configuration for the inline Live Security Proxy & Adaptive Detection."""

    host: str = "127.0.0.1"
    port: int = 8888
    mode: str = "observe"  # observe | block
    upstream_url: str = ""  # Optional cloud app / API target URL; blank = capture / forward HTTP
    rewrite_host: bool = True
    block_risk_threshold: float = 70.0
    learn_baseline: bool = True
    ruleset_version: str = "enhanced-v1"
    tls_intercept_enabled: bool = False
    tls_passthrough_hosts: list[str] = field(
        default_factory=lambda: [
            "login.microsoftonline.com",
            "accounts.google.com",
            "signin.aws.amazon.com",
        ]
    )
    provider_policies: dict[str, str] = field(
        default_factory=lambda: {
            "aws": "inherit",
            "gcp": "observe",
            "azure": "observe",
            "unknown": "inherit",
        }
    )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any] | None) -> "ProxyConfig":
        if not data:
            return cls()
        defaults = cls()
        mode = str(data.get("mode") or defaults.mode).lower()
        if mode not in {"observe", "block"}:
            mode = defaults.mode
        host = str(data.get("host") or defaults.host).strip()
        if host.lower() not in _LOOPBACK_HOSTS and os.environ.get("IDENTITY_SHIELD_ALLOW_PUBLIC_PROXY") != "1":
            raise ValueError(
                f"Refusing to bind proxy to non-loopback host {host!r} without IDENTITY_SHIELD_ALLOW_PUBLIC_PROXY=1"
            )
        upstream = str(data.get("upstream_url") or "").strip()
        if upstream:
            from urllib.parse import urlsplit

            parsed = urlsplit(upstream)
            if parsed.scheme not in {"http", "https"} or not parsed.hostname:
                raise ValueError(f"Invalid upstream_url {upstream!r}; expected http(s)://host[:port]")
            if parsed.hostname.startswith("169.254."):
                raise ValueError("Refusing upstream_url pointing to AWS link-local metadata (169.254.x.x)")
        policies = dict(defaults.provider_policies)
        if isinstance(data.get("provider_policies"), Mapping):
            for k, v in data["provider_policies"].items():
                val = str(v or "").strip().lower()
                if val in {"inherit", "observe", "block"}:
                    policies[str(k).lower()] = val
        passthrough = (
            [str(x).strip() for x in data["tls_passthrough_hosts"] if str(x).strip()]
            if isinstance(data.get("tls_passthrough_hosts"), list)
            else list(defaults.tls_passthrough_hosts)
        )
        return cls(
            host=host,
            port=int(data.get("port") if data.get("port") is not None else defaults.port),
            mode=mode,
            upstream_url=upstream,
            rewrite_host=bool(data.get("rewrite_host", defaults.rewrite_host)),
            block_risk_threshold=float(data.get("block_risk_threshold", defaults.block_risk_threshold)),
            learn_baseline=bool(data.get("learn_baseline", defaults.learn_baseline)),
            ruleset_version=str(data.get("ruleset_version") or defaults.ruleset_version),
            tls_intercept_enabled=bool(data.get("tls_intercept_enabled", defaults.tls_intercept_enabled)),
            tls_passthrough_hosts=passthrough,
            provider_policies=policies,
        )


@dataclass
class StorageConfig:
    """Self-hosted database linking, retention cap, and organization S3 archiving."""

    db_path: str = ""  # Empty = default data/identity_shield.db; custom path for mounted/org DB files
    max_proxy_events: int = 50_000
    archive_s3_bucket: str = ""
    archive_s3_prefix: str = "identity-shield-telemetry/"
    archive_gcs_bucket: str = ""
    archive_azure_account: str = ""
    archive_azure_container: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any] | None) -> "StorageConfig":
        if not data:
            return cls()
        defaults = cls()
        raw_db = str(data.get("db_path") or "").strip()
        lower_db = raw_db.lower()
        if lower_db.startswith(("postgres://", "postgresql://", "mysql://", "mongodb://")):
            raise ValueError(
                "Remote SQL servers (PostgreSQL/MySQL) require a future DB adapter. "
                "Provide a local/mounted SQLite file path (e.g. D:/SecOps/org.db) or use "
                "JSONL Export / S3 Archive below for external warehouses."
            )
        if raw_db:
            if "\x00" in raw_db or ".." in Path(raw_db).parts:
                raise ValueError("Database path cannot contain traversal segments ('..') or null bytes")
            if not lower_db.endswith((".db", ".sqlite", ".sqlite3")):
                raise ValueError("Linked database path must end in .db, .sqlite, or .sqlite3")
            resolved_str = str(Path(raw_db).expanduser().resolve()).lower()
            blocked_prefixes = ("c:\\windows", "/etc/", "/bin/", "/usr/", "/sbin/", "/system/")
            if any(resolved_str.startswith(bp) for bp in blocked_prefixes):
                raise ValueError(f"Refusing to place database inside protected system directory: {raw_db}")
        return cls(
            db_path=raw_db,
            max_proxy_events=max(0, int(data.get("max_proxy_events") if data.get("max_proxy_events") is not None else defaults.max_proxy_events)),
            archive_s3_bucket=str(data.get("archive_s3_bucket") or "").strip(),
            archive_s3_prefix=str(data.get("archive_s3_prefix") or defaults.archive_s3_prefix).strip(),
            archive_gcs_bucket=str(data.get("archive_gcs_bucket") or "").strip(),
            archive_azure_account=str(data.get("archive_azure_account") or "").strip(),
            archive_azure_container=str(data.get("archive_azure_container") or "").strip(),
        )


def workspace_config_path() -> Path:
    override = os.environ.get("IDENTITY_SHIELD_CONFIG")
    if override:
        return Path(override).expanduser().resolve()
    return config.DATA / "workspace_config.json"


def attack_overrides_path() -> Path:
    override = os.environ.get("IDENTITY_SHIELD_ATTACK_OVERRIDES")
    if override:
        return Path(override).expanduser().resolve()
    return config.DATA / "attack_overrides.json"


def load_workspace_config() -> dict[str, Any]:
    path = workspace_config_path()
    if not path.exists():
        return {
            "thresholds": ThresholdConfig().to_dict(),
            "resources": ResourceBinding().to_dict(),
            "connection": ConnectionDescriptor().to_dict(),
            "gcp_connection": GcpConnectionDescriptor().to_dict(),
            "azure_connection": AzureConnectionDescriptor().to_dict(),
            "proxy": ProxyConfig().to_dict(),
            "storage": StorageConfig().to_dict(),
        }
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        raw = {}
    return {
        "thresholds": ThresholdConfig.from_dict(raw.get("thresholds")).to_dict(),
        "resources": ResourceBinding.from_dict(raw.get("resources")).to_dict(),
        "connection": ConnectionDescriptor.from_dict(raw.get("connection")).to_dict(),
        "gcp_connection": GcpConnectionDescriptor.from_dict(raw.get("gcp_connection")).to_dict(),
        "azure_connection": AzureConnectionDescriptor.from_dict(raw.get("azure_connection")).to_dict(),
        "proxy": ProxyConfig.from_dict(raw.get("proxy")).to_dict(),
        "storage": StorageConfig.from_dict(raw.get("storage")).to_dict(),
    }


def save_workspace_config(payload: Mapping[str, Any]) -> dict[str, Any]:
    path = workspace_config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    current = load_workspace_config()
    if "thresholds" in payload:
        current["thresholds"] = ThresholdConfig.from_dict(payload["thresholds"]).to_dict()
    if "resources" in payload:
        current["resources"] = ResourceBinding.from_dict(payload["resources"]).to_dict()
    if "connection" in payload:
        # Strip any accidental secret fields before saving to disk
        conn_clean = ConnectionDescriptor.from_dict(payload["connection"]).to_dict()
        current["connection"] = conn_clean
    if "gcp_connection" in payload:
        current["gcp_connection"] = GcpConnectionDescriptor.from_dict(payload["gcp_connection"]).to_dict()
    if "azure_connection" in payload:
        current["azure_connection"] = AzureConnectionDescriptor.from_dict(payload["azure_connection"]).to_dict()
    if "proxy" in payload:
        current["proxy"] = ProxyConfig.from_dict(payload["proxy"]).to_dict()
    if "storage" in payload:
        current["storage"] = StorageConfig.from_dict(payload["storage"]).to_dict()
    path.write_text(json.dumps(current, indent=2, sort_keys=True), encoding="utf-8")
    return current


def get_storage_config() -> StorageConfig:
    return StorageConfig.from_dict(load_workspace_config().get("storage"))


def update_storage_config(updates: Mapping[str, Any]) -> StorageConfig:
    current = load_workspace_config()
    merged = {**current["storage"], **dict(updates)}
    saved = save_workspace_config({"storage": merged})
    return StorageConfig.from_dict(saved["storage"])


def get_proxy_config() -> ProxyConfig:
    return ProxyConfig.from_dict(load_workspace_config().get("proxy"))


def update_proxy_config(updates: Mapping[str, Any]) -> ProxyConfig:
    current = load_workspace_config()
    merged = {**current["proxy"], **dict(updates)}
    saved = save_workspace_config({"proxy": merged})
    return ProxyConfig.from_dict(saved["proxy"])


def get_thresholds() -> ThresholdConfig:
    return ThresholdConfig.from_dict(load_workspace_config().get("thresholds"))


def update_thresholds(updates: Mapping[str, Any]) -> ThresholdConfig:
    current = load_workspace_config()
    merged = {**current["thresholds"], **dict(updates)}
    saved = save_workspace_config({"thresholds": merged})
    return ThresholdConfig.from_dict(saved["thresholds"])


def get_resources() -> ResourceBinding:
    return ResourceBinding.from_dict(load_workspace_config().get("resources"))


def update_resources(updates: Mapping[str, Any]) -> ResourceBinding:
    current = load_workspace_config()
    merged = {**current["resources"], **dict(updates)}
    saved = save_workspace_config({"resources": merged})
    return ResourceBinding.from_dict(saved["resources"])


def get_connection_descriptor() -> ConnectionDescriptor:
    return ConnectionDescriptor.from_dict(load_workspace_config().get("connection"))


def update_connection_descriptor(updates: Mapping[str, Any]) -> ConnectionDescriptor:
    current = load_workspace_config()
    merged = {**current["connection"], **dict(updates)}
    saved = save_workspace_config({"connection": merged})
    return ConnectionDescriptor.from_dict(saved["connection"])


def get_gcp_connection_descriptor() -> GcpConnectionDescriptor:
    return GcpConnectionDescriptor.from_dict(load_workspace_config().get("gcp_connection"))


def update_gcp_connection_descriptor(updates: Mapping[str, Any]) -> GcpConnectionDescriptor:
    current = load_workspace_config()
    merged = {**current["gcp_connection"], **dict(updates)}
    saved = save_workspace_config({"gcp_connection": merged})
    return GcpConnectionDescriptor.from_dict(saved["gcp_connection"])


def get_azure_connection_descriptor() -> AzureConnectionDescriptor:
    return AzureConnectionDescriptor.from_dict(load_workspace_config().get("azure_connection"))


def update_azure_connection_descriptor(updates: Mapping[str, Any]) -> AzureConnectionDescriptor:
    current = load_workspace_config()
    merged = {**current["azure_connection"], **dict(updates)}
    saved = save_workspace_config({"azure_connection": merged})
    return AzureConnectionDescriptor.from_dict(saved["azure_connection"])


# ---------------------------------------------------------------------------
# Attack Overrides (enable/disable built-ins + custom attack CRUD)
# ---------------------------------------------------------------------------


def load_attack_overrides() -> dict[str, Any]:
    path = attack_overrides_path()
    if not path.exists():
        return {"disabled_techniques": [], "custom_techniques": []}
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"disabled_techniques": [], "custom_techniques": []}
    return {
        "disabled_techniques": [str(t) for t in raw.get("disabled_techniques") or []],
        "custom_techniques": [dict(t) for t in raw.get("custom_techniques") or [] if isinstance(t, Mapping)],
    }


def save_attack_overrides(overrides: Mapping[str, Any]) -> dict[str, Any]:
    path = attack_overrides_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    clean = {
        "disabled_techniques": sorted({str(t).strip() for t in overrides.get("disabled_techniques") or [] if str(t).strip()}),
        "custom_techniques": [dict(t) for t in overrides.get("custom_techniques") or []],
    }
    path.write_text(json.dumps(clean, indent=2), encoding="utf-8")
    return clean


def validate_custom_technique(entry: Mapping[str, Any]) -> dict[str, Any]:
    """Validate and normalise a custom attack specification."""
    technique_id = str(entry.get("technique_id") or "").strip()
    if not _TECHNIQUE_RE.match(technique_id):
        raise ValueError(
            f"Invalid technique_id {technique_id!r}. Expected ATT&CK format like 'T1087.004' or 'T1538' or 'T9001.custom'."
        )
    name = str(entry.get("name") or "").strip()
    if not name:
        raise ValueError("Attack name is required")
    tactic = str(entry.get("tactic") or "discovery").strip() or "discovery"
    inferred_cloud = "gcp" if ".GCP" in technique_id.upper() else ("azure" if ".AZ" in technique_id.upper() else "aws")
    cloud_provider = str(entry.get("cloud_provider") or inferred_cloud).strip().lower()
    if cloud_provider not in {"aws", "gcp", "azure"}:
        raise ValueError(f"Unsupported cloud_provider {cloud_provider!r}. Expected aws, gcp, or azure.")

    event_names = entry.get("event_names") or []
    if isinstance(event_names, str):
        event_names = [item.strip() for item in event_names.split(",") if item.strip()]
    event_names = [str(item).strip() for item in event_names if str(item).strip()]
    if not event_names:
        raise ValueError("At least one audit event / operation name is required (e.g. DescribeVpcs, CreateServiceAccountKey, or SecretGet)")

    required_actions = entry.get("required_actions") or []
    if isinstance(required_actions, str):
        required_actions = [item.strip() for item in required_actions.split(",") if item.strip()]
    required_actions = [str(item).strip() for item in required_actions if str(item).strip()]

    api_calls_raw = entry.get("api_calls") or []
    api_calls: list[dict[str, Any]] = []
    if isinstance(api_calls_raw, list):
        for call in api_calls_raw:
            if not isinstance(call, Mapping):
                continue
            service = str(call.get("service") or "").strip().lower()
            operation = str(call.get("operation") or "").strip()
            if service and operation:
                kwargs = call.get("kwargs") if isinstance(call.get("kwargs"), Mapping) else {}
                api_calls.append({"service": service, "operation": operation, "kwargs": dict(kwargs)})

    # Convenience shorthand if single service/operation supplied
    if not api_calls and entry.get("service") and entry.get("operation"):
        svc_val = str(entry["service"]).strip()
        api_calls.append(
            {
                "service": svc_val.lower() if cloud_provider != "azure" else svc_val,
                "operation": str(entry["operation"]).strip(),
                "kwargs": dict(entry.get("kwargs") or {}),
            }
        )

    if not api_calls:
        # Derive conservative fallback call appropriate for the target cloud if only event_names supplied
        if cloud_provider == "gcp":
            api_calls.append({"service": str(entry.get("service") or "iam.googleapis.com").strip(), "operation": event_names[0], "kwargs": {}})
        elif cloud_provider == "azure":
            api_calls.append({"service": str(entry.get("service") or "Microsoft.Authorization").strip(), "operation": event_names[0], "kwargs": {}})
        else:
            api_calls.append({"service": "sts", "operation": "get_caller_identity", "kwargs": {}})

    if not required_actions and api_calls:
        required_actions = [f"{c['service']}:{c['operation']}" for c in api_calls]

    success_check = dict(entry.get("success_check") or {})
    if not success_check:
        success_check = {"type": "api_calls_succeeded", "minimum": 1}

    excluded_levels = {
        str(k): [str(v) for v in vals]
        for k, vals in (entry.get("excluded_levels") or {}).items()
        if isinstance(vals, list) and vals
    }
    baseline_levels = {
        str(k): str(v)
        for k, v in (entry.get("baseline_levels") or {}).items()
        if v
    }

    default_exec = "custom_boto3" if cloud_provider == "aws" else f"{cloud_provider}_synthetic"
    return {
        "technique_id": technique_id,
        "cloud_provider": cloud_provider,
        "name": name,
        "tactic": tactic,
        "executor": str(entry.get("executor") or default_exec),
        "executor_ref": str(entry.get("executor_ref") or ("identity_shield.runner.executors.custom_api" if cloud_provider == "aws" else "")),
        "event_names": event_names,
        "requires_data_events": bool(entry.get("requires_data_events", False)),
        "required_actions": required_actions,
        "api_calls": api_calls,
        "success_check": success_check,
        "excluded_levels": excluded_levels,
        "baseline_levels": baseline_levels,
        "notes": str(entry.get("notes") or "Custom user-authored technique").strip(),
    }


def add_or_update_custom_attack(entry: Mapping[str, Any]) -> dict[str, Any]:
    clean = validate_custom_technique(entry)
    overrides = load_attack_overrides()
    existing = [
        item for item in overrides["custom_techniques"] if item.get("technique_id") != clean["technique_id"]
    ]
    existing.append(clean)
    overrides["custom_techniques"] = existing
    # Re-enable automatically if it was disabled
    overrides["disabled_techniques"] = [
        t for t in overrides["disabled_techniques"] if t.upper() != clean["technique_id"].upper()
    ]
    save_attack_overrides(overrides)
    return clean


def set_attack_enabled(technique_id: str, enabled: bool) -> dict[str, Any]:
    tid = technique_id.strip()
    overrides = load_attack_overrides()
    disabled = [t for t in overrides["disabled_techniques"] if t.upper() != tid.upper()]
    if not enabled:
        disabled.append(tid)
    overrides["disabled_techniques"] = sorted(set(disabled))
    return save_attack_overrides(overrides)


def remove_attack(technique_id: str) -> dict[str, Any]:
    """Delete a custom attack completely; for built-in attacks, disable it cleanly."""
    tid = technique_id.strip()
    overrides = load_attack_overrides()
    before_len = len(overrides["custom_techniques"])
    overrides["custom_techniques"] = [
        item for item in overrides["custom_techniques"] if str(item.get("technique_id") or "").upper() != tid.upper()
    ]
    was_custom = len(overrides["custom_techniques"]) < before_len
    if not was_custom:
        disabled = [t for t in overrides["disabled_techniques"] if t.upper() != tid.upper()]
        disabled.append(tid)
        overrides["disabled_techniques"] = sorted(set(disabled))
    else:
        overrides["disabled_techniques"] = [t for t in overrides["disabled_techniques"] if t.upper() != tid.upper()]
    return {**save_attack_overrides(overrides), "deleted_custom": was_custom}


# ---------------------------------------------------------------------------
# In-memory Runtime Session Store (Zero Disk Secret Persistence)
# ---------------------------------------------------------------------------


class RuntimeSessionStore:
    """Process-local multi-cloud session cache (AWS, GCP, Azure). Secrets never touch disk."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._active: dict[str, Any] | None = None
        self._providers: dict[str, dict[str, Any]] = {}

    def set_connection(
        self,
        *,
        descriptor: ConnectionDescriptor,
        boto_session: Any,
        classification: dict[str, Any],
        caller_arn: str,
        account_id: str,
        in_memory_keys: Mapping[str, str] | None = None,
    ) -> None:
        with self._lock:
            entry = {
                "descriptor": descriptor.to_dict(),
                "boto_session": boto_session,
                "classification": copy.deepcopy(classification),
                "caller_arn": caller_arn,
                "account_id": account_id,
                "has_temp_keys": bool(in_memory_keys),
            }
            self._active = entry
            self._providers["aws"] = entry

    def set_cloud_connection(
        self,
        provider: str,
        *,
        descriptor: Mapping[str, Any],
        identity: Mapping[str, Any],
        material: Mapping[str, Any] | None = None,
    ) -> None:
        clean_provider = str(provider or "").strip().lower()
        if clean_provider not in {"aws", "gcp", "azure"}:
            raise ValueError(f"Unsupported cloud provider: {provider!r}")
        with self._lock:
            self._providers[clean_provider] = {
                "descriptor": copy.deepcopy(dict(descriptor)),
                "identity": copy.deepcopy(dict(identity)),
                "material": dict(material or {}),
            }

    def clear(self, provider: str | None = None) -> None:
        with self._lock:
            if provider is None:
                self._active = None
                self._providers.clear()
                return
            clean = str(provider).strip().lower()
            if clean == "aws":
                self._active = None
            self._providers.pop(clean, None)

    def status(self) -> dict[str, Any]:
        with self._lock:
            if not self._active:
                return {"connected": False, "descriptor": get_connection_descriptor().to_dict()}
            return {
                "connected": True,
                "account_id": self._active["account_id"],
                "caller_arn": self._active["caller_arn"],
                "descriptor": self._active["descriptor"],
                "classification": self._active["classification"],
            }

    def provider_status(self, provider: str) -> dict[str, Any]:
        clean = str(provider or "").strip().lower()
        with self._lock:
            if clean == "aws":
                return self.status()
            if clean == "gcp":
                entry = self._providers.get("gcp")
                if not entry:
                    return {"connected": False, "descriptor": get_gcp_connection_descriptor().to_dict()}
                return {
                    "connected": True,
                    "descriptor": copy.deepcopy(entry["descriptor"]),
                    "identity": copy.deepcopy(entry["identity"]),
                }
            if clean == "azure":
                entry = self._providers.get("azure")
                if not entry:
                    return {"connected": False, "descriptor": get_azure_connection_descriptor().to_dict()}
                return {
                    "connected": True,
                    "descriptor": copy.deepcopy(entry["descriptor"]),
                    "identity": copy.deepcopy(entry["identity"]),
                }
        raise ValueError(f"Unsupported cloud provider: {provider!r}")

    def all_statuses(self) -> dict[str, dict[str, Any]]:
        return {
            "aws": self.provider_status("aws"),
            "gcp": self.provider_status("gcp"),
            "azure": self.provider_status("azure"),
        }

    def get_provider_material(self, provider: str) -> dict[str, Any] | None:
        clean = str(provider or "").strip().lower()
        with self._lock:
            entry = self._providers.get(clean)
            if not entry:
                return None
            return dict(entry.get("material") or {})

    def boto_session(self) -> Any | None:
        with self._lock:
            if not self._active:
                return None
            return self._active.get("boto_session")


RUNTIME_SESSION = RuntimeSessionStore()
