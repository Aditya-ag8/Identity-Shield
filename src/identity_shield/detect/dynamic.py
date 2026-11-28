"""Adaptive & Dynamic Behavioral Detection Engine.

Evaluates streaming proxy traffic and stored CloudTrail events across time
windows, multi-step attack sequences, behavioral drift from learned baselines,
and web-application HTTP anomalies — complementing static single-event Sigma rules.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping, Sequence

from identity_shield.detect import policy as detect_policy
from identity_shield.detect import replay as detect_replay
from identity_shield.detect.rules import Rule, get_field

ISO = "%Y-%m-%dT%H:%M:%SZ"

SEVERITY_SCORES = {
    "critical": 85.0,
    "high": 70.0,
    "medium": 45.0,
    "low": 25.0,
}

DEFAULT_DYNAMIC_RULES: tuple[dict[str, Any], ...] = (
    {
        "rule_id": "DYN-VEL-001",
        "name": "API Discovery & Enumeration Burst",
        "kind": "velocity",
        "enabled": 1,
        "severity": "high",
        "window_seconds": 60,
        "threshold": 5,
        "config": {
            "prefixes": ["List", "Describe", "Get", "Head"],
            "min_distinct_ops": 2,
            "include_http_gets": True,
        },
        "description": (
            "Detects rapid bursts of enumeration/read API calls within a sliding window, "
            "regardless of client tool or specific operation name."
        ),
    },
    {
        "rule_id": "DYN-SEQ-001",
        "name": "Reconnaissance to Persistence / Escalation Chain",
        "kind": "sequence",
        "enabled": 1,
        "severity": "critical",
        "window_seconds": 300,
        "threshold": 2,
        "config": {
            "stages": [
                [
                    "ListUsers",
                    "ListRoles",
                    "ListAccessKeys",
                    "GetAccountAuthorizationDetails",
                    "DescribeInstances",
                    "DescribeSecurityGroups",
                    "DescribeVpcs",
                    "ListBuckets",
                    "ListSecrets",
                    "storage.objects.list",
                    "storage.buckets.get",
                    "v1.compute.instances.list",
                    "google.cloud.secretmanager.v1.SecretManagerService.ListSecrets",
                    "List users",
                    "SecretList",
                ],
                [
                    "CreateAccessKey",
                    "CreateLoginProfile",
                    "UpdateLoginProfile",
                    "AttachRolePolicy",
                    "PutRolePolicy",
                    "UpdateAssumeRolePolicy",
                    "PassRole",
                    "AssumeRole",
                    "GetObject",
                    "google.iam.admin.v1.CreateServiceAccountKey",
                    "google.cloud.resourcemanager.v3.Projects.SetIamPolicy",
                    "SetIamPolicy",
                    "google.cloud.secretmanager.v1.SecretManagerService.AccessSecretVersion",
                    "storage.objects.get",
                    "Microsoft.Authorization/roleAssignments/write",
                    "Add service principal credentials",
                    "SecretGet",
                ],
            ]
        },
        "description": (
            "Stateful correlation across events: alerts when an identity performs cloud "
            "discovery and follows up with credential/role manipulation or data exfiltration."
        ),
    },
    {
        "rule_id": "DYN-DRIFT-001",
        "name": "Principal Behavioral Drift (Tool / Region / Off-Hours)",
        "kind": "drift",
        "enabled": 1,
        "severity": "medium",
        "window_seconds": 3600,
        "threshold": 1,
        "config": {
            "min_baseline_events": 3,
            "watch": ["user_agent", "aws_region", "sensitive_service", "off_hours"],
            "sensitive_services": [
                "iam",
                "sts",
                "secretsmanager",
                "kms",
                "iam.googleapis.com",
                "secretmanager.googleapis.com",
                "Microsoft.Authorization",
                "Microsoft.EntraID",
                "Microsoft.KeyVault",
            ],
            "off_hours_utc": [0, 1, 2, 3, 4, 5],
        },
        "description": (
            "Learns normal tools, regions, and hours per principal from clean proxy traffic, "
            "and flags sudden deviations (e.g., boto3 user suddenly switching to curl or us-east-1)."
        ),
    },
    {
        "rule_id": "DYN-APP-001",
        "name": "Cloud Web App Probe / Traversal / Auth Spike",
        "kind": "app_anomaly",
        "enabled": 1,
        "severity": "high",
        "window_seconds": 60,
        "threshold": 4,
        "config": {
            "suspicious_paths": [
                "/.env",
                "/.git",
                "/wp-admin",
                "/actuator",
                "/admin",
                "/etc/passwd",
                "/debug",
                "/metadata",
                "/latest/meta-data",
            ],
            "payload_patterns": [
                "../",
                "..\\",
                "<script",
                "union select",
                "or 1=1",
                "${jndi:",
                "169.254.169.254",
            ],
            "auth_failure_statuses": [401, 403],
        },
        "description": (
            "Inspects HTTP cloud application traffic for path probing, traversal/injection payloads, "
            "SSRF/IMDS hits, and rapid authentication failures."
        ),
    },
)


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime(ISO)


def _parse_ts(value: str | None) -> datetime:
    if not value:
        return datetime.now(timezone.utc)
    text = str(value).strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return datetime.now(timezone.utc)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def ensure_default_dynamic_rules(conn) -> None:
    """Seed built-in adaptive dynamic rules idempotently."""
    existing = {
        row["rule_id"] for row in conn.execute("SELECT rule_id FROM dynamic_rule").fetchall()
    }
    now = _utc_now()
    for spec in DEFAULT_DYNAMIC_RULES:
        if spec["rule_id"] in existing:
            continue
        conn.execute(
            """
            INSERT INTO dynamic_rule (
                rule_id, name, kind, enabled, severity,
                window_seconds, threshold, config_json, description, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                spec["rule_id"],
                spec["name"],
                spec["kind"],
                int(spec["enabled"]),
                spec["severity"],
                int(spec["window_seconds"]),
                int(spec["threshold"]),
                json.dumps(spec["config"], sort_keys=True),
                spec["description"],
                now,
            ),
        )
    conn.commit()


def list_dynamic_rules(conn, *, enabled_only: bool = False) -> list[dict[str, Any]]:
    ensure_default_dynamic_rules(conn)
    sql = "SELECT * FROM dynamic_rule"
    if enabled_only:
        sql += " WHERE enabled = 1"
    sql += " ORDER BY rule_id"
    out = []
    for row in conn.execute(sql).fetchall():
        item = dict(row)
        item["enabled"] = bool(item["enabled"])
        try:
            item["config"] = json.loads(item.pop("config_json") or "{}")
        except json.JSONDecodeError:
            item["config"] = {}
        out.append(item)
    return out


def upsert_dynamic_rule(conn, payload: Mapping[str, Any]) -> dict[str, Any]:
    ensure_default_dynamic_rules(conn)
    rule_id = str(payload.get("rule_id") or "").strip() or f"DYN-CUSTOM-{uuid.uuid4().hex[:6].upper()}"
    name = str(payload.get("name") or "").strip()
    if not name:
        raise ValueError("Dynamic rule name is required")
    kind = str(payload.get("kind") or "velocity").strip().lower()
    if kind not in {"velocity", "sequence", "drift", "app_anomaly"}:
        raise ValueError(f"Unsupported dynamic rule kind {kind!r}")
    severity = str(payload.get("severity") or "medium").strip().lower()
    if severity not in SEVERITY_SCORES:
        severity = "medium"
    enabled = 1 if payload.get("enabled", True) else 0
    window_seconds = max(5, int(payload.get("window_seconds") or 60))
    threshold = max(1, int(payload.get("threshold") or 3))
    cfg = payload.get("config")
    if isinstance(cfg, str):
        cfg = json.loads(cfg or "{}")
    if not isinstance(cfg, Mapping):
        cfg = {}
    description = str(payload.get("description") or "User-authored dynamic behavioral rule").strip()

    conn.execute(
        """
        INSERT INTO dynamic_rule (
            rule_id, name, kind, enabled, severity,
            window_seconds, threshold, config_json, description, created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(rule_id) DO UPDATE SET
            name=excluded.name,
            kind=excluded.kind,
            enabled=excluded.enabled,
            severity=excluded.severity,
            window_seconds=excluded.window_seconds,
            threshold=excluded.threshold,
            config_json=excluded.config_json,
            description=excluded.description
        """,
        (
            rule_id,
            name,
            kind,
            enabled,
            severity,
            window_seconds,
            threshold,
            json.dumps(dict(cfg), sort_keys=True),
            description,
            _utc_now(),
        ),
    )
    conn.commit()
    return next(r for r in list_dynamic_rules(conn) if r["rule_id"] == rule_id)


def toggle_dynamic_rule(conn, rule_id: str, enabled: bool) -> dict[str, Any]:
    ensure_default_dynamic_rules(conn)
    cur = conn.execute(
        "UPDATE dynamic_rule SET enabled = ? WHERE rule_id = ?",
        (1 if enabled else 0, rule_id),
    )
    if cur.rowcount == 0:
        raise KeyError(f"Unknown dynamic rule {rule_id!r}")
    conn.commit()
    return next(r for r in list_dynamic_rules(conn) if r["rule_id"] == rule_id)


def delete_dynamic_rule(conn, rule_id: str) -> dict[str, Any]:
    cur = conn.execute("DELETE FROM dynamic_rule WHERE rule_id = ?", (rule_id,))
    conn.commit()
    return {"deleted": cur.rowcount > 0, "rule_id": rule_id}


def _profile_identity(record: Mapping[str, Any]) -> tuple[str, str, str, str]:
    cloud_provider = str(record.get("cloud_provider") or "").strip().lower()
    if not cloud_provider:
        tk = str(record.get("traffic_kind") or "")
        if tk.startswith("gcp"):
            cloud_provider = "gcp"
        elif tk.startswith("azure"):
            cloud_provider = "azure"
        elif tk.startswith("aws"):
            cloud_provider = "aws"
        else:
            cloud_provider = "unknown"
    account_scope = str(record.get("account_scope") or "").strip()
    principal = str(record.get("principal") or record.get("client_ip") or "").strip()
    profile_key = f"{cloud_provider}:{account_scope}:{principal}"
    return profile_key, cloud_provider, account_scope, principal


def update_principal_profile(conn, record: Mapping[str, Any]) -> None:
    """Learn clean baseline behavior for a cloud-scoped principal from non-synthetic normal traffic."""
    # Prevent baseline poisoning from synthetic trials or lab attacks
    if record.get("is_synthetic") or record.get("is_lab") or record.get("simulation"):
        return
    event_obj = record.get("event_obj")
    if isinstance(event_obj, Mapping) and event_obj.get("synthetic"):
        return

    profile_key, cloud_provider, account_scope, principal = _profile_identity(record)
    if not principal:
        return
    row = conn.execute(
        "SELECT * FROM principal_profile WHERE profile_key = ?", (profile_key,)
    ).fetchone()
    ts = _parse_ts(record.get("timestamp"))
    hour = int(ts.hour)

    if row:
        uas = json.loads(row["known_user_agents"])
        regs = json.loads(row["known_regions"])
        svcs = json.loads(row["known_services"])
        ops = json.loads(row["known_operations"])
        hrs = json.loads(row["known_hours"])
        count = int(row["request_count"]) + 1
    else:
        uas, regs, svcs, ops, hrs, count = [], [], [], [], [], 1

    def _add(lst: list[Any], val: Any, cap: int = 32) -> list[Any]:
        if val is not None and val != "" and val not in lst:
            lst.append(val)
        return lst[-cap:]

    uas = _add(uas, record.get("user_agent"))
    regs = _add(regs, record.get("aws_region") or record.get("region"))
    svcs = _add(svcs, record.get("service"))
    ops = _add(ops, record.get("operation"), cap=64)
    hrs = _add(hrs, hour, cap=24)
    cold_start_complete = 1 if count >= 3 else 0

    conn.execute(
        """
        INSERT INTO principal_profile (
            profile_key, cloud_provider, account_scope, principal,
            known_user_agents, known_regions, known_services, known_operations,
            known_hours, request_count, cold_start_complete, last_seen
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(profile_key) DO UPDATE SET
            known_user_agents=excluded.known_user_agents,
            known_regions=excluded.known_regions,
            known_services=excluded.known_services,
            known_operations=excluded.known_operations,
            known_hours=excluded.known_hours,
            request_count=excluded.request_count,
            cold_start_complete=excluded.cold_start_complete,
            last_seen=excluded.last_seen
        """,
        (
            profile_key,
            cloud_provider,
            account_scope,
            principal,
            json.dumps(uas),
            json.dumps(regs),
            json.dumps(svcs),
            json.dumps(ops),
            json.dumps(hrs),
            count,
            cold_start_complete,
            record.get("timestamp") or _utc_now(),
        ),
    )


def _is_velocity_op(op: str, method: str, traffic_kind: str, prefixes: tuple[str, ...], include_http: bool) -> bool:
    op_l = op.lower()
    if op_l.startswith(prefixes):
        return True
    if any(tok in op_l for tok in (".list", ".get", "/read", "/list", ":list", ":get", "secretlist")):
        return True
    return bool(include_http and traffic_kind == "http_app" and method == "GET")


def _eval_velocity(
    rule: Mapping[str, Any],
    current: Mapping[str, Any],
    history: Sequence[Mapping[str, Any]],
) -> dict[str, Any] | None:
    cfg = rule.get("config") or {}
    prefixes = tuple(str(p).lower() for p in cfg.get("prefixes") or ("list", "describe", "get", "head"))
    include_http = bool(cfg.get("include_http_gets", True))
    op = str(current.get("operation") or "")
    method = str(current.get("method") or "").upper()
    if not _is_velocity_op(op, method, str(current.get("traffic_kind") or ""), prefixes, include_http):
        return None

    window_start = _parse_ts(current.get("timestamp")) - timedelta(seconds=int(rule["window_seconds"]))
    matches = [current]
    for prev in history:
        if _parse_ts(prev.get("timestamp")) < window_start:
            continue
        prev_op = str(prev.get("operation") or "")
        prev_method = str(prev.get("method") or "").upper()
        if _is_velocity_op(prev_op, prev_method, str(prev.get("traffic_kind") or ""), prefixes, include_http):
            matches.append(prev)

    threshold = int(rule["threshold"])
    distinct_ops = {str(m.get("operation") or m.get("path") or "") for m in matches}
    min_distinct = int(cfg.get("min_distinct_ops") or 1)
    if len(matches) >= threshold and len(distinct_ops) >= min_distinct:
        return {
            "rule_id": rule["rule_id"],
            "rule_name": rule["name"],
            "kind": "velocity",
            "severity": rule["severity"],
            "summary": f"{len(matches)} read/discovery calls ({len(distinct_ops)} distinct) in {rule['window_seconds']}s",
            "evidence": {
                "count": len(matches),
                "window_seconds": rule["window_seconds"],
                "distinct_operations": sorted(distinct_ops),
            },
        }
    return None


def _eval_sequence(
    rule: Mapping[str, Any],
    current: Mapping[str, Any],
    history: Sequence[Mapping[str, Any]],
) -> dict[str, Any] | None:
    cfg = rule.get("config") or {}
    stages = cfg.get("stages") or []
    if len(stages) < 2:
        return None

    final_stage = {str(x).casefold() for x in stages[-1]}
    cur_op = str(current.get("operation") or "").casefold()
    cur_path = str(current.get("path") or "").casefold()
    if cur_op not in final_stage and cur_path not in final_stage:
        return None

    window_start = _parse_ts(current.get("timestamp")) - timedelta(seconds=int(rule["window_seconds"]))
    recent = sorted(
        [h for h in history if _parse_ts(h.get("timestamp")) >= window_start],
        key=lambda item: str(item.get("timestamp") or ""),
    )

    stage_idx = 0
    matched_chain: list[str] = []
    for item in recent:
        target = {str(x).casefold() for x in stages[stage_idx]}
        op_val = str(item.get("operation") or "").casefold()
        path_val = str(item.get("path") or "").casefold()
        if op_val in target or path_val in target:
            matched_chain.append(str(item.get("operation") or item.get("path")))
            stage_idx += 1
            if stage_idx >= len(stages) - 1:
                break

    if stage_idx >= len(stages) - 1:
        matched_chain.append(str(current.get("operation") or current.get("path")))
        return {
            "rule_id": rule["rule_id"],
            "rule_name": rule["name"],
            "kind": "sequence",
            "severity": rule["severity"],
            "summary": f"Multi-step sequence matched: {' -> '.join(matched_chain)}",
            "evidence": {"chain": matched_chain, "window_seconds": rule["window_seconds"]},
        }
    return None


def _eval_drift(
    rule: Mapping[str, Any],
    current: Mapping[str, Any],
    profile: Mapping[str, Any] | None,
) -> dict[str, Any] | None:
    if not profile:
        return None
    cfg = rule.get("config") or {}
    min_events = int(cfg.get("min_baseline_events") or 3)
    if int(profile.get("request_count") or 0) < min_events:
        return None

    watch = set(cfg.get("watch") or ("user_agent", "aws_region", "sensitive_service", "off_hours"))
    anomalies: list[str] = []

    ua = str(current.get("user_agent") or "").strip()
    known_uas = set(profile.get("known_user_agents") or [])
    if "user_agent" in watch and ua and known_uas and ua not in known_uas:
        anomalies.append(f"new user_agent={ua!r}")

    reg = str(current.get("aws_region") or "").strip()
    known_regs = set(profile.get("known_regions") or [])
    if "aws_region" in watch and reg and known_regs and reg not in known_regs:
        anomalies.append(f"unseen region={reg}")

    svc = str(current.get("service") or "").lower()
    known_svcs = {str(s).lower() for s in profile.get("known_services") or []}
    sens = {str(s).lower() for s in cfg.get("sensitive_services") or ("iam", "secretsmanager", "kms")}
    if "sensitive_service" in watch and svc in sens and known_svcs and svc not in known_svcs:
        anomalies.append(f"first-time sensitive service={svc}")

    if "off_hours" in watch:
        off_hours = {int(h) for h in cfg.get("off_hours_utc") or (0, 1, 2, 3, 4, 5)}
        known_hours = {int(h) for h in profile.get("known_hours") or []}
        cur_hour = _parse_ts(current.get("timestamp")).hour
        if cur_hour in off_hours and known_hours and cur_hour not in known_hours:
            anomalies.append(f"off-hours UTC={cur_hour:02d}:00")

    if len(anomalies) >= int(rule["threshold"]):
        return {
            "rule_id": rule["rule_id"],
            "rule_name": rule["name"],
            "kind": "drift",
            "severity": rule["severity"],
            "summary": "Behavioral drift: " + ", ".join(anomalies),
            "evidence": {"anomalies": anomalies, "baseline_requests": profile.get("request_count")},
        }
    return None


def _eval_app_anomaly(
    rule: Mapping[str, Any],
    current: Mapping[str, Any],
    history: Sequence[Mapping[str, Any]],
) -> dict[str, Any] | None:
    cfg = rule.get("config") or {}
    path = str(current.get("path") or "").lower()
    params_text = str(current.get("params_json") or "").lower()
    combined = f"{path} {params_text}"

    suspicious_paths = [str(p).lower() for p in cfg.get("suspicious_paths") or ()]
    payload_patterns = [str(p).lower() for p in cfg.get("payload_patterns") or ()]

    hit_paths = [p for p in suspicious_paths if p and p in path]
    hit_payloads = [p for p in payload_patterns if p and p in combined]
    if hit_paths or hit_payloads:
        findings = hit_paths + hit_payloads
        return {
            "rule_id": rule["rule_id"],
            "rule_name": rule["name"],
            "kind": "app_anomaly",
            "severity": rule["severity"],
            "summary": f"Suspicious HTTP probe/payload detected: {', '.join(findings[:4])}",
            "evidence": {"matched_paths": hit_paths, "matched_payloads": hit_payloads, "path": path},
        }

    # Auth failure / denied burst check against recent history
    auth_codes = {int(c) for c in cfg.get("auth_failure_statuses") or (401, 403)}
    window_start = _parse_ts(current.get("timestamp")) - timedelta(seconds=int(rule["window_seconds"]))
    denied = [
        h
        for h in history
        if _parse_ts(h.get("timestamp")) >= window_start
        and int(h.get("status_code") or 0) in auth_codes
    ]
    if len(denied) >= int(rule["threshold"]):
        return {
            "rule_id": rule["rule_id"],
            "rule_name": rule["name"],
            "kind": "app_anomaly",
            "severity": rule["severity"],
            "summary": f"{len(denied)} HTTP {sorted(auth_codes)} responses in {rule['window_seconds']}s",
            "evidence": {"denied_count": len(denied), "window_seconds": rule["window_seconds"]},
        }
    return None


def _load_static_rules(conn, ruleset_version: str) -> list[Rule]:
    """Load static Sigma/Python rules for live proxy inspection."""
    cfg = detect_replay.load_ruleset_config()
    target = ruleset_version if ruleset_version in cfg else (
        "enhanced-v1" if "enhanced-v1" in cfg else (
            "improved-v1" if "improved-v1" in cfg else "baseline-v1"
        )
    )
    if target not in cfg:
        return []
    try:
        loaded = detect_replay.load_ruleset(conn, target)
        return list(loaded.rules)
    except Exception:
        return []


def _load_profile(
    conn,
    profile_key: str,
    *,
    fallback_principal: str | None = None,
    cloud_provider: str | None = None,
    account_scope: str = "",
) -> dict[str, Any] | None:
    row = None
    if profile_key:
        row = conn.execute(
            "SELECT * FROM principal_profile WHERE profile_key = ?", (profile_key,)
        ).fetchone()
    if row is None and fallback_principal and cloud_provider and not account_scope:
        row = conn.execute(
            "SELECT * FROM principal_profile WHERE cloud_provider = ? AND principal = ? ORDER BY request_count DESC LIMIT 1",
            (cloud_provider, fallback_principal),
        ).fetchone()
    if not row:
        return None
    return {
        "profile_key": row["profile_key"],
        "cloud_provider": row["cloud_provider"],
        "account_scope": row["account_scope"],
        "principal": row["principal"],
        "known_user_agents": json.loads(row["known_user_agents"]),
        "known_regions": json.loads(row["known_regions"]),
        "known_services": json.loads(row["known_services"]),
        "known_operations": json.loads(row["known_operations"]),
        "known_hours": json.loads(row["known_hours"]),
        "request_count": int(row["request_count"]),
        "cold_start_complete": bool(row["cold_start_complete"]) if "cold_start_complete" in row.keys() else int(row["request_count"]) >= 3,
        "last_seen": row["last_seen"],
    }


def evaluate_live_event(
    conn,
    record: Mapping[str, Any],
    *,
    ruleset_version: str = "enhanced-v1",
    mode: str = "observe",
    block_threshold: float = 70.0,
    learn_baseline: bool = True,
    static_rules: Sequence[Rule] | None = None,
    provider_policies: Mapping[str, str] | None = None,
    inspection_capable: bool = True,
    explicit_tunnel_block: bool = False,
) -> dict[str, Any]:
    """Evaluate one live proxy request against cloud-scoped static + behavioral rules + policy gate."""
    ensure_default_dynamic_rules(conn)
    rules = list(static_rules) if static_rules is not None else _load_static_rules(conn, ruleset_version)
    dyn_rules = list_dynamic_rules(conn, enabled_only=True)

    profile_key, cloud_provider, account_scope, principal = _profile_identity(record)
    principal = principal or "anonymous"
    traffic_type = str(
        record.get("traffic_type")
        or ("connect_tunnel" if record.get("traffic_kind") == "connect_tunnel" else ("http_app" if record.get("traffic_kind") == "http_app" else "cloud_api"))
    )

    event_obj = record.get("event_obj") or {}
    if not event_obj and record.get("event_json"):
        event_obj = json.loads(str(record["event_json"]))

    # 1. Static Sigma/Python rule matching (filtered by cloud provider when rule declares one)
    matched_static: list[dict[str, Any]] = []
    if inspection_capable:
        for r in rules:
            if not r.matches_cloud(cloud_provider):
                continue
            try:
                if r.matches(event_obj):
                    matched_static.append(
                        {
                            "rule_id": r.native_id,
                            "title": r.title,
                            "level": r.level or "medium",
                            "technique_id": r.technique_id,
                            "cloud_provider": r.cloud_provider or cloud_provider,
                        }
                    )
            except Exception:
                continue

    # 2. Load recent sliding history isolated per (cloud_provider, principal)
    max_window = max([int(dr["window_seconds"]) for dr in dyn_rules] or [300])
    cutoff = (_parse_ts(record.get("timestamp")) - timedelta(seconds=max_window)).strftime(ISO)
    if principal.startswith("ip:") or principal == "anonymous":
        hist_where = "cloud_provider = ? AND (principal = ? OR client_ip = ?)"
        hist_params: tuple[Any, ...] = (cloud_provider, principal, str(record.get("client_ip") or ""), cutoff)
    else:
        hist_where = "cloud_provider = ? AND principal = ?"
        hist_params = (cloud_provider, principal, cutoff)

    hist_rows = conn.execute(
        f"""
        SELECT proxy_event_id, timestamp, cloud_provider, account_scope, traffic_kind,
               principal, client_ip, method, path, service, operation, user_agent,
               aws_region, params_json, status_code
        FROM proxy_event
        WHERE {hist_where} AND timestamp >= ?
        ORDER BY timestamp ASC
        LIMIT 250
        """,
        hist_params,
    ).fetchall()
    history = [dict(r) for r in hist_rows]

    profile = _load_profile(
        conn,
        profile_key,
        fallback_principal=principal,
        cloud_provider=cloud_provider,
        account_scope=account_scope,
    )
    is_cold_start = (profile is None) or (int(profile.get("request_count") or 0) < 3)

    # 3. Dynamic behavioral detectors
    matched_dynamic: list[dict[str, Any]] = []
    if inspection_capable:
        for dr in dyn_rules:
            hit = None
            if dr["kind"] == "velocity":
                hit = _eval_velocity(dr, record, history)
            elif dr["kind"] == "sequence":
                hit = _eval_sequence(dr, record, history)
            elif dr["kind"] == "drift":
                hit = _eval_drift(dr, record, profile)
            elif dr["kind"] == "app_anomaly":
                hit = _eval_app_anomaly(dr, record, history)
            if hit:
                matched_dynamic.append(hit)

    # 4. Separate policy evaluation & enforcement decision
    decision = detect_policy.evaluate_policy(
        cloud_provider=cloud_provider,
        traffic_type=traffic_type,
        proxy_mode=mode,
        block_threshold=float(block_threshold),
        matched_static=matched_static,
        matched_dynamic=matched_dynamic,
        provider_policies=provider_policies,
        inspection_capable=inspection_capable,
        explicit_tunnel_block=explicit_tunnel_block,
    )

    # Only clean, non-synthetic, inspectable traffic trains the cloud-isolated baseline
    is_synthetic = bool(record.get("is_synthetic") or record.get("is_lab") or (isinstance(event_obj, Mapping) and event_obj.get("synthetic")))
    if learn_baseline and inspection_capable and not is_synthetic and decision.risk_score == 0.0:
        enriched = dict(record)
        enriched["cloud_provider"] = cloud_provider
        enriched["account_scope"] = account_scope
        update_principal_profile(conn, enriched)

    return {
        "cloud_provider": cloud_provider,
        "account_scope": account_scope,
        "traffic_type": traffic_type,
        "cold_start": is_cold_start,
        "matched_static": matched_static,
        "matched_dynamic": matched_dynamic,
        "risk_score": decision.risk_score,
        "action_taken": decision.action_taken,
        "policy_decision": decision.policy_decision,
        "policy_reason": decision.policy_reason,
        "effective_mode": decision.effective_mode,
    }


def record_dynamic_alerts(
    conn,
    *,
    source: str,
    ref_id: str,
    timestamp: str,
    principal: str,
    hits: Sequence[Mapping[str, Any]],
    action_taken: str = "alerted",
    cloud_provider: str = "aws",
    account_scope: str = "",
    ruleset_version: str | None = None,
) -> int:
    count = 0
    for hit in hits:
        aid = hashlib.sha256(
            f"{source}|{ref_id}|{hit['rule_id']}".encode("utf-8")
        ).hexdigest()[:32]
        conn.execute(
            """
            INSERT OR IGNORE INTO dynamic_alert (
                alert_id, rule_id, rule_name, source, ref_id,
                cloud_provider, account_scope, ruleset_version,
                timestamp, severity, principal, summary, evidence_json, action_taken
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                aid,
                str(hit["rule_id"]),
                str(hit["rule_name"]),
                source,
                ref_id,
                cloud_provider,
                account_scope,
                ruleset_version,
                timestamp,
                str(hit["severity"]),
                principal,
                str(hit["summary"]),
                json.dumps(hit.get("evidence") or {}, sort_keys=True),
                action_taken,
            ),
        )
        count += 1
    return count


def run_dynamic_replay(conn, *, run_id: str | None = None) -> dict[str, Any]:
    """Evaluate enabled dynamic behavioral rules over stored CloudTrail batch events."""
    ensure_default_dynamic_rules(conn)
    dyn_rules = [r for r in list_dynamic_rules(conn, enabled_only=True) if r["kind"] != "app_anomaly"]

    conn.execute("DELETE FROM dynamic_alert WHERE source = 'batch'")
    sql = """
        SELECT e.event_id, e.trial_id, e.cloud_provider, e.account_scope,
               e.event_time, e.event_source, e.event_name,
               e.aws_region, e.source_ip, e.user_agent, e.user_identity_arn, e.raw,
               v.variant_set
        FROM event e
        LEFT JOIN trial t ON t.trial_id = e.trial_id
        LEFT JOIN variant v ON v.variant_id = t.variant_id
        WHERE 1 = 1
    """
    params: list[Any] = []
    if run_id:
        sql += " AND t.run_id = ?"
        params.append(run_id)
    sql += " ORDER BY e.event_time ASC"

    rows = conn.execute(sql, tuple(params)).fetchall()
    # Seed lightweight baseline profile from benign batch events ONLY (never synthetic attack variants)
    benign_profiles: dict[str, dict[str, Any]] = {}
    records: list[dict[str, Any]] = []
    for row in rows:
        raw_ev = json.loads(row["raw"]) if row["raw"] else {}
        cloud = str(row["cloud_provider"] or raw_ev.get("cloudProvider") or "aws").lower()
        scope = str(row["account_scope"] or raw_ev.get("accountScope") or "")
        principal = str(
            row["user_identity_arn"]
            or get_field(raw_ev, "userIdentity.principalId")
            or row["source_ip"]
            or "batch-principal"
        )
        pkey = f"{cloud}:{scope}:{principal}"
        raw_src = str(row["event_source"] or "")
        svc = raw_src.split(".", 1)[0] if cloud == "aws" else raw_src
        rec = {
            "event_id": row["event_id"],
            "trial_id": row["trial_id"],
            "cloud_provider": cloud,
            "account_scope": scope,
            "profile_key": pkey,
            "timestamp": row["event_time"],
            "traffic_kind": f"{cloud}_api" if cloud in {"aws", "gcp", "azure"} else "http_app",
            "principal": principal,
            "client_ip": row["source_ip"],
            "service": svc,
            "operation": row["event_name"],
            "user_agent": row["user_agent"],
            "aws_region": row["aws_region"],
            "variant_set": row["variant_set"],
        }
        records.append(rec)
        if row["variant_set"] == "benign":
            prof = benign_profiles.setdefault(
                pkey,
                {
                    "profile_key": pkey,
                    "cloud_provider": cloud,
                    "account_scope": scope,
                    "principal": principal,
                    "known_user_agents": [],
                    "known_regions": [],
                    "known_services": [],
                    "known_operations": [],
                    "known_hours": [],
                    "request_count": 0,
                },
            )
            prof["request_count"] += 1
            for key, val in (
                ("known_user_agents", rec["user_agent"]),
                ("known_regions", rec["aws_region"]),
                ("known_services", rec["service"]),
                ("known_operations", rec["operation"]),
            ):
                if val and val not in prof[key]:
                    prof[key].append(val)
            hr = _parse_ts(rec["timestamp"]).hour
            if hr not in prof["known_hours"]:
                prof["known_hours"].append(hr)

    history_by_principal: dict[str, list[dict[str, Any]]] = {}
    total_alerts = 0
    for rec in records:
        pkey = rec["profile_key"]
        hist = history_by_principal.setdefault(pkey, [])
        hits: list[dict[str, Any]] = []
        for dr in dyn_rules:
            hit = None
            if dr["kind"] == "velocity":
                hit = _eval_velocity(dr, rec, hist)
            elif dr["kind"] == "sequence":
                hit = _eval_sequence(dr, rec, hist)
            elif dr["kind"] == "drift":
                prof = benign_profiles.get(pkey) or _load_profile(
                    conn,
                    pkey,
                    fallback_principal=rec["principal"],
                    cloud_provider=rec["cloud_provider"],
                    account_scope=rec["account_scope"],
                )
                hit = _eval_drift(dr, rec, prof)
            if hit:
                hits.append(hit)
        if hits:
            total_alerts += record_dynamic_alerts(
                conn,
                source="batch",
                ref_id=rec["event_id"],
                timestamp=rec["timestamp"],
                principal=rec["principal"],
                hits=hits,
                action_taken="alerted",
                cloud_provider=rec["cloud_provider"],
                account_scope=rec["account_scope"],
            )
        hist.append(rec)
        if len(hist) > 100:
            hist.pop(0)

    conn.commit()
    return {"events_scanned": len(records), "dynamic_alerts": total_alerts, "rules": len(dyn_rules)}
