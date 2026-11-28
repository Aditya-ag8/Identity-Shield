"""Shared operational service layer powering both the Web Control Plane and CLI.

All core operations — AWS connection management, live resource census & binding,
Terraform lab lifecycle, Attack Studio CRUD, 5-factor variant generation,
campaign execution, Sigma rule management, threshold gates, and log/analytics
queries — pass through this single coherent layer so GUI and CLI maintain 100% parity.
"""

from __future__ import annotations

import configparser
import json
import os
import queue
import shlex
import subprocess
import sys
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator, Mapping

import yaml

from identity_shield import config, settings
from identity_shield.analysis import outcomes
from identity_shield.contracts import VISIBLE_SETS, read_variants, write_json, write_variants
from identity_shield.db.connection import connect
from identity_shield.db.init import ensure_tables, init_db
from identity_shield.detect import dynamic as detect_dynamic
from identity_shield.detect import enhancer as detect_enhancer
from identity_shield.detect import loader as detect_loader
from identity_shield.detect import replay as detect_replay
from identity_shield.lab import census as census_module
from identity_shield.lab import destroy as destroy_module
from identity_shield.proxy import simulator as proxy_simulator
from identity_shield.proxy.server import PROXY_RUNTIME
from identity_shield.lab import doctor as doctor_module
from identity_shield.lab import integration, provision
from identity_shield.lab.aws import GuardedSession, LabSession
from identity_shield.runner import orchestrator
from identity_shield.runner.capabilities import check_technique_capability
from identity_shield.variants.benign import generate_benign, load_benign
from identity_shield.variants.cli import persist as persist_variants
from identity_shield.variants.coverage import build_coverage, render_markdown
from identity_shield.variants.generator import GenerationOptions, generate
from identity_shield.variants.loader import load_catalogue, load_factors, load_techniques

ISO = "%Y-%m-%dT%H:%M:%SZ"


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime(ISO)


def resolve_db_path(db_path: str | Path | None = None) -> Path:
    if db_path:
        return Path(db_path).expanduser().resolve()
    return config.resolve_db(os.environ.get("IDENTITY_SHIELD_DB"))


def ensure_database(db_path: Path | None = None) -> Path:
    path = resolve_db_path(db_path)
    if not path.exists():
        init_db(path, drop=False)
    conn = connect(path)
    try:
        ensure_tables(conn)
        t_count = conn.execute("SELECT COUNT(*) FROM technique").fetchone()[0]
        if t_count == 0:
            detect_loader.load_techniques(conn)
        existing_rs = {
            r[0] for r in conn.execute("SELECT ruleset_version FROM ruleset").fetchall()
        }
        for name in detect_replay.load_ruleset_config():
            if not existing_rs or name not in existing_rs:
                try:
                    detect_replay.load_ruleset(conn, name)
                except Exception:
                    continue
        detect_dynamic.ensure_default_dynamic_rules(conn)
    finally:
        conn.close()
    return path


def db_health(db_path: Path | None = None) -> dict[str, Any]:
    path = resolve_db_path(db_path)
    if not path.exists():
        return {
            "exists": False,
            "path": str(path),
            "runs": 0,
            "trials": 0,
            "events": 0,
            "alerts": 0,
            "variants": 0,
            "rulesets": [],
        }
    conn = connect(path)
    try:
        ensure_database(path)
        counts = conn.execute(
            """
            SELECT
                (SELECT COUNT(*) FROM lab_run) AS runs,
                (SELECT COUNT(*) FROM trial) AS trials,
                (SELECT COUNT(*) FROM event) AS events,
                (SELECT COUNT(*) FROM alert) AS alerts,
                (SELECT COUNT(*) FROM variant) AS variants,
                (SELECT COUNT(*) FROM proxy_event) AS proxy_events,
                (SELECT COUNT(*) FROM dynamic_rule) AS dynamic_rules,
                (SELECT COUNT(*) FROM dynamic_alert) AS dynamic_alerts,
                (SELECT COUNT(*) FROM principal_profile) AS principal_profiles
            """
        ).fetchone()
        rulesets = [
            dict(r)
            for r in conn.execute(
                "SELECT ruleset_version, created_at, frozen_at, source, manifest_sha256 "
                "FROM ruleset ORDER BY created_at"
            ).fetchall()
        ]
        runs = [
            dict(r)
            for r in conn.execute(
                "SELECT run_id, started_at, ended_at, aws_account_id, region, "
                "ruleset_version, synthetic, notes FROM lab_run ORDER BY started_at DESC"
            ).fetchall()
        ]
        storage_cfg = settings.get_storage_config()
        return {
            "exists": True,
            "path": str(path),
            "size_bytes": path.stat().st_size if path.exists() else 0,
            "linked_custom_db": bool(storage_cfg.db_path),
            "runs": int(counts["runs"]),
            "trials": int(counts["trials"]),
            "events": int(counts["events"]),
            "alerts": int(counts["alerts"]),
            "variants": int(counts["variants"]),
            "proxy_events": int(counts["proxy_events"]),
            "dynamic_rules": int(counts["dynamic_rules"]),
            "dynamic_alerts": int(counts["dynamic_alerts"]),
            "principal_profiles": int(counts["principal_profiles"]),
            "rulesets": rulesets,
            "run_list": runs,
        }
    finally:
        conn.close()


def reset_database(db_path: Path | None = None) -> dict[str, Any]:
    path = resolve_db_path(db_path)
    init_db(path, drop=True)
    ensure_database(path)
    return db_health(path)


# ---------------------------------------------------------------------------
# AWS Connection & Customer Onboarding
# ---------------------------------------------------------------------------


def list_local_aws_profiles() -> list[str]:
    profiles: list[str] = []
    seen: set[str] = set()
    for fname, strip_prefix in (("~/.aws/credentials", False), ("~/.aws/config", True)):
        p = Path(os.path.expanduser(fname))
        if not p.exists():
            continue
        parser = configparser.ConfigParser()
        try:
            parser.read(p, encoding="utf-8")
        except Exception:
            continue
        for section in parser.sections():
            name = section[8:] if strip_prefix and section.startswith("profile ") else section
            name = name.strip()
            if name and name not in seen:
                seen.add(name)
                profiles.append(name)
        if "default" in parser and "default" not in seen:
            seen.add("default")
            profiles.insert(0, "default")
    return profiles


def _build_boto_session(
    *,
    auth_mode: str,
    region: str,
    profile_name: str = "lab",
    role_arn: str = "",
    external_id: str = "",
    session_name: str = "identity-shield-session",
    access_key: str = "",
    secret_key: str = "",
    session_token: str = "",
):
    import boto3

    if auth_mode == "profile":
        return boto3.Session(profile_name=profile_name or None, region_name=region)
    if auth_mode == "assume_role":
        if not role_arn:
            raise ValueError("Role ARN is required for STS AssumeRole")
        base = boto3.Session(profile_name=profile_name or None, region_name=region)
        return integration.assume_role(
            base,
            role_arn=role_arn,
            external_id=external_id or None,
            session_name=session_name or "identity-shield-session",
        )
    if auth_mode == "in_memory":
        if not access_key or not secret_key:
            raise ValueError("Access Key ID and Secret Access Key are required")
        return boto3.Session(
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            aws_session_token=session_token or None,
            region_name=region,
        )
    raise ValueError(f"Unsupported auth_mode: {auth_mode!r}")


def connect_aws(payload: Mapping[str, Any]) -> dict[str, Any]:
    auth_mode = str(payload.get("auth_mode") or "profile")
    region = str(payload.get("region") or "eu-west-1")
    profile_name = str(payload.get("profile_name") or "")
    role_arn = str(payload.get("role_arn") or "")
    external_id = str(payload.get("external_id") or "")
    session_name = str(payload.get("session_name") or "identity-shield-session")
    scope_val = str(payload.get("scope") or "single_account")

    boto_session = _build_boto_session(
        auth_mode=auth_mode,
        region=region,
        profile_name=profile_name,
        role_arn=role_arn,
        external_id=external_id,
        session_name=session_name,
        access_key=str(payload.get("access_key") or ""),
        secret_key=str(payload.get("secret_key") or ""),
        session_token=str(payload.get("session_token") or ""),
    )

    guarded = GuardedSession(boto_session, region_name=region)
    identity = boto_session.client("sts", region_name=region).get_caller_identity()
    account_id = str(identity.get("Account") or "unknown")
    caller_arn = str(identity.get("Arn") or "unknown")

    scope_enum = (
        integration.DeploymentScope.ORGANIZATION
        if scope_val == "organization"
        else integration.DeploymentScope.SINGLE_ACCOUNT
    )
    classification = integration.classify_account(guarded, scope=scope_enum)

    descriptor = settings.ConnectionDescriptor(
        auth_mode=auth_mode,
        profile_name=profile_name,
        role_arn=role_arn,
        external_id=external_id,
        session_name=session_name,
        region=region,
        scope=scope_val,
    )
    settings.update_connection_descriptor(descriptor.to_dict())
    settings.update_resources({"region": region})

    settings.RUNTIME_SESSION.set_connection(
        descriptor=descriptor,
        boto_session=boto_session,
        classification=classification.to_dict(),
        caller_arn=caller_arn,
        account_id=account_id,
        in_memory_keys={"present": "yes"} if auth_mode == "in_memory" else None,
    )
    return settings.RUNTIME_SESSION.status()


def disconnect_aws() -> dict[str, Any]:
    settings.RUNTIME_SESSION.clear()
    return settings.RUNTIME_SESSION.status()


def resolve_sessions(region_override: str | None = None) -> tuple[GuardedSession, LabSession, str, str | None]:
    """Return ``(guarded_session, lab_session, region, profile_name)`` honoring active connection."""
    conn_desc = settings.get_connection_descriptor()
    region = region_override or conn_desc.region or "eu-west-1"
    runtime_boto = settings.RUNTIME_SESSION.boto_session()
    if runtime_boto is not None:
        return (
            GuardedSession(runtime_boto, region_name=region),
            LabSession(session=runtime_boto, region_name=region),
            region,
            conn_desc.profile_name if conn_desc.auth_mode == "profile" else None,
        )
    if conn_desc.auth_mode == "assume_role" and conn_desc.role_arn:
        try:
            boto_sess = _build_boto_session(
                auth_mode="assume_role",
                region=region,
                profile_name=conn_desc.profile_name,
                role_arn=conn_desc.role_arn,
                external_id=conn_desc.external_id,
                session_name=conn_desc.session_name,
            )
            return (
                GuardedSession(boto_sess, region_name=region),
                LabSession(session=boto_sess, region_name=region),
                region,
                None,
            )
        except Exception:
            pass
    profile = conn_desc.profile_name or None
    return (
        GuardedSession(region_name=region, profile_name=profile),
        LabSession(region_name=region, profile_name=profile),
        region,
        profile,
    )


def customer_onboarding_templates() -> dict[str, Any]:
    """Read real customer deployment templates for GUI onboarding wizard."""
    templates: dict[str, Any] = {}
    for mode in ("single-account", "organization"):
        folder = config.INFRA / "customer" / mode
        files: dict[str, str] = {}
        if folder.exists():
            for file in sorted(folder.iterdir()):
                if file.is_file():
                    files[file.name] = file.read_text(encoding="utf-8")
        templates[mode] = {"path": str(folder), "files": files}
    return templates


# ---------------------------------------------------------------------------
# Lab Doctor, Census & Resource Binding
# ---------------------------------------------------------------------------


def run_lab_doctor() -> dict[str, Any]:
    guarded, _, region, _ = resolve_sessions()
    report = doctor_module.run_doctor(session=guarded, region=region)
    return report.to_dict()


def run_live_resource_probe() -> dict[str, Any]:
    guarded, _, region, _ = resolve_sessions()
    bound = settings.get_resources()
    conn_status = settings.RUNTIME_SESSION.status()
    account_id = conn_status.get("account_id") if conn_status.get("connected") else None

    if not guarded.has_credentials():
        return {
            "connected": False,
            "error": "No active AWS credentials resolved. Connect via Profile, STS AssumeRole, or Session Keys first.",
            "bound": bound.to_dict(),
            "terraform_outputs": _safe_tf_outputs(),
        }

    census = census_module.collect(guarded, region=region, account_id=account_id, lab_name=bound.lab_name)
    deep = census_module.collect_live_inventory(
        guarded,
        region=region,
        data_bucket=bound.data_bucket,
        data_key=bound.data_key,
    )
    tf_outputs = _safe_tf_outputs()
    return {
        "connected": True,
        "account_id": census.account_id,
        "region": census.region,
        "generated_at": census.generated_at,
        "census": census.to_dict(),
        "census_summary": census_module.summarise(census),
        "inventory": deep,
        "bound": bound.to_dict(),
        "terraform_outputs": tf_outputs,
    }


def _safe_tf_outputs() -> dict[str, Any]:
    try:
        if provision.available():
            return provision.outputs()
    except Exception:
        pass
    return {}


def terraform_plan_preview(extra_vars: Mapping[str, Any] | None = None) -> dict[str, Any]:
    if not provision.available():
        return {"ok": False, "error": "Terraform CLI is not installed on PATH"}
    guarded, _, region, profile = resolve_sessions()
    thresholds = settings.get_thresholds()
    bound = settings.get_resources()
    variables = _terraform_variables(region=region, thresholds=thresholds, bound=bound, extra=extra_vars)
    tf_env = provision.aws_env(session=guarded if guarded.has_credentials() else None, profile=profile, region=region)

    init_res = provision.init(env=tf_env)
    if not init_res.ok:
        return {"ok": False, "stage": "init", "returncode": init_res.returncode, "output": init_res.stdout + "\n" + init_res.stderr}
    plan_res = provision.plan(variables=variables, env=tf_env)
    return {
        "ok": plan_res.ok,
        "stage": "plan",
        "returncode": plan_res.returncode,
        "variables": variables,
        "output": plan_res.stdout + ("\n" + plan_res.stderr if plan_res.stderr else ""),
    }


def _terraform_variables(
    *,
    region: str,
    thresholds: settings.ThresholdConfig,
    bound: settings.ResourceBinding,
    extra: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    variables: dict[str, Any] = {
        "region": region,
        "lab_name": bound.lab_name or "identity-shield",
        "data_bucket_name": bound.data_bucket or "is-lab-crown-jewels",
        "budget_usd": int(thresholds.budget_usd),
        "enable_data_events": "true" if thresholds.enable_data_events else "false",
        "enable_instance": "true" if thresholds.enable_instance else "false",
        "enable_budget": "true" if thresholds.budget_usd > 0 else "false",
        "log_retention_days": int(thresholds.log_retention_days),
    }
    for k, v in (extra or {}).items():
        if v is not None and v != "":
            variables[str(k)] = v
    return variables


# ---------------------------------------------------------------------------
# Attack Catalogue Studio & 5-Factor Variant Engine
# ---------------------------------------------------------------------------


def _sync_variants_for_catalogue(db_path: Path, *, include_benign: bool = True, master_seed: int = 2026) -> dict[str, Any]:
    catalogue = load_catalogue()
    result = generate(catalogue, GenerationOptions(master_seed=master_seed))
    variants = list(result.variants)

    out_path = config.VARIANTS_DIR / "variants.jsonl"
    coverage_path = config.VARIANTS_DIR / "coverage.json"
    markdown_path = config.VARIANTS_DIR / "coverage.md"

    write_variants(out_path, variants)
    coverage = build_coverage(catalogue, variants, generation_stats=result.stats)
    write_json(coverage_path, coverage)
    markdown_path.write_text(render_markdown(coverage), encoding="utf-8")

    benign_rows = []
    if include_benign:
        benign_rows = list(generate_benign(catalogue, activities=load_benign()))
        write_variants(config.VARIANTS_DIR / "benign.jsonl", benign_rows)

    conn = connect(db_path)
    try:
        detect_loader.load_techniques(conn)
        stale = persist_variants(conn, variants, catalogue, prune=False)
        if benign_rows:
            persist_variants(conn, benign_rows, catalogue, prune=False)
    finally:
        conn.close()

    return {
        "variants_total": len(variants),
        "benign_total": len(benign_rows),
        "totals": result.totals,
        "level_coverage": coverage["level_coverage"],
        "pair_coverage": coverage["pair_coverage"],
        "invalid_variants": coverage["invalid_variants"],
        "stale_removed": stale,
    }


def list_attacks_overview(
    db_path: Path | None = None,
    *,
    cloud_provider: str = "",
) -> dict[str, Any]:
    """Return rich inventory of all attacks (enabled + disabled + custom + multi-cloud) with rule mapping."""
    path = ensure_database(db_path)
    full_catalogue = load_catalogue(include_disabled=True)
    bound = settings.get_resources()
    thresholds = settings.get_thresholds()
    overrides = settings.load_attack_overrides()
    disabled_set = {t.upper() for t in overrides.get("disabled_techniques") or []}

    lab_cfg = {
        **bound.to_dict(),
        "enable_data_events": thresholds.enable_data_events,
        "enable_instance": thresholds.enable_instance,
    }

    conn = connect(path)
    try:
        rule_rows = conn.execute(
            "SELECT ruleset_version, native_id, title, level, technique_id FROM rule"
        ).fetchall()
        variant_counts = {
            row["technique_id"]: int(row["cnt"])
            for row in conn.execute(
                "SELECT technique_id, COUNT(*) AS cnt FROM variant GROUP BY technique_id"
            ).fetchall()
        }
    finally:
        conn.close()

    rules_by_tech: dict[str, list[dict[str, Any]]] = {}
    for r in rule_rows:
        tid = str(r["technique_id"] or "")
        if tid:
            rules_by_tech.setdefault(tid, []).append(dict(r))

    items = []
    for tech in full_catalogue.techniques:
        enabled = tech.technique_id.upper() not in disabled_set
        cap_live = check_technique_capability(
            tech.technique_id, lab_cfg, synthetic=False, technique=tech
        )
        items.append(
            {
                "technique_id": tech.technique_id,
                "name": tech.name,
                "tactic": tech.tactic,
                "cloud_provider": "aws",
                "catalogue_backed": True,
                "executor": tech.executor,
                "executor_ref": tech.executor_ref,
                "event_names": list(tech.event_names),
                "required_actions": list(tech.required_actions),
                "requires_data_events": tech.requires_data_events,
                "excluded_levels": {k: list(v) for k, v in tech.excluded_levels.items()},
                "baseline_levels": dict(tech.baseline_levels),
                "success_check": dict(tech.success_check),
                "api_calls": [dict(c) for c in tech.api_calls],
                "notes": tech.notes,
                "custom": tech.custom,
                "enabled": enabled,
                "live_capability": cap_live.to_dict(),
                "variant_count": variant_counts.get(tech.technique_id, 0),
                "mapped_rules": rules_by_tech.get(tech.technique_id, []),
            }
        )

    # Surface multi-cloud (GCP / Azure) technique definitions alongside AWS without mutating AWS default variants
    seen_ids = {it["technique_id"] for it in items}
    if config.MULTICLOUD_TECHNIQUES_YAML.is_file():
        try:
            mc_doc = yaml.safe_load(config.MULTICLOUD_TECHNIQUES_YAML.read_text(encoding="utf-8")) or {}
        except Exception:
            mc_doc = {}
        for raw_t in mc_doc.get("techniques") or []:
            if not isinstance(raw_t, Mapping):
                continue
            tid = str(raw_t.get("technique_id") or "").strip()
            if not tid or tid in seen_ids:
                continue
            seen_ids.add(tid)
            cp = str(raw_t.get("cloud_provider") or ("gcp" if ".GCP" in tid else "azure")).strip().lower()
            svc = str(raw_t.get("service") or "").strip()
            items.append(
                {
                    "technique_id": tid,
                    "name": str(raw_t.get("name") or tid),
                    "tactic": str(raw_t.get("tactic") or "discovery"),
                    "cloud_provider": cp,
                    "catalogue_backed": False,
                    "executor": f"{cp}_synthetic",
                    "executor_ref": None,
                    "event_names": list(raw_t.get("event_names") or []),
                    "required_actions": list(raw_t.get("required_actions") or []),
                    "requires_data_events": False,
                    "excluded_levels": {},
                    "baseline_levels": {},
                    "success_check": {},
                    "api_calls": [{"service": svc, "operation": str((raw_t.get("event_names") or [""])[0])}] if svc else [],
                    "notes": str(raw_t.get("notes") or f"Multi-cloud {cp.upper()} detection/closed-loop technique."),
                    "custom": False,
                    "enabled": True,
                    "live_capability": {
                        "technique_id": tid,
                        "available": False,
                        "reason": f"Offline synthetic, log ingestion & closed-loop proxy support ({cp.upper()}); live {cp.upper()} execution requires external SDK setup.",
                        "required_services": [svc] if svc else [],
                        "telemetry_dependency": "audit_logs",
                        "limitations": "Offline-first multi-cloud pack.",
                    },
                    "variant_count": variant_counts.get(tid, 0),
                    "mapped_rules": rules_by_tech.get(tid, []),
                }
            )

    cloud_filter = str(cloud_provider or "").strip().lower()
    if cloud_filter and cloud_filter != "all":
        items = [it for it in items if str(it.get("cloud_provider") or "aws").lower() == cloud_filter]

    return {"attacks": items, "factors": _factors_payload()}


def _factors_payload() -> dict[str, Any]:
    factors = load_factors()
    return {
        name: {
            "description": f.description,
            "baseline": f.baseline,
            "levels": list(f.levels),
            "surface": list(f.surface),
        }
        for name, f in factors.items()
    }


def add_custom_attack(payload: Mapping[str, Any], *, db_path: Path | None = None, sync_variants: bool = True) -> dict[str, Any]:
    path = ensure_database(db_path)
    clean = settings.add_or_update_custom_attack(payload)
    # Validate merged catalogue immediately
    try:
        load_catalogue()
    except Exception:
        # Roll back on catalogue validation failure
        settings.remove_attack(clean["technique_id"])
        raise
    sync_info = _sync_variants_for_catalogue(path) if sync_variants else {}
    return {"attack": clean, "variant_sync": sync_info}


def toggle_attack(technique_id: str, enabled: bool, *, db_path: Path | None = None, sync_variants: bool = True) -> dict[str, Any]:
    path = ensure_database(db_path)
    result = settings.set_attack_enabled(technique_id, enabled)
    sync_info = _sync_variants_for_catalogue(path) if sync_variants else {}
    return {**result, "variant_sync": sync_info}


def delete_attack(technique_id: str, *, db_path: Path | None = None, sync_variants: bool = True) -> dict[str, Any]:
    path = ensure_database(db_path)
    result = settings.remove_attack(technique_id)
    sync_info = _sync_variants_for_catalogue(path) if sync_variants else {}
    return {**result, "variant_sync": sync_info}


def generate_all_variants(
    *,
    db_path: Path | None = None,
    master_seed: int = 2026,
    holdout_per_technique: int = 3,
    include_pairwise: bool = True,
) -> dict[str, Any]:
    path = ensure_database(db_path)
    catalogue = load_catalogue()
    result = generate(
        catalogue,
        GenerationOptions(
            master_seed=master_seed,
            holdout_per_technique=holdout_per_technique,
            include_pairwise=include_pairwise,
        ),
    )
    variants = list(result.variants)
    out_path = config.VARIANTS_DIR / "variants.jsonl"
    coverage_path = config.VARIANTS_DIR / "coverage.json"
    markdown_path = config.VARIANTS_DIR / "coverage.md"

    write_variants(out_path, variants)
    coverage = build_coverage(catalogue, variants, generation_stats=result.stats)
    write_json(coverage_path, coverage)
    markdown_path.write_text(render_markdown(coverage), encoding="utf-8")

    benign_rows = list(generate_benign(catalogue, activities=load_benign()))
    write_variants(config.VARIANTS_DIR / "benign.jsonl", benign_rows)

    conn = connect(path)
    try:
        detect_loader.load_techniques(conn)
        stale = persist_variants(conn, variants, catalogue, prune=False)
        persist_variants(conn, benign_rows, catalogue, prune=False)
    finally:
        conn.close()

    return {
        "variants": len(variants),
        "benign": len(benign_rows),
        "totals": result.totals,
        "coverage": coverage,
        "stale_removed": stale,
    }


def get_variants_view(
    *,
    technique_id: str | None = None,
    variant_set: str | None = None,
    cloud_provider: str = "",
    limit: int = 200,
) -> dict[str, Any]:
    catalogue = load_catalogue()
    factors = _factors_payload()
    cov_path = config.VARIANTS_DIR / "coverage.json"
    coverage = json.loads(cov_path.read_text(encoding="utf-8")) if cov_path.exists() else None

    v_path = config.VARIANTS_DIR / "variants.jsonl"
    b_path = config.VARIANTS_DIR / "benign.jsonl"
    rows = []
    if v_path.exists():
        # Never expose sealed holdout details before evaluation
        rows.extend(read_variants(v_path, include_holdout=False))
    if b_path.exists():
        rows.extend(read_variants(b_path, include_holdout=True))

    total_count = len(rows)
    if technique_id:
        rows = [v for v in rows if v.technique_id == technique_id]
    if variant_set:
        rows = [v for v in rows if v.variant_set == variant_set]
    cloud_filter = str(cloud_provider or "").strip().lower()
    if cloud_filter and cloud_filter != "all":
        rows = [
            v
            for v in rows
            if (
                ("gcp" if ".GCP" in v.technique_id else ("azure" if ".AZ" in v.technique_id else "aws"))
                == cloud_filter
            )
        ]

    serialized = []
    for v in rows[:limit]:
        tech = next((t for t in catalogue.techniques if t.technique_id == v.technique_id), None)
        expected_surface = (
            list(catalogue.expected_surface(tech, v.factor_levels))
            if tech is not None and v.variant_set not in {"baseline", "benign"}
            else []
        )
        serialized.append(
            {
                "variant_id": v.variant_id,
                "technique_id": v.technique_id,
                "cloud_provider": "gcp" if ".GCP" in v.technique_id else ("azure" if ".AZ" in v.technique_id else "aws"),
                "variant_set": v.variant_set,
                "factor_levels": dict(v.factor_levels),
                "expected_surface": expected_surface,
                "seed": v.seed,
                "spec_sha256": v.spec_sha256,
                "notes": v.notes,
            }
        )

    return {
        "total": total_count,
        "filtered": len(rows),
        "factors": factors,
        "coverage": coverage,
        "variants": serialized,
    }


# ---------------------------------------------------------------------------
# Rulesets, Custom Sigma Rules & Threshold Evaluation
# ---------------------------------------------------------------------------


def _infer_rule_cloud(row: Mapping[str, Any]) -> str:
    body = str(row.get("body") or "")
    if body.strip() and row.get("loader") != "python":
        try:
            doc = yaml.safe_load(body)
            if isinstance(doc, Mapping):
                ls = doc.get("logsource")
                if isinstance(ls, Mapping) and ls.get("product"):
                    return str(ls["product"]).strip().lower()
        except Exception:
            pass
    rs = str(row.get("ruleset_version") or "").lower()
    if rs.startswith("gcp"):
        return "gcp"
    if rs.startswith("azure"):
        return "azure"
    tid = str(row.get("technique_id") or "")
    if ".GCP" in tid:
        return "gcp"
    if ".AZ" in tid:
        return "azure"
    return "aws"


def list_rules_view(
    db_path: Path | None = None,
    *,
    cloud_provider: str = "",
) -> dict[str, Any]:
    path = ensure_database(db_path)
    conn = connect(path)
    try:
        # Ensure custom-v1 is loaded if custom rules exist
        if "custom-v1" in detect_replay.load_ruleset_config():
            try:
                detect_replay.load_ruleset(conn, "custom-v1")
            except Exception:
                pass
        rulesets = [
            dict(r)
            for r in conn.execute(
                "SELECT ruleset_version, created_at, frozen_at, description, source, manifest_sha256, git_sha "
                "FROM ruleset ORDER BY created_at"
            ).fetchall()
        ]
        rules = []
        cloud_filter = str(cloud_provider or "").strip().lower()
        for r in conn.execute(
            "SELECT rule_id, ruleset_version, native_id, title, level, technique_id, loader, path, body "
            "FROM rule ORDER BY ruleset_version, technique_id, native_id"
        ).fetchall():
            item = dict(r)
            item["cloud_provider"] = _infer_rule_cloud(item)
            if cloud_filter and cloud_filter != "all" and item["cloud_provider"] != cloud_filter:
                continue
            rules.append(item)
        compiles = [
            dict(r)
            for r in conn.execute(
                "SELECT rule_id, ruleset_version, title, status, reason, checked_at FROM rule_compile"
            ).fetchall()
        ]
    finally:
        conn.close()
    return {"rulesets": rulesets, "rules": rules, "compile_status": compiles}


def save_custom_sigma_rule(
    *,
    filename: str,
    yaml_content: str,
    db_path: Path | None = None,
) -> dict[str, Any]:
    from identity_shield.detect.rules import load_sigma_text

    # Validate rule syntax & AST before saving
    parsed_doc = yaml.safe_load(yaml_content)
    if not isinstance(parsed_doc, Mapping) or "detection" not in parsed_doc:
        raise ValueError("Custom rule must be valid Sigma YAML with a 'detection' block")
    rule = load_sigma_text(yaml_content, path=filename)

    safe_name = settings.validate_rule_stem(filename)
    custom_dir = config.DATA / "rules" / "custom"
    custom_dir.mkdir(parents=True, exist_ok=True)
    target = (custom_dir / f"{safe_name}.yml").resolve()
    if not target.is_relative_to(custom_dir.resolve()):
        raise ValueError(f"Unsafe custom rule target path {filename!r}")
    target.write_text(yaml_content, encoding="utf-8")

    path = ensure_database(db_path)
    conn = connect(path)
    try:
        loaded = detect_replay.load_ruleset(conn, "custom-v1")
        stats = detect_replay.run_replay(conn, loaded)
    finally:
        conn.close()

    return {
        "saved_path": str(target),
        "rule_title": rule.title,
        "technique_id": rule.technique_id,
        "replay_stats": stats,
    }


def delete_custom_sigma_rule(native_or_filename: str, *, db_path: Path | None = None) -> dict[str, Any]:
    stem = settings.validate_rule_stem(native_or_filename)
    custom_dir = (config.DATA / "rules" / "custom").resolve()
    deleted = False
    for candidate in (
        custom_dir / Path(native_or_filename).name,
        custom_dir / f"{stem}.yml",
        custom_dir / f"{stem}.yaml",
    ):
        resolved = candidate.resolve()
        if not resolved.is_relative_to(custom_dir):
            raise ValueError(f"Unsafe rule path {native_or_filename!r}")
        if resolved.exists() and resolved.is_file():
            resolved.unlink()
            deleted = True
    path = ensure_database(db_path)
    conn = connect(path)
    try:
        conn.execute(
            "DELETE FROM alert WHERE rule_id IN (SELECT rule_id FROM rule WHERE ruleset_version = 'custom-v1')"
        )
        conn.execute("DELETE FROM rule WHERE ruleset_version = 'custom-v1'")
        conn.execute("DELETE FROM ruleset WHERE ruleset_version = 'custom-v1'")
        conn.commit()
        if "custom-v1" in detect_replay.load_ruleset_config():
            loaded = detect_replay.load_ruleset(conn, "custom-v1")
            detect_replay.run_replay(conn, loaded)
    finally:
        conn.close()
    return {"deleted": deleted}


def replay_rules(ruleset_version: str | None = None, *, db_path: Path | None = None) -> dict[str, Any]:
    path = ensure_database(db_path)
    conn = connect(path)
    results = {}
    try:
        targets = [ruleset_version] if ruleset_version else list(detect_replay.load_ruleset_config().keys())
        for name in targets:
            loaded = detect_replay.load_ruleset(conn, name)
            results[name] = detect_replay.run_replay(conn, loaded)
    finally:
        conn.close()
    return results


# ---------------------------------------------------------------------------
# Analytics & Searchable Telemetry / Execution Logs
# ---------------------------------------------------------------------------


def get_analytics_payload(
    *,
    db_path: Path | None = None,
    ruleset: str = "baseline-v1",
    run_id: str | None = None,
    cloud_provider: str = "",
) -> dict[str, Any]:
    path = ensure_database(db_path)
    thresholds = settings.get_thresholds()
    conn = connect(path)
    try:
        # Fallback if requested ruleset isn't loaded yet
        available = [
            r["ruleset_version"]
            for r in conn.execute("SELECT ruleset_version FROM ruleset ORDER BY created_at").fetchall()
        ]
        if ruleset not in available and available:
            ruleset = available[0]

        summary = outcomes.summarise(conn, ruleset, run_id=run_id)
        fa = outcomes.false_alarms(conn, ruleset, run_id=run_id)
        lat = outcomes.latency(conn, ruleset, run_id=run_id)
        cloud_ev_counts = {
            str(r["cloud_provider"]): int(r["cnt"])
            for r in conn.execute("SELECT cloud_provider, COUNT(*) AS cnt FROM event GROUP BY cloud_provider").fetchall()
        }
        compare_target = ruleset if (ruleset in available and ruleset != "baseline-v1") else "improved-v1"
        try:
            paired = outcomes.paired(conn, "baseline-v1", compare_target, run_id=run_id)
        except Exception:
            paired = None
        try:
            diff = outcomes.rule_diff(conn, "baseline-v1", compare_target)
        except Exception:
            diff = None

        sql = """
            SELECT t.trial_id, t.run_id, t.variant_id, t.repetition,
                   t.attack_succeeded, t.variant_changed, t.error,
                   t.technique_id, t.technique_name, t.tactic, t.variant_set,
                   t.factor_levels, t.synthetic, t.attack_evidence, t.variant_diff,
                   CASE WHEN EXISTS (
                       SELECT 1 FROM alert a JOIN rule r ON r.rule_id = a.rule_id
                       WHERE a.trial_id = t.trial_id AND r.ruleset_version = ?
                   ) THEN 1 ELSE 0 END AS detected,
                   (SELECT GROUP_CONCAT(DISTINCT r.native_id) FROM alert a JOIN rule r ON r.rule_id = a.rule_id
                     WHERE a.trial_id = t.trial_id AND r.ruleset_version = ?) AS fired_rules
            FROM v_trial_outcome t
            WHERE 1 = 1
        """
        params: list[Any] = [ruleset, ruleset]
        if run_id:
            sql += " AND t.run_id = ?"
            params.append(run_id)
        sql += " ORDER BY t.technique_id, t.variant_set, t.variant_id LIMIT 600"
        trial_rows = []
        for row in conn.execute(sql, tuple(params)).fetchall():
            item = dict(row)
            try:
                item["factor_levels"] = json.loads(item["factor_levels"] or "{}")
            except Exception:
                item["factor_levels"] = {}
            try:
                item["attack_evidence"] = json.loads(item["attack_evidence"] or "{}")
            except Exception:
                item["attack_evidence"] = {}
            item["valid"] = bool(item["attack_succeeded"] == 1 and (item["variant_set"] == "baseline" or item["variant_changed"] == 1))
            trial_rows.append(item)

        reports = sorted(config.LAB_DIR.glob("teardown-*.json"))
        latest_teardown = (
            json.loads(reports[-1].read_text(encoding="utf-8")) if reports else None
        )
    finally:
        conn.close()

    overall = summary.get("overall", {})
    det_rate = overall.get("detection_rate")
    fa_rate = fa.get("rate")
    ingest_p95 = (lat.get("ingest_lag_ms") or {}).get("p95") if lat.get("live") else None

    gates = {
        "detection_rate": {
            "actual": det_rate,
            "threshold": thresholds.min_detection_rate,
            "passed": None if det_rate is None else det_rate >= thresholds.min_detection_rate,
        },
        "false_alarm_rate": {
            "actual": fa_rate,
            "threshold": thresholds.max_false_alarm_rate,
            "passed": None if fa.get("trials", 0) == 0 or fa_rate is None else fa_rate <= thresholds.max_false_alarm_rate,
        },
        "ingest_latency_ms": {
            "actual": ingest_p95,
            "threshold": thresholds.max_ingest_lag_ms,
            "passed": None if ingest_p95 is None else ingest_p95 <= thresholds.max_ingest_lag_ms,
        },
    }

    cloud_filter = str(cloud_provider or "").strip().lower()
    if cloud_filter and cloud_filter not in {"", "all"}:
        if cloud_filter in {"gcp", "azure"}:
            trial_rows = [
                tr
                for tr in trial_rows
                if (".GCP" in str(tr.get("technique_id") or "") and cloud_filter == "gcp")
                or (".AZ" in str(tr.get("technique_id") or "") and cloud_filter == "azure")
            ]

    return {
        "ruleset": ruleset,
        "compare_target": compare_target,
        "available_rulesets": available,
        "run_id": run_id,
        "cloud_provider": cloud_filter or "all",
        "cloud_event_counts": cloud_ev_counts,
        "summary": summary,
        "false_alarms": fa,
        "latency": lat,
        "paired": paired,
        "rule_diff": diff,
        "trials": trial_rows,
        "gates": gates,
        "latest_teardown": latest_teardown,
    }


def get_logs_view(
    *,
    db_path: Path | None = None,
    search: str = "",
    run_id: str | None = None,
    cloud_provider: str = "",
    alerts_only: bool = False,
    limit: int = 300,
) -> dict[str, Any]:
    path = ensure_database(db_path)
    conn = connect(path)
    try:
        where = ["1 = 1"]
        params: list[Any] = []
        if run_id:
            where.append("e.trial_id LIKE ?")
            params.append(f"{run_id}|%")
        if cloud_provider and cloud_provider != "all":
            where.append("e.cloud_provider = ?")
            params.append(cloud_provider.lower())
        if search:
            where.append("(e.event_name LIKE ? OR e.event_source LIKE ? OR e.user_agent LIKE ? OR e.user_identity_arn LIKE ? OR e.source_ip LIKE ? OR e.cloud_provider LIKE ?)")
            like = f"%{search}%"
            params.extend([like, like, like, like, like, like])
        if alerts_only:
            where.append("EXISTS (SELECT 1 FROM alert a WHERE a.event_id = e.event_id)")

        sql = f"""
            SELECT e.event_id, e.trial_id, e.fixture_key, e.cloud_provider, e.account_scope,
                   e.source_type, e.schema_version, e.event_time, e.received_at,
                   e.event_source, e.event_name, e.aws_region, e.source_ip,
                   e.user_agent, e.user_identity_type, e.user_identity_arn, e.error_code, e.raw,
                   (SELECT GROUP_CONCAT(r.ruleset_version || ':' || r.native_id, ', ')
                      FROM alert a JOIN rule r ON r.rule_id = a.rule_id
                     WHERE a.event_id = e.event_id) AS matched_rules
            FROM event e
            WHERE {' AND '.join(where)}
            ORDER BY e.event_time DESC
            LIMIT ?
        """
        params.append(limit)
        events = []
        for row in conn.execute(sql, tuple(params)).fetchall():
            item = dict(row)
            try:
                item["raw_json"] = json.loads(item["raw"])
            except Exception:
                item["raw_json"] = {}
            del item["raw"]
            events.append(item)

        trial_logs = [
            dict(r)
            for r in conn.execute(
                """
                SELECT t.trial_id, t.run_id, v.technique_id, v.variant_id, v.variant_set,
                       t.window_start, t.window_end, t.attack_succeeded, t.variant_changed, t.error
                FROM trial t JOIN variant v ON v.variant_id = t.variant_id
                ORDER BY t.window_start DESC LIMIT 200
                """
            ).fetchall()
        ]
    finally:
        conn.close()

    return {
        "events": events,
        "trial_logs": trial_logs,
        "jobs": JOBS.list_jobs(),
    }


# ---------------------------------------------------------------------------
# Background Job & Streaming Execution Engine
# ---------------------------------------------------------------------------


class JobManager:
    """Thread-safe async job runner for streaming Terraform, Variant & Campaign jobs."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._jobs: dict[str, dict[str, Any]] = {}
        self._queues: dict[str, list[queue.Queue[str | None]]] = {}

    def start_job(self, kind: str, title: str, target_fn) -> str:
        job_id = f"job-{uuid.uuid4().hex[:10]}"
        record = {
            "job_id": job_id,
            "kind": kind,
            "title": title,
            "status": "running",
            "started_at": _utc_now(),
            "finished_at": None,
            "logs": [],
            "result": None,
            "error": None,
        }
        with self._lock:
            self._jobs[job_id] = record
            self._queues[job_id] = []

        def log(line: str) -> None:
            stamp = datetime.now(timezone.utc).strftime("%H:%M:%S")
            msg = f"[{stamp}] {line}"
            with self._lock:
                record["logs"].append(msg)
                for q in self._queues.get(job_id, []):
                    q.put(msg)

        def runner() -> None:
            try:
                res = target_fn(log)
                with self._lock:
                    record["status"] = "completed"
                    record["result"] = res
                    record["finished_at"] = _utc_now()
            except Exception as exc:  # noqa: BLE001
                log(f"ERROR: {type(exc).__name__}: {exc}")
                with self._lock:
                    record["status"] = "failed"
                    record["error"] = f"{type(exc).__name__}: {exc}"
                    record["finished_at"] = _utc_now()
            finally:
                with self._lock:
                    for q in self._queues.get(job_id, []):
                        q.put(None)

        thread = threading.Thread(target=runner, daemon=True)
        thread.start()
        return job_id

    def get_job(self, job_id: str) -> dict[str, Any] | None:
        with self._lock:
            rec = self._jobs.get(job_id)
            return dict(rec) if rec else None

    def list_jobs(self) -> list[dict[str, Any]]:
        with self._lock:
            return [
                {
                    "job_id": j["job_id"],
                    "kind": j["kind"],
                    "title": j["title"],
                    "status": j["status"],
                    "started_at": j["started_at"],
                    "finished_at": j["finished_at"],
                    "log_count": len(j["logs"]),
                    "error": j["error"],
                }
                for j in reversed(list(self._jobs.values()))
            ][:30]

    def stream_logs(self, job_id: str) -> Iterator[str]:
        q: queue.Queue[str | None] = queue.Queue()
        with self._lock:
            rec = self._jobs.get(job_id)
            if rec is None:
                yield f"data: {json.dumps({'done': True, 'status': 'unknown'})}\n\n"
                return
            backlog = list(rec["logs"])
            finished = rec["status"] != "running"
            if not finished:
                self._queues[job_id].append(q)

        for line in backlog:
            yield f"data: {json.dumps({'line': line})}\n\n"
        if finished:
            rec = self.get_job(job_id) or {}
            yield f"data: {json.dumps({'done': True, 'status': rec.get('status'), 'result': rec.get('result'), 'error': rec.get('error')})}\n\n"
            return

        try:
            while True:
                item = q.get(timeout=30)
                if item is None:
                    rec = self.get_job(job_id) or {}
                    yield f"data: {json.dumps({'done': True, 'status': rec.get('status'), 'result': rec.get('result'), 'error': rec.get('error')})}\n\n"
                    break
                yield f"data: {json.dumps({'line': item})}\n\n"
        except queue.Empty:
            rec = self.get_job(job_id) or {}
            yield f"data: {json.dumps({'done': rec.get('status') != 'running', 'status': rec.get('status'), 'result': rec.get('result'), 'error': rec.get('error')})}\n\n"
        finally:
            with self._lock:
                qs = self._queues.get(job_id, [])
                if q in qs:
                    qs.remove(q)


JOBS = JobManager()


def start_campaign_job(payload: Mapping[str, Any], *, db_path: Path | None = None) -> str:
    path = ensure_database(db_path)
    synthetic = bool(payload.get("synthetic", True))
    sets = list(payload.get("sets") or ["baseline", "ofat", "pairwise"])
    techniques = [str(t).upper() for t in (payload.get("techniques") or []) if str(t).strip()]
    repetitions = max(1, min(10, int(payload.get("repetitions") or 1)))
    ruleset = str(payload.get("ruleset") or "baseline-v1")
    force = bool(payload.get("force", False))

    mode_label = "Synthetic Rehearsal" if synthetic else "Live AWS Lab Campaign"
    title = f"{mode_label} ({', '.join(techniques) if techniques else 'all active'})"

    def task(log) -> dict[str, Any]:
        log(f"Starting {mode_label}...")
        catalogue = load_catalogue()
        if not catalogue.techniques:
            raise RuntimeError("No attacks are enabled in the catalogue.")

        # Sync variants cleanly so custom/active attacks have variants ready
        sync_res = _sync_variants_for_catalogue(path)
        log(f"Variants synchronized: {sync_res.get('variants_total')} attack, {sync_res.get('benign_total')} benign.")

        from identity_shield.runner.cli import _select

        selected = _select(
            catalogue,
            sets=sets,
            techniques=techniques or None,
            include_holdout=False,
        )
        if not selected:
            raise RuntimeError("No variants matched the selected technique/set filters.")
        log(f"Selected {len(selected)} variant(s) x {repetitions} repetition(s).")

        bound = settings.get_resources()
        thresholds = settings.get_thresholds()
        _, lab_session, region, profile = resolve_sessions(bound.region)
        session = None
        account_id = "123456789012"

        if not synthetic:
            if not lab_session.has_credentials():
                raise RuntimeError("No active AWS session found. Connect an AWS account before launching a live campaign.")
            session = lab_session
            account_id = lab_session.account_id()
            log(f"Live session authenticated -> Account {account_id} ({region})")

        tf_outputs = _safe_tf_outputs() if not synthetic else {}
        lab = {
            "queue_url": payload.get("queue_url") or bound.queue_url or tf_outputs.get("queue_url"),
            "trail_name": payload.get("trail_name") or bound.trail_name or tf_outputs.get("trail_name") or "identity-shield-trail",
            "data_bucket": payload.get("data_bucket") or bound.data_bucket or tf_outputs.get("data_bucket_name") or "is-lab-crown-jewels",
            "data_key": payload.get("data_key") or bound.data_key or "finance/q4.csv",
            "instance_id": payload.get("instance_id") or bound.instance_id or tf_outputs.get("instance_id"),
            "test_user_name": payload.get("test_user_name") or bound.test_user_name or "is-test-user",
            "admin_role_name": payload.get("admin_role_name") or bound.admin_role_name or "is-admin-role",
            "aws_profile": profile or "lab",
            "ruleset_version": ruleset,
            "enable_data_events": thresholds.enable_data_events,
            "enable_instance": thresholds.enable_instance,
            "allowed_regions": thresholds.allowed_regions,
            "max_delivery_lag_seconds": thresholds.max_delivery_lag_minutes * 60,
        }

        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        run_id = f"{'sim' if synthetic else 'run'}-{stamp}"
        conn = connect(path)
        try:
            log(f"Executing run_id={run_id} across {len(selected)} variant(s)...")
            result = orchestrator.run_campaign(
                conn,
                run_id=run_id,
                variants=selected,
                catalogue=catalogue,
                account_id=account_id,
                region=region,
                repetitions=repetitions,
                synthetic=synthetic,
                session=session,
                lab=lab,
                force=force,
            )
            log(f"Campaign complete: trials={result.trials}, attack_succeeded={result.succeeded}, errors={len(result.errors)}")
            for err in result.errors[:10]:
                log(f"  WARN/ERR: {err}")

            log("Replaying detection rulesets against captured events...")
            replay_stats = {}
            for rs_name in detect_replay.load_ruleset_config():
                try:
                    loaded = detect_replay.load_ruleset(conn, rs_name)
                    replay_stats[rs_name] = detect_replay.run_replay(conn, loaded)
                    log(f"  Replay {rs_name}: {replay_stats[rs_name]['alerts']} alerts across {replay_stats[rs_name]['events']} events")
                except Exception as exc:
                    log(f"  Replay {rs_name} skipped: {exc}")

            return {
                "run_id": run_id,
                "synthetic": synthetic,
                "trials": result.trials,
                "succeeded": result.succeeded,
                "errors": result.errors,
                "replay": replay_stats,
            }
        finally:
            conn.close()

    return JOBS.start_job("campaign", title, task)


def start_lab_up_job(extra_vars: Mapping[str, Any] | None = None) -> str:
    def task(log) -> dict[str, Any]:
        if not provision.available():
            raise RuntimeError("Terraform CLI is not installed on PATH.")
        guarded, _, region, profile = resolve_sessions()
        if not guarded.has_credentials():
            raise RuntimeError("No active AWS credentials. Connect an AWS account first.")
        thresholds = settings.get_thresholds()
        bound = settings.get_resources()
        account_id = guarded.account_id()

        variables = _terraform_variables(region=region, thresholds=thresholds, bound=bound, extra=extra_vars)
        tf_env = provision.aws_env(session=guarded, profile=profile, region=region)

        log(f"Initializing Terraform in {provision.workdir()} for AWS account {account_id} ({region})...")
        init_res = provision.init(env=tf_env)
        for line in (init_res.stdout + "\n" + init_res.stderr).splitlines():
            if line.strip():
                log(line)
        if not init_res.ok:
            raise RuntimeError(f"terraform init failed ({init_res.returncode})")

        log(f"Applying lab infrastructure with variables: {json.dumps(variables)}")
        apply_res = provision.apply(variables=variables, env=tf_env)
        for line in (apply_res.stdout + "\n" + apply_res.stderr).splitlines():
            if line.strip():
                log(line)
        if not apply_res.ok:
            raise RuntimeError(f"terraform apply failed ({apply_res.returncode})")

        outputs = provision.outputs()
        log(f"Terraform outputs: {json.dumps(outputs)}")

        # Automatically bind newly created outputs to workspace resources!
        updates: dict[str, Any] = {"region": region}
        if outputs.get("queue_url"):
            updates["queue_url"] = outputs["queue_url"]
        if outputs.get("trail_name"):
            updates["trail_name"] = outputs["trail_name"]
        if outputs.get("data_bucket_name") or outputs.get("data_bucket"):
            updates["data_bucket"] = outputs.get("data_bucket_name") or outputs.get("data_bucket")
        if outputs.get("data_key"):
            updates["data_key"] = outputs["data_key"]
        if outputs.get("instance_id"):
            updates["instance_id"] = outputs["instance_id"]
        if outputs.get("test_user_name"):
            updates["test_user_name"] = outputs["test_user_name"]
        if outputs.get("admin_role_name"):
            updates["admin_role_name"] = outputs["admin_role_name"]
        settings.update_resources(updates)
        log("Auto-bound Terraform outputs into active workspace resource configuration.")

        snap = census_module.collect(guarded, region=region, account_id=account_id, lab_name=bound.lab_name)
        log(f"Post-apply census verified {len(snap.resources)} lab-owned resource(s).")
        return {"outputs": outputs, "census": snap.to_dict()}

    return JOBS.start_job("lab_up", "Provision AWS Lab Infrastructure", task)


def start_lab_down_job(*, check_only: bool = False) -> str:
    title = "Census Check (Check-Only)" if check_only else "Destroy AWS Lab & Verify Zero Residue"

    def task(log) -> dict[str, Any]:
        guarded, _, region, profile = resolve_sessions()
        if not guarded.has_credentials():
            raise RuntimeError("No active AWS credentials. Connect an AWS account first.")
        bound = settings.get_resources()
        log(f"Running pre-teardown census in {region}...")
        report_path = destroy_module.default_report_path(
            f"gui-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S')}"
        )
        # Note: teardown builds tf_env from guarded session cleanly
        report = destroy_module.teardown(
            guarded,
            region=region,
            lab_name=bound.lab_name,
            report_path=report_path,
            check_only=check_only,
        )
        log(f"Before: {len(report.before)} | After: {len(report.after)} | Residue: {len(report.residue)}")
        log(f"Terraform exit: {report.terraform_exit_code} | Verdict: {'PASS - ZERO RESIDUE' if report.passed else 'FAIL'}")
        for note in report.notes:
            log(f"Note: {note}")
        return {**report.to_dict(), "report_path": str(report_path)}

    return JOBS.start_job("lab_down", title, task)


def execute_cli_command(raw_command: str, *, db_path: Path | None = None) -> dict[str, Any]:
    """Execute an allowed Identity Shield CLI subcommand safely from the Web Console."""
    cleaned = raw_command.strip()
    if len(cleaned) > 512 or "\x00" in cleaned:
        raise ValueError("CLI command too long or contains invalid characters")
    if any(tok in cleaned for tok in (";", "&&", "||", "|", "`", "$(", "\n", "\r")):
        raise ValueError("Shell chaining/control operators are not permitted in Web Console")
    tokens = shlex.split(cleaned)
    if not tokens:
        raise ValueError("Empty command")
    if tokens[0] in ("identity-shield", "identity-shield.exe"):
        tokens = tokens[1:]
    if not tokens:
        tokens = ["--help"]

    subcmd = tokens[0]
    allowed_web_commands = {
        "--help",
        "-h",
        "init",
        "load",
        "replay",
        "compile",
        "variants",
        "lab",
        "runner",
        "analyse",
        "bench",
        "attacks",
        "config",
        "logs",
        "proxy",
        "dynamic",
    }
    if subcmd not in allowed_web_commands:
        raise ValueError(f"Command {subcmd!r} is disabled from Web Console for safety")
    if subcmd == "lab" and len(tokens) > 1 and tokens[1] in {"up", "down", "apply", "destroy"}:
        raise ValueError("Run Terraform lab provisioning/teardown from the Lab Setup UI with explicit confirmation")
    if subcmd == "proxy" and len(tokens) > 1 and tokens[1] == "start":
        raise ValueError("Start the Live Proxy via the Live Proxy UI tab instead of CLI Console")
    if any(t == "--db" or t.startswith("--db=") for t in tokens):
        raise ValueError("Cannot override --db path from Web Console; use Connections -> Database & Archive")

    # Inject active --db only for subcommands whose argparse parser defines --db
    sub_action = tokens[1] if len(tokens) > 1 else ""
    db_subcommands: dict[str, set[str]] = {
        "variants": {"generate", "benign"},
        "runner": {"campaign", "preflight", "collect", "sweep"},
        "analyse": {"summary", "misses", "diff", "report"},
        "attacks": {"list", "show", "add", "enable", "disable", "remove"},
        "config": {"export"},
        "logs": {"events", "ingest", "trials"},
        "proxy": {"status", "events", "simulate", "clear"},
        "dynamic": {
            "list",
            "enable",
            "disable",
            "add",
            "delete",
            "replay",
            "alerts",
            "profiles",
            "audit",
            "enhance",
            "loop",
            "siem-export",
        },
    }
    inject_db = subcmd in {"init", "load", "replay", "compile"} or (
        subcmd in db_subcommands and sub_action in db_subcommands[subcmd]
    )
    if db_path and "--db" not in tokens and inject_db:
        if not any(flag in tokens for flag in ("-h", "--help")):
            tokens.extend(["--db", str(db_path)])

    env = dict(os.environ)
    if db_path:
        env["IDENTITY_SHIELD_DB"] = str(db_path)
    conn_desc = settings.get_connection_descriptor()
    if conn_desc.region:
        env.setdefault("AWS_REGION", conn_desc.region)
    runtime_boto = settings.RUNTIME_SESSION.boto_session()
    if runtime_boto is not None:
        env.update(provision.aws_env(session=runtime_boto, region=conn_desc.region))
    elif conn_desc.profile_name:
        env.setdefault("AWS_PROFILE", conn_desc.profile_name)

    cmd = [sys.executable, "-m", "identity_shield.cli", *tokens]
    started = time.perf_counter()
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300, env=env)
    elapsed = time.perf_counter() - started
    return {
        "command": "identity-shield " + " ".join(tokens),
        "returncode": proc.returncode,
        "duration_s": round(elapsed, 3),
        "stdout": proc.stdout,
        "stderr": proc.stderr,
    }


# ---------------------------------------------------------------------------
# Live Security Proxy, Adaptive Rule Enhancement & Dynamic Detection Engine
# ---------------------------------------------------------------------------


def proxy_status(*, db_path: Path | None = None) -> dict[str, Any]:
    path = ensure_database(db_path)
    st = PROXY_RUNTIME.status()
    conn = connect(path)
    try:
        row = conn.execute(
            """
            SELECT
                COUNT(*) AS total_events,
                SUM(CASE WHEN action_taken = 'blocked' THEN 1 ELSE 0 END) AS blocked_events,
                SUM(CASE WHEN action_taken = 'alerted' THEN 1 ELSE 0 END) AS alerted_events,
                SUM(CASE WHEN traffic_kind = 'aws_api' OR cloud_provider = 'aws' THEN 1 ELSE 0 END) AS aws_events,
                SUM(CASE WHEN traffic_kind = 'gcp_api' OR cloud_provider = 'gcp' THEN 1 ELSE 0 END) AS gcp_events,
                SUM(CASE WHEN traffic_kind = 'azure_api' OR cloud_provider = 'azure' THEN 1 ELSE 0 END) AS azure_events,
                SUM(CASE WHEN traffic_kind IN ('http_app', 'cloud_app') THEN 1 ELSE 0 END) AS app_events
            FROM proxy_event
            """
        ).fetchone()
        st["stats"] = {
            "total_events": int(row["total_events"] or 0),
            "blocked_events": int(row["blocked_events"] or 0),
            "alerted_events": int(row["alerted_events"] or 0),
            "aws_events": int(row["aws_events"] or 0),
            "gcp_events": int(row["gcp_events"] or 0),
            "azure_events": int(row["azure_events"] or 0),
            "app_events": int(row["app_events"] or 0),
        }
    finally:
        conn.close()
    return st


def update_proxy_settings(payload: Mapping[str, Any]) -> dict[str, Any]:
    updated = settings.update_proxy_config(payload)
    return {"config": updated.to_dict(), "status": PROXY_RUNTIME.status()}


def start_proxy_server(
    *,
    db_path: Path | None = None,
    host: str | None = None,
    port: int | None = None,
) -> dict[str, Any]:
    path = ensure_database(db_path)
    PROXY_RUNTIME.start(db_path=path, host=host, port=port)
    return proxy_status(db_path=path)


def stop_proxy_server(*, db_path: Path | None = None) -> dict[str, Any]:
    PROXY_RUNTIME.stop()
    return proxy_status(db_path=db_path)


def list_proxy_events(
    *,
    db_path: Path | None = None,
    search: str = "",
    alerts_only: bool = False,
    traffic_kind: str = "",
    cloud_provider: str = "",
    limit: int = 100,
) -> dict[str, Any]:
    path = ensure_database(db_path)
    conn = connect(path)
    try:
        sql = """
            SELECT proxy_event_id, timestamp, cloud_provider, account_scope,
                   traffic_type, traffic_kind, classification_confidence, classification_reason,
                   mode, action_taken, policy_decision, policy_reason,
                   client_ip, principal, method, target_host, path, service,
                   operation, user_agent, aws_region, params_json, status_code,
                   latency_ms, risk_score, matched_static, matched_dynamic
            FROM proxy_event
            WHERE 1 = 1
        """
        params: list[Any] = []
        if alerts_only:
            sql += " AND action_taken IN ('alerted', 'blocked')"
        if traffic_kind:
            sql += " AND traffic_kind = ?"
            params.append(traffic_kind)
        if cloud_provider and cloud_provider != "all":
            sql += " AND cloud_provider = ?"
            params.append(cloud_provider.lower())
        if search:
            like = f"%{search}%"
            sql += (
                " AND (operation LIKE ? OR service LIKE ? OR principal LIKE ?"
                " OR path LIKE ? OR user_agent LIKE ? OR target_host LIKE ?)"
            )
            params.extend([like] * 6)
        sql += " ORDER BY timestamp DESC, rowid DESC LIMIT ?"
        params.append(max(1, min(int(limit), 500)))
        rows = []
        for r in conn.execute(sql, tuple(params)).fetchall():
            item = dict(r)
            item["matched_static"] = json.loads(item["matched_static"] or "[]")
            item["matched_dynamic"] = json.loads(item["matched_dynamic"] or "[]")
            rows.append(item)
        return {"events": rows, "count": len(rows)}
    finally:
        conn.close()


def clear_proxy_events(*, db_path: Path | None = None) -> dict[str, Any]:
    path = ensure_database(db_path)
    conn = connect(path)
    try:
        c1 = conn.execute("DELETE FROM proxy_event").rowcount
        c2 = conn.execute("DELETE FROM dynamic_alert WHERE source = 'proxy'").rowcount
        conn.commit()
        return {"deleted_events": c1, "deleted_alerts": c2}
    finally:
        conn.close()


def simulate_proxy_traffic(
    *,
    db_path: Path | None = None,
    scenario: str = "mixed",
) -> dict[str, Any]:
    path = ensure_database(db_path)
    was_running = PROXY_RUNTIME.is_running()
    status = PROXY_RUNTIME.start(db_path=path) if not was_running else PROXY_RUNTIME.status()
    sent = proxy_simulator.send_sample_traffic(
        host=status["host"],
        port=int(status["port"]),
        scenario=scenario,
    )
    return {
        "scenario": scenario,
        "sent_count": len(sent),
        "requests": sent,
        "status": proxy_status(db_path=path),
    }


def audit_ruleset_view(
    *,
    db_path: Path | None = None,
    ruleset_version: str = "baseline-v1",
) -> dict[str, Any]:
    path = ensure_database(db_path)
    conn = connect(path)
    try:
        return detect_enhancer.audit_ruleset(conn, ruleset_version=ruleset_version)
    finally:
        conn.close()


def preview_rule_enhancement(rule_id: str, *, db_path: Path | None = None) -> dict[str, Any]:
    path = ensure_database(db_path)
    conn = connect(path)
    try:
        return detect_enhancer.build_enhanced_rule(conn, rule_id)
    finally:
        conn.close()


def apply_enhanced_rule_service(
    *,
    filename: str,
    yaml_content: str,
    target_ruleset: str = "enhanced-v1",
    replay: bool = True,
    db_path: Path | None = None,
) -> dict[str, Any]:
    path = ensure_database(db_path)
    conn = connect(path)
    try:
        return detect_enhancer.apply_enhanced_rule(
            conn,
            filename=filename,
            yaml_content=yaml_content,
            target_ruleset=target_ruleset,
            replay=replay,
        )
    finally:
        conn.close()


def enhance_ruleset_service(
    *,
    source_ruleset: str = "baseline-v1",
    target_ruleset: str = "enhanced-v1",
    db_path: Path | None = None,
) -> dict[str, Any]:
    path = ensure_database(db_path)
    conn = connect(path)
    try:
        return detect_enhancer.enhance_entire_ruleset(
            conn,
            source_ruleset=source_ruleset,
            target_ruleset=target_ruleset,
        )
    finally:
        conn.close()


def list_dynamic_rules_view(
    *,
    db_path: Path | None = None,
    enabled_only: bool = False,
) -> dict[str, Any]:
    path = ensure_database(db_path)
    conn = connect(path)
    try:
        rules = detect_dynamic.list_dynamic_rules(conn, enabled_only=enabled_only)
        return {"rules": rules, "count": len(rules)}
    finally:
        conn.close()


def save_dynamic_rule_service(
    payload: Mapping[str, Any],
    *,
    db_path: Path | None = None,
) -> dict[str, Any]:
    path = ensure_database(db_path)
    conn = connect(path)
    try:
        return detect_dynamic.upsert_dynamic_rule(conn, payload)
    finally:
        conn.close()


def toggle_dynamic_rule_service(
    rule_id: str,
    enabled: bool,
    *,
    db_path: Path | None = None,
) -> dict[str, Any]:
    path = ensure_database(db_path)
    conn = connect(path)
    try:
        return detect_dynamic.toggle_dynamic_rule(conn, rule_id, enabled)
    finally:
        conn.close()


def delete_dynamic_rule_service(
    rule_id: str,
    *,
    db_path: Path | None = None,
) -> dict[str, Any]:
    path = ensure_database(db_path)
    conn = connect(path)
    try:
        return detect_dynamic.delete_dynamic_rule(conn, rule_id)
    finally:
        conn.close()


def list_dynamic_alerts_view(
    *,
    db_path: Path | None = None,
    source: str = "",
    cloud_provider: str = "",
    limit: int = 100,
) -> dict[str, Any]:
    path = ensure_database(db_path)
    conn = connect(path)
    try:
        sql = """
            SELECT alert_id, rule_id, rule_name, source, ref_id, cloud_provider, account_scope,
                   ruleset_version, timestamp, principal, severity, action_taken, summary, evidence_json
            FROM dynamic_alert
            WHERE 1 = 1
        """
        params: list[Any] = []
        if source:
            sql += " AND source = ?"
            params.append(source)
        if cloud_provider and cloud_provider != "all":
            sql += " AND cloud_provider = ?"
            params.append(cloud_provider.lower())
        sql += " ORDER BY timestamp DESC, rowid DESC LIMIT ?"
        params.append(max(1, min(int(limit), 500)))
        rows = []
        for r in conn.execute(sql, tuple(params)).fetchall():
            item = dict(r)
            item["evidence"] = json.loads(item["evidence_json"] or "{}")
            rows.append(item)
        return {"alerts": rows, "count": len(rows)}
    finally:
        conn.close()


def list_principal_profiles_view(
    *,
    db_path: Path | None = None,
    cloud_provider: str = "",
    limit: int = 50,
) -> dict[str, Any]:
    path = ensure_database(db_path)
    conn = connect(path)
    try:
        sql = "SELECT * FROM principal_profile WHERE 1 = 1"
        params: list[Any] = []
        if cloud_provider and cloud_provider != "all":
            sql += " AND cloud_provider = ?"
            params.append(cloud_provider.lower())
        sql += " ORDER BY last_seen DESC LIMIT ?"
        params.append(max(1, min(int(limit), 200)))
        rows = []
        for r in conn.execute(sql, tuple(params)).fetchall():
            rows.append(
                {
                    "profile_key": r["profile_key"],
                    "cloud_provider": r["cloud_provider"],
                    "account_scope": r["account_scope"],
                    "principal": r["principal"],
                    "known_user_agents": json.loads(r["known_user_agents"] or "[]"),
                    "known_regions": json.loads(r["known_regions"] or "[]"),
                    "known_services": json.loads(r["known_services"] or "[]"),
                    "known_operations": json.loads(r["known_operations"] or "[]"),
                    "known_hours": json.loads(r["known_hours"] or "[]"),
                    "request_count": int(r["request_count"] or 0),
                    "cold_start_complete": bool(r["cold_start_complete"]) if "cold_start_complete" in r.keys() else int(r["request_count"] or 0) >= 3,
                    "last_seen": r["last_seen"],
                }
            )
        return {"profiles": rows, "count": len(rows)}
    finally:
        conn.close()


def run_dynamic_replay_service(
    *,
    db_path: Path | None = None,
    run_id: str | None = None,
) -> dict[str, Any]:
    path = ensure_database(db_path)
    conn = connect(path)
    try:
        return detect_dynamic.run_dynamic_replay(conn, run_id=run_id)
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Self-Hosted Storage Linking, JSONL Export & Organization S3 Archive
# ---------------------------------------------------------------------------


def get_storage_status(*, db_path: Path | None = None) -> dict[str, Any]:
    return {
        "storage": settings.get_storage_config().to_dict(),
        "db": db_health(db_path),
    }


def update_storage_link(payload: Mapping[str, Any]) -> dict[str, Any]:
    updated = settings.update_storage_config(payload)
    # Re-resolve & initialize newly linked DB when explicit env override isn't pinning it
    target_path = resolve_db_path()
    ensure_database(target_path)
    if PROXY_RUNTIME._db_path is not None and not os.environ.get("IDENTITY_SHIELD_DB"):
        PROXY_RUNTIME._db_path = target_path
    return {
        "storage": updated.to_dict(),
        "db": db_health(target_path),
    }


def export_telemetry_jsonl(
    *,
    db_path: Path | None = None,
    limit: int = 5000,
) -> dict[str, Any]:
    path = ensure_database(db_path)
    conn = connect(path)
    cap = max(1, min(int(limit), 50_000))
    lines: list[str] = []
    try:
        for row in conn.execute(
            "SELECT * FROM proxy_event ORDER BY timestamp DESC, rowid DESC LIMIT ?",
            (cap,),
        ).fetchall():
            rec = dict(row)
            rec["record_type"] = "proxy_event"
            lines.append(json.dumps(rec, sort_keys=True))
        for row in conn.execute(
            "SELECT * FROM dynamic_alert ORDER BY timestamp DESC, rowid DESC LIMIT ?",
            (cap,),
        ).fetchall():
            rec = dict(row)
            rec["record_type"] = "dynamic_alert"
            lines.append(json.dumps(rec, sort_keys=True))
    finally:
        conn.close()
    content = "\n".join(lines) + ("\n" if lines else "")
    return {
        "records": len(lines),
        "db_path": str(path),
        "jsonl": content,
    }


def archive_telemetry_to_s3(
    *,
    db_path: Path | None = None,
    bucket: str | None = None,
    prefix: str | None = None,
) -> dict[str, Any]:
    storage = settings.get_storage_config()
    target_bucket = (bucket or storage.archive_s3_bucket or "").strip()
    if not target_bucket:
        raise ValueError("Archive S3 bucket name is required (set in Storage Settings first)")
    session = settings.RUNTIME_SESSION.boto_session()
    if session is None:
        raise RuntimeError("Connect AWS first before archiving telemetry to your S3 bucket")

    export = export_telemetry_jsonl(db_path=db_path)
    clean_prefix = (prefix if prefix is not None else storage.archive_s3_prefix or "identity-shield-telemetry/").strip()
    if clean_prefix and not clean_prefix.endswith("/"):
        clean_prefix += "/"
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    key = f"{clean_prefix}telemetry-{stamp}.jsonl"

    s3 = session.client("s3")
    s3.put_object(
        Bucket=target_bucket,
        Key=key,
        Body=export["jsonl"].encode("utf-8"),
        ContentType="application/x-ndjson",
    )
    return {
        "archived": True,
        "bucket": target_bucket,
        "key": key,
        "s3_uri": f"s3://{target_bucket}/{key}",
        "records": export["records"],
        "bytes": len(export["jsonl"].encode("utf-8")),
    }


def external_tools_status_service() -> dict[str, Any]:
    """Return lazy availability status of optional OSS tools plus saved CloudFox inventory summary."""
    from identity_shield.integrations import get_external_tools_status
    from identity_shield.variants.closed_loop import load_cloudfox_inventory

    status = get_external_tools_status()
    cf = load_cloudfox_inventory()
    status["cloudfox_inventory"] = (
        {
            "loaded": True,
            "imported_at": cf.get("imported_at"),
            "total_resources": cf.get("total_resources", 0),
            "counts": cf.get("counts") or {},
            "suggested_bindings": cf.get("suggested_bindings") or {},
        }
        if cf
        else {"loaded": False, "total_resources": 0, "counts": {}, "suggested_bindings": {}}
    )
    return status


def import_cloudfox_service(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Import bounded CloudFox JSON inventory from raw text, structured dict/list, or safe path."""
    from identity_shield.integrations import load_cloudfox_inventory_file, parse_cloudfox_inventory
    from identity_shield.variants.closed_loop import save_cloudfox_inventory

    apply_bindings = bool(payload.get("apply_bindings"))
    if payload.get("path"):
        inventory = load_cloudfox_inventory_file(str(payload["path"]), base_dir=config.ROOT)
    else:
        raw_input = (
            payload.get("json_text")
            if payload.get("json_text") is not None
            else (
                payload.get("raw_json")
                if payload.get("raw_json") is not None
                else (payload.get("inventory") if payload.get("inventory") is not None else payload.get("data"))
            )
        )
        if raw_input is None or (isinstance(raw_input, str) and not raw_input.strip()):
            raise ValueError("Provide CloudFox JSON via json_text, inventory, or path.")
        inventory = parse_cloudfox_inventory(raw_input)

    save_cloudfox_inventory(inventory)
    applied_bindings: dict[str, str] = {}
    if apply_bindings and inventory.get("suggested_bindings"):
        current = settings.get_resources()
        updates = {
            k: str(v)
            for k, v in inventory["suggested_bindings"].items()
            if hasattr(current, k) and v
        }
        if updates:
            settings.update_resources(updates)
            applied_bindings = updates

    return {
        "ok": True,
        "inventory": inventory,
        "applied_bindings": applied_bindings,
    }


def run_cloudfox_recon_service(payload: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Lazily run CloudFox CLI if installed and store discovered inventory."""
    from identity_shield.integrations import run_cloudfox_recon
    from identity_shield.variants.closed_loop import save_cloudfox_inventory

    opts = payload or {}
    res = run_cloudfox_recon(
        profile=opts.get("profile") or None,
        region=opts.get("region") or None,
    )
    if res.get("ok") and isinstance(res.get("inventory"), dict):
        save_cloudfox_inventory(res["inventory"])
    return res


def run_pacu_recon_service(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Execute an allowlisted read-only Pacu reconnaissance module if installed."""
    from identity_shield.integrations import run_pacu_recon

    module_name = str(payload.get("module") or payload.get("module_name") or "").strip()
    return run_pacu_recon(
        module_name,
        profile=payload.get("profile") or None,
        session_name=str(payload.get("session_name") or "identity_shield_recon"),
        proxy_url=payload.get("proxy_url") or None,
    )


def preview_closed_loop_service(
    *,
    mode: str = "both",
    limit: int = 8,
    cloud_provider: str = "all",
    db_path: Path | None = None,
) -> dict[str, Any]:
    """Preview closed-loop candidate attack vectors for the chosen source mode & cloud filter."""
    from identity_shield.variants.closed_loop import (
        load_last_closed_loop_report,
        preview_closed_loop_vectors,
    )

    path = ensure_database(db_path)
    conn = connect(path)
    try:
        res = preview_closed_loop_vectors(conn, mode=mode, limit=limit, cloud_provider=cloud_provider)
    finally:
        conn.close()
    res["last_report"] = load_last_closed_loop_report()
    return res


def run_closed_loop_service(
    *,
    mode: str = "both",
    include_pairwise: bool = False,
    auto_enhance: bool = True,
    limit: int = 6,
    cloud_provider: str = "all",
    db_path: Path | None = None,
) -> dict[str, Any]:
    """Run Multi-Cloud Closed-Loop 5-Factor Attack Synthesis -> Detection Replay -> Optional Auto-Hardening."""
    from identity_shield.variants.closed_loop import run_closed_loop

    path = ensure_database(db_path)
    conn = connect(path)
    try:
        report = run_closed_loop(
            conn,
            mode=mode,
            include_pairwise=include_pairwise,
            auto_enhance=auto_enhance,
            limit=limit,
            cloud_provider=cloud_provider,
        )
    finally:
        conn.close()
    return report


def multicloud_status_service(*, db_path: Path | None = None) -> dict[str, Any]:
    """Return provider capability descriptors, event counts by cloud, and multi-cloud techniques."""
    import yaml
    from identity_shield.clouds import list_provider_capabilities

    path = ensure_database(db_path)
    conn = connect(path)
    try:
        ev_counts = {
            row["cloud_provider"]: int(row["cnt"])
            for row in conn.execute(
                "SELECT cloud_provider, COUNT(*) AS cnt FROM event GROUP BY cloud_provider"
            ).fetchall()
        }
        px_counts = {
            row["cloud_provider"]: int(row["cnt"])
            for row in conn.execute(
                "SELECT cloud_provider, COUNT(*) AS cnt FROM proxy_event GROUP BY cloud_provider"
            ).fetchall()
        }
    finally:
        conn.close()

    mc_techs: list[dict[str, Any]] = []
    if config.MULTICLOUD_TECHNIQUES_YAML.is_file():
        doc = yaml.safe_load(config.MULTICLOUD_TECHNIQUES_YAML.read_text(encoding="utf-8")) or {}
        mc_techs = list(doc.get("techniques") or [])

    return {
        "providers": list_provider_capabilities(),
        "event_counts_by_cloud": ev_counts,
        "proxy_counts_by_cloud": px_counts,
        "multicloud_techniques": mc_techs,
    }


def ingest_cloud_logs_service(
    payload: Mapping[str, Any],
    *,
    db_path: Path | None = None,
) -> dict[str, Any]:
    """Ingest offline AWS CloudTrail, GCP Cloud Audit, or Azure Activity/Entra JSON logs."""
    from identity_shield.detect.loader import ingest_audit_payload

    cloud_provider = str(payload.get("cloud_provider") or "auto").strip().lower()
    if cloud_provider not in {"auto", "aws", "gcp", "azure"}:
        raise ValueError("cloud_provider must be one of: auto, aws, gcp, azure")

    raw_data: Any = payload.get("events") if payload.get("events") is not None else payload.get("payload")
    if raw_data is None and payload.get("json_text") is not None:
        raw_text = str(payload["json_text"])
        if len(raw_text.encode("utf-8")) > 4 * 1024 * 1024:
            raise ValueError("Log payload exceeds 4 MiB ingestion limit.")
        lines = [ln.strip() for ln in raw_text.splitlines() if ln.strip()]
        try:
            raw_data = json.loads(raw_text)
        except json.JSONDecodeError:
            # Also accept NDJSON lines
            raw_data = [json.loads(ln) for ln in lines]
    if raw_data is None:
        raise ValueError("Provide logs via json_text, events, or payload.")

    path = ensure_database(db_path)
    conn = connect(path)
    try:
        res = ingest_audit_payload(conn, raw_data, cloud_provider=cloud_provider)
    finally:
        conn.close()
    return {"ok": True, **res}


def import_scoutsuite_service(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Import bounded AWS/GCP/Azure ScoutSuite or multi-cloud resource JSON."""
    from identity_shield.variants.closed_loop import import_scoutsuite_json

    raw_input = (
        payload.get("json_text")
        if payload.get("json_text") is not None
        else (payload.get("inventory") if payload.get("inventory") is not None else payload.get("data"))
    )
    if raw_input is None or (isinstance(raw_input, str) and not raw_input.strip()):
        raise ValueError("Provide ScoutSuite/recon JSON via json_text or inventory.")
    return import_scoutsuite_json(raw_input)


def export_siem_rule_service(
    payload: Mapping[str, Any],
    *,
    db_path: Path | None = None,
) -> dict[str, Any]:
    """Export either inline Sigma YAML or a stored rule_id/native_id to SIEM query format."""
    from identity_shield.detect.rules import load_sigma_text
    from identity_shield.detect.siem_export import export_rule_to_siem, export_sigma_yaml_to_siem

    target = str(payload.get("target") or "aws_cloudwatch").strip().lower()
    if payload.get("yaml_content"):
        return export_sigma_yaml_to_siem(str(payload["yaml_content"]), target)

    rule_ref = str(payload.get("rule_id") or payload.get("native_id") or "").strip()
    ruleset = str(payload.get("ruleset_version") or "").strip()
    if not rule_ref:
        raise ValueError("Provide either yaml_content or rule_id to export.")

    path = ensure_database(db_path)
    conn = connect(path)
    try:
        if ruleset and ruleset in detect_replay.load_ruleset_config():
            try:
                detect_replay.load_ruleset(conn, ruleset)
            except Exception:
                pass
        row = conn.execute(
            """
            SELECT rule_id, native_id, title, level, technique_id, loader, path, body
            FROM rule
            WHERE (rule_id = ? OR native_id = ?)
              AND (? = '' OR ruleset_version = ?)
            LIMIT 1
            """,
            (rule_ref, rule_ref, ruleset, ruleset),
        ).fetchone()
    finally:
        conn.close()

    if not row:
        raise KeyError(f"Rule {rule_ref!r} not found in database.")
    if row["loader"] == "python":
        from identity_shield.detect.rules import Rule

        py_rule = Rule(
            native_id=row["native_id"],
            title=row["title"] or row["native_id"],
            level=row["level"] or "medium",
            technique_id=row["technique_id"],
            loader="python",
            body=row["body"],
        )
        return export_rule_to_siem(py_rule, target)
    return export_rule_to_siem(load_sigma_text(row["body"], path=row["path"]), target)
