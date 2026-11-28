"""Local Rule Inspector & Auto-Enhancer (`detect/enhancer.py`).

Inspects existing rulesets (`baseline-v1`, `improved-v1`, `custom-v1`) via
their compiled AST (`FieldMatch` / `BoolNode`), diagnoses hardcoded / brittle
conditions, incorporates learned normal baseline context from the Live Proxy
and variant-test misses, and synthesizes hardened Sigma YAML rules (`enhanced-v1`)
with dynamic behavioral rule recommendations — 100% locally with zero external APIs.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Mapping, Sequence

import yaml

from identity_shield import config, settings
from identity_shield.detect import replay as detect_replay
from identity_shield.detect.rules import BoolNode, FieldMatch, Node, load_sigma_text
from identity_shield.variants.loader import load_catalogue

# Known CloudTrail API equivalence families per MITRE ATT&CK technique / service
API_FAMILIES: dict[str, dict[str, Any]] = {
    "T1087.004": {
        "eventSource": "iam.amazonaws.com",
        "eventName": [
            "ListUsers",
            "ListRoles",
            "ListAccessKeys",
            "GetAccountAuthorizationDetails",
            "ListPolicies",
            "ListGroups",
        ],
    },
    "T1526": {
        "eventSource": ["sts.amazonaws.com", "ec2.amazonaws.com", "s3.amazonaws.com", "rds.amazonaws.com"],
        "eventName": [
            "DescribeInstances",
            "DescribeDBInstances",
            "ListBuckets",
            "DescribeRegions",
            "ListFunctions",
        ],
    },
    "T1580": {
        "eventSource": ["ec2.amazonaws.com", "s3.amazonaws.com"],
        "eventName": [
            "DescribeInstances",
            "DescribeSecurityGroups",
            "DescribeSubnets",
            "DescribeVpcs",
            "DescribeRouteTables",
            "DescribeNetworkInterfaces",
            "ListBuckets",
        ],
    },
    "T1078.004": {
        "eventSource": ["signin.amazonaws.com", "sts.amazonaws.com"],
        "eventName": ["ConsoleLogin"],
    },
    "T1098.001": {
        "eventSource": "iam.amazonaws.com",
        "eventName": [
            "CreateAccessKey",
            "CreateLoginProfile",
            "UpdateLoginProfile",
            "UpdateAccessKey",
        ],
    },
    "T1098.003": {
        "eventSource": "iam.amazonaws.com",
        "eventName": [
            "AttachRolePolicy",
            "PutRolePolicy",
            "UpdateAssumeRolePolicy",
            "PassRole",
            "AttachUserPolicy",
            "PutUserPolicy",
        ],
    },
    "T1552.005": {
        "eventSource": ["sts.amazonaws.com", "ec2.amazonaws.com"],
        "eventName": ["GetCallerIdentity", "DescribeInstances"],
    },
    "T1530": {
        "eventSource": "s3.amazonaws.com",
        "eventName": [
            "GetObject",
            "ListBucket",
            "GetObjectAcl",
            "GetObjectVersion",
            "SelectObjectContent",
        ],
    },
}


def _collect_field_matches(node: Node | None) -> list[FieldMatch]:
    if node is None:
        return []
    if isinstance(node, FieldMatch):
        return [node]
    found: list[FieldMatch] = []
    for child in node.children:
        found.extend(_collect_field_matches(child))
    return found


def _parse_rule_ast(row: Mapping[str, Any]) -> tuple[list[FieldMatch], dict[str, Any]]:
    body = str(row.get("body") or "")
    if row.get("loader") != "python" and body.strip():
        try:
            doc = yaml.safe_load(body) or {}
            rule = load_sigma_text(body, path=row.get("path"))
            return _collect_field_matches(rule.node), (doc if isinstance(doc, dict) else {})
        except Exception:
            pass
    # Synthetic representation for authored python rules (`python_rules.py`)
    nid = str(row.get("native_id") or "")
    matches: list[FieldMatch] = []
    if nid == "IS-DISC-001":
        matches = [
            FieldMatch("eventName", "eq", ("ListUsers", "ListRoles", "GetAccountAuthorizationDetails")),
            FieldMatch("userAgent", "contains", ("aws-cli",)),
        ]
    elif nid == "IS-CRED-001":
        matches = [FieldMatch("eventName", "eq", ("CreateAccessKey",))]
    elif nid == "IS-CRED-002":
        matches = [FieldMatch("eventName", "eq", ("UpdateAssumeRolePolicy", "AttachRolePolicy", "PutRolePolicy"))]
    elif nid == "IS-COLL-001":
        matches = [
            FieldMatch("eventName", "eq", ("GetObject",)),
            FieldMatch("sourceIPAddress", "re", ("public-ip-only",)),
        ]
    elif nid == "IS-INIT-001":
        matches = [
            FieldMatch("eventName", "eq", ("ConsoleLogin",)),
            FieldMatch("additionalEventData.MFAUsed", "eq", ("No",)),
        ]
    return matches, {}


def _missed_events_for_technique(conn, technique_id: str | None, ruleset: str) -> list[str]:
    if not technique_id:
        return []
    rows = conn.execute(
        """
        SELECT DISTINCT e.event_name
        FROM trial t
        JOIN variant v ON v.variant_id = t.variant_id
        JOIN event e ON e.trial_id = t.trial_id
        WHERE v.technique_id = ?
          AND v.variant_set IN ('baseline', 'ofat', 'pairwise')
          AND t.attack_succeeded = 1
          AND NOT EXISTS (
              SELECT 1 FROM alert a JOIN rule r ON r.rule_id = a.rule_id
              WHERE a.trial_id = t.trial_id AND r.ruleset_version = ?
          )
        """,
        (technique_id, ruleset),
    ).fetchall()
    return sorted({str(r["event_name"]) for r in rows if r["event_name"]})


def _learned_proxy_context(conn) -> dict[str, Any]:
    rows = conn.execute("SELECT * FROM principal_profile").fetchall()
    uas: set[str] = set()
    regions: set[str] = set()
    for r in rows:
        try:
            uas.update(yaml.safe_load(r["known_user_agents"]) or [])
            regions.update(yaml.safe_load(r["known_regions"]) or [])
        except Exception:
            continue
    return {
        "principals_profiled": len(rows),
        "known_user_agents": sorted(uas),
        "known_regions": sorted(regions),
    }


def audit_rule(
    conn,
    row: Mapping[str, Any],
    *,
    catalogue=None,
    proxy_ctx: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Audit one rule and diagnose brittle / static weaknesses."""
    matches, doc = _parse_rule_ast(row)
    tid = row.get("technique_id")
    ruleset = str(row.get("ruleset_version") or "baseline-v1")
    loader = str(row.get("loader") or "sigma")
    body = str(row.get("body") or "")
    orig_logsource = doc.get("logsource") if isinstance(doc.get("logsource"), dict) else {}
    product = str(orig_logsource.get("product") or "aws").strip().lower() or "aws"
    ls_service = str(orig_logsource.get("service") or "").strip().lower()

    paths = [m.path.lower() for m in matches]
    event_vals: list[str] = []
    ua_vals: list[str] = []
    resource_vals: list[str] = []
    for m in matches:
        p = m.path.lower()
        if p == "eventname":
            event_vals.extend(m.values)
        elif p == "useragent":
            ua_vals.extend(m.values)
        elif p.startswith("requestparameters."):
            resource_vals.extend(f"{m.path}={','.join(m.values)}" for _ in [0])

    weaknesses: list[dict[str, str]] = []

    if ua_vals and "not filter" not in body.lower():
        weaknesses.append(
            {
                "code": "TOOL_LOCKIN",
                "severity": "high",
                "detail": f"Keys positively on userAgent ({', '.join(ua_vals)}); switching tool evades detection.",
                "fix": "Remove userAgent requirement; match underlying API behavior instead.",
            }
        )

    expected_family = list((API_FAMILIES.get(str(tid or "")) or {}).get("eventName") or [])
    if catalogue and tid:
        try:
            tech = catalogue.technique(tid)
            for en in tech.event_names:
                if en not in expected_family:
                    expected_family.append(en)
        except KeyError:
            pass

    if expected_family and event_vals and len(set(event_vals)) < len(set(expected_family)):
        missing = [e for e in expected_family if e not in event_vals]
        if missing:
            weaknesses.append(
                {
                    "code": "SINGLE_API_LOCKIN",
                    "severity": "high",
                    "detail": f"Covers only {', '.join(event_vals)}; misses equivalent APIs: {', '.join(missing[:4])}.",
                    "fix": "Generalize eventName list across equivalent AWS API operations.",
                }
            )

    if resource_vals:
        weaknesses.append(
            {
                "code": "HARDCODED_RESOURCE",
                "severity": "medium",
                "detail": f"Hardcodes parameter constraint ({'; '.join(resource_vals)}); targets outside that literal are missed.",
                "fix": "Drop literal target name or generalize across account targets.",
            }
        )

    if "sourceipaddress" in paths or loader == "python" and str(row.get("native_id")) == "IS-COLL-001":
        weaknesses.append(
            {
                "code": "NETWORK_ASSUMPTION",
                "severity": "medium",
                "detail": "Relies on network/IP check which shifts across VPC NAT gateways or service mediation.",
                "fix": "Detect on API/identity behavior rather than IP assumption.",
            }
        )

    body_lower = body.lower()
    if product == "gcp":
        has_error_filter = (
            "protopayload.status.code" in paths
            or "status.code" in body_lower
            or "filter_errors" in body_lower
            or "filter_denied" in body_lower
        )
        error_fix = "Exclude protoPayload.status.code=7 (PERMISSION_DENIED) unless hunting failures."
    elif product == "azure":
        has_error_filter = (
            "resulttype" in paths
            or "status.errorcode" in paths
            or "result" in paths
            or "filter_errors" in body_lower
            or "filter_denied" in body_lower
        )
        error_fix = (
            "Check status.errorCode on Entra sign-in logs unless hunting failures."
            if ls_service == "signinlogs"
            else "Exclude failed operations (resultType=Failed or status.errorCode!=0) unless hunting failures."
        )
    else:
        has_error_filter = "errorcode" in paths or "filter_errors" in body_lower
        error_fix = "Exclude AccessDenied / UnauthorizedOperation unless hunting failures."

    if not has_error_filter:
        weaknesses.append(
            {
                "code": "NO_ERROR_FILTER",
                "severity": "low",
                "detail": "Does not exclude denied/unauthorized failed calls (risks noisy false positives).",
                "fix": error_fix,
            }
        )

    if product == "aws" and tid == "T1078.004" and any(m.path.lower() == "additionaleventdata.mfaused" and "No" in m.values for m in matches):
        weaknesses.append(
            {
                "code": "EXACT_MFA_VALUE",
                "severity": "medium",
                "detail": "Checks MFAUsed == 'No'; misses logins where MFAUsed is omitted.",
                "fix": "Invert to `not filter_mfa` (`MFAUsed == 'Yes'`).",
            }
        )

    missed_live = _missed_events_for_technique(conn, tid, ruleset)
    if missed_live:
        weaknesses.append(
            {
                "code": "OBSERVED_MISSES",
                "severity": "high",
                "detail": f"Missed variants emitted eventNames: {', '.join(missed_live)}.",
                "fix": "Include missed eventNames and pair with dynamic behavioral rules.",
            }
        )

    # Every static rule is stateless by nature
    weaknesses.append(
        {
            "code": "STATELESS_ONLY",
            "severity": "info",
            "detail": "Evaluates 1 event at a time; misses rapid bursts and multi-step chains.",
            "fix": "Pair with Dynamic Engine (`DYN-VEL-001` burst / `DYN-SEQ-001` sequence / `DYN-DRIFT-001` drift).",
        }
    )

    penalty = sum(
        25 if w["severity"] == "high" else (15 if w["severity"] == "medium" else (8 if w["severity"] == "low" else 0))
        for w in weaknesses
    )
    score = max(10, 100 - penalty)

    return {
        "rule_id": row["rule_id"],
        "native_id": row["native_id"],
        "ruleset_version": ruleset,
        "technique_id": tid,
        "title": row["title"],
        "level": row.get("level") or "medium",
        "loader": loader,
        "watched_fields": sorted(set(paths)),
        "health_score": score,
        "weaknesses": weaknesses,
        "proxy_context": dict(proxy_ctx or {}),
        "doc": doc,
    }


def audit_ruleset(conn, ruleset_version: str = "baseline-v1") -> dict[str, Any]:
    """Audit every rule in a ruleset and summarize structural weaknesses."""
    catalogue = load_catalogue(include_disabled=True)
    proxy_ctx = _learned_proxy_context(conn)
    rows = conn.execute(
        """
        SELECT rule_id, ruleset_version, native_id, title, level, technique_id, loader, path, body
        FROM rule
        WHERE ruleset_version = ?
        ORDER BY technique_id, native_id
        """,
        (ruleset_version,),
    ).fetchall()
    audited = [audit_rule(conn, dict(r), catalogue=catalogue, proxy_ctx=proxy_ctx) for r in rows]
    avg_score = round(sum(a["health_score"] for a in audited) / len(audited), 1) if audited else 0.0
    weak_count = sum(1 for a in audited if a["health_score"] < 75)
    return {
        "ruleset_version": ruleset_version,
        "total_rules": len(audited),
        "weak_rules": weak_count,
        "average_health_score": avg_score,
        "proxy_context": proxy_ctx,
        "rules": audited,
    }


def build_enhanced_rule(
    conn,
    rule_id: str,
) -> dict[str, Any]:
    """Generate a hardened Sigma YAML rule from an existing weak rule + misses + proxy context."""
    row = conn.execute(
        """
        SELECT rule_id, ruleset_version, native_id, title, level, technique_id, loader, path, body
        FROM rule
        WHERE rule_id = ?
        """,
        (rule_id,),
    ).fetchone()
    if not row:
        raise KeyError(f"Unknown rule_id {rule_id!r}")

    catalogue = load_catalogue(include_disabled=True)
    proxy_ctx = _learned_proxy_context(conn)
    audit = audit_rule(conn, dict(row), catalogue=catalogue, proxy_ctx=proxy_ctx)

    tid = str(row["technique_id"] or "")
    family = API_FAMILIES.get(tid, {})
    matches, orig_doc = _parse_rule_ast(dict(row))

    orig_logsource = orig_doc.get("logsource") if isinstance(orig_doc.get("logsource"), dict) else {}
    product = str(orig_logsource.get("product") or "aws").strip().lower() or "aws"
    default_ls_svc = "cloudtrail" if product == "aws" else ("gcp.audit" if product == "gcp" else "activitylogs")
    ls_service = str(orig_logsource.get("service") or default_ls_svc).strip() or default_ls_svc

    title_base = str(row["title"] or row["native_id"]).replace(" - Enhanced", "")
    new_title = f"{title_base} (Enhanced)"
    new_id = hashlib.sha256(f"enhanced:{product}:{tid}:{row['native_id']}".encode("utf-8")).hexdigest()[:32]
    tags = list(orig_doc.get("tags") or [])
    if tid and f"attack.{tid.lower()}" not in [t.lower() for t in tags]:
        tags.append(f"attack.{tid.lower()}")

    if product != "aws" and isinstance(orig_doc.get("detection"), dict):
        # Preserve native GCP / Azure detection semantics while stripping brittle userAgent locks & adding cloud-native error filters
        detection = {
            k: v
            for k, v in orig_doc["detection"].items()
            if str(k).lower() != "condition"
        }
        condition = str(orig_doc["detection"].get("condition") or "selection")
        if product == "gcp" and "filter_errors" not in detection and "status.code" not in str(detection).lower():
            detection["filter_errors"] = {"protoPayload.status.code": 7}
            condition = f"({condition}) and not filter_errors"
        elif product == "azure" and ls_service == "activitylogs" and "filter_errors" not in detection and "resulttype" not in str(detection).lower():
            detection["filter_errors"] = {"resultType": "Failed"}
            condition = f"({condition}) and not filter_errors"
        detection["condition"] = condition
    else:
        # Build generalized eventSource + eventName set for AWS CloudTrail rules
        sources: list[str] = []
        fam_src = family.get("eventSource")
        if isinstance(fam_src, list):
            sources.extend(fam_src)
        elif fam_src:
            sources.append(str(fam_src))
        for m in matches:
            if m.path.lower() == "eventsource":
                for v in m.values:
                    if v not in sources:
                        sources.append(v)

        events: list[str] = list(family.get("eventName") or [])
        if catalogue and tid:
            try:
                for en in catalogue.technique(tid).event_names:
                    if en not in events:
                        events.append(en)
            except KeyError:
                pass
        for en in _missed_events_for_technique(conn, tid, str(row["ruleset_version"])):
            if en not in events:
                events.append(en)
        for m in matches:
            if m.path.lower() == "eventname":
                for v in m.values:
                    if v not in events:
                        events.append(v)

        selection: dict[str, Any] = {}
        if sources:
            selection["eventSource"] = sources[0] if len(sources) == 1 else sources
        if events:
            selection["eventName"] = events[0] if len(events) == 1 else events

        detection = {"selection": selection}
        condition = "selection"

        if tid == "T1078.004":
            detection["selection"] = {
                "eventSource": "signin.amazonaws.com",
                "eventName": "ConsoleLogin",
                "responseElements.ConsoleLogin": "Success",
            }
            detection["filter_mfa"] = {"additionalEventData.MFAUsed": "Yes"}
            condition = "selection and not filter_mfa"
        elif tid == "T1552.005":
            detection = {
                "selection_role": {"userIdentity.arn|contains": ":assumed-role/is-ec2-role/"},
                "filter_instance_sdk": {"userAgent|contains": ["aws-internal", "aws-sdk-java"]},
            }
            condition = "selection_role and not filter_instance_sdk"
        else:
            detection["filter_errors"] = {
                "errorCode": ["AccessDenied", "UnauthorizedOperation", "Client.UnauthorizedOperation"]
            }
            condition = "selection and not filter_errors"

        detection["condition"] = condition

    fixes_applied = [w["fix"] for w in audit["weaknesses"] if w["severity"] != "info"]
    enhanced_doc = {
        "title": new_title,
        "id": new_id,
        "status": "test",
        "description": (
            "Auto-enhanced by Identity Shield Rule Enhancer. Fixes: "
            + ("; ".join(fixes_applied) if fixes_applied else "generalized field selection")
        ),
        "tags": tags or ["attack.discovery"],
        "logsource": {"product": product, "service": ls_service},
        "detection": detection,
        "falsepositives": [
            "Normal authorized admin activity (tune via Dynamic Baseline Drift / allow-list)"
        ],
        "level": str(row["level"] or "medium"),
    }
    enhanced_yaml = yaml.safe_dump(enhanced_doc, sort_keys=False)

    safe_slug = (tid or str(row["native_id"])).lower().replace(".", "-")
    prefix = "enhanced" if product == "aws" else f"enhanced-{product}"
    filename = f"{prefix}-{safe_slug}.yml"

    # Validate compilation before returning
    compiled = load_sigma_text(enhanced_yaml, path=filename)

    recommended_dynamic = {
        "kind": "sequence" if tid in {"T1098.001", "T1098.003", "T1530"} else "velocity",
        "suggestion": (
            f"Pair with Dynamic {'Sequence' if tid in {'T1098.001', 'T1098.003', 'T1530'} else 'Velocity'} "
            f"rule to catch repeated/chained {tid or 'API'} calls across all clients."
        ),
    }

    return {
        "source_rule_id": row["rule_id"],
        "source_title": row["title"],
        "technique_id": tid,
        "filename": filename,
        "original_yaml": str(row["body"] or ""),
        "enhanced_yaml": enhanced_yaml,
        "enhanced_title": compiled.title,
        "weaknesses": audit["weaknesses"],
        "fixes_applied": fixes_applied,
        "recommended_dynamic": recommended_dynamic,
    }


def apply_enhanced_rule(
    conn,
    *,
    filename: str,
    yaml_content: str,
    target_ruleset: str = "enhanced-v1",
    replay: bool = True,
) -> dict[str, Any]:
    """Save enhanced Sigma YAML to `data/rules/enhanced/` (or `custom`) and replay."""
    compiled = load_sigma_text(yaml_content, path=filename)
    subdir = "enhanced" if target_ruleset == "enhanced-v1" else "custom"
    rule_dir = config.DATA / "rules" / subdir
    rule_dir.mkdir(parents=True, exist_ok=True)

    safe_name = settings.validate_rule_stem(filename or f"enhanced-{compiled.native_id[:8]}")
    target = (rule_dir / f"{safe_name}.yml").resolve()
    if not target.is_relative_to(rule_dir.resolve()):
        raise ValueError(f"Unsafe enhanced rule target path {filename!r}")
    target.write_text(yaml_content, encoding="utf-8")

    replay_stats = None
    if replay:
        loaded = detect_replay.load_ruleset(conn, target_ruleset)
        replay_stats = detect_replay.run_replay(conn, loaded)

    return {
        "saved_path": str(target),
        "ruleset": target_ruleset,
        "rule_title": compiled.title,
        "technique_id": compiled.technique_id,
        "replay_stats": replay_stats,
    }


def enhance_entire_ruleset(
    conn,
    *,
    source_ruleset: str = "baseline-v1",
    target_ruleset: str = "enhanced-v1",
) -> dict[str, Any]:
    """Automatically enhance all Sigma/Python rules in a ruleset into `enhanced-v1` and replay."""
    audit = audit_ruleset(conn, source_ruleset)
    saved: list[dict[str, Any]] = []
    seen_filenames: set[str] = set()

    for rule_info in audit["rules"]:
        # Prefer Sigma rules first if both Sigma and Python cover same technique
        tid = rule_info.get("technique_id") or ""
        preview = build_enhanced_rule(conn, rule_info["rule_id"])
        fname = preview["filename"]
        if fname in seen_filenames:
            continue
        seen_filenames.add(fname)
        res = apply_enhanced_rule(
            conn,
            filename=fname,
            yaml_content=preview["enhanced_yaml"],
            target_ruleset=target_ruleset,
            replay=False,
        )
        saved.append(res)

    loaded = detect_replay.load_ruleset(conn, target_ruleset)
    replay_stats = detect_replay.run_replay(conn, loaded)
    return {
        "source_ruleset": source_ruleset,
        "target_ruleset": target_ruleset,
        "rules_generated": len(saved),
        "saved": saved,
        "replay_stats": replay_stats,
    }
