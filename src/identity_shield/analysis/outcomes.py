"""Outcome aggregation for the dashboard and report.

The unit of analysis is a trial, not an event. A trial is detected when at
least one alert from the selected rule set points at one of its events. Validity
is a separate axis: a trial whose evidence did not change is excluded from the
detection denominator rather than counted as an evasion.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping

from identity_shield.analysis import stats

ISO = "%Y-%m-%dT%H:%M:%SZ"


def _parse(value: str | None) -> datetime | None:
    if not value:
        return None
    text = str(value)
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        moment = datetime.fromisoformat(text)
    except ValueError:
        return None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc)


def trial_rows(
    conn,
    ruleset: str,
    *,
    run_id: str | None = None,
    include_holdout: bool = False,
    include_benign: bool = False,
) -> list[dict[str, Any]]:
    clauses = ["1 = 1"]
    where: list[Any] = []
    if run_id:
        clauses.append("t.run_id = ?")
        where.append(run_id)
    if not include_holdout:
        clauses.append("v.variant_set <> 'holdout'")
    if not include_benign:
        # Benign activity is measured as false alarms, never counted in the
        # attack detection denominator.
        clauses.append("v.variant_set <> 'benign'")
    sql = f"""
        SELECT t.trial_id, t.run_id, t.variant_id, t.repetition,
               t.window_start, t.window_end, t.attack_succeeded,
               t.variant_changed, t.error,
               v.technique_id, v.variant_set, v.factor_levels,
               lr.synthetic,
               COALESCE(te.tactic, '') AS tactic,
               CASE WHEN EXISTS (
                   SELECT 1 FROM alert a JOIN rule r ON r.rule_id = a.rule_id
                   WHERE a.trial_id = t.trial_id AND r.ruleset_version = ?
               ) THEN 1 ELSE 0 END AS detected,
               (SELECT COUNT(*) FROM alert a JOIN rule r ON r.rule_id = a.rule_id
                 WHERE a.trial_id = t.trial_id AND r.ruleset_version = ?) AS alerts
        FROM trial t
        JOIN variant v ON v.variant_id = t.variant_id
        JOIN lab_run lr ON lr.run_id = t.run_id
        LEFT JOIN technique te ON te.technique_id = v.technique_id
        WHERE {' AND '.join(clauses)}
        ORDER BY t.variant_id, t.repetition
    """
    # The two detection placeholders come before the WHERE placeholders.
    ordered = [ruleset, ruleset] + where
    rows = []
    for row in conn.execute(sql, ordered):
        record = dict(row)
        try:
            record["factor_levels"] = json.loads(record.get("factor_levels") or "{}")
        except json.JSONDecodeError:
            record["factor_levels"] = {}
        record["valid"] = bool(
            record["attack_succeeded"] == 1
            and (record["variant_set"] == "baseline" or record["variant_changed"] == 1)
        )
        rows.append(record)
    return rows


def _aggregate(rows: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    rows = list(rows)
    attempted = len(rows)
    verified = sum(1 for row in rows if row["attack_succeeded"] == 1)
    valid = [row for row in rows if row["valid"]]
    detected = sum(1 for row in valid if row["detected"])
    alerts = sum(int(row["alerts"] or 0) for row in rows)
    low, high = stats.wilson_interval(detected, len(valid))
    return {
        "attempted": attempted,
        "verified": verified,
        "valid": len(valid),
        "invalid_or_unverified": attempted - len(valid),
        "detected": detected,
        "evaded": len(valid) - detected,
        "detection_rate": stats.percentage(detected, len(valid)),
        "evasion_rate": stats.percentage(len(valid) - detected, len(valid)),
        "wilson_low": round(low, 4),
        "wilson_high": round(high, 4),
        "alerts": alerts,
        "errors": sum(1 for row in rows if row["error"]),
    }


def summarise(
    conn,
    ruleset: str,
    *,
    run_id: str | None = None,
    include_holdout: bool = False,
) -> dict[str, Any]:
    rows = trial_rows(conn, ruleset, run_id=run_id, include_holdout=include_holdout)
    overall = _aggregate(rows)

    by_technique: dict[str, Any] = {}
    for row in rows:
        by_technique.setdefault(row["technique_id"], []).append(row)
    techniques = {
        technique: _aggregate(group)
        for technique, group in sorted(by_technique.items())
    }

    by_set: dict[str, Any] = {}
    for row in rows:
        by_set.setdefault(row["variant_set"], []).append(row)
    sets = {name: _aggregate(group) for name, group in sorted(by_set.items())}

    levels: dict[str, dict[str, Any]] = {}
    for row in rows:
        if not row["valid"]:
            continue
        for factor, level in row["factor_levels"].items():
            entry = levels.setdefault(factor, {}).setdefault(
                level, {"n": 0, "detected": 0}
            )
            entry["n"] += 1
            entry["detected"] += int(row["detected"])
    for factor, entries in levels.items():
        for level, entry in entries.items():
            entry["detection_rate"] = stats.percentage(entry["detected"], entry["n"])
            entry["evasion_rate"] = round(1 - entry["detection_rate"], 4) if entry["n"] else 0.0

    alert_rules = [
        dict(row)
        for row in conn.execute(
            """
            SELECT r.native_id, r.title, r.loader, COUNT(*) AS alerts
            FROM alert a JOIN rule r ON r.rule_id = a.rule_id
            WHERE r.ruleset_version = ?
            GROUP BY r.rule_id ORDER BY alerts DESC, r.native_id
            """,
            (ruleset,),
        )
    ]

    return {
        "ruleset": ruleset,
        "run_id": run_id,
        "overall": overall,
        "techniques": techniques,
        "sets": sets,
        "factor_levels": levels,
        "alert_rules": alert_rules,
        "provenance": {
            "synthetic_trials": sum(1 for row in rows if row["synthetic"]),
            "live_trials": sum(1 for row in rows if not row["synthetic"]),
            "holdout_included": include_holdout,
        },
    }


def paired(
    conn,
    baseline_ruleset: str,
    improved_ruleset: str,
    *,
    run_id: str | None = None,
) -> dict[str, Any]:
    baseline = {
        row["trial_id"]: row
        for row in trial_rows(conn, baseline_ruleset, run_id=run_id)
    }
    improved = {
        row["trial_id"]: row
        for row in trial_rows(conn, improved_ruleset, run_id=run_id)
    }
    shared = sorted(set(baseline) & set(improved))
    usable = [
        trial
        for trial in shared
        if baseline[trial]["valid"] and improved[trial]["valid"]
    ]
    both = sum(
        1 for trial in usable if baseline[trial]["detected"] and improved[trial]["detected"]
    )
    baseline_only = sum(
        1 for trial in usable if baseline[trial]["detected"] and not improved[trial]["detected"]
    )
    improved_only = sum(
        1 for trial in usable if not baseline[trial]["detected"] and improved[trial]["detected"]
    )
    neither = sum(
        1 for trial in usable if not baseline[trial]["detected"] and not improved[trial]["detected"]
    )
    test = stats.mcnemar_exact(baseline_only, improved_only)
    baseline_detected = both + baseline_only
    improved_detected = both + improved_only
    return {
        "baseline_ruleset": baseline_ruleset,
        "improved_ruleset": improved_ruleset,
        "pairs": len(usable),
        "both_detected": both,
        "baseline_only": baseline_only,
        "improved_only": improved_only,
        "neither": neither,
        "baseline_detection_rate": stats.percentage(baseline_detected, len(usable)),
        "improved_detection_rate": stats.percentage(improved_detected, len(usable)),
        "delta": round(
            stats.percentage(improved_detected, len(usable))
            - stats.percentage(baseline_detected, len(usable)),
            4,
        ),
        "mcnemar": test,
    }


def latency(conn, ruleset: str, *, run_id: str | None = None) -> dict[str, Any]:
    """Live ingest and replay timings.

    Synthetic trials are excluded. Their event times come from a rehearsal
    clock and their replay timestamps are "now", so any interval computed from
    them is an artefact, not a measurement.
    """
    clause = "AND t.run_id = ?" if run_id else ""
    params: tuple[Any, ...] = (run_id,) if run_id else ()
    ingest: list[float] = []
    for row in conn.execute(
        f"""
        SELECT e.event_time, e.received_at FROM event e
        JOIN trial t ON t.trial_id = e.trial_id
        JOIN lab_run lr ON lr.run_id = t.run_id
        WHERE e.trial_id IS NOT NULL AND lr.synthetic = 0 {clause}
        """,
        params,
    ):
        start = _parse(row["event_time"])
        end = _parse(row["received_at"])
        if start and end:
            ingest.append((end - start).total_seconds() * 1000)

    rule_latency: list[float] = []
    for row in conn.execute(
        f"""
        SELECT e.event_time, a.evaluated_at FROM alert a
        JOIN rule r ON r.rule_id = a.rule_id
        JOIN event e ON e.event_id = a.event_id
        JOIN trial t ON t.trial_id = a.trial_id
        JOIN lab_run lr ON lr.run_id = t.run_id
        WHERE r.ruleset_version = ? AND lr.synthetic = 0 {clause}
        """,
        (ruleset,) + params,
    ):
        start = _parse(row["event_time"])
        end = _parse(row["evaluated_at"])
        if start and end:
            rule_latency.append((end - start).total_seconds() * 1000)

    km = stats.kaplan_meier(rule_latency, [True] * len(rule_latency))
    return {
        "live": bool(ingest or rule_latency),
        "note": (
            "no live trials in scope; synthetic rehearsal timings are not "
            "measurements"
            if not ingest and not rule_latency
            else "replay timestamps measure evaluation time, not live alert delivery"
        ),
        "ingest_lag_ms": {
            "n": len(ingest),
            "median": stats.quantile(ingest, 0.5),
            "p95": stats.quantile(ingest, 0.95),
            "max": max(ingest) if ingest else None,
        },
        "rule_latency_ms": {
            "n": len(rule_latency),
            "median": stats.quantile(rule_latency, 0.5),
            "p95": stats.quantile(rule_latency, 0.95),
            "km_median": km["median"],
            "km_curve": km["curve"],
        },
    }


def false_alarms(conn, ruleset: str, *, run_id: str | None = None) -> dict[str, Any]:
    clause = "AND t.run_id = ?" if run_id else ""
    params: tuple[Any, ...] = (ruleset,) + ((run_id,) if run_id else ())
    rows = list(
        conn.execute(
            f"""
            SELECT v.technique_id, v.variant_id, t.trial_id,
                   CASE WHEN EXISTS (
                       SELECT 1 FROM alert a JOIN rule r ON r.rule_id = a.rule_id
                       WHERE a.trial_id = t.trial_id AND r.ruleset_version = ?
                   ) THEN 1 ELSE 0 END AS detected
            FROM trial t JOIN variant v ON v.variant_id = t.variant_id
            WHERE v.variant_set = 'benign' {clause}
            """,
            params,
        )
    )
    total = len(rows)
    detected = sum(1 for row in rows if row["detected"])
    low, high = stats.wilson_interval(detected, total)
    by_technique: dict[str, dict[str, int]] = {}
    for row in rows:
        entry = by_technique.setdefault(row["technique_id"], {"trials": 0, "alerted": 0})
        entry["trials"] += 1
        entry["alerted"] += int(row["detected"])
    return {
        "trials": total,
        "alerted": detected,
        "rate": stats.percentage(detected, total),
        "wilson_low": round(low, 4),
        "wilson_high": round(high, 4),
        "by_technique": by_technique,
    }


def rule_diff(conn, baseline_ruleset: str, improved_ruleset: str) -> dict[str, Any]:
    def load(version: str) -> dict[str, dict[str, Any]]:
        return {
            row["native_id"]: dict(row)
            for row in conn.execute(
                "SELECT native_id, title, loader, body FROM rule WHERE ruleset_version = ?",
                (version,),
            )
        }

    baseline = load(baseline_ruleset)
    improved = load(improved_ruleset)
    added = sorted(set(improved) - set(baseline))
    removed = sorted(set(baseline) - set(improved))
    changed = sorted(
        native_id
        for native_id in set(baseline) & set(improved)
        if baseline[native_id]["body"] != improved[native_id]["body"]
    )
    return {
        "baseline": baseline_ruleset,
        "improved": improved_ruleset,
        "added": [{"native_id": key, "title": improved[key]["title"]} for key in added],
        "removed": [{"native_id": key, "title": baseline[key]["title"]} for key in removed],
        "changed": [
            {
                "native_id": key,
                "title": improved[key]["title"],
                "baseline_loader": baseline[key]["loader"],
                "improved_loader": improved[key]["loader"],
            }
            for key in changed
        ],
        "counts": {
            "baseline": len(baseline),
            "improved": len(improved),
            "added": len(added),
            "removed": len(removed),
        },
    }
