"""Replay a rule set against stored events (Module 7 protocol).

    python -m identity_shield.detect.replay --ruleset baseline-v1

This is the whole point of the replay architecture: rule iteration never needs a
new AWS run. The events are fixed; only the rules move.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping

import yaml

from identity_shield import config
from identity_shield.detect import python_rules
from identity_shield.detect.rules import Rule, RuleError, load_sigma_text

SIGMA_SUFFIXES = (".yml", ".yaml")


@dataclass
class RulesetLoad:
    version: str
    rules: list[Rule] = field(default_factory=list)
    statuses: dict[str, int] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)

    @property
    def attempted(self) -> int:
        return sum(self.statuses.values())

    @property
    def compile_rate(self) -> float:
        attempted = self.attempted
        if not attempted:
            return 0.0
        return self.statuses.get("pysigma", 0) / attempted


def load_ruleset_config(path: Path | None = None) -> dict[str, Any]:
    path = path or config.RULESETS_YAML
    document = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return document.get("rulesets") or {}


def _bump(statuses: dict[str, int], status: str) -> None:
    statuses[status] = statuses.get(status, 0) + 1


def _persist_rule(conn, version: str, rule: Rule, seen: set[str]) -> str:
    base = rule.native_id or "unnamed"
    rule_id = f"{version}:{base}"
    suffix = 2
    while rule_id in seen:
        rule_id = f"{version}:{base}#{suffix}"
        suffix += 1
    seen.add(rule_id)

    conn.execute(
        """
        INSERT INTO rule (rule_id, ruleset_version, native_id, title, level,
                          technique_id, loader, path, body, authored_by)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(rule_id) DO UPDATE SET
            title=excluded.title, level=excluded.level,
            technique_id=excluded.technique_id, loader=excluded.loader,
            path=excluded.path, body=excluded.body
        """,
        (
            rule_id,
            version,
            base,
            rule.title,
            rule.level,
            rule.technique_id,
            rule.loader,
            rule.path,
            rule.body,
            "identity-shield" if rule.loader == "python" else None,
        ),
    )
    return rule_id


def load_ruleset(
    conn,
    version: str,
    *,
    use_pysigma: bool = True,
    rulesets_path: Path | None = None,
) -> RulesetLoad:
    configs = load_ruleset_config(rulesets_path)
    if version not in configs:
        raise KeyError(f"unknown ruleset {version!r}; known: {sorted(configs)}")
    entry = configs[version]

    conn.execute(
        """
        INSERT INTO ruleset (ruleset_version, created_at, frozen_at, description, source)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(ruleset_version) DO UPDATE SET description=excluded.description
        """,
        (
            version,
            datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            entry.get("frozen_at"),
            (entry.get("description") or "").strip(),
            entry.get("source"),
        ),
    )

    result = RulesetLoad(version=version)
    seen: set[str] = set()
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    backend = None
    if use_pysigma:
        try:
            from identity_shield.detect import pysigma_backend

            backend = pysigma_backend
        except Exception as exc:  # pragma: no cover - environment dependent
            result.warnings.append(f"pySigma backend unavailable: {exc}")

    for relative in entry.get("sigma_dirs") or []:
        directory = config.ROOT / relative
        if not directory.exists():
            result.warnings.append(f"sigma dir missing: {relative}")
            continue

        for path in sorted(directory.iterdir()):
            if path.suffix.lower() not in SIGMA_SUFFIXES or not path.is_file():
                continue
            text = path.read_text(encoding="utf-8")
            rule: Rule | None = None
            reason: str | None = None

            if backend is not None:
                try:
                    rule = backend.convert_text(text, path=str(path))
                    rule.loader = "pysigma"
                except Exception as exc:
                    reason = f"pysigma: {exc}"

            if rule is None:
                try:
                    rule = load_sigma_text(text, path=str(path))
                    rule.loader = "fallback"
                except RuleError as exc:
                    status = "parse_error" if "yaml" in str(exc).lower() else "unsupported"
                    if reason is None:
                        reason = f"reference parser: {exc}"
                    _bump(result.statuses, status)
                    conn.execute(
                        """
                        INSERT INTO rule_compile (rule_id, ruleset_version, path, title,
                                                  status, reason, checked_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                        ON CONFLICT(rule_id) DO UPDATE SET
                            status=excluded.status, reason=excluded.reason,
                            checked_at=excluded.checked_at
                        """,
                        (
                            f"{version}:{path.stem}",
                            version,
                            str(path.relative_to(config.ROOT)),
                            path.stem,
                            status,
                            reason,
                            now,
                        ),
                    )
                    result.warnings.append(f"{path.name}: {reason}")
                    continue

            _bump(result.statuses, "pysigma" if rule.loader == "pysigma" else "fallback")
            _persist_rule(conn, version, rule, seen)
            result.rules.append(rule)

    if entry.get("include_python_rules"):
        for rule in python_rules.rules():
            _persist_rule(conn, version, rule, seen)
            result.rules.append(rule)

    conn.commit()
    return result


def _alert_id(rule_id: str, event_id: str) -> str:
    return hashlib.sha256(f"{rule_id}|{event_id}".encode("utf-8")).hexdigest()[:32]


def _event_names(node) -> set[str] | None:
    """Literal eventName values a rule requires, or None if it cannot be indexed.

    This is an evaluation optimisation only. A wrong answer here could suppress
    an alert, so anything uncertain (OR with an unrelated branch, ``not``,
    regex/contains/modifiers, wildcards) returns None and the rule is evaluated
    for every event.
    """
    from identity_shield.detect.rules import BoolNode, FieldMatch

    if isinstance(node, FieldMatch):
        if node.path.casefold() != "eventname" or node.op != "eq":
            return None
        values = {value.casefold() for value in node.values}
        if any("*" in value or "?" in value for value in values):
            return None
        return values
    if isinstance(node, BoolNode):
        if node.op not in {"and", "or"}:
            return None
        collected: set[str] = set()
        for child in node.children:
            names = _event_names(child)
            if names is None:
                if node.op == "or":
                    # Another branch can fire on a different event name, so
                    # indexing on this branch alone would suppress alerts.
                    return None
                continue
            collected |= names
        return collected or None
    return None


def run_replay(conn, loaded: RulesetLoad, *, clear: bool = True) -> dict[str, int]:
    prefix = f"{loaded.version}:"
    if clear:
        conn.execute(
            "DELETE FROM alert WHERE rule_id IN (SELECT rule_id FROM rule WHERE ruleset_version = ?)",
            (loaded.version,),
        )
        conn.commit()

    rule_ids = {
        row["native_id"]: row["rule_id"]
        for row in conn.execute(
            "SELECT rule_id, native_id FROM rule WHERE ruleset_version = ?", (loaded.version,)
        )
    }

    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    alerts = 0
    events = 0

    # Index rules that constrain eventName. A rule that can only fire on
    # ListUsers does not need to be evaluated for a GetObject event. At 50k
    # events this is the difference between a scan and a coffee break.
    indexed: dict[str, list[Rule]] = {}
    generic: list[Rule] = []
    for rule in loaded.rules:
        names = _event_names(rule.node) if rule.node is not None else None
        if names:
            for name in names:
                indexed.setdefault(name, []).append(rule)
        else:
            generic.append(rule)

    pending: list[tuple[Any, ...]] = []
    cursor = conn.execute("SELECT event_id, fixture_key, trial_id, raw FROM event")
    for row in cursor:
        events += 1
        try:
            event = json.loads(row["raw"])
        except json.JSONDecodeError:
            continue
        name = str(event.get("eventName") or "").casefold()
        candidates = generic + indexed.get(name, [])
        for rule in candidates:
            rule_id = rule_ids.get(rule.native_id) or f"{prefix}{rule.native_id}"
            try:
                fired = rule.matches(event)
            except RuleError:
                continue
            if not fired:
                continue
            pending.append(
                (
                    _alert_id(rule_id, row["event_id"]),
                    rule_id,
                    row["event_id"],
                    row["trial_id"],
                    row["fixture_key"],
                    now,
                    None,
                    json.dumps(list(rule.fields)) if rule.fields else None,
                )
            )
            alerts += 1
        if len(pending) >= 5000:
            conn.executemany(
                """
                INSERT OR IGNORE INTO alert (alert_id, rule_id, event_id, trial_id,
                                             fixture_key, evaluated_at, latency_ms,
                                             matched_fields)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                pending,
            )
            pending.clear()

    if pending:
        conn.executemany(
            """
            INSERT OR IGNORE INTO alert (alert_id, rule_id, event_id, trial_id,
                                         fixture_key, evaluated_at, latency_ms,
                                         matched_fields)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            pending,
        )

    conn.commit()
    return {"events": events, "alerts": alerts, "rules": len(loaded.rules)}


def fixture_summary(conn, version: str) -> list[dict[str, Any]]:
    rows = conn.execute(
        """
        SELECT f.fixture_key, f.technique_id, f.flavour, f.expected_detected,
               COUNT(DISTINCT e.event_id) AS events,
               CASE WHEN EXISTS (
                   SELECT 1 FROM alert a JOIN event e2 ON e2.event_id = a.event_id
                   WHERE e2.fixture_key = f.fixture_key
                     AND a.rule_id IN (SELECT rule_id FROM rule WHERE ruleset_version = ?)
               ) THEN 1 ELSE 0 END AS detected,
               (SELECT GROUP_CONCAT(DISTINCT r.native_id) FROM alert a
                  JOIN event e3 ON e3.event_id = a.event_id
                  JOIN rule  r  ON r.rule_id  = a.rule_id
                 WHERE e3.fixture_key = f.fixture_key
                   AND r.ruleset_version = ?) AS fired
        FROM fixture f
        LEFT JOIN event e ON e.fixture_key = f.fixture_key
        GROUP BY f.fixture_key
        ORDER BY f.technique_id, f.fixture_key
        """,
        (version, version),
    )
    return [dict(row) for row in rows]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Replay a rule set against stored events.")
    parser.add_argument("--ruleset", default="baseline-v1")
    parser.add_argument("--db", default=None)
    parser.add_argument("--no-pysigma", action="store_true", help="use the reference parser only")
    parser.add_argument("--json", action="store_true", help="emit machine-readable output")
    args = parser.parse_args(argv)

    from identity_shield.db.connection import connect

    conn = connect(args.db)
    try:
        loaded = load_ruleset(conn, args.ruleset, use_pysigma=not args.no_pysigma)
        stats = run_replay(conn, loaded)
        summary = fixture_summary(conn, args.ruleset)
    finally:
        conn.close()

    if args.json:
        print(
            json.dumps(
                {
                    "ruleset": args.ruleset,
                    "statuses": loaded.statuses,
                    "compile_rate": round(loaded.compile_rate, 3),
                    "warnings": loaded.warnings,
                    **stats,
                    "fixtures": summary,
                },
                indent=2,
            )
        )
        return 0

    print(f"ruleset:       {args.ruleset}")
    print(f"rules loaded:  {stats['rules']}  ({_format_statuses(loaded.statuses)})")
    print(f"compile rate:  {loaded.compile_rate:.0%}  (pysigma conversions / sigma files attempted)")
    print(f"events:        {stats['events']}")
    print(f"alerts:        {stats['alerts']}")
    for warning in loaded.warnings:
        print(f"warning: {warning}", file=sys.stderr)

    print()
    print(f"{'fixture':<26} {'events':>6} {'exp':>4} {'got':>4}  fired")
    print("-" * 78)
    for row in summary:
        expected = "-" if row["expected_detected"] is None else str(row["expected_detected"])
        print(
            f"{row['fixture_key']:<26} {row['events']:>6} {expected:>4} "
            f"{row['detected']:>4}  {row['fired'] or ''}"
        )

    mismatches = [
        row for row in summary
        if row["expected_detected"] is not None and row["detected"] != row["expected_detected"]
    ]
    print()
    if mismatches:
        print(f"{len(mismatches)} fixture expectation(s) not met", file=sys.stderr)
        return 1
    print("all fixture expectations met")
    return 0


def _format_statuses(statuses: Mapping[str, int]) -> str:
    if not statuses:
        return "no sigma rules"
    return ", ".join(f"{key}={value}" for key, value in sorted(statuses.items()))


if __name__ == "__main__":
    sys.exit(main())
