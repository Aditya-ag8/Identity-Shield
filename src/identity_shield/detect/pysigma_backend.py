"""pySigma backend: compile Sigma rules into Identity Shield predicates.

This is the piece with no off-the-shelf equivalent. pySigma ships backends for
Splunk, Elastic, Sentinel and friends, but nothing that emits a Python predicate
over CloudTrail JSON. The backend is therefore split in two halves:

* **pySigma does the semantics.** ``SigmaRule.from_yaml`` resolves field names,
  modifiers and ``SigmaString`` wildcard handling, including the implicit
  ``.*x.*`` wrapping that ``contains`` produces.
* **this module does the structure.** Selection trees become ``FieldMatch`` /
  ``BoolNode`` nodes and the condition string is parsed by the shared reference
  parser in :mod:`identity_shield.detect.rules`.

Anything outside the supported subset raises :class:`UnsupportedRule` with a
reason, and the reason is recorded. The share of rules that compile is the
M0 go/no-go number; uncompileable rules are a reported finding, not a bug to
chase.

Supported modifiers
-------------------
``contains``, ``startswith``, ``endswith``, ``all``, ``re``.

Everything else (``base64``, ``base64offset``, ``windash``, ``cidr``, ``lt``,
``gt``, ``fieldref``, ``exists``, ``expand``) raises ``UnsupportedRule``.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

import yaml

from identity_shield.detect.rules import (
    BoolNode,
    FieldMatch,
    Node,
    Rule,
    RuleError,
    UnsupportedRule,
    collect_fields,
    load_sigma_text,
    parse_condition,
    technique_from_tags,
)

try:  # pragma: no cover - trivial import guard
    from sigma.rule import SigmaDetection, SigmaDetectionItem, SigmaRule

    PYSIGMA_AVAILABLE = True
    PYSIGMA_ERROR: str | None = None
except Exception as exc:  # pragma: no cover
    SigmaDetection = SigmaDetectionItem = SigmaRule = None  # type: ignore[assignment]
    PYSIGMA_AVAILABLE = False
    PYSIGMA_ERROR = str(exc)

SUPPORTED_MODIFIERS = {
    "SigmaContainsModifier",
    "SigmaStartswithModifier",
    "SigmaEndswithModifier",
    "SigmaAllModifier",
    "SigmaRegularExpressionModifier",
}

SIGMA_SUFFIXES = (".yml", ".yaml")


def require_pysigma() -> None:
    if not PYSIGMA_AVAILABLE:
        raise UnsupportedRule(f"pySigma is not importable: {PYSIGMA_ERROR}")


def _linking(node: Any) -> str:
    """pySigma exposes linking as either a class or an instance; handle both."""
    name = getattr(node, "__name__", None) or type(node).__name__
    return "and" if str(name).endswith("AND") else "or"


def _combine(op: str, nodes: list[Node]) -> Node:
    if not nodes:
        raise UnsupportedRule("empty selection")
    if len(nodes) == 1:
        return nodes[0]
    return BoolNode(op=op, children=tuple(nodes))


def _value_pattern(value: Any, *, regex_mode: bool) -> str:
    """Turn one pySigma value into a regex pattern for ``op='regex'``."""
    kind = type(value).__name__

    if regex_mode:
        inner = getattr(value, "regexp", value)
        return str(inner)

    if kind == "SigmaString":
        return str(value.to_regex().regexp)
    if kind == "SigmaBool":
        return "true" if str(value).lower() == "true" else "false"
    if kind == "SigmaNull":
        return "null"
    if kind == "SigmaNumber":
        return re.escape(str(value))
    raise UnsupportedRule(f"unsupported value type {kind}")


def _convert_item(item: Any) -> Node:
    if isinstance(item, SigmaDetection):
        return _convert_detection(item)

    field_name = getattr(item, "field", None)
    if not field_name:
        raise UnsupportedRule("keyword search (null field) is not supported")

    modifier_names = {
        getattr(modifier, "__name__", None) or type(modifier).__name__
        for modifier in getattr(item, "modifiers", [])
    }
    unknown = modifier_names - SUPPORTED_MODIFIERS
    if unknown:
        raise UnsupportedRule(f"unsupported modifier(s): {', '.join(sorted(unknown))}")

    regex_mode = "SigmaRegularExpressionModifier" in modifier_names
    values = tuple(_value_pattern(value, regex_mode=regex_mode) for value in item.value)
    if not values:
        raise UnsupportedRule(f"empty value list for {field_name!r}")

    match_all = _linking(getattr(item, "value_linking", None)) == "and"
    return FieldMatch(
        path=str(field_name),
        op="re" if regex_mode else "regex",
        values=values,
        match_all=match_all,
    )


def _convert_detection(detection: Any) -> Node:
    items = [_convert_item(item) for item in detection.detection_items]
    return _combine(_linking(getattr(detection, "item_linking", None)), items)


def convert_text(text: str, *, path: str | None = None) -> Rule:
    """Compile one Sigma rule document. Raises UnsupportedRule with a reason."""
    require_pysigma()

    try:
        parsed = SigmaRule.from_yaml(text)
    except Exception as exc:
        raise UnsupportedRule(f"pySigma could not parse the rule: {exc}") from exc

    document = yaml.safe_load(text)
    if not isinstance(document, Mapping):
        raise UnsupportedRule("rule document is not a mapping")

    detection = document.get("detection")
    if not isinstance(detection, Mapping):
        raise UnsupportedRule("missing detection block")
    condition = detection.get("condition")
    if condition is None:
        raise UnsupportedRule("detection has no condition")

    detections = getattr(parsed.detection, "detections", None)
    if not detections:
        raise UnsupportedRule("pySigma produced no detections")

    selections = {str(name): _convert_detection(det) for name, det in detections.items()}
    node = parse_condition(condition, selections)

    native_id = str(document.get("id") or (path or "unnamed"))
    return Rule(
        native_id=native_id,
        title=str(document.get("title") or native_id),
        level=str(document.get("level") or "medium"),
        technique_id=technique_from_tags(document.get("tags")),
        loader="pysigma",
        body=text,
        path=path,
        node=node,
        description=str(document.get("description") or ""),
        fields=collect_fields(node),
    )


def convert_file(path: str | Path) -> Rule:
    path = Path(path)
    return convert_text(path.read_text(encoding="utf-8"), path=str(path))


# ---------------------------------------------------------------------------
# Corpus compile-rate report
# ---------------------------------------------------------------------------


@dataclass
class CompileResult:
    path: str
    title: str
    status: str
    reason: str | None = None


@dataclass
class CompileReport:
    total: int = 0
    statuses: dict[str, int] = field(default_factory=dict)
    results: list[CompileResult] = field(default_factory=list)

    @property
    def compile_rate(self) -> float:
        return self.statuses.get("pysigma", 0) / self.total if self.total else 0.0

    @property
    def usable_rate(self) -> float:
        usable = self.statuses.get("pysigma", 0) + self.statuses.get("fallback", 0)
        return usable / self.total if self.total else 0.0

    def by_reason(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for result in self.results:
            if result.status in ("unsupported", "parse_error") and result.reason:
                key = _reason_key(result.reason)
                counts[key] = counts.get(key, 0) + 1
        return dict(sorted(counts.items(), key=lambda item: -item[1]))


def _reason_key(reason: str) -> str:
    if "unsupported modifier" in reason:
        return reason.split("unsupported modifier(s):", 1)[-1].strip()
    if "keyword search" in reason:
        return "keyword search (null field)"
    if "condition" in reason:
        return "condition expression"
    if "parse" in reason or "yaml" in reason.lower():
        return "parse error"
    return reason[:60]


def compile_corpus(root: str | Path) -> CompileReport:
    root = Path(root)
    report = CompileReport()
    if not root.exists():
        raise FileNotFoundError(f"corpus not found: {root}")

    for path in sorted(root.rglob("*")):
        if path.suffix.lower() not in SIGMA_SUFFIXES or not path.is_file():
            continue
        report.total += 1
        text = path.read_text(encoding="utf-8", errors="replace")
        try:
            rule = convert_text(text, path=str(path))
            report.statuses["pysigma"] = report.statuses.get("pysigma", 0) + 1
            report.results.append(CompileResult(str(path), rule.title, "pysigma"))
            continue
        except RuleError as exc:
            reason = str(exc)

        try:
            fallback = load_sigma_text(text, path=str(path))
            report.statuses["fallback"] = report.statuses.get("fallback", 0) + 1
            report.results.append(
                CompileResult(str(path), fallback.title, "fallback", f"pysigma: {reason}")
            )
            continue
        except RuleError as exc:
            fallback_reason = str(exc)

        status = "parse_error" if "yaml" in fallback_reason.lower() else "unsupported"
        report.statuses[status] = report.statuses.get(status, 0) + 1
        report.results.append(
            CompileResult(
                str(path),
                path.stem,
                status,
                f"{reason}; reference parser: {fallback_reason}",
            )
        )

    return report


def persist_report(conn, report: CompileReport, *, ruleset_version: str = "community") -> None:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    for result in report.results:
        conn.execute(
            """
            INSERT INTO rule_compile (rule_id, ruleset_version, path, title, status, reason, checked_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(rule_id) DO UPDATE SET
                path=excluded.path, title=excluded.title, status=excluded.status,
                reason=excluded.reason, checked_at=excluded.checked_at
            """,
            (
                f"{ruleset_version}:{result.path}",
                ruleset_version,
                result.path,
                result.title,
                result.status,
                result.reason,
                now,
            ),
        )
    conn.commit()


def main(argv: list[str] | None = None) -> int:
    from identity_shield import config

    parser = argparse.ArgumentParser(description="Sigma compile-rate report.")
    parser.add_argument(
        "--corpus",
        default=str(config.VENDOR / "sigma" / "rules" / "cloud" / "aws"),
        help="directory of Sigma rules to compile",
    )
    parser.add_argument("--db", default=None, help="persist results into rule_compile")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--reasons", type=int, default=8, help="show the N most common failure reasons")
    args = parser.parse_args(argv)

    if not PYSIGMA_AVAILABLE:
        print(f"pySigma unavailable: {PYSIGMA_ERROR}", file=sys.stderr)
        print("install it with: pip install pysigma", file=sys.stderr)
        return 2

    corpus = Path(args.corpus)
    if not corpus.exists():
        print(f"corpus not found: {corpus}", file=sys.stderr)
        print("pull it with: .\\scripts\\pull_sigma.ps1", file=sys.stderr)
        return 2

    report = compile_corpus(corpus)

    if args.db:
        from identity_shield.db.connection import connect

        conn = connect(args.db)
        try:
            persist_report(conn, report)
        finally:
            conn.close()

    if args.json:
        print(
            json.dumps(
                {
                    "corpus": str(corpus),
                    "total": report.total,
                    "statuses": report.statuses,
                    "compile_rate": round(report.compile_rate, 3),
                    "usable_rate": round(report.usable_rate, 3),
                    "failures": report.by_reason(),
                },
                indent=2,
            )
        )
        return 0

    print(f"corpus:        {corpus}")
    print(f"rules:         {report.total}")
    for status, count in sorted(report.statuses.items()):
        print(f"  {status:<12} {count:>5}  ({count / report.total:.0%})")
    print(f"compile rate:  {report.compile_rate:.0%}   (pySigma only)")
    print(f"usable rate:   {report.usable_rate:.0%}   (pySigma + reference fallback)")
    print()
    if report.by_reason():
        print("top failure reasons:")
        for reason, count in list(report.by_reason().items())[: args.reasons]:
            print(f"  {count:>5}  {reason}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
