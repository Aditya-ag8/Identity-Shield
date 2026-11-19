"""Miss analysis: turn failed detections into reviewable findings.

This is deliberately mechanical. It records which fields the baseline rule set
actually inspects, which fields the variant moved, and the overlap between the
two. It does not claim a causal explanation that the evidence cannot support.
"""

from __future__ import annotations

import hashlib
from typing import Any, Iterable, Mapping

import yaml

from identity_shield.analysis import outcomes
from identity_shield.contracts import Finding, FindingsArtifact, VISIBLE_SETS, utc_now
from identity_shield.variants.loader import Catalogue


def _walk_fields(value: Any, prefix: str = "") -> Iterable[str]:
    if isinstance(value, Mapping):
        for key, item in value.items():
            key_text = str(key)
            if key_text == "condition":
                continue
            path = f"{prefix}.{key_text}" if prefix else key_text
            if isinstance(item, Mapping):
                yield from _walk_fields(item, path)
            else:
                # Strip Sigma modifiers: userAgent|contains -> userAgent.
                yield path.split("|")[0]
    elif isinstance(value, list):
        for item in value:
            yield from _walk_fields(item, prefix)


def rule_fields(conn, ruleset: str, technique_id: str) -> tuple[list[str], list[str]]:
    """Return (field names, rule titles) inspected by the rules for a technique."""
    fields: set[str] = set()
    titles: list[str] = []
    for row in conn.execute(
        "SELECT native_id, title, body FROM rule WHERE ruleset_version = ? "
        "AND (technique_id = ? OR technique_id IS NULL)",
        (ruleset, technique_id),
    ):
        titles.append(f"{row['native_id']}: {row['title']}")
        try:
            document = yaml.safe_load(row["body"] or "") or {}
        except yaml.YAMLError:
            continue
        for field_name in document.get("fields") or []:
            fields.add(str(field_name))
        detection = document.get("detection") or {}
        # Walk each selection body, not the ``detection`` wrapper: otherwise
        # every path gains a bogus ``selection.`` prefix (and ``condition``
        # appears as if it were a field).
        for name, block in detection.items():
            if name == "condition":
                continue
            fields.update(_walk_fields(block))
    return sorted(field for field in fields if field), titles


def build(
    conn,
    catalogue: Catalogue,
    ruleset: str,
    *,
    run_id: str | None = None,
    include_holdout: bool = False,
) -> FindingsArtifact:
    rows = outcomes.trial_rows(
        conn, ruleset, run_id=run_id, include_holdout=include_holdout
    )
    findings: list[Finding] = []
    for row in rows:
        if not row["valid"] or row["detected"]:
            continue
        if row["variant_set"] not in VISIBLE_SETS:
            continue
        technique = catalogue.technique(row["technique_id"])
        surface = catalogue.expected_surface(technique, row["factor_levels"])
        if not surface:
            continue
        inspected, titles = rule_fields(conn, ruleset, row["technique_id"])
        overlap = sorted(set(surface) & set(inspected))
        if overlap:
            rationale = (
                f"variant changed {', '.join(surface)}; rules inspect "
                f"{', '.join(overlap)} but still missed, so the rule is keyed on a "
                "baseline-specific value or a different API in the same field set"
            )
        else:
            rationale = (
                f"variant changed {', '.join(surface)}; rules inspect "
                f"{', '.join(inspected) or 'no declared fields'}, none of which covers "
                "the changed surface"
            )
        fired = [
            str(alert["native_id"])
            for alert in conn.execute(
                """
                SELECT DISTINCT r.native_id FROM alert a JOIN rule r ON r.rule_id = a.rule_id
                WHERE a.trial_id = ? AND r.ruleset_version = ?
                """,
                (row["trial_id"], ruleset),
            )
        ]
        digest = hashlib.sha256(
            f"{ruleset}|{row['trial_id']}|{row['variant_id']}".encode("utf-8")
        ).hexdigest()[:16]
        findings.append(
            Finding(
                finding_id=f"miss-{digest}",
                technique_id=row["technique_id"],
                variant_id=row["variant_id"],
                variant_set=row["variant_set"],
                factor_levels=row["factor_levels"],
                expected_surface=tuple(surface),
                fired_rules=tuple(fired),
                rule_fields=tuple(inspected),
                rationale=f"{rationale}. Rules: {'; '.join(titles) if titles else 'none'}",
                created_at=utc_now(),
                synthetic=bool(row["synthetic"]),
            )
        )

    by_technique: dict[str, int] = {}
    by_factor: dict[str, int] = {}
    for finding in findings:
        by_technique[finding.technique_id] = by_technique.get(finding.technique_id, 0) + 1
        for factor in finding.factor_levels:
            by_factor[factor] = by_factor.get(factor, 0) + 1

    return FindingsArtifact(
        generated_at=utc_now(),
        ruleset_version=ruleset,
        findings=tuple(findings),
        summary={
            "total": len(findings),
            "by_technique": by_technique,
            "by_factor": by_factor,
            "synthetic": sum(1 for finding in findings if finding.synthetic),
        },
    )
