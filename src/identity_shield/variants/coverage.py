"""Coverage reporting and the offline validity gate (Module 4).

Two questions the report must answer without looking at any attack result:

1. **Did the generator actually explore the space?** Every allowed level of
   every factor must appear, and every pair of levels across two factors must
   appear at least once. Pairwise coverage is computed *after* deduplication,
   so it cannot claim coverage that was dropped as a duplicate.
2. **Can each variant be distinguished from baseline in CloudTrail?** A variant
   whose expected field delta is empty would produce the same log record as the
   canonical call. It is flagged invalid here, and the live gate re-checks it
   against captured events in M5.

The holdout set is excluded from every coverage number. Reporting it would leak
which combinations are reserved, which defeats the point of sealing it.
"""

from __future__ import annotations

from itertools import combinations
from typing import Any, Iterable, Mapping, Sequence

from identity_shield.contracts import VISIBLE_SETS, Variant, utc_now
from identity_shield.variants.loader import Catalogue, Technique


def _visible(variants: Iterable[Variant]) -> list[Variant]:
    return [variant for variant in variants if variant.variant_set in VISIBLE_SETS]


def _level_counts(technique: Technique, catalogue: Catalogue, variants: Sequence[Variant]) -> dict[str, Any]:
    counts: dict[str, Any] = {}
    for name, factor in catalogue.factors.items():
        allowed = catalogue.allowed_levels(technique, factor)
        entry: dict[str, Any] = {}
        for level in allowed:
            used = sum(1 for variant in variants if variant.factor_levels.get(name) == level)
            entry[level] = used
        counts[name] = {
            "levels": entry,
            "allowed": len(allowed),
            "covered": sum(1 for used in entry.values() if used > 0),
        }
    return counts


def _pair_counts(technique: Technique, catalogue: Catalogue, variants: Sequence[Variant]) -> dict[str, Any]:
    pairs: dict[str, Any] = {}
    for left, right in combinations(catalogue.factors, 2):
        left_levels = catalogue.allowed_levels(technique, catalogue.factors[left])
        right_levels = catalogue.allowed_levels(technique, catalogue.factors[right])
        seen = {
            (variant.factor_levels[left], variant.factor_levels[right]) for variant in variants
        }
        total = len(left_levels) * len(right_levels)
        pairs[f"{left}+{right}"] = {
            "covered": len(seen),
            "total": total,
            "ratio": round(len(seen) / total, 4) if total else 0.0,
        }
    return pairs


def build_coverage(
    catalogue: Catalogue,
    variants: Sequence[Variant],
    *,
    generation_stats: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    visible = _visible(variants)
    techniques: dict[str, Any] = {}

    for technique in catalogue.techniques:
        own = [variant for variant in visible if variant.technique_id == technique.technique_id]
        level_counts = _level_counts(technique, catalogue, own)
        pair_counts = _pair_counts(technique, catalogue, own)

        baseline = catalogue.baseline_for(technique)
        unsurfaced: list[str] = []
        surfaces: dict[str, list[str]] = {}
        for variant in own:
            if variant.variant_set == "baseline":
                continue
            surface = catalogue.expected_surface(technique, variant.factor_levels)
            surfaces[variant.variant_id] = list(surface)
            if not surface:
                unsurfaced.append(variant.variant_id)

        techniques[technique.technique_id] = {
            "name": technique.name,
            "baseline": baseline,
            "excluded_levels": {
                name: list(levels) for name, levels in technique.excluded_levels.items()
            },
            "counts": _counts_by_set(variants, technique.technique_id),
            "levels": level_counts,
            "pairs": pair_counts,
            "pair_coverage_min": min((row["ratio"] for row in pair_counts.values()), default=0.0),
            "unsurfaced_variants": unsurfaced,
            "surface_fields": sorted({field for fields in surfaces.values() for field in fields}),
        }
        if generation_stats and technique.technique_id in generation_stats:
            techniques[technique.technique_id]["generation"] = generation_stats[technique.technique_id]

    covered_pairs = [
        row["ratio"] for entry in techniques.values() for row in entry["pairs"].values()
    ]
    levels_total = sum(entry["allowed"] for entry in _all_levels(techniques).values())
    levels_covered = sum(entry["covered"] for entry in _all_levels(techniques).values())

    return {
        "schema_version": 1,
        "kind": "variant-coverage",
        "generated_at": utc_now(),
        "sets_included": list(VISIBLE_SETS),
        "holdout_sealed": True,
        "totals": _counts_by_set(variants, None),
        "level_coverage": {
            "levels": levels_total,
            "covered": levels_covered,
            "ratio": round(levels_covered / levels_total, 4) if levels_total else 0.0,
        },
        "pair_coverage": {
            "pairs": len(covered_pairs),
            "min_ratio": round(min(covered_pairs), 4) if covered_pairs else 0.0,
            "mean_ratio": round(sum(covered_pairs) / len(covered_pairs), 4) if covered_pairs else 0.0,
        },
        "invalid_variants": sum(len(entry["unsurfaced_variants"]) for entry in techniques.values()),
        "techniques": techniques,
    }


def _all_levels(techniques: Mapping[str, Any]) -> dict[str, Any]:
    """Flatten per-technique factor coverage so totals are computed once."""
    flattened: dict[str, Any] = {}
    for technique_id, entry in techniques.items():
        for factor_name, factor_entry in entry["levels"].items():
            key = f"{technique_id}:{factor_name}"
            flattened[key] = factor_entry
    return flattened


def _counts_by_set(variants: Sequence[Variant], technique_id: str | None) -> dict[str, int]:
    counts = {name: 0 for name in ("baseline", "ofat", "pairwise", "holdout")}
    for variant in variants:
        if technique_id is not None and variant.technique_id != technique_id:
            continue
        counts[variant.variant_set] += 1
    counts["total"] = sum(counts.values())
    return counts


def render_markdown(coverage: Mapping[str, Any]) -> str:
    lines = [
        "# Variant coverage",
        "",
        f"Generated: {coverage['generated_at']}",
        "",
        "## Totals",
        "",
        "| Set | Variants |",
        "|---|---|",
    ]
    for name in ("baseline", "ofat", "pairwise", "holdout"):
        lines.append(f"| {name} | {coverage['totals'][name]} |")
    lines.append(f"| **total** | **{coverage['totals']['total']}** |")

    levels = coverage["level_coverage"]
    pairs = coverage["pair_coverage"]
    lines += [
        "",
        f"Level coverage: **{levels['covered']}/{levels['levels']}** ({levels['ratio']:.0%})",
        "",
        f"Pairwise coverage (min over all factor pairs): **{pairs['min_ratio']:.0%}**",
        "",
        f"Variants with no expected CloudTrail delta (invalid): **{coverage['invalid_variants']}**",
        "",
        "## Per technique",
        "",
        "| Technique | base | ofat | pair | hold | min pair coverage | invalid |",
        "|---|---|---|---|---|---|---|",
    ]
    for technique_id, entry in coverage["techniques"].items():
        counts = entry["counts"]
        lines.append(
            f"| {technique_id} | {counts['baseline']} | {counts['ofat']} | "
            f"{counts['pairwise']} | {counts['holdout']} | "
            f"{entry['pair_coverage_min']:.0%} | {len(entry['unsurfaced_variants'])} |"
        )

    lines += [
        "",
        "## Exclusions",
        "",
        "Levels that cannot be combined with a technique, and are therefore never generated:",
        "",
    ]
    any_exclusions = False
    for technique_id, entry in coverage["techniques"].items():
        for factor_name, levels in entry["excluded_levels"].items():
            any_exclusions = True
            lines.append(f"- `{technique_id}` / `{factor_name}`: {', '.join(levels)}")
    if not any_exclusions:
        lines.append("- none")

    lines += [
        "",
        "## Notes",
        "",
        "The holdout set is generated but excluded from every number above. Analysis",
        "code reads `variants.jsonl` with `include_holdout=False` until round-2 rules",
        "are frozen; unsealing early invalidates the before/after comparison.",
        "",
    ]
    return "\n".join(lines)


def uncovered_pairs(coverage: Mapping[str, Any], threshold: float = 1.0) -> list[str]:
    """Pairs whose coverage is below ``threshold``, for the CLI gate."""
    findings: list[str] = []
    for technique_id, entry in coverage["techniques"].items():
        for pair, row in entry["pairs"].items():
            if row["ratio"] < threshold:
                findings.append(f"{technique_id} {pair}: {row['covered']}/{row['total']}")
    return findings
