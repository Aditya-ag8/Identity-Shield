"""Deterministic variant generation (Module 4).

The generator turns the catalogue into four sets per technique:

``baseline``  the canonical call, one per technique
``ofat``      one factor changed at a time, relative to that technique's baseline
``pairwise``  a covering array over all five factors (allpairspy)
``holdout``   seeded sample of combinations not used by the other three sets

Determinism is a hard requirement, not a nicety: the report compares round-1 and
round-2 results trial by trial, so regenerating the same inputs must produce the
same ids, the same hashes and the same order. Nothing here reads the clock or
uses an unseeded RNG; ``generated_at`` is the only time-dependent field and it
lives outside the variant rows.

Deduplication happens on ``spec_sha256``, not on ids. A pairwise row that happens
to differ in only one factor is the same attack as an OFAT row, so it is dropped
and counted. Coverage is computed after deduplication, so the report never
claims coverage that was thrown away.
"""

from __future__ import annotations

import hashlib
import math
from dataclasses import dataclass, field
from itertools import product
from typing import Iterable, Mapping, Sequence

from allpairspy import AllPairs

from identity_shield.contracts import Variant, spec_hash, utc_now
from identity_shield.variants.loader import Catalogue, CatalogueError, Technique

SET_TAGS = {
    "baseline": "base",
    "ofat": "ofat",
    "pairwise": "pair",
    "holdout": "hold",
}


@dataclass(frozen=True)
class GenerationOptions:
    master_seed: int = 20261119
    holdout_per_technique: int = 4
    include_pairwise: bool = True

    def seed_for(self, technique_id: str) -> int:
        digest = hashlib.sha256(f"{self.master_seed}:{technique_id}".encode("utf-8")).hexdigest()
        return int(digest[:8], 16)


@dataclass
class GenerationResult:
    generated_at: str
    master_seed: int
    catalogue_version: int
    variants: tuple[Variant, ...]
    stats: dict[str, dict] = field(default_factory=dict)

    @property
    def totals(self) -> dict[str, int]:
        counts = {name: 0 for name in SET_TAGS}
        for variant in self.variants:
            counts[variant.variant_set] += 1
        counts["total"] = len(self.variants)
        return counts

    def for_technique(self, technique_id: str) -> tuple[Variant, ...]:
        return tuple(v for v in self.variants if v.technique_id == technique_id)


def _raw_rows(technique: Technique, catalogue: Catalogue, options: GenerationOptions) -> dict[str, list[dict[str, str]]]:
    """Build the four candidate sets as plain level maps, before dedupe."""
    baseline = catalogue.baseline_for(technique)
    rows: dict[str, list[dict[str, str]]] = {
        "baseline": [dict(baseline)],
        "ofat": [],
        "pairwise": [],
        "holdout": [],
    }

    # --- one factor at a time ------------------------------------------------
    for name, factor in catalogue.factors.items():
        for level in factor.levels:
            if level == baseline[name]:
                continue
            if not technique.is_allowed(name, level):
                continue
            candidate = dict(baseline)
            candidate[name] = level
            rows["ofat"].append(candidate)

    # --- pairwise covering array --------------------------------------------
    if options.include_pairwise:
        names = list(catalogue.factors)
        parameters = [
            [level for level in catalogue.factors[name].levels if technique.is_allowed(name, level)]
            for name in names
        ]

        def keep(row: Sequence[str]) -> bool:
            return all(
                technique.is_allowed(names[index], str(level))
                for index, level in enumerate(row)
            )

        try:
            combinations = list(AllPairs(parameters, filter_func=keep))
        except Exception as exc:  # pragma: no cover - allpairspy edge cases
            raise CatalogueError(f"{technique.technique_id}: pairwise generation failed: {exc}") from exc

        for combination in combinations:
            rows["pairwise"].append(
                {name: str(level) for name, level in zip(names, combination)}
            )
        rows["pairwise"].sort(key=lambda row: tuple(catalogue.factors[n].index(row[n]) for n in names))

    # --- sealed holdout ------------------------------------------------------
    if options.holdout_per_technique > 0:
        names = list(catalogue.factors)
        space: list[dict[str, str]] = []
        level_lists = [
            [level for level in catalogue.factors[name].levels if technique.is_allowed(name, level)]
            for name in names
        ]
        for combination in product(*level_lists):
            space.append({name: level for name, level in zip(names, combination)})

        used = {spec_hash(technique.technique_id, row) for rows_of_set in rows.values() for row in rows_of_set}
        pool = [row for row in space if spec_hash(technique.technique_id, row) not in used]
        pool.sort(key=lambda row: tuple(catalogue.factors[n].index(row[n]) for n in names))

        import random

        rng = random.Random(options.seed_for(technique.technique_id))
        take = min(options.holdout_per_technique, len(pool))
        rows["holdout"] = sorted(
            rng.sample(pool, take),
            key=lambda row: tuple(catalogue.factors[n].index(row[n]) for n in names),
        )

    return rows


def generate_for_technique(
    technique: Technique,
    catalogue: Catalogue,
    options: GenerationOptions,
) -> tuple[list[Variant], dict]:
    raw = _raw_rows(technique, catalogue, options)

    seen: set[str] = set()
    ordered: list[tuple[str, dict[str, str]]] = []
    duplicates = 0

    for set_name in ("baseline", "ofat", "pairwise", "holdout"):
        for levels in raw[set_name]:
            digest = spec_hash(technique.technique_id, levels)
            if digest in seen:
                duplicates += 1
                continue
            seen.add(digest)
            ordered.append((set_name, dict(levels)))

    counters = {name: 0 for name in SET_TAGS}
    variants: list[Variant] = []
    seed = options.seed_for(technique.technique_id)
    for set_name, levels in ordered:
        index = counters[set_name]
        counters[set_name] += 1
        variant = Variant(
            variant_id=f"{technique.technique_id}-{SET_TAGS[set_name]}-{index:03d}",
            technique_id=technique.technique_id,
            variant_set=set_name,
            factor_levels=levels,
            seed=seed + index,
            spec_sha256=spec_hash(technique.technique_id, levels),
        )
        variant.validate()
        variants.append(variant)

    stats = {
        "counts": {name: counters[name] for name in SET_TAGS},
        "total": len(variants),
        "duplicates_dropped": duplicates,
        "candidates": {name: len(rows) for name, rows in raw.items()},
    }
    return variants, stats


def generate(catalogue: Catalogue, options: GenerationOptions | None = None) -> GenerationResult:
    options = options or GenerationOptions()
    variants: list[Variant] = []
    stats: dict[str, dict] = {}

    for technique in catalogue.techniques:
        technique_variants, technique_stats = generate_for_technique(technique, catalogue, options)
        variants.extend(technique_variants)
        stats[technique.technique_id] = technique_stats

    return GenerationResult(
        generated_at=utc_now(),
        master_seed=options.master_seed,
        catalogue_version=catalogue.version,
        variants=tuple(variants),
        stats=stats,
    )


def select(
    result: GenerationResult,
    *,
    techniques: Iterable[str] | None = None,
    sets: Iterable[str] | None = None,
) -> tuple[Variant, ...]:
    wanted_techniques = {t.upper() for t in techniques} if techniques else None
    wanted_sets = set(sets) if sets else None
    return tuple(
        variant
        for variant in result.variants
        if (wanted_techniques is None or variant.technique_id in wanted_techniques)
        and (wanted_sets is None or variant.variant_set in wanted_sets)
    )


def factorial_size(catalogue: Catalogue) -> int:
    total = 0
    for technique in catalogue.techniques:
        size = 1
        for factor in catalogue.factors.values():
            size *= len(catalogue.allowed_levels(technique, factor))
        total += size
    return total


def summarise(result: GenerationResult) -> str:
    """Human-readable per-technique summary used by the CLI."""
    lines = [
        f"{'technique':<12} {'base':>5} {'ofat':>5} {'pair':>5} {'hold':>5} "
        f"{'total':>6} {'dup':>5}",
        "-" * 52,
    ]
    for technique_id, stats in result.stats.items():
        counts = stats["counts"]
        lines.append(
            f"{technique_id:<12} {counts['baseline']:>5} {counts['ofat']:>5} "
            f"{counts['pairwise']:>5} {counts['holdout']:>5} "
            f"{stats['total']:>6} {stats['duplicates_dropped']:>5}"
        )
    totals = result.totals
    lines.append("-" * 52)
    lines.append(
        f"{'total':<12} {totals['baseline']:>5} {totals['ofat']:>5} "
        f"{totals['pairwise']:>5} {totals['holdout']:>5} {totals['total']:>6}"
    )
    return "\n".join(lines)
