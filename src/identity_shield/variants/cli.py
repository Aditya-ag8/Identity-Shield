"""Module 4 command line.

    identity-shield variants generate
    identity-shield variants generate --technique T1098.003 --seed 7
    identity-shield variants coverage
    identity-shield variants validate --file data/variants/variants.jsonl

``generate`` writes three artefacts that later modules consume:

    data/variants/variants.jsonl    Module 5 reads this
    data/variants/coverage.json     Module 8 reports this
    data/variants/coverage.md       human-readable version
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import sys
from pathlib import Path

from identity_shield import config
from identity_shield.contracts import (
    VISIBLE_SETS,
    ContractError,
    Variant,
    read_variants,
    write_json,
    write_variants,
)
from identity_shield.variants.coverage import build_coverage, render_markdown, uncovered_pairs
from identity_shield.variants.generator import GenerationOptions, generate, summarise
from identity_shield.variants.loader import CatalogueError, load_catalogue


def persist(conn, variants: list[Variant], catalogue, *, prune: bool = True) -> int:
    """Upsert variants into SQLite.

    When ``prune`` is set, remove stale rows **for the sets being persisted
    only**. The first version scoped deletion by technique, which meant writing
    the benign file deleted every attack variant for the same eight techniques.
    A trial that references a stale id still blocks the delete via the foreign
    key, which is the correct outcome: history is not rewritten.
    """
    from identity_shield.detect.loader import load_techniques

    load_techniques(conn)
    technique_ids = {technique.technique_id for technique in catalogue.techniques}
    fresh = {variant.variant_id for variant in variants}
    sets = {variant.variant_set for variant in variants}

    placeholders = ",".join("?" for _ in technique_ids)
    set_placeholders = ",".join("?" for _ in sets)
    existing = {
        row["variant_id"]
        for row in conn.execute(
            f"SELECT variant_id FROM variant WHERE technique_id IN ({placeholders}) "
            f"AND variant_set IN ({set_placeholders})",
            tuple(technique_ids) + tuple(sets),
        )
    } if sets else set()
    stale = existing - fresh if prune else set()
    for variant_id in sorted(stale):
        conn.execute("DELETE FROM variant WHERE variant_id = ?", (variant_id,))

    conn.executemany(
        """
        INSERT INTO variant (variant_id, technique_id, variant_set, factor_levels,
                             seed, spec_sha256, notes)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(variant_id) DO UPDATE SET
            technique_id=excluded.technique_id,
            variant_set=excluded.variant_set,
            factor_levels=excluded.factor_levels,
            seed=excluded.seed,
            spec_sha256=excluded.spec_sha256,
            notes=excluded.notes
        """,
        [
            (
                variant.variant_id,
                variant.technique_id,
                variant.variant_set,
                json.dumps(dict(variant.factor_levels), sort_keys=True),
                variant.seed,
                variant.spec_sha256,
                variant.notes,
            )
            for variant in variants
        ],
    )
    conn.commit()
    return len(stale)


def _filtered_catalogue(catalogue, techniques: list[str] | None):
    if not techniques:
        return catalogue
    wanted = {technique.upper() for technique in techniques}
    known = {technique.technique_id for technique in catalogue.techniques}
    unknown = wanted - known
    if unknown:
        raise SystemExit(f"unknown technique(s): {', '.join(sorted(unknown))}")
    return dataclasses.replace(
        catalogue,
        techniques=tuple(t for t in catalogue.techniques if t.technique_id in wanted),
    )


def _generate(args) -> int:
    catalogue = _filtered_catalogue(load_catalogue(), args.technique)
    options = GenerationOptions(
        master_seed=args.seed,
        holdout_per_technique=args.holdout,
        include_pairwise=not args.no_pairwise,
    )
    result = generate(catalogue, options)
    variants = list(result.variants)

    out = Path(args.out) if args.out else config.VARIANTS_DIR / "variants.jsonl"
    coverage_path = Path(args.coverage) if args.coverage else out.with_name("coverage.json")
    markdown_path = coverage_path.with_suffix(".md")

    write_variants(out, variants)
    coverage = build_coverage(catalogue, variants, generation_stats=result.stats)
    write_json(coverage_path, coverage)
    markdown_path.write_text(render_markdown(coverage), encoding="utf-8")

    stale = 0
    if args.db:
        from identity_shield.db.connection import connect

        conn = connect(args.db)
        try:
            stale = persist(conn, variants, catalogue)
        finally:
            conn.close()

    if args.json:
        print(
            json.dumps(
                {
                    "variants": len(variants),
                    "totals": result.totals,
                    "stats": result.stats,
                    "level_coverage": coverage["level_coverage"],
                    "pair_coverage": coverage["pair_coverage"],
                    "invalid_variants": coverage["invalid_variants"],
                    "out": str(out),
                    "coverage": str(coverage_path),
                    "stale_rows_removed": stale,
                },
                indent=2,
            )
        )
    else:
        print(summarise(result))
        print()
        print(f"variants written:  {out}")
        print(f"coverage report:   {coverage_path}")
        levels = coverage["level_coverage"]
        pairs = coverage["pair_coverage"]
        print(f"level coverage:    {levels['covered']}/{levels['levels']} ({levels['ratio']:.0%})")
        print(f"pairwise coverage: min {pairs['min_ratio']:.0%}, mean {pairs['mean_ratio']:.0%}")
        if coverage["invalid_variants"]:
            print(
                f"invalid variants:  {coverage['invalid_variants']} with no expected CloudTrail delta",
                file=sys.stderr,
            )
        if stale:
            print(f"stale DB rows removed: {stale}")

    findings = uncovered_pairs(coverage)
    if findings:
        print(f"\n{len(findings)} factor pair(s) below 100% coverage:", file=sys.stderr)
        for finding in findings[:12]:
            print(f"  {finding}", file=sys.stderr)
        if args.strict:
            return 1
    return 0


def _benign(args) -> int:
    from identity_shield.variants.benign import generate_benign, load_benign

    catalogue = _filtered_catalogue(load_catalogue(), args.technique)
    activities = tuple(
        activity
        for activity in load_benign()
        if activity.technique_id in {technique.technique_id for technique in catalogue.techniques}
    )
    variants = list(generate_benign(catalogue, activities=activities))
    out = Path(args.out) if args.out else config.VARIANTS_DIR / "benign.jsonl"
    write_variants(out, variants)

    stale = 0
    if args.db:
        from identity_shield.db.connection import connect

        conn = connect(args.db)
        try:
            stale = persist(conn, variants, catalogue)
        finally:
            conn.close()

    if args.json:
        print(json.dumps({"variants": len(variants), "out": str(out), "stale_rows_removed": stale}, indent=2))
    else:
        print(f"benign variants: {len(variants)}")
        print(f"written:         {out}")
        if stale:
            print(f"stale DB rows removed: {stale}")
    return 0


def _coverage(args) -> int:
    catalogue = load_catalogue()
    path = Path(args.file) if args.file else config.VARIANTS_DIR / "variants.jsonl"
    variants = read_variants(path, include_holdout=False)
    coverage = build_coverage(catalogue, variants)

    if args.json:
        print(json.dumps(coverage, indent=2))
        return 0

    levels = coverage["level_coverage"]
    pairs = coverage["pair_coverage"]
    print(f"file:              {path}")
    print(f"visible variants:  {coverage['totals']['total']}")
    print(f"level coverage:    {levels['covered']}/{levels['levels']} ({levels['ratio']:.0%})")
    print(f"pairwise coverage: min {pairs['min_ratio']:.0%}, mean {pairs['mean_ratio']:.0%}")
    print(f"invalid variants:  {coverage['invalid_variants']}")
    print()
    print(
        f"{'technique':<12} {'base':>5} {'ofat':>5} {'pair':>5} {'hold':>5} {'min pair':>9}"
    )
    for technique_id, entry in coverage["techniques"].items():
        counts = entry["counts"]
        print(
            f"{technique_id:<12} {counts['baseline']:>5} {counts['ofat']:>5} "
            f"{counts['pairwise']:>5} {counts['holdout']:>5} {entry['pair_coverage_min']:>8.0%}"
        )
    return 0


def _validate(args) -> int:
    catalogue = load_catalogue()
    path = Path(args.file) if args.file else config.VARIANTS_DIR / "variants.jsonl"
    try:
        variants = read_variants(path)
    except ContractError as exc:
        print(f"contract error: {exc}", file=sys.stderr)
        return 1

    problems: list[str] = []
    known = {technique.technique_id for technique in catalogue.techniques}
    by_technique: dict[str, set[str]] = {}

    for variant in variants:
        if variant.technique_id not in known:
            problems.append(f"{variant.variant_id}: unknown technique {variant.technique_id}")
            continue
        technique = catalogue.technique(variant.technique_id)
        for factor_name, level in variant.factor_levels.items():
            factor = catalogue.factors.get(factor_name)
            if factor is None:
                problems.append(f"{variant.variant_id}: unknown factor {factor_name!r}")
                continue
            if level not in factor.levels:
                problems.append(f"{variant.variant_id}: unknown level {level!r} for {factor_name!r}")
            elif not technique.is_allowed(factor_name, level):
                problems.append(
                    f"{variant.variant_id}: uses {factor_name}={level}, excluded for this technique"
                )
        digest = variant.spec_sha256
        seen = by_technique.setdefault(variant.technique_id, set())
        if digest in seen:
            problems.append(f"{variant.variant_id}: duplicate variant spec")
        seen.add(digest)

    for technique in catalogue.techniques:
        if technique.technique_id not in by_technique:
            # Validating a subset file (for example `--technique T1530`) must not
            # demand baselines for techniques that were never generated.
            continue
        sets = {
            variant.variant_set
            for variant in variants
            if variant.technique_id == technique.technique_id
        }
        if "baseline" not in sets:
            problems.append(f"{technique.technique_id}: no baseline variant")

    if problems:
        print(f"{len(problems)} problem(s) in {path}:", file=sys.stderr)
        for problem in problems:
            print(f"  {problem}", file=sys.stderr)
        return 1

    counts = {
        name: sum(1 for variant in variants if variant.variant_set == name)
        for name in ("baseline", "ofat", "pairwise", "holdout")
    }
    print(f"valid: {len(variants)} variants across {len(by_technique)} techniques")
    print("sets: " + ", ".join(f"{name}={count}" for name, count in counts.items()))
    print(f"holdout visible to analysis: {'yes' if counts['holdout'] else 'n/a'}")
    return 0


def _add_generate(commands) -> None:
    generate_parser = commands.add_parser("generate", help="generate variants.jsonl")
    generate_parser.add_argument("--technique", action="append", help="limit to a technique (repeatable)")
    generate_parser.add_argument("--seed", type=int, default=20261119, help="master seed")
    generate_parser.add_argument("--holdout", type=int, default=4, help="holdout size per technique")
    generate_parser.add_argument("--no-pairwise", action="store_true", help="skip the covering array")
    generate_parser.add_argument("--out", default=None, help="output JSONL path")
    generate_parser.add_argument("--coverage", default=None, help="output coverage JSON path")
    generate_parser.add_argument("--db", default=None, help="also persist into the variant table")
    generate_parser.add_argument("--json", action="store_true")
    generate_parser.add_argument("--strict", action="store_true", help="fail on incomplete pair coverage")
    generate_parser.set_defaults(handler=_generate)


def _add_benign(commands) -> None:
    parser = commands.add_parser("benign", help="generate the normal-activity baseline")
    parser.add_argument("--technique", action="append")
    parser.add_argument("--out", default=None)
    parser.add_argument("--db", default=None)
    parser.add_argument("--json", action="store_true")
    parser.set_defaults(handler=_benign)


def _add_coverage(commands) -> None:
    coverage_parser = commands.add_parser("coverage", help="recompute coverage from a variants file")
    coverage_parser.add_argument("--file", default=None)
    coverage_parser.add_argument("--json", action="store_true")
    coverage_parser.set_defaults(handler=_coverage)


def _add_validate(commands) -> None:
    validate_parser = commands.add_parser("validate", help="check a variants file against the catalogue")
    validate_parser.add_argument("--file", default=None)
    validate_parser.set_defaults(handler=_validate)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="identity-shield variants")
    commands = parser.add_subparsers(dest="command", required=True)
    _add_generate(commands)
    _add_benign(commands)
    _add_coverage(commands)
    _add_validate(commands)
    args = parser.parse_args(argv)
    try:
        return args.handler(args)
    except (CatalogueError, ContractError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
