from __future__ import annotations

import dataclasses
import json

import pytest
import yaml

from identity_shield import config
from identity_shield.contracts import VISIBLE_SETS, Variant, read_variants, spec_hash
from identity_shield.variants import cli as variants_cli
from identity_shield.variants.coverage import build_coverage, render_markdown, uncovered_pairs
from identity_shield.variants.generator import (
    GenerationOptions,
    factorial_size,
    generate,
    select,
)
from identity_shield.variants.loader import CatalogueError, load_catalogue, load_factors


@pytest.fixture(scope="module")
def catalogue():
    return load_catalogue()


@pytest.fixture(scope="module")
def one_technique(catalogue):
    return dataclasses.replace(
        catalogue,
        techniques=tuple(t for t in catalogue.techniques if t.technique_id == "T1098.001"),
    )


@pytest.fixture(scope="module")
def generated(one_technique):
    # A single technique keeps the suite fast; the full space is covered by
    # test_full_catalogue_is_valid, which runs the same code on all eight.
    return generate(one_technique, GenerationOptions(master_seed=11))


def test_catalogue_loads_eight_techniques_and_five_factors(catalogue):
    assert len(catalogue.techniques) == 8
    assert len(catalogue.factors) == 5
    assert {technique.technique_id for technique in catalogue.techniques} == {
        "T1087.004",
        "T1526",
        "T1580",
        "T1078.004",
        "T1098.001",
        "T1098.003",
        "T1552.005",
        "T1530",
    }


def test_every_technique_baseline_uses_allowed_levels(catalogue):
    for technique in catalogue.techniques:
        baseline = catalogue.baseline_for(technique)
        assert set(baseline) == set(catalogue.factors)
        for factor_name, level in baseline.items():
            assert technique.is_allowed(factor_name, level)


def test_every_non_baseline_level_moves_some_cloudtrail_field(catalogue):
    for technique in catalogue.techniques:
        baseline = catalogue.baseline_for(technique)
        for factor_name, factor in catalogue.factors.items():
            for level in catalogue.allowed_levels(technique, factor):
                surface = catalogue.expected_surface(
                    technique, {**baseline, factor_name: level}
                )
                if level == baseline[factor_name]:
                    assert surface == ()
                else:
                    assert surface, f"{technique.technique_id} {factor_name}={level} has no surface"


def test_catalogue_rejects_unknown_excluded_level(tmp_path, catalogue):
    raw = yaml.safe_load(config.TECHNIQUES_YAML.read_text(encoding="utf-8"))
    raw["techniques"][0]["excluded_levels"] = {"identity_context": ["no_such_level"]}
    path = tmp_path / "techniques.yaml"
    path.write_text(yaml.safe_dump(raw), encoding="utf-8")
    with pytest.raises(CatalogueError, match="no_such_level"):
        load_catalogue(techniques_path=path)


def test_catalogue_rejects_factor_without_surface(tmp_path):
    raw = yaml.safe_load(config.FACTORS_YAML.read_text(encoding="utf-8"))
    raw["factors"]["timing"]["cloudtrail_surface"] = []
    path = tmp_path / "factors.yaml"
    path.write_text(yaml.safe_dump(raw), encoding="utf-8")
    with pytest.raises(CatalogueError, match="cloudtrail_surface"):
        load_factors(path)


def test_generation_is_deterministic(generated, one_technique):
    again = generate(one_technique, GenerationOptions(master_seed=11))
    assert [v.to_dict() for v in generated.variants] == [v.to_dict() for v in again.variants]


def test_generation_has_one_baseline_per_technique(generated):
    baselines = [v for v in generated.variants if v.variant_set == "baseline"]
    assert len(baselines) == 1
    assert baselines[0].variant_id.endswith("base-000")


def test_generation_deduplicates_and_covers(generated):
    hashes = [variant.spec_sha256 for variant in generated.variants]
    assert len(hashes) == len(set(hashes))

    coverage = build_coverage(
        dataclasses.replace(
            load_catalogue(),
            techniques=tuple(
                t for t in load_catalogue().techniques if t.technique_id == "T1098.001"
            ),
        ),
        list(generated.variants),
    )
    assert coverage["invalid_variants"] == 0
    assert coverage["level_coverage"]["ratio"] == 1.0
    assert coverage["pair_coverage"]["min_ratio"] == 1.0
    assert uncovered_pairs(coverage) == []


def test_holdout_is_disjoint_from_every_visible_set(generated):
    visible = {
        variant.spec_sha256
        for variant in generated.variants
        if variant.variant_set in VISIBLE_SETS
    }
    holdout = {
        variant.spec_sha256
        for variant in generated.variants
        if variant.variant_set == "holdout"
    }
    assert holdout
    assert holdout.isdisjoint(visible)


def test_holdout_changes_with_the_seed_but_visible_sets_do_not(one_technique):
    first = generate(one_technique, GenerationOptions(master_seed=1, holdout_per_technique=4))
    second = generate(one_technique, GenerationOptions(master_seed=2, holdout_per_technique=4))

    def visible(result):
        return [
            (v.variant_id, v.factor_levels)
            for v in result.variants
            if v.variant_set in VISIBLE_SETS
        ]

    assert visible(first) == visible(second)
    assert {
        v.spec_sha256 for v in first.variants if v.variant_set == "holdout"
    } != {
        v.spec_sha256 for v in second.variants if v.variant_set == "holdout"
    }


def test_holdout_size_is_capped_by_the_unused_space(one_technique):
    result = generate(one_technique, GenerationOptions(holdout_per_technique=10_000))
    technique = one_technique.techniques[0]
    visible = {v.spec_sha256 for v in result.variants if v.variant_set != "holdout"}
    holdout = [v for v in result.variants if v.variant_set == "holdout"]
    space = factorial_size(one_technique)
    assert len(holdout) == space - len(visible)
    assert len({v.spec_sha256 for v in holdout}) == len(holdout)


def test_select_filters_by_technique_and_set(generated):
    assert all(v.variant_set == "baseline" for v in select(generated, sets=["baseline"]))
    assert select(generated, techniques=["T1530"]) == ()
    assert select(generated, techniques=["t1098.001"])


def test_coverage_never_counts_the_holdout(one_technique, generated):
    coverage = build_coverage(one_technique, list(generated.variants))
    holdout = sum(1 for v in generated.variants if v.variant_set == "holdout")
    assert holdout > 0
    assert coverage["totals"]["holdout"] == holdout
    assert coverage["holdout_sealed"] is True
    assert coverage["sets_included"] == list(VISIBLE_SETS)
    technique = coverage["techniques"]["T1098.001"]
    assert technique["counts"]["holdout"] == holdout


def test_coverage_flags_a_non_baseline_row_that_matches_baseline(one_technique):
    technique = one_technique.techniques[0]
    baseline = one_technique.baseline_for(technique)
    noop = Variant(
        variant_id="T1098.001-ofat-999",
        technique_id="T1098.001",
        variant_set="ofat",
        factor_levels=baseline,
        seed=1,
        spec_sha256=spec_hash("T1098.001", baseline),
    )
    coverage = build_coverage(one_technique, [noop])
    assert coverage["invalid_variants"] == 1
    assert coverage["techniques"]["T1098.001"]["unsurfaced_variants"] == [
        "T1098.001-ofat-999"
    ]


def test_coverage_markdown_mentions_the_seal(one_technique, generated):
    markdown = render_markdown(build_coverage(one_technique, list(generated.variants)))
    assert "holdout" in markdown.lower()
    assert "sealed" in markdown.lower() or "excluded" in markdown.lower()


def test_generate_cli_writes_valid_artefacts(tmp_path):
    out = tmp_path / "variants.jsonl"
    code = variants_cli.main(
        [
            "generate",
            "--technique",
            "T1098.001",
            "--out",
            str(out),
            "--coverage",
            str(tmp_path / "coverage.json"),
            "--json",
        ]
    )
    assert code == 0
    variants = read_variants(out)
    assert variants and {v.technique_id for v in variants} == {"T1098.001"}

    document = json.loads((tmp_path / "coverage.json").read_text(encoding="utf-8"))
    assert document["invalid_variants"] == 0

    assert variants_cli.main(["validate", "--file", str(out)]) == 0
    assert variants_cli.main(["coverage", "--file", str(out), "--json"]) == 0


def test_validate_cli_rejects_an_excluded_level(tmp_path):
    out = tmp_path / "variants.jsonl"
    assert (
        variants_cli.main(
            [
                "generate",
                "--technique",
                "T1552.005",
                "--no-pairwise",
                "--holdout",
                "0",
                "--out",
                str(out),
                "--coverage",
                str(tmp_path / "coverage.json"),
            ]
        )
        == 0
    )

    rows = [json.loads(line) for line in out.read_text(encoding="utf-8").splitlines()]
    # T1552.005 excludes network_origin=service_mediated; splice it into a visible
    # row and recompute the hash so only the exclusion check can object.
    from identity_shield.contracts import spec_hash

    row = next(r for r in rows if r["variant_id"].endswith("ofat-000"))
    row["factor_levels"]["network_origin"] = "service_mediated"
    row["spec_sha256"] = spec_hash(row["technique_id"], row["factor_levels"])
    out.write_text(
        "\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8"
    )

    assert variants_cli.main(["validate", "--file", str(out)]) == 1


def test_full_catalogue_is_valid(catalogue):
    result = generate(catalogue)
    assert result.totals["baseline"] == 8
    assert result.totals["total"] > 300
    coverage = build_coverage(catalogue, list(result.variants))
    assert coverage["invalid_variants"] == 0
    assert coverage["level_coverage"]["ratio"] == 1.0
    assert coverage["pair_coverage"]["min_ratio"] == 1.0
