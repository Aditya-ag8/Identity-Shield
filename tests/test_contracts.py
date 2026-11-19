from __future__ import annotations

import json

import pytest

from identity_shield.contracts import (
    Census,
    ContractError,
    ResourceRef,
    TeardownReport,
    Variant,
    read_variants,
    spec_hash,
    write_variants,
)


def _variant(**overrides) -> Variant:
    levels = overrides.pop(
        "factor_levels", {"identity_context": "iam_user", "client_tool": "aws_cli"}
    )
    technique_id = overrides.pop("technique_id", "T1098.001")
    payload = {
        "variant_id": "T1098.001-ofat-000",
        "technique_id": technique_id,
        "variant_set": "ofat",
        "factor_levels": levels,
        "seed": 7,
        "spec_sha256": spec_hash(technique_id, levels),
    }
    payload.update(overrides)
    return Variant(**payload)


def test_variant_round_trips():
    variant = _variant()
    variant.validate()
    assert Variant.from_dict(variant.to_dict()) == variant


def test_variant_hash_is_over_semantics_not_identity():
    levels = {"timing": "off_hours"}
    first = _variant(variant_id="T1098.001-ofat-000", factor_levels=levels)
    second = _variant(variant_id="T1098.001-pair-042", factor_levels=levels)
    assert first.spec_sha256 == second.spec_sha256


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("variant_id", "has spaces"),
        ("technique_id", "1098.001"),
        ("variant_set", "extra"),
        ("seed", -1),
        ("spec_sha256", "not-a-hash"),
    ],
)
def test_variant_rejects_bad_fields(field, value):
    with pytest.raises(ContractError):
        _variant(**{field: value}).validate()


def test_variant_rejects_tampered_hash():
    variant = _variant()
    tampered = Variant(
        variant_id=variant.variant_id,
        technique_id=variant.technique_id,
        variant_set=variant.variant_set,
        factor_levels={"timing": "off_hours"},
        seed=variant.seed,
        spec_sha256=variant.spec_sha256,
    )
    with pytest.raises(ContractError, match="spec_sha256"):
        tampered.validate()


def test_variant_rejects_empty_levels():
    with pytest.raises(ContractError):
        _variant(factor_levels={}).validate()


def test_read_variants_can_seal_the_holdout(tmp_path):
    holdout = _variant(
        variant_id="T1098.001-hold-000",
        variant_set="holdout",
        factor_levels={"timing": "burst"},
    )
    visible = _variant()
    path = write_variants(tmp_path / "variants.jsonl", [visible, holdout])

    assert len(read_variants(path)) == 2
    assert [variant.variant_set for variant in read_variants(path, include_holdout=False)] == ["ofat"]
    assert len(read_variants(path, techniques=["T1098.001"])) == 2
    assert read_variants(path, techniques=["T1530"]) == []


def test_read_variants_reports_the_line_number(tmp_path):
    path = tmp_path / "variants.jsonl"
    path.write_text('{"schema_version": 1, "kind": "variant"}\n', encoding="utf-8")
    with pytest.raises(ContractError, match=r":1:"):
        read_variants(path)


def _resource(identifier: str = "is-lab-crown-jewels") -> ResourceRef:
    return ResourceRef(
        service="s3",
        kind="bucket",
        identifier=identifier,
        arn=f"arn:aws:s3:::{identifier}",
        source="s3",
        tags={"identity-shield:lab": "identity-shield"},
    )


def test_census_round_trips_and_rejects_duplicates():
    census = Census(
        generated_at="2026-11-19T10:00:00Z",
        account_id="123456789012",
        region="eu-west-1",
        resources=(_resource(),),
        errors=({"service": "s3", "operation": "list_buckets", "code": "AccessDenied"},),
    )
    assert Census.from_dict(census.to_dict()).resources == census.resources

    duplicate = Census(
        generated_at=census.generated_at,
        account_id=census.account_id,
        region=census.region,
        resources=(_resource(), _resource()),
    )
    with pytest.raises(ContractError, match="duplicate"):
        duplicate.validate()


def test_teardown_report_round_trips():
    report = TeardownReport(
        run_id="lab-1",
        started_at="2026-11-19T10:00:00Z",
        finished_at="2026-11-19T10:05:00Z",
        account_id="123456789012",
        region="eu-west-1",
        before=(_resource(),),
        after=(),
        residue=(),
        census_errors=(),
        terraform_exit_code=0,
        passed=True,
        notes=("clean",),
    )
    restored = TeardownReport.from_dict(json.loads(json.dumps(report.to_dict())))
    assert restored == report
