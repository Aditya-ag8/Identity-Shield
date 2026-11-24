from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from identity_shield.analysis import misses, outcomes, report, stats
from identity_shield.contracts import (
    ContractError,
    Finding,
    FindingsArtifact,
    Variant,
    spec_hash,
)
from identity_shield.db.connection import connect
from identity_shield.db.init import init_db
from identity_shield.detect import loader, replay
from identity_shield.runner import orchestrator
from identity_shield.runner.models import TrialContext
from identity_shield.runner.preflight import run_preflight
from identity_shield.variants.benign import generate_benign, load_benign
from identity_shield.variants.cli import persist
from identity_shield.variants.generator import GenerationOptions, generate_for_technique
from identity_shield.variants.loader import load_catalogue


def test_wilson_interval_bounds() -> None:
    assert stats.wilson_interval(0, 0) == (0.0, 0.0)
    low, high = stats.wilson_interval(5, 10)
    assert 0.23 < low < 0.24
    assert 0.76 < high < 0.77
    assert stats.wilson_interval(10, 10)[1] == 1.0


def test_mcnemar_exact_is_symmetric_and_small_for_a_one_sided_swing() -> None:
    symmetric = stats.mcnemar_exact(5, 5)
    assert symmetric["p_value"] == pytest.approx(1.0)
    swing = stats.mcnemar_exact(0, 10)
    assert swing["p_value"] < 0.01
    assert swing["discordant"] == 10


def test_kaplan_meier_median_and_censoring() -> None:
    result = stats.kaplan_meier([1, 2, 3, 4], [True, True, True, True])
    assert result["median"] == 2.0
    censored = stats.kaplan_meier([1, 2, 3, 4], [True, False, False, False])
    assert censored["median"] is None


def test_finding_contract_round_trip_and_visible_set_rule() -> None:
    finding = Finding(
        finding_id="miss-1",
        technique_id="T1530",
        variant_id="T1530-ofat-001",
        variant_set="ofat",
        factor_levels={"api_form": "alternative_api"},
        expected_surface=("eventName",),
        fired_rules=(),
        rule_fields=("eventName", "requestParameters.bucketName"),
        rationale="the rule keys on GetObject",
        created_at="2026-11-19T00:00:00Z",
    )
    finding.validate()
    artifact = FindingsArtifact(
        generated_at="2026-11-19T00:00:00Z",
        ruleset_version="baseline-v1",
        findings=(finding,),
        summary={"total": 1},
    )
    restored = FindingsArtifact.from_dict(artifact.to_dict())
    assert restored.findings == (finding,)

    with pytest.raises(ContractError):
        Finding(
            finding_id="miss-2",
            technique_id="T1530",
            variant_id="benign-1",
            variant_set="benign",
            factor_levels={},
            expected_surface=(),
            fired_rules=(),
            rule_fields=(),
            rationale="",
            created_at="2026-11-19T00:00:00Z",
        ).validate()


def _campaign_fixture(tmp_path, technique_id: str = "T1530"):
    path = tmp_path / "campaign.db"
    init_db(path, drop=True)
    conn = connect(path)
    loader.load_techniques(conn)
    loader.load_fixtures(conn)
    catalogue = load_catalogue()
    technique = catalogue.technique(technique_id)
    variants, _ = generate_for_technique(
        technique, catalogue, GenerationOptions(include_pairwise=False)
    )
    variants = [row for row in variants if row.variant_set != "holdout"]
    benign = list(
        generate_benign(
            catalogue,
            activities=tuple(
                activity
                for activity in load_benign()
                if activity.technique_id == technique_id
            ),
        )
    )
    persist(conn, variants, catalogue, prune=False)
    persist(conn, benign, catalogue, prune=False)
    result = orchestrator.run_campaign(
        conn,
        run_id="test-run",
        variants=list(variants) + benign,
        catalogue=catalogue,
        account_id="123456789012",
        region="eu-west-1",
        synthetic=True,
    )
    return conn, catalogue, variants, benign, result


def test_synthetic_campaign_replay_analysis_and_report(tmp_path) -> None:
    conn, catalogue, variants, benign, campaign = _campaign_fixture(tmp_path)
    try:
        assert campaign.errors == []
        assert campaign.trials == len(variants) + len(benign)
        assert campaign.succeeded == campaign.trials

        baseline = replay.run_replay(conn, replay.load_ruleset(conn, "baseline-v1"))
        improved = replay.run_replay(conn, replay.load_ruleset(conn, "improved-v1"))
        assert baseline["alerts"] > 0
        assert improved["alerts"] > 0

        summary = outcomes.summarise(conn, "baseline-v1", run_id="test-run")
        assert summary["overall"]["valid"] > 0
        assert summary["provenance"]["synthetic_trials"] == len(variants)
        assert "benign" not in summary["sets"]

        false_alarms = outcomes.false_alarms(conn, "improved-v1", run_id="test-run")
        assert false_alarms["trials"] == len(benign)
        assert false_alarms["alerted"] >= 1  # the broad S3 rule is expected to alert

        paired = outcomes.paired(conn, "baseline-v1", "improved-v1", run_id="test-run")
        assert paired["pairs"] == summary["overall"]["valid"]
        assert paired["improved_detection_rate"] >= paired["baseline_detection_rate"]

        artifact = misses.build(
            conn, catalogue, "baseline-v1", run_id="test-run"
        )
        assert artifact.summary["total"] == len(artifact.findings)
        assert all(finding.variant_set != "benign" for finding in artifact.findings)
        assert all(finding.synthetic for finding in artifact.findings)
        assert all(not field.startswith("selection.") for finding in artifact.findings for field in finding.rule_fields)

        bundle = report.build(conn, catalogue, run_id="test-run")
        assert "synthetic rehearsal" in bundle["markdown"].lower()
        assert bundle["latency"]["baseline"]["live"] is False
        markdown_path, json_path = report.write(bundle, directory=tmp_path)
        assert markdown_path.exists() and json_path.exists()
        payload = json.loads(json_path.read_text(encoding="utf-8"))
        assert payload["provenance"]["live_trials"] == 0
    finally:
        conn.close()


def test_improved_ruleset_does_not_stack_on_the_baseline_python_rules(conn) -> None:
    baseline = replay.load_ruleset(conn, "baseline-v1")
    improved = replay.load_ruleset(conn, "improved-v1")
    assert len(baseline.rules) == 13
    assert len(improved.rules) == 8
    assert all(rule.loader != "python" for rule in improved.rules)
    assert any(rule.loader == "python" for rule in baseline.rules)


def test_offline_pipeline_stays_fast() -> None:
    from identity_shield.bench import run_benchmark

    result = run_benchmark()
    assert result["trials"] == 300
    assert result["total_seconds"] < 15.0


def test_synthetic_preflight_never_claims_aws_readiness() -> None:
    catalogue = load_catalogue()
    technique = catalogue.technique("T1530")
    variant = Variant(
        variant_id="T1530-base-999",
        technique_id="T1530",
        variant_set="baseline",
        factor_levels=catalogue.baseline_for(technique),
        seed=1,
        spec_sha256=spec_hash("T1530", catalogue.baseline_for(technique)),
    )
    ctx = TrialContext(
        run_id="preflight-test",
        variant=variant,
        technique=technique,
        repetition=1,
        account_id="123456789012",
        region="eu-west-1",
        synthetic=True,
        started_at=datetime.now(timezone.utc),
    )
    result = run_preflight(ctx)
    assert result.ok
    assert [check.name for check in result.checks] == ["synthetic"]


def test_holdout_evaluation_requires_frozen_ruleset(tmp_path) -> None:
    conn, catalogue, variants, benign, campaign = _campaign_fixture(tmp_path)
    try:
        replay.load_ruleset(conn, "baseline-v1")
        # Intentionally unfreeze ruleset
        conn.execute("UPDATE ruleset SET frozen_at = NULL WHERE ruleset_version = 'baseline-v1'")
        with pytest.raises(ValueError, match="is not frozen"):
            outcomes.trial_rows(conn, "baseline-v1", include_holdout=True)

        # Re-freeze ruleset but clear manifest_sha256
        conn.execute("UPDATE ruleset SET frozen_at = '2026-11-19T00:00:00Z', manifest_sha256 = NULL WHERE ruleset_version = 'baseline-v1'")
        with pytest.raises(ValueError, match="no cryptographic manifest hash"):
            outcomes.trial_rows(conn, "baseline-v1", include_holdout=True)

        # Set manifest_sha256 but clear git_sha
        conn.execute("UPDATE ruleset SET manifest_sha256 = 'b20e7084fbf6ad51f691ef8beabdf29e1b31e3b51c0613659ce7f8932bc4e311', git_sha = NULL WHERE ruleset_version = 'baseline-v1'")
        with pytest.raises(ValueError, match="no registered git_sha commit identifier"):
            outcomes.trial_rows(conn, "baseline-v1", include_holdout=True)

        # Restore valid manifest hash and git_sha, but tamper with a rule body
        original_manifest = "b20e7084fbf6ad51f691ef8beabdf29e1b31e3b51c0613659ce7f8932bc4e311"
        conn.execute(
            "UPDATE ruleset SET manifest_sha256 = ?, git_sha = '9b103b1cd162cf031fdd3ca0abe7aa54ee828607' WHERE ruleset_version = 'baseline-v1'",
            (original_manifest,),
        )
        conn.execute(
            "UPDATE rule SET body = 'modified: rule' WHERE rowid = (SELECT rowid FROM rule WHERE ruleset_version = 'baseline-v1' LIMIT 1)"
        )
        with pytest.raises(ValueError, match="manifest integrity check failed"):
            outcomes.trial_rows(conn, "baseline-v1", include_holdout=True)

        # Reload cleanly and verify valid holdout evaluation succeeds
        conn.execute("DELETE FROM rule WHERE ruleset_version = 'baseline-v1'")
        conn.execute("DELETE FROM ruleset WHERE ruleset_version = 'baseline-v1'")
        replay.load_ruleset(conn, "baseline-v1")
        rows = outcomes.trial_rows(conn, "baseline-v1", include_holdout=True)
        assert rows

        # Verify holdout variants are completely excluded when include_holdout=False (sealed)
        standard_rows = outcomes.trial_rows(conn, "baseline-v1", include_holdout=False)
        assert all(r["variant_set"] != "holdout" for r in standard_rows)
    finally:
        conn.close()


def test_frozen_ruleset_immutability_enforced(tmp_path) -> None:
    path = tmp_path / "immutability.db"
    init_db(path, drop=True)
    conn = connect(path)
    try:
        loader.load_techniques(conn)
        replay.load_ruleset(conn, "baseline-v1")
        # Try to modify ruleset with an altered fake manifest in config
        with pytest.raises(ValueError, match="Ruleset manifest mismatch"):
            custom_config = tmp_path / "custom_rulesets.yaml"
            custom_config.write_text(
                "rulesets:\n"
                "  baseline-v1:\n"
                "    sigma_dirs: [conf/rules/baseline]\n"
                "    include_python_rules: true\n"
                "    frozen_at: '2026-11-19T00:00:00Z'\n"
                "    manifest_sha256: 'tampered-hash-00000000000000000000000000000000000000000000'\n",
                encoding="utf-8",
            )
            replay.load_ruleset(conn, "baseline-v1", rulesets_path=custom_config)
    finally:
        conn.close()


def test_zero_event_trial_is_never_classified_as_evasion(tmp_path) -> None:
    path = tmp_path / "zero_event.db"
    init_db(path, drop=True)
    conn = connect(path)
    try:
        loader.load_techniques(conn)
        loader.load_fixtures(conn)
        conn.execute(
            "INSERT INTO lab_run (run_id, started_at, aws_account_id, region, ruleset_version, synthetic)"
            " VALUES ('r0', '2026-11-19T09:00:00Z', '123456789012', 'eu-west-1', 'baseline-v1', 0)"
        )
        conn.execute(
            "INSERT INTO variant (variant_id, technique_id, variant_set, factor_levels, seed, spec_sha256)"
            " VALUES ('v0', 'T1530', 'baseline', '{}', 1, 'sha')"
        )
        # Succeeded attack, but ZERO events in event table
        conn.execute(
            "INSERT INTO trial (trial_id, run_id, variant_id, repetition, window_start, attack_succeeded, variant_changed)"
            " VALUES ('t0', 'r0', 'v0', 1, '2026-11-19T09:00:00Z', 1, 0)"
        )
        summary = outcomes.summarise(conn, "baseline-v1", run_id="r0")
        assert summary["overall"]["attempted"] == 1
        assert summary["overall"]["valid"] == 0
        assert summary["overall"]["evaded"] == 0
        assert summary["overall"]["invalid_or_unverified"] == 1
    finally:
        conn.close()
