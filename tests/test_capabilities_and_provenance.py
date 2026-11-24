"""Tests for technique capability gating and live factor provenance."""

from __future__ import annotations

from typing import Any
import pytest

from identity_shield.contracts import Variant, spec_hash
from identity_shield.runner.capabilities import capability_matrix, check_technique_capability
from identity_shield.runner.models import ExecutionResult, TrialContext
from identity_shield.runner.preflight import run_preflight
from identity_shield.runner.provenance import record_factor_provenance
from identity_shield.variants.loader import load_catalogue


def _ctx(technique_id: str, factor_levels: dict[str, str], lab: dict[str, Any], *, synthetic: bool = False) -> TrialContext:
    catalogue = load_catalogue()
    technique = catalogue.technique(technique_id)
    variant = Variant(
        variant_id=f"{technique_id}-test",
        technique_id=technique_id,
        variant_set="baseline",
        factor_levels=factor_levels,
        seed=1,
        spec_sha256=spec_hash(technique_id, factor_levels),
    )
    return TrialContext(
        run_id="run-test",
        variant=variant,
        technique=technique,
        repetition=1,
        account_id="123456789012",
        region="eu-west-1",
        lab=lab,
        synthetic=synthetic,
    )


def test_technique_capability_matrix_under_default_cost_controls():
    """Under default cost controls (enable_data_events=false, enable_instance=false),

    T1530 and T1552.005 must be marked unavailable for live execution.
    """
    default_lab = {
        "enable_data_events": False,
        "enable_instance": False,
        "instance_id": "",
        "data_bucket": "is-lab-crown-jewels",
    }
    matrix = capability_matrix(default_lab, synthetic=False)

    assert matrix["T1087.004"]["available"] is True
    assert matrix["T1526"]["available"] is True
    assert matrix["T1580"]["available"] is True
    assert matrix["T1078.004"]["available"] is True
    assert matrix["T1098.001"]["available"] is True
    assert matrix["T1098.003"]["available"] is True

    # Gated techniques:
    assert matrix["T1552.005"]["available"] is False
    assert "enable_instance=true" in matrix["T1552.005"]["reason"]

    assert matrix["T1530"]["available"] is False
    assert "enable_data_events=true" in matrix["T1530"]["reason"]


def test_technique_capability_when_features_enabled():
    """When enable_data_events and enable_instance are true, all techniques are available."""
    full_lab = {
        "enable_data_events": True,
        "enable_instance": True,
        "instance_id": "i-0123456789abcdef0",
        "data_bucket": "is-lab-crown-jewels",
    }
    matrix = capability_matrix(full_lab, synthetic=False)
    for tech_id, cap in matrix.items():
        assert cap["available"] is True, f"{tech_id} should be available"


def test_synthetic_rehearsal_preserves_availability_for_all_techniques():
    """Synthetic rehearsal is always available regardless of live lab configuration."""
    empty_lab = {
        "enable_data_events": False,
        "enable_instance": False,
    }
    matrix = capability_matrix(empty_lab, synthetic=True)
    for tech_id, cap in matrix.items():
        assert cap["available"] is True, f"{tech_id} must be available in synthetic rehearsal"


def test_preflight_fails_when_technique_is_unavailable():
    """Live preflight rejects execution of a technique whose required feature is disabled."""
    ctx = _ctx(
        "T1530",
        {"api_form": "canonical"},
        {"enable_data_events": False},
        synthetic=False,
    )
    # Fake client to satisfy other checks
    from aws_fakes import FakeClient
    clients = {
        "sts": FakeClient({"get_caller_identity": {"Account": "123456789012", "Arn": "arn:aws:iam::123456789012:user/op"}}),
        "cloudtrail": FakeClient({
            "describe_trails": {"trailList": [{"Name": "identity-shield-trail"}]},
            "get_trail_status": {"IsLogging": True, "LatestDeliveryTime": "2026-11-22T19:00:00Z"},
        }),
        "sqs": FakeClient({"get_queue_attributes": {"Attributes": {}}}),
        "iam": FakeClient({"simulate_principal_policy": {"EvaluationResults": [{"EvalDecision": "allowed"}]}}),
        "resourcegroupstaggingapi": FakeClient({"get_resources": {"ResourceTagMappingList": []}}),
    }
    report = run_preflight(ctx, clients=clients)
    assert not report.ok
    cap_failures = [f for f in report.failures if f.name == "technique_capability"]
    assert len(cap_failures) == 1
    assert "enable_data_events=true" in cap_failures[0].detail


def test_factor_provenance_distinguishes_genuine_partial_and_synthetic():
    """Verifies that factor mutations are honestly classified."""
    # 1. Partial User-Agent change (not CLI execution)
    ctx_cli = _ctx("T1087.004", {"client_tool": "aws_cli", "network_origin": "alternate_endpoint", "timing": "off_hours", "api_form": "alternative_api"}, {})
    res = ExecutionResult(ok=True, evidence={"api_form": "alternative_api"})
    prov = record_factor_provenance(ctx_cli, res)

    # client_tool: partial
    tool = prov["factors"]["client_tool"]
    assert tool["mutation_type"] == "partial"
    assert "NOT a genuine aws_cli binary" in tool["detail"]

    # network_origin: partial
    net = prov["factors"]["network_origin"]
    assert net["mutation_type"] == "partial"
    assert "Client source IP is NOT modified" in net["detail"]

    # timing: synthetic-only
    timing = prov["factors"]["timing"]
    assert timing["mutation_type"] == "synthetic-only"

    # api_form: genuine
    api = prov["factors"]["api_form"]
    assert api["mutation_type"] == "genuine"

    assert prov["is_fully_genuine"] is False
    assert prov["provenance_summary"]["partial"] >= 2


def test_factor_provenance_synthetic_marks_all_synthetic_only():
    """In synthetic mode, all factors are classified as synthetic-only."""
    ctx_synth = _ctx("T1087.004", {"client_tool": "aws_cli", "network_origin": "nat_a"}, {}, synthetic=True)
    res = ExecutionResult(ok=True, evidence={})
    prov = record_factor_provenance(ctx_synth, res)

    for factor_name, data in prov["factors"].items():
        assert data["mutation_type"] == "synthetic-only"
    assert prov["is_fully_genuine"] is False
    assert prov["provenance_summary"]["synthetic_only"] == 5
