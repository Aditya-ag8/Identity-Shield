from __future__ import annotations

from datetime import datetime, timezone
import pytest

from aws_fakes import FakeClient
from identity_shield.contracts import Variant, spec_hash
from identity_shield.runner import preflight
from identity_shield.runner.models import TrialContext
from identity_shield.variants.loader import load_catalogue


def _ctx(*, synthetic: bool = False, region: str = "eu-west-1", account_id: str = "123456789012") -> TrialContext:
    catalogue = load_catalogue()
    technique = catalogue.technique("T1087.004")
    variant = Variant(
        variant_id="T1087.004-base-0",
        technique_id="T1087.004",
        variant_set="baseline",
        factor_levels={"timing": "business_hours"},
        seed=1,
        spec_sha256=spec_hash("T1087.004", {"timing": "business_hours"}),
    )
    return TrialContext(
        run_id="run-1",
        variant=variant,
        technique=technique,
        repetition=1,
        account_id=account_id,
        region=region,
        synthetic=synthetic,
        lab={"trail_name": "identity-shield-trail", "queue_url": "https://sqs.queue"},
    )


def test_preflight_synthetic_skips_aws():
    ctx = _ctx(synthetic=True)
    report = preflight.run_preflight(ctx)
    assert report.ok
    assert len(report.checks) == 1
    assert report.checks[0].name == "synthetic"


def test_preflight_disallowed_region_fails():
    ctx = _ctx(region="ap-southeast-1")
    report = preflight.run_preflight(ctx, clients={
        "sts": FakeClient({"get_caller_identity": {"Account": "123456789012"}}),
        "cloudtrail": FakeClient({
            "describe_trails": {"trailList": [{"Name": "identity-shield-trail"}]},
            "get_trail_status": {"IsLogging": True, "LatestDeliveryTime": datetime.now(timezone.utc)},
        }),
        "sqs": FakeClient({"get_queue_attributes": {}}),
        "resourcegroupstaggingapi": FakeClient({"get_resources": {"ResourceTagMappingList": []}}),
        "iam": FakeClient({"simulate_principal_policy": {"EvaluationResults": [{"EvalDecision": "allowed"}]}}),
    })
    assert not report.ok
    assert any(c.name == "region" and c.status == "fail" for c in report.checks)


def test_preflight_account_mismatch_fails():
    ctx = _ctx(account_id="123456789012")
    clients = {
        "sts": FakeClient({"get_caller_identity": {"Account": "999999999999"}}),
        "cloudtrail": FakeClient({
            "describe_trails": {"trailList": [{"Name": "identity-shield-trail"}]},
            "get_trail_status": {"IsLogging": True, "LatestDeliveryTime": datetime.now(timezone.utc)},
        }),
        "sqs": FakeClient({"get_queue_attributes": {}}),
        "resourcegroupstaggingapi": FakeClient({"get_resources": {"ResourceTagMappingList": []}}),
        "iam": FakeClient({"simulate_principal_policy": {"EvaluationResults": [{"EvalDecision": "allowed"}]}}),
    }
    report = preflight.run_preflight(ctx, clients=clients)
    assert not report.ok
    assert any(c.name == "identity" and c.status == "fail" for c in report.checks)


def test_preflight_stopped_trail_fails():
    ctx = _ctx()
    clients = {
        "sts": FakeClient({"get_caller_identity": {"Account": "123456789012"}}),
        "cloudtrail": FakeClient({
            "describe_trails": {"trailList": [{"Name": "identity-shield-trail"}]},
            "get_trail_status": {"IsLogging": False},
        }),
        "sqs": FakeClient({"get_queue_attributes": {}}),
        "resourcegroupstaggingapi": FakeClient({"get_resources": {"ResourceTagMappingList": []}}),
        "iam": FakeClient({"simulate_principal_policy": {"EvaluationResults": [{"EvalDecision": "allowed"}]}}),
    }
    report = preflight.run_preflight(ctx, clients=clients)
    assert not report.ok
    assert any(c.name == "trail" and c.status == "fail" for c in report.checks)


def test_preflight_boundary_denial_fails():
    ctx = _ctx()
    clients = {
        "sts": FakeClient({"get_caller_identity": {"Account": "123456789012", "Arn": "arn:aws:iam::123:user/test"}}),
        "cloudtrail": FakeClient({
            "describe_trails": {"trailList": [{"Name": "identity-shield-trail"}]},
            "get_trail_status": {"IsLogging": True, "LatestDeliveryTime": datetime.now(timezone.utc)},
        }),
        "sqs": FakeClient({"get_queue_attributes": {}}),
        "resourcegroupstaggingapi": FakeClient({"get_resources": {"ResourceTagMappingList": []}}),
        "iam": FakeClient({
            "simulate_principal_policy": {
                "EvaluationResults": [
                    {"EvalActionName": "iam:ListUsers", "EvalDecision": "allowed"},
                    {"EvalActionName": "iam:ListRoles", "EvalDecision": "explicitDeny"},
                ]
            }
        }),
    }
    report = preflight.run_preflight(ctx, clients=clients)
    assert not report.ok
    assert any(c.name == "permissions" and c.status == "fail" for c in report.checks)
