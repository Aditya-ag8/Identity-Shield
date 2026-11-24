from __future__ import annotations

import dataclasses
from typing import Any
import pytest

from identity_shield.contracts import Variant, spec_hash
from identity_shield.runner.models import ExecutionResult, TrialContext
from identity_shield.runner.verifiers import verify
from identity_shield.variants.loader import load_catalogue


def _ctx(check_type: str, spec_kwargs: dict[str, Any] | None = None) -> TrialContext:
    catalogue = load_catalogue()
    base_tech = catalogue.technique("T1087.004")
    check = {"type": check_type}
    if spec_kwargs:
        check.update(spec_kwargs)
    technique = dataclasses.replace(base_tech, success_check=check)
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
        account_id="123456789012",
        region="eu-west-1",
    )


def test_verify_returns_failure_when_execution_result_is_not_ok():
    ctx = _ctx("api_result_non_empty")
    res = ExecutionResult(ok=False, error="boto3 AccessDenied")
    v = verify(ctx, res)
    assert not v.passed
    assert "AccessDenied" in v.detail


def test_verify_synthetic_assumes_success_when_events_present():
    ctx = _ctx("api_result_non_empty")
    res = ExecutionResult(ok=True, evidence={"synthetic": True, "events": 2})
    v = verify(ctx, res)
    assert v.passed
    assert "synthetic" in v.detail


def test_verify_api_result_non_empty():
    ctx = _ctx("api_result_non_empty", {"field": "Users"})
    passed = verify(ctx, ExecutionResult(ok=True, evidence={"users": 5}))
    assert passed.passed
    assert "Users=5" in passed.detail

    failed = verify(ctx, ExecutionResult(ok=True, evidence={"users": 0}))
    assert not failed.passed


def test_verify_services_responding():
    ctx = _ctx("services_responding", {"minimum": 2})
    passed = verify(
        ctx,
        ExecutionResult(
            ok=True,
            evidence={"services": {"s3": True, "ec2": True, "rds": "error: AccessDenied"}},
        ),
    )
    assert passed.passed

    failed = verify(
        ctx,
        ExecutionResult(
            ok=True,
            evidence={"services": {"s3": "error: AccessDenied", "ec2": "error: AccessDenied"}},
        ),
    )
    assert not failed.passed


def test_verify_inventory_snapshot():
    ctx = _ctx("inventory_snapshot", {"minimum_services": 2})
    passed = verify(
        ctx,
        ExecutionResult(
            ok=True,
            evidence={"describe_instances": True, "describe_subnets": True},
        ),
    )
    assert passed.passed

    failed = verify(
        ctx,
        ExecutionResult(ok=True, evidence={"describe_instances": True}),
    )
    assert not failed.passed


def test_verify_session_established():
    ctx = _ctx("session_established")
    passed = verify(
        ctx,
        ExecutionResult(
            ok=True,
            evidence={"account": "123456789012", "arn": "arn:aws:iam::123:user/op"},
        ),
    )
    assert passed.passed

    failed = verify(ctx, ExecutionResult(ok=True, evidence={}))
    assert not failed.passed


def test_verify_new_credential_login_profile():
    ctx = _ctx("new_credential_authenticates")
    passed = verify(
        ctx,
        ExecutionResult(ok=True, evidence={"login_profile": True}),
    )
    assert passed.passed
    assert "login profile created" in passed.detail


def test_verify_escalated_action_succeeds():
    ctx = _ctx("escalated_action_succeeds")
    passed_policy = verify(
        ctx,
        ExecutionResult(ok=True, evidence={"policy_attached": True}),
    )
    assert passed_policy.passed

    passed_trust = verify(
        ctx,
        ExecutionResult(ok=True, evidence={"trust_policy_updated": True}),
    )
    assert passed_trust.passed

    failed = verify(ctx, ExecutionResult(ok=True, evidence={}))
    assert not failed.passed


def test_verify_stolen_credentials_synthetic():
    ctx = _ctx("stolen_credentials_authenticate")
    res = ExecutionResult(ok=True, evidence={"synthetic": True, "events": 1})
    v = verify(ctx, res)
    assert v.passed


def test_verify_object_bytes_match():
    ctx = _ctx("object_bytes_match")
    passed_bytes = verify(
        ctx,
        ExecutionResult(ok=True, evidence={"bytes": 1024}),
    )
    assert passed_bytes.passed

    passed_objects = verify(
        ctx,
        ExecutionResult(ok=True, evidence={"objects_listed": 3}),
    )
    assert passed_objects.passed

    failed = verify(
        ctx,
        ExecutionResult(ok=True, evidence={"bytes": 0, "objects_listed": 0}),
    )
    assert not failed.passed


def test_verify_unsupported_type_fails():
    ctx = _ctx("completely_unknown_type")
    res = ExecutionResult(ok=True, evidence={})
    v = verify(ctx, res)
    assert not v.passed
    assert "unsupported" in v.detail
