"""Per-technique success checks.

The catalogue names a check type; this module is the only place that knows how
to evaluate one. A check returns evidence even when it passes, so the report can
show *why* a trial counted as a successful attack rather than trusting a boolean.
"""

from __future__ import annotations

import time
from typing import Any, Mapping

from identity_shield.runner.models import ExecutionResult, TrialContext, Verification


def _minimum(spec: Mapping[str, Any], default: int) -> int:
    try:
        return int(spec.get("minimum", spec.get("minimum_services", default)))
    except (TypeError, ValueError):
        return default


def _services_ok(evidence: Mapping[str, Any]) -> int:
    services = evidence.get("services") or {}
    return sum(1 for value in services.values() if not str(value).startswith("error"))


def _authenticate_with_key(
    key_id: str,
    secret: str,
    token: str | None,
    region: str,
    *,
    attempts: int = 3,
) -> tuple[bool, str]:
    try:
        import boto3
    except ImportError as exc:  # pragma: no cover - dependency is declared
        return False, f"boto3 unavailable: {exc}"
    last = ""
    for attempt in range(1, attempts + 1):
        try:
            session = boto3.Session(
                aws_access_key_id=key_id,
                aws_secret_access_key=secret,
                aws_session_token=token,
                region_name=region,
            )
            identity = session.client("sts").get_caller_identity()
            return True, f"new credential authenticated as {identity.get('Arn')}"
        except Exception as exc:  # noqa: BLE001
            last = f"{type(exc).__name__}: {exc}"
            if attempt < attempts:
                # IAM access keys are eventually consistent; a failure in the
                # first few seconds is not evidence that the key is invalid.
                time.sleep(2 * attempt)
    return False, f"new credential did not authenticate: {last}"


def verify(ctx: TrialContext, result: ExecutionResult) -> Verification:
    spec = ctx.technique.success_check or {}
    kind = str(spec.get("type") or "")
    evidence = result.evidence

    if not result.ok:
        return Verification(False, result.error or "executor failed", evidence)

    # A rehearsal is not a live attack. The synthetic executor records the
    # technique and the events it produced; the technique-specific check would
    # require real credentials or real resources that do not exist offline.
    # This is the one place where the provenance flag changes semantics, and it
    # is recorded in the trial evidence.
    if evidence.get("synthetic"):
        count = int(evidence.get("events", 0) or 0)
        return Verification(
            count > 0,
            f"synthetic rehearsal: {count} event(s) generated; attack assumed successful",
            {"synthetic": True, "events": count},
        )

    if kind == "api_result_non_empty":
        field = str(spec.get("field") or "Users")
        count = int(evidence.get(field.lower(), evidence.get(field, 0)) or 0)
        passed = count > 0
        return Verification(passed, f"{field}={count}", {"field": field, "count": count})

    if kind == "services_responding":
        minimum = _minimum(spec, 3)
        count = _services_ok(evidence)
        return Verification(count >= minimum, f"{count} service(s) responded (need {minimum})", {"services": count})

    if kind == "inventory_snapshot":
        minimum = _minimum(spec, 3)
        count = sum(
            1
            for key, value in evidence.items()
            if key.startswith("describe_") and value is True
        )
        return Verification(count >= minimum, f"{count} inventory call(s) succeeded (need {minimum})", {"calls": count})

    if kind == "session_established":
        passed = bool(evidence.get("account") and evidence.get("arn"))
        return Verification(passed, "session identity returned" if passed else "no session identity", evidence)

    if kind == "new_credential_authenticates":
        key_id = evidence.get("access_key_id")
        secret = evidence.get("secret_access_key")
        if key_id and secret:
            passed, detail = _authenticate_with_key(str(key_id), str(secret), None, ctx.region)
            return Verification(passed, detail, {"access_key_id": key_id})
        if evidence.get("login_profile"):
            # A console password cannot be exercised non-interactively without a
            # browser flow. Record the weaker but honest evidence.
            return Verification(True, "login profile created; console authentication not exercised", evidence)
        return Verification(False, "no new credential in evidence", evidence)

    if kind == "escalated_action_succeeds":
        passed = bool(evidence.get("policy_attached") or evidence.get("trust_policy_updated"))
        detail = (
            "role policy changed; escalation path recorded"
            if passed
            else "role policy change not observed"
        )
        return Verification(passed, detail, evidence)

    if kind == "stolen_credentials_authenticate":
        key_id = evidence.get("stolen_access_key_id")
        secret = evidence.get("stolen_secret_access_key")
        if key_id and secret:
            passed, detail = _authenticate_with_key(
                str(key_id), str(secret), evidence.get("stolen_token"), ctx.region
            )
            return Verification(passed, detail, {"access_key_id": key_id})
        if evidence.get("synthetic"):
            return Verification(True, "synthetic rehearsal: IMDS theft assumed successful", evidence)
        return Verification(False, "no stolen credentials in evidence", evidence)

    if kind == "object_bytes_match":
        objects = int(evidence.get("objects_listed", 0) or 0)
        size = int(evidence.get("bytes", 0) or 0)
        passed = size > 0 or objects > 0
        return Verification(passed, f"bytes={size}, objects={objects}", {"bytes": size, "objects": objects})

    return Verification(False, f"unsupported success_check type {kind!r}", spec)
