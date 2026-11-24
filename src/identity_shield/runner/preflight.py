"""Hard preflight checks for a live trial.

A warning is never enough for these: a boundary that blocks the attack looks
exactly like an evasion in the results, and a stopped trail looks exactly like a
detection failure. Each check therefore fails closed.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Mapping

from identity_shield.runner.models import PreflightCheck, PreflightReport, TrialContext

ALLOWED_REGIONS = {"eu-west-1", "us-east-1", "us-west-2"}
MAX_DELIVERY_LAG_SECONDS = 15 * 60


def _client(ctx: TrialContext, service: str, clients: Mapping[str, Any] | None = None):
    if clients and service in clients:
        return clients[service]
    if ctx.synthetic:
        raise RuntimeError("synthetic trials do not call AWS")
    if getattr(ctx, "session", None) is None:
        raise RuntimeError("no AWS session supplied")
    return ctx.session.client(service, region_name=ctx.region)  # type: ignore[attr-defined]


def _check_identity(ctx: TrialContext, clients: Mapping[str, Any] | None) -> PreflightCheck:
    try:
        identity = _client(ctx, "sts", clients).get_caller_identity()
    except Exception as exc:  # pragma: no cover - live AWS path
        return PreflightCheck("identity", "fail", f"sts:GetCallerIdentity failed: {exc}")
    account = str(identity.get("Account") or "")
    if ctx.account_id and account != ctx.account_id:
        return PreflightCheck(
            "identity",
            "fail",
            f"caller account {account} != expected lab account {ctx.account_id}",
        )
    return PreflightCheck("identity", "ok", f"account {account}")


def _check_region(ctx: TrialContext) -> PreflightCheck:
    if ctx.region not in ALLOWED_REGIONS:
        return PreflightCheck(
            "region",
            "fail",
            f"region {ctx.region} is not in the allow-list {sorted(ALLOWED_REGIONS)}",
        )
    return PreflightCheck("region", "ok", ctx.region)


def _trail_name(ctx: TrialContext) -> str:
    return str(ctx.lab.get("trail_name") or "identity-shield-trail")


def _check_trail(ctx: TrialContext, clients: Mapping[str, Any] | None) -> PreflightCheck:
    client = _client(ctx, "cloudtrail", clients)
    try:
        trails = client.describe_trails(includeShadowTrails=False).get("trailList", [])
        names = {trail.get("Name") for trail in trails}
        if _trail_name(ctx) not in names:
            return PreflightCheck(
                "trail",
                "fail",
                f"trail {_trail_name(ctx)!r} not found; found {sorted(n for n in names if n)}",
            )
        status = client.get_trail_status(Name=_trail_name(ctx))
    except Exception as exc:  # pragma: no cover - live AWS path
        return PreflightCheck("trail", "fail", f"CloudTrail status failed: {exc}")

    if not status.get("IsLogging"):
        return PreflightCheck("trail", "fail", "trail is not logging")
    latest = status.get("LatestDeliveryTime")
    if latest is None:
        return PreflightCheck("trail", "warn", "trail is logging; no delivery timestamp yet")
    moment = latest if isinstance(latest, datetime) else datetime.fromisoformat(str(latest))
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    lag = (datetime.now(timezone.utc) - moment).total_seconds()
    if lag > MAX_DELIVERY_LAG_SECONDS:
        return PreflightCheck(
            "trail",
            "fail",
            f"last delivery was {lag / 60:.1f} min ago (> {MAX_DELIVERY_LAG_SECONDS / 60:.0f})",
        )
    return PreflightCheck("trail", "ok", f"logging, last delivery {lag:.0f}s ago")


def _check_queue(ctx: TrialContext, clients: Mapping[str, Any] | None) -> PreflightCheck:
    queue_url = ctx.lab.get("queue_url")
    if not queue_url:
        return PreflightCheck("collector_queue", "warn", "no queue_url configured")
    try:
        _client(ctx, "sqs", clients).get_queue_attributes(
            QueueUrl=str(queue_url), AttributeNames=["ApproximateNumberOfMessages"]
        )
    except Exception as exc:  # pragma: no cover - live AWS path
        return PreflightCheck("collector_queue", "fail", f"SQS queue unreachable: {exc}")
    return PreflightCheck("collector_queue", "ok", str(queue_url))


def _check_duplicate(ctx: TrialContext, clients: Mapping[str, Any] | None) -> PreflightCheck:
    try:
        response = _client(ctx, "resourcegroupstaggingapi", clients).get_resources(
            TagFilters=[
                {"Key": "identity-shield:run_id", "Values": [ctx.run_id]},
                {"Key": "identity-shield:variant", "Values": [ctx.variant.variant_id]},
            ]
        )
    except Exception as exc:  # pragma: no cover - live AWS path
        return PreflightCheck("duplicate_run", "warn", f"tag lookup unavailable: {exc}")
    resources = response.get("ResourceTagMappingList", [])
    if resources:
        return PreflightCheck(
            "duplicate_run",
            "fail",
            f"{len(resources)} resource(s) already tagged for this run/variant",
        )
    return PreflightCheck("duplicate_run", "ok", "no leftover tagged resources")


def _role_arn(caller_arn: str) -> str:
    # arn:aws:sts::acct:assumed-role/role/session -> arn:aws:iam::acct:role/role
    parts = caller_arn.split(":")
    if len(parts) < 6 or "assumed-role" not in parts[5]:
        return caller_arn
    resource = parts[5].split("/")
    if len(resource) < 2:
        return caller_arn
    return f"{parts[0]}:{parts[1]}:iam::{parts[4]}:role/{resource[1]}"


def _check_permissions(ctx: TrialContext, clients: Mapping[str, Any] | None) -> PreflightCheck:
    actions = list(ctx.technique.required_actions)
    if not actions:
        return PreflightCheck("permissions", "warn", "technique declares no required_actions")
    try:
        identity = _client(ctx, "sts", clients).get_caller_identity()
        caller = _role_arn(str(identity.get("Arn") or ""))
        response = _client(ctx, "iam", clients).simulate_principal_policy(
            PolicySourceArn=caller,
            ActionNames=actions,
        )
    except Exception as exc:  # pragma: no cover - live AWS path
        return PreflightCheck("permissions", "fail", f"SimulatePrincipalPolicy failed: {exc}")
    denied = [
        row.get("EvalActionName")
        for row in response.get("EvaluationResults", [])
        if row.get("EvalDecision") != "allowed"
    ]
    if denied:
        return PreflightCheck(
            "permissions",
            "fail",
            "boundary would block: " + ", ".join(str(action) for action in denied),
        )
    return PreflightCheck("permissions", "ok", f"{len(actions)} action(s) allowed")


def _check_capability(ctx: TrialContext) -> PreflightCheck:
    from identity_shield.runner.capabilities import check_technique_capability

    cap = check_technique_capability(
        ctx.technique.technique_id,
        ctx.lab,
        synthetic=ctx.synthetic,
    )
    if not cap.available:
        return PreflightCheck(
            "technique_capability",
            "fail",
            f"Technique {ctx.technique.technique_id} unavailable for live execution: {cap.reason}",
        )
    return PreflightCheck(
        "technique_capability",
        "ok",
        f"Available: {cap.reason}",
    )


def run_preflight(
    ctx: TrialContext,
    *,
    clients: Mapping[str, Any] | None = None,
    include_duplicate: bool = True,
) -> PreflightReport:
    if ctx.synthetic:
        return PreflightReport(
            (PreflightCheck("synthetic", "ok", "offline rehearsal: AWS checks intentionally skipped"),)
        )
    checks = [
        _check_identity(ctx, clients),
        _check_region(ctx),
        _check_trail(ctx, clients),
        _check_queue(ctx, clients),
        _check_capability(ctx),
        _check_permissions(ctx, clients),
    ]
    if include_duplicate:
        checks.append(_check_duplicate(ctx, clients))
    return PreflightReport(tuple(checks))
