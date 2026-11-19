"""Environment preflight for the lab.

Every check reports one of three states and, when it fails, what to do about it.
The point is to fail here — with a remedy — rather than halfway through an apply
that has already created a bucket.

``doctor`` never raises. A missing Terraform install is a finding, not an
exception.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from identity_shield import config
from identity_shield.contracts import utc_now
from identity_shield.lab import provision
from identity_shield.lab.aws import GuardedSession
from identity_shield.lab.models import Check, DoctorReport


def _terraform_check() -> Check:
    if not provision.available():
        return Check(
            name="terraform",
            status="fail",
            detail="not installed or not on PATH",
            remedy="winget install Hashicorp.Terraform (then open a new shell)",
        )
    return Check(name="terraform", status="ok", detail=f"{provision.version() or 'unknown version'}")


def _workdir_check(directory: str | Path | None) -> Check:
    root = Path(directory) if directory else config.TERRAFORM_LAB
    if (root / "main.tf").is_file():
        return Check(name="terraform root", status="ok", detail=str(root))
    return Check(
        name="terraform root",
        status="fail",
        detail=f"no main.tf in {root}",
        remedy="run from the repository root, or pass --workdir infra/terraform/envs/lab",
    )


def _credentials_check(session: GuardedSession) -> Check:
    if session.has_credentials():
        return Check(name="credentials", status="ok", detail="boto3 resolved a credential chain")
    return Check(
        name="credentials",
        status="fail",
        detail="boto3 found no credentials",
        remedy="set AWS_PROFILE or AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY for the lab account",
    )


def _identity_check(session: GuardedSession) -> Check:
    try:
        account_id = session.account_id()
    except Exception as exc:
        return Check(
            name="identity",
            status="fail",
            detail=f"sts:GetCallerIdentity failed: {exc}",
            remedy="check the credential source and network access to sts.amazonaws.com",
        )
    return Check(name="identity", status="ok", detail=f"account {account_id}")


def _organization_check(session: GuardedSession) -> Check:
    try:
        client = session.raw_client("organizations")
        organization = client.describe_organization().get("Organization") or {}
    except Exception as exc:
        code = ""
        response = getattr(exc, "response", None)
        if isinstance(response, dict):
            code = str((response.get("Error") or {}).get("Code") or "")
        if code in ("AWSOrganizationsNotInUseException", "AccessDeniedException"):
            return Check(
                name="organization",
                status="warn",
                detail=f"cannot determine ({code}); SCP guardrails will be disabled",
                remedy="enable SCPs only if the lab account is inside an Organization",
            )
        return Check(
            name="organization",
            status="warn",
            detail=f"describe_organization failed: {exc}",
            remedy="not fatal: pass enable_scps=false if the account is standalone",
        )

    organization_id = str(organization.get("Id") or "unknown")
    feature_set = str(organization.get("FeatureSet") or "unknown")
    if feature_set.upper() != "ALL":
        return Check(
            name="organization",
            status="warn",
            detail=f"org {organization_id} has FeatureSet={feature_set}; SCPs need ALL",
            remedy="enable all features in Organizations, or apply with enable_scps=false",
        )
    return Check(
        name="organization",
        status="ok",
        detail=f"org {organization_id}, FeatureSet={feature_set}, SCPs available",
    )


def _region_check(session: GuardedSession, region: str | None) -> Check:
    resolved = region or session.region
    if not resolved:
        return Check(
            name="region",
            status="warn",
            detail="no region resolved from arguments, environment or profile",
            remedy="pass --region or set AWS_REGION",
        )
    return Check(name="region", status="ok", detail=str(resolved))


def run_doctor(
    *,
    directory: str | Path | None = None,
    region: str | None = None,
    session: GuardedSession | None = None,
) -> DoctorReport:
    session = session or GuardedSession(region_name=region)
    checks: list[Check] = [
        _terraform_check(),
        _workdir_check(directory),
        _credentials_check(session),
        _region_check(session, region),
    ]

    if session.has_credentials():
        checks.append(_identity_check(session))
        checks.append(_organization_check(session))
    else:
        checks.append(
            Check(
                name="identity",
                status="fail",
                detail="not checked: no credentials",
                remedy="configure credentials, then re-run `identity-shield lab doctor`",
            )
        )

    return DoctorReport(
        generated_at=utc_now(),
        region=str(region or session.region or ""),
        checks=tuple(checks),
    )


def summarise(report: DoctorReport) -> str:
    lines = []
    width = max((len(check.name) for check in report.checks), default=10)
    for check in report.checks:
        lines.append(f"[{check.status.upper():<4}] {check.name:<{width}}  {check.detail}")
        if check.remedy:
            lines.append(f"       {' ' * width}  -> {check.remedy}")
    lines.append("")
    lines.append("ready to apply" if report.ok else f"{len(report.failures)} blocking issue(s)")
    return "\n".join(lines)


def as_dict(report: DoctorReport) -> dict[str, Any]:
    return report.to_dict()
