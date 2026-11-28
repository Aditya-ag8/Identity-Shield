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


def run_gcp_doctor(
    *,
    connection_status: dict[str, Any] | None = None,
    bound: dict[str, Any] | None = None,
) -> DoctorReport:
    """Environment preflight checks for Google Cloud (GCP) Cloud Audit & Lab targets."""
    import shutil

    st = dict(connection_status or {})
    bnd = dict(bound or {})
    desc = dict(st.get("descriptor") or {})
    ident = dict(st.get("identity") or {})
    region = str(bnd.get("gcp_region") or desc.get("region") or "us-central1")
    checks: list[Check] = []

    gcloud_bin = shutil.which("gcloud")
    if gcloud_bin:
        checks.append(Check(name="gcloud cli", status="ok", detail=gcloud_bin))
    else:
        checks.append(
            Check(
                name="gcloud cli",
                status="warn",
                detail="gcloud CLI not found on PATH (Service Account JSON / Workload Identity / Token modes still work via HTTPS REST)",
                remedy="Install Google Cloud SDK or connect via Service Account JSON / Token",
            )
        )

    if st.get("connected"):
        principal = str(ident.get("principal") or desc.get("service_account") or "authenticated")
        mode = str(desc.get("auth_mode") or "gcloud_adc")
        checks.append(Check(name="gcp session", status="ok", detail=f"{principal} ({mode})"))
    else:
        checks.append(
            Check(
                name="gcp session",
                status="fail",
                detail="GCP session offline",
                remedy="Connect GCP in Connections (gcloud ADC, SA Impersonation, SA JSON, Workload Identity, or Access Token)",
            )
        )

    scope = str(desc.get("scope") or "single_project")
    proj = str(bnd.get("gcp_project_id") or desc.get("project_id") or ident.get("project_id") or "")
    org_id = str(desc.get("organization_id") or ident.get("organization_id") or "")
    if scope == "organization":
        if org_id:
            checks.append(Check(name="gcp org scope", status="ok", detail=f"organization/{org_id}"))
        else:
            checks.append(
                Check(
                    name="gcp org scope",
                    status="warn",
                    detail="Organization scope chosen but organization_id not set",
                    remedy="Provide GCP Organization ID in Connections or bind a Project ID in Lab Resources",
                )
            )
    elif proj:
        checks.append(Check(name="gcp target project", status="ok", detail=f"project={proj} ({region})"))
    else:
        checks.append(
            Check(
                name="gcp target project",
                status="fail",
                detail="No GCP project bound",
                remedy="Enter GCP Project ID in Lab Resources or connect GCP with a project ID",
            )
        )

    log_sink = str(bnd.get("gcp_log_sink") or "identity-shield-audit-sink")
    bucket = str(bnd.get("gcp_bucket") or "")
    checks.append(
        Check(
            name="gcp siem & targets",
            status="ok" if st.get("connected") else "warn",
            detail=f"log_sink={log_sink}" + (f", bucket={bucket}" if bucket else " (no GCS bucket bound yet)"),
            remedy="" if st.get("connected") else "Connect GCP then click Discover GCP to inspect sinks, buckets, secrets, and service accounts",
        )
    )

    return DoctorReport(generated_at=utc_now(), region=region, checks=tuple(checks))


def run_azure_doctor(
    *,
    connection_status: dict[str, Any] | None = None,
    bound: dict[str, Any] | None = None,
) -> DoctorReport:
    """Environment preflight checks for Microsoft Azure & Entra ID SIEM/Lab targets."""
    import shutil

    st = dict(connection_status or {})
    bnd = dict(bound or {})
    desc = dict(st.get("descriptor") or {})
    ident = dict(st.get("identity") or {})
    region = str(bnd.get("azure_location") or desc.get("location") or "eastus")
    checks: list[Check] = []

    az_bin = shutil.which("az")
    if az_bin:
        checks.append(Check(name="az cli", status="ok", detail=az_bin))
    else:
        checks.append(
            Check(
                name="az cli",
                status="warn",
                detail="az CLI not found on PATH (Service Principal / OIDC / Token REST modes still work directly)",
                remedy="Install Azure CLI or connect via App Registration Client Secret / OIDC / Token",
            )
        )

    if st.get("connected"):
        principal = str(ident.get("principal") or desc.get("client_id") or "authenticated")
        mode = str(desc.get("auth_mode") or "az_cli")
        checks.append(Check(name="azure session", status="ok", detail=f"{principal} ({mode})"))
    else:
        checks.append(
            Check(
                name="azure session",
                status="fail",
                detail="Azure / Entra session offline",
                remedy="Connect Azure in Connections (az CLI, Service Principal, OIDC, Managed Identity, or Access Token)",
            )
        )

    scope = str(desc.get("scope") or "single_subscription")
    sub_id = str(bnd.get("azure_subscription_id") or desc.get("subscription_id") or ident.get("subscription_id") or "")
    mg_id = str(desc.get("management_group_id") or ident.get("management_group_id") or "")
    tenant_id = str(desc.get("tenant_id") or ident.get("tenant_id") or "")
    if scope == "organization":
        if mg_id or tenant_id:
            checks.append(Check(name="azure org scope", status="ok", detail=f"tenant={tenant_id or 'resolved'}, mg={mg_id or 'root'}"))
        else:
            checks.append(
                Check(
                    name="azure org scope",
                    status="warn",
                    detail="Organization / Tenant scope chosen without tenant_id or management_group_id",
                    remedy="Supply Azure Tenant ID / Management Group in Connections",
                )
            )
    elif sub_id:
        checks.append(Check(name="azure subscription", status="ok", detail=f"sub={sub_id} ({region})"))
    else:
        checks.append(
            Check(
                name="azure subscription",
                status="fail",
                detail="No Azure subscription bound",
                remedy="Enter Subscription ID in Lab Resources or connect Azure",
            )
        )

    rg = str(bnd.get("azure_resource_group") or "rg-identity-shield-lab")
    kv = str(bnd.get("azure_key_vault") or "")
    checks.append(
        Check(
            name="azure siem & targets",
            status="ok" if st.get("connected") else "warn",
            detail=f"resource_group={rg}" + (f", key_vault={kv}" if kv else " (no Key Vault bound yet)"),
            remedy="" if st.get("connected") else "Connect Azure then click Discover Azure to inspect Key Vaults, storage accounts, VMs, and subscriptions",
        )
    )

    return DoctorReport(generated_at=utc_now(), region=region, checks=tuple(checks))


def as_dict(report: DoctorReport) -> dict[str, Any]:
    return report.to_dict()
