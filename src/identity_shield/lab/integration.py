"""Safe account-scope and temporary-role integration primitives.

This module deliberately performs no mutation.  It provides the identity and
credential boundary used by both local profiles and future customer-deployed
cross-account roles.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any


class DeploymentScope(StrEnum):
    SINGLE_ACCOUNT = "single_account"
    ORGANIZATION = "organization"


class OrganizationStatus(StrEnum):
    STANDALONE = "standalone"
    MANAGEMENT = "management"
    MEMBER = "member"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class AccountClassification:
    account_id: str
    deployment_scope: DeploymentScope
    organization_status: OrganizationStatus
    organization_id: str | None = None
    management_account_id: str | None = None
    inspectable: bool = False
    detail: str = ""
    can_list_accounts: bool = False
    accounts: tuple[str, ...] = ()
    effective_scope: DeploymentScope = DeploymentScope.SINGLE_ACCOUNT

    def to_dict(self) -> dict[str, Any]:
        return {
            "account_id": self.account_id,
            "deployment_scope": self.deployment_scope.value,
            "organization_status": self.organization_status.value,
            "organization_id": self.organization_id,
            "management_account_id": self.management_account_id,
            "inspectable": self.inspectable,
            "detail": self.detail,
            "can_list_accounts": self.can_list_accounts,
            "accounts": list(self.accounts),
            "effective_scope": self.effective_scope.value,
        }


def _error_code(exc: Exception) -> str:
    response = getattr(exc, "response", None)
    if isinstance(response, dict):
        return str((response.get("Error") or {}).get("Code") or "")
    return ""


def classify_account(session: Any, *, scope: DeploymentScope = DeploymentScope.SINGLE_ACCOUNT) -> AccountClassification:
    """Classify the caller without mistaking AccessDenied for standalone.

    If organization scope is requested from a member account that lacks permission
    to list all accounts, gracefully falls back to single-account assessment of the member account.
    """
    try:
        identity = session.client("sts").get_caller_identity()
        account_id = str(identity.get("Account") or "unknown")
    except Exception as exc:  # noqa: BLE001
        return AccountClassification(
            account_id="unknown",
            deployment_scope=scope,
            organization_status=OrganizationStatus.UNKNOWN,
            detail=f"STS identity unavailable: {type(exc).__name__}: {exc}",
        )

    try:
        organization = session.raw_client("organizations").describe_organization().get("Organization") or {}
    except Exception as exc:  # noqa: BLE001
        code = _error_code(exc)
        if code == "AWSOrganizationsNotInUseException":
            return AccountClassification(
                account_id=account_id,
                deployment_scope=scope,
                organization_status=OrganizationStatus.STANDALONE,
                inspectable=True,
                detail="AWS explicitly reports that Organizations is not in use",
                can_list_accounts=False,
                accounts=(account_id,),
                effective_scope=DeploymentScope.SINGLE_ACCOUNT,
            )
        return AccountClassification(
            account_id=account_id,
            deployment_scope=scope,
            organization_status=OrganizationStatus.UNKNOWN,
            inspectable=False,
            detail=f"Organizations status unavailable ({code or type(exc).__name__}); not assumed standalone",
            can_list_accounts=False,
            accounts=(account_id,),
            effective_scope=DeploymentScope.SINGLE_ACCOUNT,
        )

    organization_id = str(organization.get("Id") or "") or None
    management_id = str(organization.get("MasterAccountId") or "") or None
    status = (
        OrganizationStatus.MANAGEMENT
        if management_id == account_id
        else OrganizationStatus.MEMBER
    )

    can_list = False
    accounts: list[str] = [account_id]
    effective_scope = DeploymentScope.SINGLE_ACCOUNT
    detail = f"organization {organization_id or 'unknown'}; caller is {status.value}"

    if scope == DeploymentScope.ORGANIZATION:
        try:
            org_client = session.raw_client("organizations")
            try:
                pages = org_client.get_paginator("list_accounts").paginate()
                accounts = []
                for page in pages:
                    for acct in page.get("Accounts", []):
                        if "Id" in acct:
                            accounts.append(str(acct["Id"]))
            except (AttributeError, AssertionError, Exception):
                response = org_client.list_accounts()
                accounts = [str(a["Id"]) for a in response.get("Accounts", []) if "Id" in a]
            can_list = True
            effective_scope = DeploymentScope.ORGANIZATION
            detail = f"organization {organization_id}; caller is {status.value}; enumerated {len(accounts)} account(s)"
        except Exception as exc:  # noqa: BLE001
            code = _error_code(exc) or type(exc).__name__
            can_list = False
            effective_scope = DeploymentScope.SINGLE_ACCOUNT
            detail = (
                f"organization {organization_id}; caller is {status.value}; "
                f"cannot enumerate organization accounts ({code}); "
                f"gracefully falling back to single-account assessment of {account_id}"
            )

    return AccountClassification(
        account_id=account_id,
        deployment_scope=scope,
        organization_status=status,
        organization_id=organization_id,
        management_account_id=management_id,
        inspectable=True,
        detail=detail,
        can_list_accounts=can_list,
        accounts=tuple(sorted(accounts)),
        effective_scope=effective_scope,
    )


def assume_role(session: Any, role_arn: str, external_id: str | None = None, *, session_name: str = "identity-shield") -> Any:
    """Return a boto3 Session backed by short-lived STS credentials."""
    if not role_arn:
        raise ValueError("role_arn is required")
    kwargs: dict[str, Any] = {
        "RoleArn": role_arn,
        "RoleSessionName": session_name,
    }
    if external_id:
        kwargs["ExternalId"] = external_id
    response = session.client("sts").assume_role(**kwargs)
    credentials = response.get("Credentials") or {}
    required = ("AccessKeyId", "SecretAccessKey", "SessionToken")
    if any(not credentials.get(key) for key in required):
        raise RuntimeError("STS AssumeRole returned incomplete temporary credentials")
    import boto3

    return boto3.Session(
        aws_access_key_id=credentials["AccessKeyId"],
        aws_secret_access_key=credentials["SecretAccessKey"],
        aws_session_token=credentials["SessionToken"],
    )
