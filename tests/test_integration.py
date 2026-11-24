from __future__ import annotations

import pytest

from aws_fakes import FakeClient, FakeSession
from identity_shield.lab import integration


ACCOUNT = "123456789012"


def test_classify_account_standalone():
    session = FakeSession(
        {
            "sts": FakeClient({"get_caller_identity": {"Account": ACCOUNT}}),
            "organizations": FakeClient(
                {
                    "describe_organization": lambda _kwargs: (_ for _ in ()).throw(
                        RuntimeError("AWSOrganizationsNotInUseException")
                    )
                }
            ),
        }
    )
    # Give response error code attribute
    exc = RuntimeError("AWSOrganizationsNotInUseException")
    exc.response = {"Error": {"Code": "AWSOrganizationsNotInUseException"}}
    session = FakeSession(
        {
            "sts": FakeClient({"get_caller_identity": {"Account": ACCOUNT}}),
            "organizations": FakeClient(
                {
                    "describe_organization": lambda _kwargs: (_ for _ in ()).throw(exc)
                }
            ),
        }
    )
    res = integration.classify_account(session)
    assert res.organization_status is integration.OrganizationStatus.STANDALONE
    assert res.inspectable is True
    assert res.account_id == ACCOUNT


def test_classify_account_management():
    session = FakeSession(
        {
            "sts": FakeClient({"get_caller_identity": {"Account": ACCOUNT}}),
            "organizations": FakeClient(
                {
                    "describe_organization": {
                        "Organization": {
                            "Id": "o-xyz123",
                            "MasterAccountId": ACCOUNT,
                            "FeatureSet": "ALL",
                        }
                    }
                }
            ),
        }
    )
    res = integration.classify_account(session, scope=integration.DeploymentScope.ORGANIZATION)
    assert res.organization_status is integration.OrganizationStatus.MANAGEMENT
    assert res.deployment_scope is integration.DeploymentScope.ORGANIZATION
    assert res.management_account_id == ACCOUNT
    assert res.organization_id == "o-xyz123"


def test_classify_account_member():
    session = FakeSession(
        {
            "sts": FakeClient({"get_caller_identity": {"Account": ACCOUNT}}),
            "organizations": FakeClient(
                {
                    "describe_organization": {
                        "Organization": {
                            "Id": "o-xyz123",
                            "MasterAccountId": "888888888888",
                            "FeatureSet": "ALL",
                        }
                    }
                }
            ),
        }
    )
    res = integration.classify_account(session)
    assert res.organization_status is integration.OrganizationStatus.MEMBER
    assert res.management_account_id == "888888888888"


def test_classify_account_access_denied_is_unknown():
    exc = RuntimeError("AccessDeniedException")
    exc.response = {"Error": {"Code": "AccessDeniedException"}}
    session = FakeSession(
        {
            "sts": FakeClient({"get_caller_identity": {"Account": ACCOUNT}}),
            "organizations": FakeClient(
                {
                    "describe_organization": lambda _kwargs: (_ for _ in ()).throw(exc)
                }
            ),
        }
    )
    res = integration.classify_account(session)
    assert res.organization_status is integration.OrganizationStatus.UNKNOWN
    assert res.inspectable is False


def test_assume_role_requires_role_arn():
    session = FakeSession({})
    with pytest.raises(ValueError, match="role_arn is required"):
        integration.assume_role(session, "", "ext-id")


def test_assume_role_allows_optional_external_id_for_self_hosted():
    sts_client = FakeClient(
        {
            "assume_role": {
                "Credentials": {
                    "AccessKeyId": "ASIAKEY",
                    "SecretAccessKey": "SECRET",
                    "SessionToken": "TOKEN",
                }
            }
        }
    )
    session = FakeSession({"sts": sts_client})
    # Calling without external_id (self-hosted / same-account)
    assumed = integration.assume_role(session, "arn:aws:iam::123:role/r")
    assert assumed is not None
    assert sts_client.calls[0][0] == "assume_role"
    assert "ExternalId" not in sts_client.calls[0][1]

    # Calling with external_id (cross-account / vendor)
    assumed_ext = integration.assume_role(session, "arn:aws:iam::123:role/r", "customer-ext-id")
    assert assumed_ext is not None
    assert sts_client.calls[1][1]["ExternalId"] == "customer-ext-id"


def test_classify_account_member_fallback_when_list_accounts_denied():
    exc = RuntimeError("AccessDeniedException")
    exc.response = {"Error": {"Code": "AccessDeniedException"}}
    session = FakeSession(
        {
            "sts": FakeClient({"get_caller_identity": {"Account": ACCOUNT}}),
            "organizations": FakeClient(
                {
                    "describe_organization": {
                        "Organization": {
                            "Id": "o-xyz123",
                            "MasterAccountId": "888888888888",
                            "FeatureSet": "ALL",
                        }
                    },
                    "list_accounts": lambda _kwargs: (_ for _ in ()).throw(exc),
                }
            ),
        }
    )
    res = integration.classify_account(session, scope=integration.DeploymentScope.ORGANIZATION)
    assert res.organization_status is integration.OrganizationStatus.MEMBER
    assert res.deployment_scope is integration.DeploymentScope.ORGANIZATION
    # Graceful fallback:
    assert res.can_list_accounts is False
    assert res.effective_scope is integration.DeploymentScope.SINGLE_ACCOUNT
    assert res.accounts == (ACCOUNT,)
    assert "gracefully falling back" in res.detail


def test_classify_account_management_enumerates_accounts():
    session = FakeSession(
        {
            "sts": FakeClient({"get_caller_identity": {"Account": ACCOUNT}}),
            "organizations": FakeClient(
                {
                    "describe_organization": {
                        "Organization": {
                            "Id": "o-xyz123",
                            "MasterAccountId": ACCOUNT,
                            "FeatureSet": "ALL",
                        }
                    },
                    "list_accounts": {
                        "Accounts": [
                            {"Id": ACCOUNT},
                            {"Id": "999999999999"},
                        ]
                    },
                }
            ),
        }
    )
    res = integration.classify_account(session, scope=integration.DeploymentScope.ORGANIZATION)
    assert res.organization_status is integration.OrganizationStatus.MANAGEMENT
    assert res.can_list_accounts is True
    assert res.effective_scope is integration.DeploymentScope.ORGANIZATION
    assert res.accounts == (ACCOUNT, "999999999999")
    assert "enumerated 2 account(s)" in res.detail


def test_assume_role_checks_incomplete_credentials():
    session = FakeSession(
        {
            "sts": FakeClient(
                {
                    "assume_role": {
                        "Credentials": {
                            "AccessKeyId": "ASIAKEY",
                            # Missing SecretAccessKey
                        }
                    }
                }
            )
        }
    )
    with pytest.raises(RuntimeError, match="incomplete"):
        integration.assume_role(session, "arn:aws:iam::123:role/r", "ext-id")


def test_assume_role_returns_boto3_session():
    session = FakeSession(
        {
            "sts": FakeClient(
                {
                    "assume_role": {
                        "Credentials": {
                            "AccessKeyId": "ASIAKEY",
                            "SecretAccessKey": "SECRET",
                            "SessionToken": "TOKEN",
                        }
                    }
                }
            )
        }
    )
    assumed = integration.assume_role(session, "arn:aws:iam::123:role/r", "ext-id")
    assert assumed is not None
    creds = assumed.get_credentials()
    assert creds.access_key == "ASIAKEY"
    assert creds.secret_key == "SECRET"
    assert creds.token == "TOKEN"
