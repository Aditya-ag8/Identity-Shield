"""Authored Python detection rules.

These stand in for the round-1 rule set's hand-written half. They are
**deliberately naive**, because the point of Module 7 is to show what naive
rules miss:

* ``IS-DISC-001`` keys on the client user agent. Change the client and it dies.
* ``IS-CRED-001`` keys on a single API name. Use a different persistence API
  and it dies.
* ``IS-CRED-002`` keys on two API names, with no check on who was changed.
* ``IS-COLL-001`` keys on the request source being outside the VPC. Come in
  through a NAT gateway and it dies.

Do not "fix" them here. They are the baseline that `improved-v1` is measured
against; the improved versions belong in ``conf/rules/improved``.
"""

from __future__ import annotations

import ipaddress
from typing import Any, Mapping

from identity_shield.detect.rules import Rule, as_text, get_field


def _event_name(event: Mapping[str, Any]) -> str:
    return as_text(get_field(event, "eventName"))


def _flag(event: Mapping[str, Any], path: str) -> bool:
    return as_text(get_field(event, path)).casefold() in {"true", "1", "yes"}


def _is_private_ip(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_private
    except ValueError:
        return False


def is_discovery(event: Mapping[str, Any]) -> bool:
    if _event_name(event) not in {"ListUsers", "ListRoles", "GetAccountAuthorizationDetails"}:
        return False
    return "aws-cli" in as_text(get_field(event, "userAgent")).casefold()


def is_create_access_key(event: Mapping[str, Any]) -> bool:
    return _event_name(event) == "CreateAccessKey" and not get_field(event, "errorCode")


def is_trust_modification(event: Mapping[str, Any]) -> bool:
    return (
        _event_name(event) in {"UpdateAssumeRolePolicy", "AttachRolePolicy", "PutRolePolicy"}
        and not get_field(event, "errorCode")
    )


def is_external_object_read(event: Mapping[str, Any]) -> bool:
    if _event_name(event) != "GetObject":
        return False
    if get_field(event, "errorCode"):
        return False
    source = as_text(get_field(event, "sourceIPAddress"))
    if not source:
        return False
    return not _is_private_ip(source)


def is_console_login_without_mfa(event: Mapping[str, Any]) -> bool:
    if _event_name(event) != "ConsoleLogin":
        return False
    return as_text(get_field(event, "additionalEventData.MFAUsed")).casefold() == "no"


PYTHON_RULES: tuple[Rule, ...] = (
    Rule(
        native_id="IS-DISC-001",
        title="Account enumeration from the AWS CLI",
        level="medium",
        technique_id="T1087.004",
        loader="python",
        fn=is_discovery,
        description="Detects IAM enumeration, but only when the client is the AWS CLI.",
        fields=("eventName", "userAgent"),
    ),
    Rule(
        native_id="IS-CRED-001",
        title="Access key created",
        level="high",
        technique_id="T1098.001",
        loader="python",
        fn=is_create_access_key,
        description="Detects iam:CreateAccessKey by name only.",
        fields=("eventName", "errorCode"),
    ),
    Rule(
        native_id="IS-CRED-002",
        title="Role trust policy modified",
        level="high",
        technique_id="T1098.003",
        loader="python",
        fn=is_trust_modification,
        description="Detects three policy-change API calls by name only.",
        fields=("eventName", "errorCode"),
    ),
    Rule(
        native_id="IS-COLL-001",
        title="S3 object read from outside the VPC",
        level="medium",
        technique_id="T1530",
        loader="python",
        fn=is_external_object_read,
        description="Detects s3:GetObject when the source address is not private.",
        fields=("eventName", "sourceIPAddress"),
    ),
    Rule(
        native_id="IS-INIT-001",
        title="Console login without MFA",
        level="high",
        technique_id="T1078.004",
        loader="python",
        fn=is_console_login_without_mfa,
        description="Detects a console sign-in where additionalEventData.MFAUsed is No.",
        fields=("eventName", "additionalEventData.MFAUsed"),
    ),
)


def rules() -> tuple[Rule, ...]:
    return PYTHON_RULES
