"""Deterministic synthetic CloudTrail events for offline rehearsals.

This module exists so the runner, collector, detector and analysis paths can be
exercised end to end without an AWS account. It is **not** a substitute for the
live campaign: the events are derived from the hand-written fixtures and factor
mutations, so any evasion rate it produces is a rehearsal of the machinery, not
a finding about real CloudTrail.

The one rule that keeps it honest is provenance: every run created here is
stored with ``lab_run.synthetic = 1`` and every report labels it.
"""

from __future__ import annotations

import copy
import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping

from identity_shield import config
from identity_shield.contracts import Variant
from identity_shield.variants.loader import Technique

USER_AGENTS = {
    "boto3_default": "Boto3/1.34.49 md/Botocore#1.34.49 ua/2.0 lang/python#3.11.9",
    "aws_cli": "aws-cli/2.15.30 Python/3.11.9 Windows/10 exe/AMD64 prompt/off",
    "terraform": "Terraform/1.9.8 (+https://www.terraform.io) Terraform-Plugin-SDK/2.33.0",
    "non_sdk_http": "curl/8.4.0",
}

REGION = "eu-west-1"
ACCOUNT = "123456789012"

ALT_EVENT = {
    "T1087.004": ("GetAccountAuthorizationDetails", "iam.amazonaws.com"),
    "T1526": ("ListBuckets", "s3.amazonaws.com"),
    "T1580": ("DescribeVpcs", "ec2.amazonaws.com"),
    "T1078.004": ("GetCallerIdentity", "sts.amazonaws.com"),
    "T1098.001": ("CreateLoginProfile", "iam.amazonaws.com"),
    "T1098.003": ("UpdateAssumeRolePolicy", "iam.amazonaws.com"),
    "T1552.005": ("DescribeInstances", "ec2.amazonaws.com"),
    "T1530": ("ListBucket", "s3.amazonaws.com"),
}

# The canonical client for two techniques is not boto3. Getting this wrong
# would make the baseline itself a miss, which is a calibration error rather
# than a finding.
BASELINE_CLIENT = {
    "T1580": "stratus-red-team/2.0",
    "T1552.005": "aws-cli/2.15.30 Python/3.11.9 Windows/10 exe/AMD64 prompt/off",
}


def parse_start(value: str | datetime) -> datetime:
    if isinstance(value, datetime):
        moment = value
    else:
        text = value.strip()
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        moment = datetime.fromisoformat(text)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc)


def _iso(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _identity(level: str) -> dict[str, Any]:
    if level == "assumed_role":
        return {
            "type": "AssumedRole",
            "principalId": "AROAISAPPR0LE0001:session",
            "arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/is-app-role/session",
            "accountId": ACCOUNT,
            "accessKeyId": "ASIAISAPPSESSION01",
            "sessionContext": {
                "sessionIssuer": {
                    "type": "Role",
                    "principalId": "AROAISAPPR0LE0001",
                    "arn": f"arn:aws:iam::{ACCOUNT}:role/is-app-role",
                    "accountId": ACCOUNT,
                    "userName": "is-app-role",
                },
                "attributes": {"mfaAuthenticated": "false", "creationDate": "2026-11-19T09:00:00Z"},
            },
        }
    if level == "instance_profile":
        return {
            "type": "AssumedRole",
            "principalId": "AROAISEC2ROLE0001:i-0abc123def456",
            "arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/is-ec2-role/i-0abc123def456",
            "accountId": ACCOUNT,
            "accessKeyId": "ASIAISEC2SESSION01",
            "sessionContext": {
                "sessionIssuer": {
                    "type": "Role",
                    "principalId": "AROAISEC2ROLE0001",
                    "arn": f"arn:aws:iam::{ACCOUNT}:role/is-ec2-role",
                    "accountId": ACCOUNT,
                    "userName": "is-ec2-role",
                },
                "attributes": {"mfaAuthenticated": "false", "creationDate": "2026-11-19T09:02:44Z"},
            },
        }
    if level == "federated_session":
        return {
            "type": "AssumedRole",
            "principalId": "AROAISFEDR0LE0001:alice",
            "arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/is-federated-role/alice",
            "accountId": ACCOUNT,
            "accessKeyId": "ASIAISFEDSESSION1",
            "sessionContext": {
                "sessionIssuer": {
                    "type": "Role",
                    "principalId": "AROAISFEDR0LE0001",
                    "arn": f"arn:aws:iam::{ACCOUNT}:role/is-federated-role",
                    "accountId": ACCOUNT,
                    "userName": "is-federated-role",
                },
                "attributes": {"mfaAuthenticated": "true", "creationDate": "2026-11-19T09:00:00Z"},
                "sourceIdentity": "alice@example.invalid",
            },
        }
    return {
        "type": "IAMUser",
        "principalId": "AIDAISLABUSER0001",
        "arn": f"arn:aws:iam::{ACCOUNT}:user/is-operator",
        "accountId": ACCOUNT,
        "accessKeyId": "AKIAISLABUSER0001",
        "userName": "is-operator",
    }


def apply_tool(event: dict[str, Any], level: str) -> None:
    event["userAgent"] = USER_AGENTS.get(level, USER_AGENTS["boto3_default"])


def apply_identity(event: dict[str, Any], level: str) -> None:
    event["userIdentity"] = _identity(level)


def apply_network(event: dict[str, Any], level: str, *, technique_id: str) -> None:
    if level == "nat_b":
        event["sourceIPAddress"] = "198.51.100.20"
    elif level == "service_mediated":
        event["sourceIPAddress"] = "lambda.amazonaws.com"
        event["userIdentity"]["invokedBy"] = "lambda.amazonaws.com"
    elif level == "alternate_endpoint":
        event["sourceIPAddress"] = "192.0.2.44"
        details = event.setdefault("tlsDetails", {})
        details["clientProvidedHostHeader"] = "iam.us-east-1.amazonaws.com"
    else:
        event["sourceIPAddress"] = "203.0.113.10"


def apply_timing(event: dict[str, Any], level: str, base: datetime, index: int) -> None:
    if level == "off_hours":
        moment = base.replace(hour=2, minute=15, second=0, microsecond=0)
    elif level == "burst":
        moment = base.replace(microsecond=0)
    elif level == "spread":
        moment = base + timedelta(minutes=15 * index)
    else:
        moment = base.replace(hour=10, minute=5, second=0, microsecond=0) + timedelta(seconds=index)
    event["eventTime"] = _iso(moment)


def apply_api_form(
    event: dict[str, Any],
    level: str,
    *,
    technique_id: str,
    index: int,
) -> None:
    if level == "alternative_api" and technique_id in ALT_EVENT:
        name, source = ALT_EVENT[technique_id]
        event["eventName"] = name
        event["eventSource"] = source
        event["requestParameters"] = {}
        if name in {"GetCallerIdentity"}:
            event["readOnly"] = True
        if name in {"ListBucket", "GetObject"}:
            event["eventCategory"] = "Data"
            event["managementEvent"] = False
    elif level == "extra_parameters":
        params = event.setdefault("requestParameters", {})
        if not isinstance(params, dict):
            params = {}
            event["requestParameters"] = params
        params.setdefault("maxResults", 1000)
        params.setdefault("passwordResetRequired", True)
    elif level == "batched":
        event["requestParameters"] = {
            "maxResults": 1000,
            "nextToken": "synthetic-page-2",
        }
    elif level == "hostile_identifier":
        params = event.setdefault("requestParameters", {})
        if not isinstance(params, dict):
            params = {}
            event["requestParameters"] = params
        if "roleName" in params or "userName" not in params:
            params["roleName"] = "TempAdmin"
        else:
            params["userName"] = "TempAdmin"


def build_event(
    *,
    technique_id: str,
    event_name: str,
    event_source: str,
    run_id: str,
    variant_id: str,
    index: int,
    moment: datetime,
    identity: str = "iam_user",
    client_tool: str = "boto3_default",
    source_ip: str = "203.0.113.10",
    request_parameters: Mapping[str, Any] | None = None,
    region: str = REGION,
) -> dict[str, Any]:
    digest = hashlib.sha256(
        f"{run_id}|{variant_id}|{index}|{event_name}".encode("utf-8")
    ).hexdigest()
    event: dict[str, Any] = {
        "eventVersion": "1.09",
        "userIdentity": _identity(identity),
        "eventTime": _iso(moment + timedelta(seconds=index)),
        "eventSource": event_source,
        "eventName": event_name,
        "awsRegion": region,
        "sourceIPAddress": source_ip,
        "userAgent": USER_AGENTS.get(client_tool, USER_AGENTS["boto3_default"]),
        "requestParameters": dict(request_parameters or {}),
        "responseElements": None,
        "requestID": digest[:26].upper(),
        "eventID": digest[:32],
        "readOnly": event_name.startswith(("List", "Describe", "Get")),
        "eventType": "AwsApiCall",
        "managementEvent": event_source != "s3.amazonaws.com",
        "recipientAccountId": ACCOUNT,
        "eventCategory": "Data" if event_source == "s3.amazonaws.com" else "Management",
    }
    return event


def fixture_events(technique_id: str, flavour: str = "catch") -> list[dict[str, Any]]:
    path = config.FIXTURE_ROOT / technique_id / f"{flavour}.json"
    if not path.exists():
        path = config.FIXTURE_ROOT / technique_id / "obvious.json"
    if not path.exists():
        return []
    from identity_shield.detect.parser import extract_events

    return [copy.deepcopy(event) for event in extract_events(json.loads(path.read_text("utf-8")))]


def synthetic_events(
    technique: Technique,
    variant: Variant,
    *,
    run_id: str,
    start: str | datetime,
) -> list[dict[str, Any]]:
    """Return the CloudTrail events a variant would be expected to produce."""
    base = parse_start(start)
    levels = dict(variant.factor_levels)
    templates = fixture_events(technique.technique_id)
    if not templates:
        templates = [
            build_event(
                technique_id=technique.technique_id,
                event_name=name,
                event_source="sts.amazonaws.com"
                if name == "GetCallerIdentity"
                else "ec2.amazonaws.com",
                run_id=run_id,
                variant_id=variant.variant_id,
                index=index,
                moment=base,
            )
            for index, name in enumerate(technique.event_names or ("GetCallerIdentity",))
        ]

    events: list[dict[str, Any]] = []
    for index, template in enumerate(templates):
        event = copy.deepcopy(template)
        event["recipientAccountId"] = ACCOUNT
        event["awsRegion"] = REGION
        apply_identity(event, levels.get("identity_context", "iam_user"))
        apply_tool(event, levels.get("client_tool", "boto3_default"))
        apply_network(event, levels.get("network_origin", "nat_a"), technique_id=technique.technique_id)
        apply_timing(event, levels.get("timing", "business_hours"), base, index)
        apply_api_form(
            event,
            levels.get("api_form", "canonical"),
            technique_id=technique.technique_id,
            index=index,
        )
        if (
            levels.get("client_tool", "boto3_default") == "boto3_default"
            and technique.technique_id in BASELINE_CLIENT
        ):
            event["userAgent"] = BASELINE_CLIENT[technique.technique_id]
        if technique.technique_id == "T1552.005" and levels.get("identity_context") == "instance_profile":
            event.setdefault("userIdentity", {})["arn"] = (
                f"arn:aws:sts::{ACCOUNT}:assumed-role/is-ec2-role/i-0abc123def456"
            )
        digest = hashlib.sha256(
            f"{run_id}|{variant.variant_id}|{index}|{event.get('eventName')}".encode("utf-8")
        ).hexdigest()
        event["eventID"] = digest[:32]
        event["requestID"] = digest[32:58].upper()
        event["eventTime"] = event.get("eventTime") or _iso(base + timedelta(seconds=index))
        events.append(event)
    return events
