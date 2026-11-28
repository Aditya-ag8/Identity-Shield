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


def _infer_event_source(technique: Technique, event_name: str, index: int) -> str:
    calls = getattr(technique, "api_calls", ()) or ()
    if index < len(calls) and calls[index].get("service"):
        return f"{str(calls[index]['service']).lower()}.amazonaws.com"
    if calls and calls[0].get("service"):
        return f"{str(calls[0]['service']).lower()}.amazonaws.com"
    for action in getattr(technique, "required_actions", ()) or ():
        if ":" in str(action):
            return f"{str(action).split(':', 1)[0].lower()}.amazonaws.com"
    lower = event_name.lower()
    if any(k in lower for k in ("user", "role", "policy", "accesskey", "loginprofile", "authorization")):
        return "iam.amazonaws.com"
    if any(k in lower for k in ("bucket", "object")):
        return "s3.amazonaws.com"
    if any(k in lower for k in ("calleridentity", "assumerole")):
        return "sts.amazonaws.com"
    if "dbinstance" in lower:
        return "rds.amazonaws.com"
    return "ec2.amazonaws.com"


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
                event_source=_infer_event_source(technique, name, index),
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


def multicloud_synthetic_events(
    technique: Technique,
    variant: Variant,
    *,
    cloud_provider: str = "aws",
    account_scope: str = "",
    run_id: str,
    start: str | datetime,
) -> list[dict[str, Any]]:
    """Generate 5-factor perturbed synthetic audit events for AWS, GCP, or Azure."""
    cloud = str(cloud_provider or "aws").strip().lower()
    if cloud == "aws":
        return synthetic_events(technique, variant, run_id=run_id, start=start)

    from identity_shield.clouds.factors import user_agent_for_provider

    base = start if isinstance(start, datetime) else parse_start(start)
    levels = dict(variant.factor_levels)
    ua = user_agent_for_provider(cloud, levels.get("client_tool", "boto3_default"))
    net = levels.get("network_origin", "nat_a")
    if net == "nat_b":
        source_ip = "198.51.100.20"
    elif net == "service_mediated":
        source_ip = "gce.googleapis.com" if cloud == "gcp" else "azure-automation.internal"
    elif net == "alternate_endpoint":
        source_ip = "192.0.2.44"
    else:
        source_ip = "203.0.113.10"
    timing_lvl = levels.get("timing", "business_hours")
    id_lvl = levels.get("identity_context", "iam_user")
    api_lvl = levels.get("api_form", "canonical")
    names = tuple(technique.event_names or ("UnknownOp",))

    events: list[dict[str, Any]] = []
    for index, op_name in enumerate(names):
        if timing_lvl == "off_hours":
            moment = base.replace(hour=2, minute=15, second=0, microsecond=0) + timedelta(seconds=index)
        elif timing_lvl == "spread":
            moment = base + timedelta(minutes=15 * index)
        elif timing_lvl == "burst":
            moment = base.replace(microsecond=0)
        else:
            moment = base.replace(hour=10, minute=5, second=0, microsecond=0) + timedelta(seconds=index)
        ts = _iso(moment)
        digest = hashlib.sha256(f"{cloud}|{run_id}|{variant.variant_id}|{index}|{op_name}".encode("utf-8")).hexdigest()

        if cloud == "gcp":
            proj = account_scope or "is-gcp-lab-project"
            principal = (
                f"sim-federated@{proj}.iam.gserviceaccount.com"
                if id_lvl == "federated_session"
                else (f"gce-vm-sa@{proj}.iam.gserviceaccount.com" if id_lvl == "instance_profile" else f"operator@{proj}.iam.gserviceaccount.com")
            )
            svc = f"{str(technique.required_actions[0]).split('.')[0]}.googleapis.com" if technique.required_actions and "." in str(technique.required_actions[0]) else "iam.googleapis.com"
            if technique.api_calls and technique.api_calls[0].get("service"):
                raw_svc = str(technique.api_calls[0]["service"]).lower()
                svc = raw_svc if "." in raw_svc else f"{raw_svc}.googleapis.com"
            res_name = f"projects/{proj}/resources/{'TempAdmin' if api_lvl == 'hostile_identifier' else 'lab-target'}"
            evt = {
                "cloudProvider": "gcp",
                "accountScope": proj,
                "insertId": digest[:32],
                "eventID": digest[:32],
                "timestamp": ts,
                "eventTime": ts,
                "eventSource": svc,
                "eventName": op_name,
                "userAgent": ua,
                "sourceIPAddress": source_ip,
                "logName": f"projects/{proj}/logs/cloudaudit.googleapis.com%2Factivity",
                "protoPayload": {
                    "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
                    "serviceName": svc,
                    "methodName": op_name,
                    "resourceName": res_name,
                    "authenticationInfo": {
                        "principalEmail": principal,
                        "serviceAccountKeyName": f"projects/{proj}/serviceAccounts/{principal}/keys/k1" if id_lvl == "iam_user" else None,
                        "serviceAccountDelegationInfo": [{"firstPartyPrincipal": {"principalEmail": f"service-{proj}@gcp-sa.iam.gserviceaccount.com"}}] if net == "service_mediated" else [],
                    },
                    "requestMetadata": {
                        "callerIp": source_ip,
                        "callerSuppliedUserAgent": ua,
                    },
                    "request": {"maxResults": 1000} if api_lvl in {"extra_parameters", "batched"} else {},
                },
                "resource": {"type": "audited_resource", "labels": {"project_id": proj, "location": "global"}},
                "synthetic": True,
            }
            events.append(evt)
        else:
            # Azure Activity / Entra synthetic payload
            sub_id = account_scope or "00000000-0000-0000-0000-000000000001"
            caller = (
                "TempAdmin@contoso.onmicrosoft.com"
                if api_lvl == "hostile_identifier"
                else ("msi-vm-identity" if id_lvl == "instance_profile" else "operator@contoso.onmicrosoft.com")
            )
            svc = "Microsoft.Authorization"
            if technique.api_calls and technique.api_calls[0].get("service"):
                svc = str(technique.api_calls[0]["service"])
            evt = {
                "cloudProvider": "azure",
                "accountScope": sub_id,
                "eventDataId": digest[:32],
                "eventID": digest[:32],
                "time": ts,
                "eventTimestamp": ts,
                "eventTime": ts,
                "eventSource": svc,
                "eventName": op_name,
                "userAgent": ua,
                "sourceIPAddress": source_ip,
                "subscriptionId": sub_id,
                "operationName": {"value": op_name, "localizedValue": op_name},
                "activityDisplayName": op_name,
                "conditionalAccessStatus": "notApplied" if op_name == "UserSignIn" else None,
                "caller": caller,
                "callerIpAddress": source_ip,
                "resourceId": f"/subscriptions/{sub_id}/resourceGroups/rg-lab/providers/{svc}/targets/lab",
                "category": {"value": "SignInLogs" if op_name == "UserSignIn" else "Administrative"},
                "identity": {"delegatedFrom": "AzureResourceManager"} if net == "service_mediated" else {},
                "properties": {"userAgent": ua},
                "synthetic": True,
            }
            events.append(evt)
    return events
