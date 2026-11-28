"""Closed-Loop Alert-to-Variant & Resource-to-Variant Detection Testing Engine.

Bridges telemetry captured by the Live Security Proxy / Dynamic Engine / CloudTrail
events AND discovered AWS/CloudFox resources back into the 5-factor variant generator
(`client_tool`, `identity_context`, `network_origin`, `timing`, `api_form`), tests
evasion across generated variants, and optionally hardens Sigma rules in `enhanced-v1`.
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from identity_shield import config, settings
from identity_shield.clouds.factors import check_factor_support
from identity_shield.detect import python_rules
from identity_shield.detect.dynamic import evaluate_live_event, list_dynamic_rules
from identity_shield.detect.replay import load_ruleset_config
from identity_shield.detect.rules import Rule, RuleError, load_sigma_text
from identity_shield.integrations.tools import parse_cloudfox_inventory, parse_scoutsuite_inventory
from identity_shield.proxy.parser import parse_request
from identity_shield.runner.synthetic import multicloud_synthetic_events, synthetic_events
from identity_shield.variants.generator import GenerationOptions, generate_for_technique
from identity_shield.variants.loader import Catalogue, Technique, load_catalogue

CLOSED_LOOP_MODES = frozenset({"from_alerts", "from_resources", "both"})
CLOUD_FILTERS = frozenset({"all", "aws", "gcp", "azure"})

_SAFE_SLUG_RE = re.compile(r"[^a-z0-9_-]+")
_GENERIC_OPS = frozenset({"GetCallerIdentity"})

# Canonical MITRE technique mapping for commonly observed AWS operations.
_OP_TO_TECHNIQUE: dict[str, tuple[str, str, str]] = {
    "ListUsers": ("T1087.004", "Cloud Account Discovery", "discovery"),
    "ListRoles": ("T1087.004", "Cloud Account Discovery", "discovery"),
    "ListAccessKeys": ("T1087.004", "Cloud Account Discovery", "discovery"),
    "GetAccountAuthorizationDetails": ("T1087.004", "Cloud Account Discovery", "discovery"),
    "DescribeInstances": ("T1580", "Cloud Infrastructure Discovery", "discovery"),
    "DescribeSecurityGroups": ("T1580", "Cloud Infrastructure Discovery", "discovery"),
    "DescribeSubnets": ("T1580", "Cloud Infrastructure Discovery", "discovery"),
    "ListBuckets": ("T1526", "Cloud Service Discovery", "discovery"),
    "ListAllMyBuckets": ("T1526", "Cloud Service Discovery", "discovery"),
    "DescribeDBInstances": ("T1526", "Cloud Service Discovery", "discovery"),
    "ConsoleLogin": ("T1078.004", "Valid Accounts - Cloud Accounts", "initial-access"),
    "AssumeRole": ("T1098.003", "Additional Cloud Roles", "privilege-escalation"),
    "CreateAccessKey": ("T1098.001", "Additional Cloud Credentials", "persistence"),
    "CreateLoginProfile": ("T1098.001", "Additional Cloud Credentials", "persistence"),
    "UpdateLoginProfile": ("T1098.001", "Additional Cloud Credentials", "persistence"),
    "AttachRolePolicy": ("T1098.003", "Additional Cloud Roles", "privilege-escalation"),
    "PutRolePolicy": ("T1098.003", "Additional Cloud Roles", "privilege-escalation"),
    "PutUserPolicy": ("T1098.003", "Additional Cloud Roles", "privilege-escalation"),
    "UpdateAssumeRolePolicy": ("T1098.003", "Additional Cloud Roles", "privilege-escalation"),
    "PassRole": ("T1098.003", "Additional Cloud Roles", "privilege-escalation"),
    "ListBucket": ("T1530", "Data from Cloud Storage", "collection"),
    "GetObject": ("T1530", "Data from Cloud Storage", "collection"),
    "HeadBucket": ("T1530", "Data from Cloud Storage", "collection"),
    "GetSecretValue": ("T1555.006", "Cloud Secrets Management Access", "credential-access"),
    "ListSecrets": ("T1555.006", "Cloud Secrets Management Access", "credential-access"),
    "GetFunction": ("T1526", "Serverless Function Discovery", "discovery"),
    "ListFunctions": ("T1526", "Serverless Function Discovery", "discovery"),
    "GetQueueAttributes": ("T1526", "Cloud Messaging Queue Discovery", "discovery"),
    # GCP Cloud Audit operations
    "google.iam.admin.v1.CreateServiceAccountKey": ("T1098.GCP01", "GCP Service Account Key Creation", "persistence"),
    "CreateServiceAccountKey": ("T1098.GCP01", "GCP Service Account Key Creation", "persistence"),
    "google.cloud.resourcemanager.v3.Projects.SetIamPolicy": ("T1098.GCP03", "GCP Project IAM Policy Escalation (SetIamPolicy)", "privilege-escalation"),
    "SetIamPolicy": ("T1098.GCP03", "GCP Project IAM Policy Escalation (SetIamPolicy)", "privilege-escalation"),
    "storage.objects.list": ("T1530.GCP01", "GCP Cloud Storage Bucket Object Exfiltration", "collection"),
    "storage.objects.get": ("T1530.GCP01", "GCP Cloud Storage Bucket Object Exfiltration", "collection"),
    "google.cloud.secretmanager.v1.SecretManagerService.ListSecrets": ("T1555.GCP06", "GCP Secret Manager Version Access", "credential-access"),
    "google.cloud.secretmanager.v1.SecretManagerService.AccessSecretVersion": ("T1555.GCP06", "GCP Secret Manager Version Access", "credential-access"),
    "AccessSecretVersion": ("T1555.GCP06", "GCP Secret Manager Version Access", "credential-access"),
    "v1.compute.instances.list": ("T1580.GCP01", "GCP Compute Infrastructure Discovery", "discovery"),
    "v1.compute.firewalls.list": ("T1580.GCP01", "GCP Compute Infrastructure Discovery", "discovery"),
    # Azure Activity & Entra operations
    "Microsoft.Authorization/roleAssignments/write": ("T1098.AZ03", "Azure RBAC Role Assignment Escalation", "privilege-escalation"),
    "Add service principal credentials": ("T1098.AZ01", "Microsoft Entra Service Principal Credential Addition", "persistence"),
    "SecretList": ("T1555.AZ06", "Azure Key Vault Secret Retrieval", "credential-access"),
    "SecretGet": ("T1555.AZ06", "Azure Key Vault Secret Retrieval", "credential-access"),
    "UserSignIn": ("T1078.AZ04", "Microsoft Entra Sign-In Without Conditional Access", "initial-access"),
    "Microsoft.Compute/virtualMachines/read": ("T1580.AZ01", "Azure Virtual Machine & Network Discovery", "discovery"),
}

_RESOURCE_OP_TO_SNAKE: dict[str, str] = {
    "ListUsers": "list_users",
    "ListRoles": "list_roles",
    "ListBuckets": "list_buckets",
    "GetObject": "get_object",
    "ListBucket": "list_objects_v2",
    "CreateAccessKey": "create_access_key",
    "AssumeRole": "assume_role",
    "AttachRolePolicy": "attach_role_policy",
    "DescribeInstances": "describe_instances",
    "ListSecrets": "list_secrets",
    "GetSecretValue": "get_secret_value",
    "ListFunctions": "list_functions",
    "GetFunction": "get_function",
    "GetQueueAttributes": "get_queue_attributes",
}


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def normalize_closed_loop_mode(mode: str | None) -> str:
    raw = str(mode or "both").strip().lower().replace("-", "_")
    aliases = {
        "alerts": "from_alerts",
        "alert": "from_alerts",
        "logs": "from_alerts",
        "from_alerts": "from_alerts",
        "resources": "from_resources",
        "resource": "from_resources",
        "from_resources": "from_resources",
        "both": "both",
        "all": "both",
    }
    if raw not in aliases:
        raise ValueError("Closed-loop mode must be one of: from_alerts, from_resources, both.")
    return aliases[raw]


def _safe_slug(text: str) -> str:
    cleaned = _SAFE_SLUG_RE.sub("-", str(text or "").lower()).strip("-")
    return cleaned[:48] or "vector"


def _camel_to_snake(name: str) -> str:
    s1 = re.sub(r"(.)([A-Z][a-z]+)", r"\1_\2", str(name or "").strip())
    return re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", s1).lower() or "get_caller_identity"


def _deterministic_technique_id(service: str, operation: str, *, offset: int = 9100) -> str:
    known = _OP_TO_TECHNIQUE.get(operation)
    if known:
        return known[0]
    digest = hashlib.sha256(f"{service}:{operation}".encode("utf-8")).hexdigest()
    num = offset + (int(digest[:6], 16) % 90)
    return f"T{num}"


def _tactic_for(service: str, operation: str) -> str:
    known = _OP_TO_TECHNIQUE.get(operation)
    if known:
        return known[2]
    op_l = operation.lower()
    if any(k in op_l for k in ("create", "put", "attach", "update", "modify")):
        return "persistence"
    if any(k in op_l for k in ("secret", "password", "decrypt", "credential")):
        return "credential-access"
    if any(k in op_l for k in ("get", "read", "download")):
        return "collection"
    return "discovery"


def _cloudfox_path() -> Path:
    return config.DATA / "cloudfox_inventory.json"


def _last_loop_path() -> Path:
    return config.DATA / "closed_loop_last.json"


def save_cloudfox_inventory(inventory: dict[str, Any]) -> dict[str, Any]:
    path = _cloudfox_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(inventory, indent=2), encoding="utf-8")
    return inventory


def load_cloudfox_inventory() -> dict[str, Any] | None:
    path = _cloudfox_path()
    if not path.is_file():
        return None
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(raw, dict) and isinstance(raw.get("resources"), dict):
            return raw
    except Exception:
        return None
    return None


def import_cloudfox_json(raw_data: str | bytes | dict[str, Any] | list[Any], *, apply_bindings: bool = False) -> dict[str, Any]:
    inventory = parse_cloudfox_inventory(raw_data)
    save_cloudfox_inventory(inventory)
    applied_bindings: dict[str, str] = {}
    if apply_bindings and inventory.get("suggested_bindings"):
        current = settings.get_resources()
        updated_fields: dict[str, str] = {}
        for field_name, val in inventory["suggested_bindings"].items():
            if hasattr(current, field_name) and val:
                updated_fields[field_name] = str(val)
        if updated_fields:
            settings.update_resources(updated_fields)
            applied_bindings = updated_fields
    return {
        "inventory": inventory,
        "applied_bindings": applied_bindings,
        "saved_path": str(_cloudfox_path()),
    }


def load_last_closed_loop_report() -> dict[str, Any] | None:
    path = _last_loop_path()
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def _save_last_closed_loop_report(report: dict[str, Any]) -> None:
    path = _last_loop_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2), encoding="utf-8")


def normalize_cloud_filter(cloud_provider: str | None) -> str:
    raw = str(cloud_provider or "all").strip().lower()
    if not raw or raw in {"all", "any", "auto"}:
        return "all"
    if raw not in {"aws", "gcp", "azure"}:
        raise ValueError("cloud_provider filter must be one of: all, aws, gcp, azure.")
    return raw


def _multicloud_inv_path() -> Path:
    return config.DATA / "multicloud_inventory.json"


def save_multicloud_inventory(inventory: dict[str, Any]) -> dict[str, Any]:
    path = _multicloud_inv_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    existing = load_multicloud_inventory() or {}
    provider = str(inventory.get("cloud_provider") or "aws").lower()
    existing[provider] = inventory
    path.write_text(json.dumps(existing, indent=2), encoding="utf-8")
    return inventory


def load_multicloud_inventory() -> dict[str, Any] | None:
    path = _multicloud_inv_path()
    if not path.is_file():
        return None
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        return raw if isinstance(raw, dict) else None
    except Exception:
        return None


def import_scoutsuite_json(raw_data: str | bytes | dict[str, Any]) -> dict[str, Any]:
    inv = parse_scoutsuite_inventory(raw_data)
    save_multicloud_inventory(inv)
    return {"ok": True, "inventory": inv, "saved_path": str(_multicloud_inv_path())}


def _extract_aws_vectors_from_alerts(conn, limit: int, *, cloud_filter: str = "all") -> list[dict[str, Any]]:
    vectors: list[dict[str, Any]] = []
    seen_keys: set[str] = set()

    # 1. Proxy alerts & high-risk telemetry across AWS, GCP, Azure, and Web Apps
    rows = conn.execute(
        """
        SELECT proxy_event_id, timestamp, cloud_provider, account_scope,
               traffic_kind, action_taken, principal,
               method, target_host, path, service, operation, user_agent,
               aws_region, params_json, risk_score, matched_static, matched_dynamic
        FROM proxy_event
        WHERE action_taken IN ('alerted', 'blocked') OR risk_score >= 40.0
        ORDER BY timestamp DESC
        LIMIT ?
        """,
        (max(limit * 4, 24),),
    ).fetchall()

    for row in rows:
        if len(vectors) >= limit:
            break
        traffic_kind = str(row["traffic_kind"] or "http_app")
        cloud = str(row["cloud_provider"] or "").strip().lower()
        if not cloud or cloud == "unknown":
            if traffic_kind.startswith("gcp"):
                cloud = "gcp"
            elif traffic_kind.startswith("azure"):
                cloud = "azure"
            elif traffic_kind == "aws_api":
                cloud = "aws"
            else:
                cloud = "unknown"
        account_scope = str(row["account_scope"] or "")
        service = str(row["service"] or "http_app").lower()
        operation = str(row["operation"] or "UnknownOp")
        is_cloud_api = traffic_kind in {"aws_api", "gcp_api", "azure_api"} or (
            cloud in {"aws", "gcp", "azure"} and service not in {"http_app", "https_tunnel"}
        )

        if cloud_filter != "all":
            if is_cloud_api and cloud != cloud_filter:
                continue
            if not is_cloud_api and cloud != cloud_filter:
                continue

        try:
            params = json.loads(row["params_json"] or "{}")
        except json.JSONDecodeError:
            params = {}
        try:
            matched_static = json.loads(row["matched_static"] or "[]")
        except json.JSONDecodeError:
            matched_static = []
        try:
            matched_dynamic = json.loads(row["matched_dynamic"] or "[]")
        except json.JSONDecodeError:
            matched_dynamic = []

        if is_cloud_api:
            cloud = cloud if cloud in {"aws", "gcp", "azure"} else "aws"
            dedupe_key = f"{cloud}:{service}:{operation}"
            if dedupe_key in seen_keys:
                continue
            seen_keys.add(dedupe_key)
            tech_id = _deterministic_technique_id(service, operation)
            tactic = _tactic_for(service, operation)
            target_resource = (
                params.get("bucketName")
                or params.get("userName")
                or params.get("roleArn")
                or params.get("secretId")
                or params.get("instanceId")
                or row["path"]
                or service
            )
            vectors.append(
                {
                    "vector_id": f"alrt-{hashlib.sha256(dedupe_key.encode()).hexdigest()[:10]}",
                    "source_origin": "from_alerts",
                    "source_detail": f"proxy_event:{row['proxy_event_id']}",
                    "cloud_provider": cloud,
                    "account_scope": account_scope,
                    "traffic_kind": f"{cloud}_api",
                    "technique_id": tech_id,
                    "name": f"Alert Replay ({cloud.upper()}): {service}:{operation}",
                    "tactic": tactic,
                    "service": service,
                    "operation": operation,
                    "event_names": [operation],
                    "principal": row["principal"] or "unknown",
                    "target_resource": str(target_resource),
                    "user_agent": row["user_agent"] or "",
                    "aws_region": row["aws_region"] or ("eu-west-1" if cloud == "aws" else "global"),
                    "risk_score": float(row["risk_score"] or 0.0),
                    "matched_rules": list(matched_static) + list(matched_dynamic),
                    "reason": f"Flagged by Live Proxy ({cloud.upper()}, {row['action_taken']}, score {row['risk_score']})",
                }
            )
        else:
            path_val = str(row["path"] or "/")
            method = str(row["method"] or "GET").upper()
            dedupe_key = f"http:{method}:{path_val.split('?', 1)[0]}"
            if dedupe_key in seen_keys:
                continue
            seen_keys.add(dedupe_key)
            vectors.append(
                {
                    "vector_id": f"http-{hashlib.sha256(dedupe_key.encode()).hexdigest()[:10]}",
                    "source_origin": "from_alerts",
                    "source_detail": f"proxy_event:{row['proxy_event_id']}",
                    "cloud_provider": "unknown",
                    "account_scope": "",
                    "traffic_kind": "http_app",
                    "technique_id": "T1190",
                    "name": f"Web Probe Replay: {method} {path_val[:48]}",
                    "tactic": "initial-access",
                    "service": "http_app",
                    "operation": operation,
                    "event_names": [operation],
                    "principal": row["principal"] or "unknown",
                    "target_resource": f"{row['target_host'] or 'app.local'}{path_val}",
                    "user_agent": row["user_agent"] or "",
                    "aws_region": row["aws_region"] or "eu-west-1",
                    "risk_score": float(row["risk_score"] or 0.0),
                    "matched_rules": list(matched_static) + list(matched_dynamic),
                    "http_request": {
                        "method": method,
                        "target_host": row["target_host"] or "api.example.internal",
                        "path": path_val,
                        "user_agent": row["user_agent"] or "curl/8.4.0",
                    },
                    "reason": f"Suspicious web/app request ({row['action_taken']}, score {row['risk_score']})",
                }
            )

    # 2. Fallback/supplement from batch multi-cloud audit denied or alerted events
    if len(vectors) < limit:
        cloud_clause = "AND e.cloud_provider = ?" if cloud_filter != "all" else ""
        sql_params: list[Any] = [cloud_filter] if cloud_filter != "all" else []
        sql_params.append(max(limit - len(vectors), 0) * 2)
        ct_rows = conn.execute(
            f"""
            SELECT e.event_id, e.cloud_provider, e.account_scope,
                   e.event_source, e.event_name, e.aws_region,
                   e.user_agent, e.user_identity_arn, e.error_code
            FROM event e
            LEFT JOIN alert a ON a.event_id = e.event_id
            WHERE (e.error_code IN (
                    'AccessDenied', 'UnauthorizedOperation', 'Client.UnauthorizedOperation',
                    'PERMISSION_DENIED', '7', 'AuthorizationFailed', 'Forbidden', 'AADSTS53003', '403'
                )
               OR a.alert_id IS NOT NULL)
               {cloud_clause}
            GROUP BY e.cloud_provider, e.event_source, e.event_name
            ORDER BY MAX(e.event_time) DESC
            LIMIT ?
            """,
            tuple(sql_params),
        ).fetchall()
        for row in ct_rows:
            if len(vectors) >= limit:
                break
            cloud = str(row["cloud_provider"] or "aws").lower()
            src = str(row["event_source"] or "iam.amazonaws.com")
            service = src.split(".", 1)[0].lower() if cloud == "aws" else src
            operation = str(row["event_name"] or "GetCallerIdentity")
            dedupe_key = f"{cloud}:{service}:{operation}"
            if dedupe_key in seen_keys:
                continue
            seen_keys.add(dedupe_key)
            tech_id = _deterministic_technique_id(service, operation)
            vectors.append(
                {
                    "vector_id": f"ct-{hashlib.sha256(dedupe_key.encode()).hexdigest()[:10]}",
                    "source_origin": "from_alerts",
                    "source_detail": f"event:{row['event_id']}",
                    "cloud_provider": cloud,
                    "account_scope": str(row["account_scope"] or ""),
                    "traffic_kind": f"{cloud}_api" if cloud in {"aws", "gcp", "azure"} else "aws_api",
                    "technique_id": tech_id,
                    "name": f"Audit Flagged ({cloud.upper()}): {service}:{operation}",
                    "tactic": _tactic_for(service, operation),
                    "service": service,
                    "operation": operation,
                    "event_names": [operation],
                    "principal": row["user_identity_arn"] or f"{cloud}-actor",
                    "target_resource": service,
                    "user_agent": row["user_agent"] or "",
                    "aws_region": row["aws_region"] or ("eu-west-1" if cloud == "aws" else "global"),
                    "risk_score": 65.0 if row["error_code"] else 55.0,
                    "matched_rules": [row["error_code"]] if row["error_code"] else ["sigma-alert"],
                    "reason": (
                        f"Denied {cloud.upper()} audit call ({row['error_code']})"
                        if row["error_code"]
                        else f"Matched stored {cloud.upper()} audit alert"
                    ),
                }
            )

    return vectors[:limit]


def _vectors_from_resources(
    limit: int,
    *,
    binding: settings.ResourceBinding | None = None,
    cloudfox_inventory: dict[str, Any] | None = None,
    multicloud_inventory: dict[str, Any] | None = None,
    cloud_filter: str = "all",
) -> list[dict[str, Any]]:
    bound = binding or settings.get_resources()
    cf = cloudfox_inventory if cloudfox_inventory is not None else load_cloudfox_inventory()
    mc = multicloud_inventory if multicloud_inventory is not None else load_multicloud_inventory()
    cf_res = (cf or {}).get("resources") or {}
    vectors: list[dict[str, Any]] = []

    if cloud_filter in {"all", "aws"}:
        buckets: list[str] = list(cf_res.get("buckets") or [])
        if bound.data_bucket and bound.data_bucket not in buckets:
            buckets.insert(0, bound.data_bucket)

        iam_users: list[str] = list(cf_res.get("iam_users") or [])
        if bound.test_user_name and bound.test_user_name not in iam_users:
            iam_users.insert(0, bound.test_user_name)

        iam_roles: list[str] = list(cf_res.get("iam_roles") or [])
        if bound.admin_role_name and bound.admin_role_name not in iam_roles:
            iam_roles.insert(0, bound.admin_role_name)

        ec2_instances: list[str] = list(cf_res.get("ec2_instances") or [])
        if bound.instance_id and bound.instance_id not in ec2_instances:
            ec2_instances.insert(0, bound.instance_id)

        secrets: list[str] = list(cf_res.get("secrets") or [])
        lambdas: list[str] = list(cf_res.get("lambdas") or [])
        sqs_queues: list[str] = list(cf_res.get("sqs_queues") or [])
        if bound.queue_url and bound.queue_url not in sqs_queues:
            sqs_queues.insert(0, bound.queue_url)
        region = bound.region or "eu-west-1"

        if buckets:
            vectors.append(
                {
                    "vector_id": "res-s3-object",
                    "source_origin": "from_resources",
                    "source_detail": f"resource:s3:{buckets[0]}",
                    "cloud_provider": "aws",
                    "account_scope": "",
                    "traffic_kind": "aws_api",
                    "technique_id": "T1530",
                    "name": f"Resource Target S3 Access ({buckets[0]})",
                    "tactic": "collection",
                    "service": "s3",
                    "operation": "GetObject",
                    "event_names": ["ListBucket", "GetObject"],
                    "principal": iam_users[0] if iam_users else "bound-identity",
                    "target_resource": buckets[0],
                    "target_params": {"bucketName": buckets[0], "key": bound.data_key or "finance/q4.csv"},
                    "user_agent": "",
                    "aws_region": region,
                    "risk_score": 0.0,
                    "matched_rules": [],
                    "reason": f"Synthesized against discovered S3 bucket '{buckets[0]}'",
                }
            )
        if iam_users:
            vectors.append(
                {
                    "vector_id": "res-iam-user",
                    "source_origin": "from_resources",
                    "source_detail": f"resource:iam_user:{iam_users[0]}",
                    "cloud_provider": "aws",
                    "account_scope": "",
                    "traffic_kind": "aws_api",
                    "technique_id": "T1098.001",
                    "name": f"Resource Target IAM Key Abuse ({iam_users[0]})",
                    "tactic": "persistence",
                    "service": "iam",
                    "operation": "CreateAccessKey",
                    "event_names": ["CreateAccessKey", "ListAccessKeys"],
                    "principal": iam_users[0],
                    "target_resource": iam_users[0],
                    "target_params": {"userName": iam_users[0].split("/")[-1]},
                    "user_agent": "",
                    "aws_region": region,
                    "risk_score": 0.0,
                    "matched_rules": [],
                    "reason": f"Synthesized against discovered IAM user '{iam_users[0]}'",
                }
            )
        if iam_roles:
            vectors.append(
                {
                    "vector_id": "res-iam-role",
                    "source_origin": "from_resources",
                    "source_detail": f"resource:iam_role:{iam_roles[0]}",
                    "cloud_provider": "aws",
                    "account_scope": "",
                    "traffic_kind": "aws_api",
                    "technique_id": "T1098.003",
                    "name": f"Resource Target Role Escalation ({iam_roles[0].split('/')[-1]})",
                    "tactic": "privilege-escalation",
                    "service": "iam",
                    "operation": "AttachRolePolicy",
                    "event_names": ["AttachRolePolicy", "PutRolePolicy", "AssumeRole"],
                    "principal": iam_roles[0],
                    "target_resource": iam_roles[0],
                    "target_params": {"roleName": iam_roles[0].split("/")[-1]},
                    "user_agent": "",
                    "aws_region": region,
                    "risk_score": 0.0,
                    "matched_rules": [],
                    "reason": f"Synthesized against discovered IAM role '{iam_roles[0]}'",
                }
            )
        if ec2_instances:
            vectors.append(
                {
                    "vector_id": "res-ec2-instance",
                    "source_origin": "from_resources",
                    "source_detail": f"resource:ec2:{ec2_instances[0]}",
                    "cloud_provider": "aws",
                    "account_scope": "",
                    "traffic_kind": "aws_api",
                    "technique_id": "T1552.005",
                    "name": f"Resource Target EC2 Metadata / Enum ({ec2_instances[0]})",
                    "tactic": "credential-access",
                    "service": "ec2",
                    "operation": "DescribeInstances",
                    "event_names": ["DescribeInstances", "GetCallerIdentity"],
                    "principal": ec2_instances[0],
                    "target_resource": ec2_instances[0],
                    "target_params": {"instanceId": ec2_instances[0]},
                    "user_agent": "",
                    "aws_region": region,
                    "risk_score": 0.0,
                    "matched_rules": [],
                    "reason": f"Synthesized against discovered EC2 instance '{ec2_instances[0]}'",
                }
            )
        if secrets:
            vectors.append(
                {
                    "vector_id": "res-secretsmanager",
                    "source_origin": "from_resources",
                    "source_detail": f"resource:secret:{secrets[0]}",
                    "cloud_provider": "aws",
                    "account_scope": "",
                    "traffic_kind": "aws_api",
                    "technique_id": _deterministic_technique_id("secretsmanager", "GetSecretValue", offset=9200),
                    "name": f"Resource Target Secrets Access ({secrets[0]})",
                    "tactic": "credential-access",
                    "service": "secretsmanager",
                    "operation": "GetSecretValue",
                    "event_names": ["ListSecrets", "GetSecretValue"],
                    "principal": iam_roles[0] if iam_roles else "bound-identity",
                    "target_resource": secrets[0],
                    "target_params": {"secretId": secrets[0]},
                    "user_agent": "",
                    "aws_region": region,
                    "risk_score": 0.0,
                    "matched_rules": [],
                    "reason": f"Synthesized against CloudFox secret '{secrets[0]}'",
                }
            )
        if lambdas:
            vectors.append(
                {
                    "vector_id": "res-lambda",
                    "source_origin": "from_resources",
                    "source_detail": f"resource:lambda:{lambdas[0]}",
                    "cloud_provider": "aws",
                    "account_scope": "",
                    "traffic_kind": "aws_api",
                    "technique_id": _deterministic_technique_id("lambda", "GetFunction", offset=9200),
                    "name": f"Resource Target Lambda Recon ({lambdas[0]})",
                    "tactic": "discovery",
                    "service": "lambda",
                    "operation": "GetFunction",
                    "event_names": ["ListFunctions", "GetFunction"],
                    "principal": iam_roles[0] if iam_roles else "bound-identity",
                    "target_resource": lambdas[0],
                    "target_params": {"functionName": lambdas[0]},
                    "user_agent": "",
                    "aws_region": region,
                    "risk_score": 0.0,
                    "matched_rules": [],
                    "reason": f"Synthesized against CloudFox Lambda '{lambdas[0]}'",
                }
            )
        if sqs_queues:
            vectors.append(
                {
                    "vector_id": "res-sqs",
                    "source_origin": "from_resources",
                    "source_detail": f"resource:sqs:{sqs_queues[0]}",
                    "cloud_provider": "aws",
                    "account_scope": "",
                    "traffic_kind": "aws_api",
                    "technique_id": _deterministic_technique_id("sqs", "GetQueueAttributes", offset=9200),
                    "name": "Resource Target SQS Queue Probe",
                    "tactic": "discovery",
                    "service": "sqs",
                    "operation": "GetQueueAttributes",
                    "event_names": ["GetQueueAttributes"],
                    "principal": iam_users[0] if iam_users else "bound-identity",
                    "target_resource": sqs_queues[0],
                    "target_params": {"queueUrl": sqs_queues[0]},
                    "user_agent": "",
                    "aws_region": region,
                    "risk_score": 0.0,
                    "matched_rules": [],
                    "reason": "Synthesized against bound/CloudFox SQS queue",
                }
            )

    # Multi-cloud discovered resource vectors (GCP / Azure from ScoutSuite / recon JSON)
    if mc:
        for cid in ("gcp", "azure"):
            if cloud_filter not in {"all", cid}:
                continue
            inv = mc.get(cid)
            if not isinstance(inv, dict):
                continue
            scope = str(inv.get("account_scope") or "")
            res = inv.get("resources") or {}
            if cid == "gcp":
                if res.get("buckets"):
                    b = res["buckets"][0]
                    vectors.append(
                        {
                            "vector_id": f"res-gcp-gcs-{_safe_slug(b)[:12]}",
                            "source_origin": "from_resources",
                            "source_detail": f"scoutsuite:gcp:{b}",
                            "cloud_provider": "gcp",
                            "account_scope": scope,
                            "traffic_kind": "gcp_api",
                            "technique_id": "T1530.GCP01",
                            "name": f"GCP Target Bucket Read ({b})",
                            "tactic": "collection",
                            "service": "storage.googleapis.com",
                            "operation": "storage.objects.get",
                            "event_names": ["storage.objects.list", "storage.objects.get"],
                            "principal": (res.get("identities") or ["gcp-operator"])[0],
                            "target_resource": b,
                            "aws_region": "global",
                            "risk_score": 0.0,
                            "matched_rules": [],
                            "reason": f"Synthesized against discovered GCP bucket '{b}'",
                        }
                    )
                if res.get("secrets"):
                    sec = res["secrets"][0]
                    vectors.append(
                        {
                            "vector_id": f"res-gcp-sec-{_safe_slug(sec)[:12]}",
                            "source_origin": "from_resources",
                            "source_detail": f"scoutsuite:gcp:{sec}",
                            "cloud_provider": "gcp",
                            "account_scope": scope,
                            "traffic_kind": "gcp_api",
                            "technique_id": "T1555.GCP06",
                            "name": f"GCP Target Secret Access ({sec})",
                            "tactic": "credential-access",
                            "service": "secretmanager.googleapis.com",
                            "operation": "google.cloud.secretmanager.v1.SecretManagerService.AccessSecretVersion",
                            "event_names": ["google.cloud.secretmanager.v1.SecretManagerService.AccessSecretVersion"],
                            "principal": (res.get("identities") or ["gcp-operator"])[0],
                            "target_resource": sec,
                            "aws_region": "global",
                            "risk_score": 0.0,
                            "matched_rules": [],
                            "reason": f"Synthesized against discovered GCP Secret '{sec}'",
                        }
                    )
            else:
                if res.get("secrets"):
                    sec = res["secrets"][0]
                    vectors.append(
                        {
                            "vector_id": f"res-az-kv-{_safe_slug(sec)[:12]}",
                            "source_origin": "from_resources",
                            "source_detail": f"scoutsuite:azure:{sec}",
                            "cloud_provider": "azure",
                            "account_scope": scope,
                            "traffic_kind": "azure_api",
                            "technique_id": "T1555.AZ06",
                            "name": f"Azure Key Vault Secret Access ({sec})",
                            "tactic": "credential-access",
                            "service": "Microsoft.KeyVault",
                            "operation": "SecretGet",
                            "event_names": ["SecretList", "SecretGet"],
                            "principal": (res.get("identities") or ["azure-spn"])[0],
                            "target_resource": sec,
                            "aws_region": "global",
                            "risk_score": 0.0,
                            "matched_rules": [],
                            "reason": f"Synthesized against discovered Azure Key Vault secret '{sec}'",
                        }
                    )
                if res.get("identities"):
                    ident = res["identities"][0]
                    vectors.append(
                        {
                            "vector_id": f"res-az-rbac-{_safe_slug(ident)[:12]}",
                            "source_origin": "from_resources",
                            "source_detail": f"scoutsuite:azure:{ident}",
                            "cloud_provider": "azure",
                            "account_scope": scope,
                            "traffic_kind": "azure_api",
                            "technique_id": "T1098.AZ03",
                            "name": f"Azure RBAC Role Escalation ({ident})",
                            "tactic": "privilege-escalation",
                            "service": "Microsoft.Authorization",
                            "operation": "Microsoft.Authorization/roleAssignments/write",
                            "event_names": ["Microsoft.Authorization/roleAssignments/write"],
                            "principal": ident,
                            "target_resource": ident,
                            "aws_region": "global",
                            "risk_score": 0.0,
                            "matched_rules": [],
                            "reason": f"Synthesized against discovered Azure principal '{ident}'",
                        }
                    )

    return vectors[:limit]


def preview_closed_loop_vectors(
    conn,
    *,
    mode: str = "both",
    limit: int = 8,
    cloudfox_inventory: dict[str, Any] | None = None,
    multicloud_inventory: dict[str, Any] | None = None,
    cloud_provider: str | None = "all",
) -> dict[str, Any]:
    """Discover candidate closed-loop vectors from alerts, discovered resources, or both."""
    normalized_mode = normalize_closed_loop_mode(mode)
    cloud_filter = normalize_cloud_filter(cloud_provider)
    bounded_limit = max(1, min(int(limit), 25))
    cf = cloudfox_inventory if cloudfox_inventory is not None else load_cloudfox_inventory()
    mc = multicloud_inventory if multicloud_inventory is not None else load_multicloud_inventory()

    alert_vectors: list[dict[str, Any]] = []
    resource_vectors: list[dict[str, Any]] = []

    if normalized_mode in {"from_alerts", "both"}:
        alert_vectors = _extract_aws_vectors_from_alerts(conn, bounded_limit, cloud_filter=cloud_filter)
    if normalized_mode in {"from_resources", "both"}:
        resource_vectors = _vectors_from_resources(
            bounded_limit,
            cloudfox_inventory=cf,
            multicloud_inventory=mc,
            cloud_filter=cloud_filter,
        )

    combined: list[dict[str, Any]] = []
    seen_op: set[str] = set()
    for item in alert_vectors + resource_vectors:
        key = f"{item.get('cloud_provider', 'aws')}:{item['traffic_kind']}:{item['service']}:{item['operation']}:{item['target_resource']}"
        if key in seen_op:
            continue
        seen_op.add(key)
        combined.append(item)
        if len(combined) >= bounded_limit:
            break

    return {
        "mode": normalized_mode,
        "cloud_provider": cloud_filter,
        "vectors": combined,
        "counts": {
            "total": len(combined),
            "from_alerts": len(alert_vectors),
            "from_resources": len(resource_vectors),
            "aws_api": sum(1 for v in combined if v["traffic_kind"] == "aws_api"),
            "gcp_api": sum(1 for v in combined if v["traffic_kind"] == "gcp_api"),
            "azure_api": sum(1 for v in combined if v["traffic_kind"] == "azure_api"),
            "http_app": sum(1 for v in combined if v["traffic_kind"] == "http_app"),
        },
        "cloudfox_loaded": bool(cf),
        "cloudfox_counts": (cf or {}).get("counts") or {},
        "multicloud_loaded": sorted(mc.keys()) if mc else [],
    }


def _load_rules_for_versions(versions: list[str]) -> list[Rule]:
    """Load in-memory Rule objects across requested rulesets without mutating frozen DB rows."""
    configs = load_ruleset_config()
    loaded: list[Rule] = []
    seen_ids: set[str] = set()
    for version in versions:
        entry = configs.get(version)
        if not entry:
            continue
        for relative in entry.get("sigma_dirs") or []:
            candidate = Path(relative)
            directory = candidate if candidate.is_absolute() else (config.ROOT / candidate)
            if not directory.exists():
                continue
            for path in sorted(directory.iterdir()):
                if path.suffix.lower() not in {".yml", ".yaml"} or not path.is_file():
                    continue
                try:
                    rule = load_sigma_text(path.read_text(encoding="utf-8"), path=str(path))
                except RuleError:
                    continue
                key = f"{version}:{rule.native_id}"
                if key not in seen_ids:
                    seen_ids.add(key)
                    loaded.append(rule)
        if entry.get("include_python_rules"):
            for rule in python_rules.rules():
                key = f"{version}:{rule.native_id}"
                if key not in seen_ids:
                    seen_ids.add(key)
                    loaded.append(rule)
    return loaded


def _build_dynamic_eval_conn(source_conn) -> sqlite3.Connection:
    """Create a fast in-memory SQLite copy seeded with active dynamic_rule rows."""
    mem = sqlite3.connect(":memory:")
    mem.row_factory = sqlite3.Row
    mem.executescript(config.SCHEMA_SQL.read_text(encoding="utf-8"))
    rules = list_dynamic_rules(source_conn)
    for r in rules:
        mem.execute(
            """
            INSERT INTO dynamic_rule (rule_id, name, kind, enabled, severity,
                                      window_seconds, threshold, config_json, description, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                r["rule_id"],
                r["name"],
                r["kind"],
                1 if r["enabled"] else 0,
                r["severity"],
                int(r["window_seconds"]),
                int(r["threshold"]),
                json.dumps(r["config"]),
                r.get("description") or "",
                r["created_at"],
            ),
        )
    mem.commit()
    return mem


def _vector_to_technique(vector: Mapping[str, Any], catalogue: Catalogue) -> Technique:
    tid = str(vector["technique_id"])
    for existing in catalogue.techniques:
        if existing.technique_id == tid and vector.get("source_origin") == "from_resources":
            return existing

    service = str(vector.get("service") or "sts").lower()
    operation = str(vector.get("operation") or "GetCallerIdentity")
    event_names = tuple(vector.get("event_names") or (operation,))
    snake_op = _RESOURCE_OP_TO_SNAKE.get(operation) or _camel_to_snake(operation)

    return Technique(
        technique_id=tid,
        name=str(vector.get("name") or f"{service}:{operation}"),
        tactic=str(vector.get("tactic") or "discovery"),
        executor="custom_boto3",
        executor_ref="identity_shield.runner.executors.custom_api",
        event_names=event_names,
        required_actions=tuple(f"{service}:{op}" for op in event_names),
        requires_data_events=(service == "s3"),
        excluded_levels={},
        baseline_levels={},
        success_check={},
        api_calls=({"service": service, "operation": snake_op, "kwargs": dict(vector.get("target_params") or {})},),
        custom=True,
        enabled=True,
    )


def _patch_event_with_vector(event: dict[str, Any], vector: Mapping[str, Any]) -> None:
    if vector.get("aws_region"):
        event.setdefault("awsRegion", vector["aws_region"])
    target_params = vector.get("target_params")
    if isinstance(target_params, Mapping) and target_params:
        params = event.setdefault("requestParameters", {})
        if isinstance(params, dict):
            for k, v in target_params.items():
                params.setdefault(k, v)


def _write_closed_loop_sigma_rule(
    vector: Mapping[str, Any],
    evaded_events: list[dict[str, Any]],
) -> dict[str, str]:
    """Generate and persist a generalized cloud-scoped Sigma rule into data/rules/enhanced/."""
    cloud = str(vector.get("cloud_provider") or "aws").lower()
    service = str(vector.get("service") or cloud).lower()
    operation = str(vector.get("operation") or "GetCallerIdentity")
    tid = str(vector.get("technique_id") or "T9100")
    tactic = _safe_slug(str(vector.get("tactic") or "discovery")).replace("-", "_")

    default_src = (
        f"{service}.amazonaws.com"
        if cloud == "aws" and "." not in service
        else service
    )
    sources: list[str] = [default_src]
    names: list[str] = list(vector.get("event_names") or [operation])
    for evt in evaded_events:
        src = str(evt.get("eventSource") or "").strip()
        op = str(evt.get("eventName") or "").strip()
        if op and op not in _GENERIC_OPS and op not in names:
            names.append(op)
        if src and src not in sources and op not in _GENERIC_OPS:
            sources.append(src)

    safe_stem = _safe_slug(f"loop-{cloud}-{service}-{operation}")
    enhanced_dir = config.DATA / "rules" / "enhanced"
    enhanced_dir.mkdir(parents=True, exist_ok=True)
    target_path = (enhanced_dir / f"enhanced-{safe_stem}.yml").resolve()
    if not target_path.is_relative_to(enhanced_dir.resolve()):
        raise ValueError("Invalid enhanced rule path.")

    rule_uuid = str(uuid.uuid5(uuid.NAMESPACE_DNS, f"identity-shield.closed-loop.{cloud}.{service}.{operation}"))
    logsource_svc = "cloudtrail" if cloud == "aws" else ("gcp.audit" if cloud == "gcp" else "activitylogs")
    if cloud == "gcp":
        detection_lines = [
            "detection:",
            "  selection_native:",
            "    protoPayload.serviceName:",
            *[f"      - '{src}'" for src in sources],
            "    protoPayload.methodName:",
            *[f"      - '{name}'" for name in names],
            "  selection_canonical:",
            "    eventSource:",
            *[f"      - '{src}'" for src in sources],
            "    eventName:",
            *[f"      - '{name}'" for name in names],
            "  condition: 1 of selection_*",
        ]
    elif cloud == "azure":
        detection_lines = [
            "detection:",
            "  selection_activity:",
            "    operationName.value:",
            *[f"      - '{name}'" for name in names],
            "  selection_entra:",
            "    activityDisplayName:",
            *[f"      - '{name}'" for name in names],
            "  selection_canonical:",
            "    eventSource:",
            *[f"      - '{src}'" for src in sources],
            "    eventName:",
            *[f"      - '{name}'" for name in names],
            "  condition: 1 of selection_*",
        ]
    else:
        detection_lines = [
            "detection:",
            "  selection_op:",
            "    eventSource:",
            *[f"      - '{src}'" for src in sources],
            "    eventName:",
            *[f"      - '{name}'" for name in names],
            "  condition: selection_op",
        ]
    lines = [
        f"title: 'Closed-Loop Guard ({cloud.upper()}): {service}:{operation}'",
        f"id: {rule_uuid}",
        "status: experimental",
        f"description: 'Auto-hardened by Closed-Loop Engine to cover 5-factor evasion variants of {cloud}:{service}:{operation}.'",
        "author: Identity Shield Closed-Loop Engine",
        f"date: {datetime.now(timezone.utc).strftime('%Y/%m/%d')}",
        "tags:",
        f"  - attack.{tactic}",
        f"  - attack.{tid.lower()}",
        "logsource:",
        f"  product: {cloud if cloud in {'aws', 'gcp', 'azure'} else 'aws'}",
        f"  service: {logsource_svc}",
        *detection_lines,
        "falsepositives:",
        "  - Authorized administrative workflows using bound resources",
        "level: high",
        "",
    ]
    yaml_text = "\n".join(lines)
    load_sigma_text(yaml_text, path=str(target_path))
    target_path.write_text(yaml_text, encoding="utf-8")
    return {
        "path": str(target_path),
        "rule_id": rule_uuid,
        "title": f"Closed-Loop Guard ({cloud.upper()}): {service}:{operation}",
        "cloud_provider": cloud,
    }


def _http_variants_for_vector(vector: Mapping[str, Any]) -> list[dict[str, Any]]:
    req = vector.get("http_request") or {}
    method = str(req.get("method") or "GET").upper()
    host = str(req.get("target_host") or "api.example.internal")
    raw_path = str(req.get("path") or "/.env")
    base_ua = str(req.get("user_agent") or "curl/8.4.0")

    return [
        {
            "variant_label": "baseline_probe",
            "factor_note": "Original captured probe",
            "method": method,
            "host": host,
            "path": raw_path,
            "user_agent": base_ua,
        },
        {
            "variant_label": "spoofed_boto3_ua",
            "factor_note": "client_tool -> boto3_default",
            "method": method,
            "host": host,
            "path": raw_path,
            "user_agent": "Boto3/1.35.0 Python/3.12.7",
        },
        {
            "variant_label": "spoofed_terraform_ua",
            "factor_note": "client_tool -> terraform",
            "method": method,
            "host": host,
            "path": raw_path,
            "user_agent": "HashiCorp-Terraform/1.9.8",
        },
        {
            "variant_label": "double_encoded_path",
            "factor_note": "api_form -> URL percent-encoding",
            "method": method,
            "host": host,
            "path": raw_path.replace("../", "%2e%2e%2f").replace(".env", ".%65nv"),
            "user_agent": base_ua,
        },
        {
            "variant_label": "case_and_query_pad",
            "factor_note": "api_form -> mixed-case + query noise",
            "method": method,
            "host": host,
            "path": (raw_path.upper() if "?" not in raw_path else raw_path) + ("&v=1" if "?" in raw_path else "?v=1"),
            "user_agent": "Mozilla/5.0 (compatible; ProbeBot/1.0)",
        },
    ]


def _match_any(rules: list[Rule], event: Mapping[str, Any], *, cloud_provider: str | None = None) -> list[str]:
    hits: list[str] = []
    event_cloud = cloud_provider or str(event.get("cloudProvider") or "aws").lower()
    for rule in rules:
        if not rule.matches_cloud(event_cloud):
            continue
        try:
            if rule.matches(event):
                hits.append(rule.native_id)
        except RuleError:
            continue
    return hits


def run_closed_loop(
    conn,
    *,
    mode: str = "both",
    include_pairwise: bool = False,
    auto_enhance: bool = True,
    limit: int = 6,
    cloudfox_inventory: dict[str, Any] | None = None,
    multicloud_inventory: dict[str, Any] | None = None,
    cloud_provider: str | None = "all",
) -> dict[str, Any]:
    """Execute Multi-Cloud Closed-Loop Alert/Resource -> 5-Factor Variants -> Harden workflow."""
    preview = preview_closed_loop_vectors(
        conn,
        mode=mode,
        limit=limit,
        cloudfox_inventory=cloudfox_inventory,
        multicloud_inventory=multicloud_inventory,
        cloud_provider=cloud_provider,
    )
    vectors = preview["vectors"]
    loop_run_id = f"cl-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-{uuid.uuid4().hex[:6]}"

    if not vectors:
        report = {
            "loop_run_id": loop_run_id,
            "executed_at": _utc_now(),
            "mode": preview["mode"],
            "cloud_provider": preview["cloud_provider"],
            "auto_enhance": bool(auto_enhance),
            "include_pairwise": bool(include_pairwise),
            "summary": {
                "vectors_tested": 0,
                "aws_variants_tested": 0,
                "gcp_variants_tested": 0,
                "azure_variants_tested": 0,
                "http_variants_tested": 0,
                "total_variants_tested": 0,
                "before_detected": 0,
                "after_detected": 0,
                "before_rate": 0.0,
                "after_rate": 0.0,
                "dynamic_detected": 0,
                "rules_generated": 0,
            },
            "vectors": [],
            "generated_rules": [],
            "message": "No alert or resource vectors found for the selected cloud and mode.",
        }
        _save_last_closed_loop_report(report)
        return report

    catalogue = load_catalogue(include_disabled=True)
    options = GenerationOptions(
        master_seed=20261119,
        holdout_per_technique=2,
        include_pairwise=bool(include_pairwise),
    )

    before_ruleset_label = "baseline-v1 + multicloud-v1 + enhanced-v1 + custom-v1"
    before_rules = _load_rules_for_versions(["baseline-v1", "multicloud-v1", "enhanced-v1", "custom-v1"])
    dyn_conn = _build_dynamic_eval_conn(conn)

    now_dt = datetime.now(timezone.utc)
    aws_total = 0
    gcp_total = 0
    azure_total = 0
    http_total = 0
    before_detected_total = 0
    dynamic_detected_total = 0

    vector_results: list[dict[str, Any]] = []
    aws_generated_records: list[tuple[dict[str, Any], list[dict[str, Any]]]] = []
    generated_rules: list[dict[str, str]] = []

    try:
        for vec in vectors:
            if vec["traffic_kind"] in {"aws_api", "gcp_api", "azure_api"}:
                vec_cloud = str(vec.get("cloud_provider") or "aws").lower()
                vec_scope = str(vec.get("account_scope") or "")
                technique = _vector_to_technique(vec, catalogue)
                variants, _stats = generate_for_technique(technique, catalogue, options)

                eval_items: list[dict[str, Any]] = []
                evaded_events: list[dict[str, Any]] = []
                unsupported_notes: list[str] = []
                unsupported_skipped = 0
                vec_before_hits = 0
                vec_dyn_hits = 0

                for variant in variants:
                    supported_ok, unsup_reasons = check_factor_support(vec_cloud, dict(variant.factor_levels))
                    if not supported_ok:
                        unsupported_notes.extend(unsup_reasons)
                        unsupported_skipped += 1
                        continue

                    events = multicloud_synthetic_events(
                        technique,
                        variant,
                        cloud_provider=vec_cloud,
                        account_scope=vec_scope,
                        run_id=loop_run_id,
                        start=now_dt,
                    )
                    for evt in events:
                        _patch_event_with_vector(evt, vec)

                    matched_before: list[str] = []
                    dyn_hits: list[str] = []
                    for evt in events:
                        for rid in _match_any(before_rules, evt, cloud_provider=vec_cloud):
                            if rid not in matched_before:
                                matched_before.append(rid)
                        proxy_like = {
                            "proxy_event_id": evt.get("eventID", uuid.uuid4().hex[:16]),
                            "timestamp": evt.get("eventTime", _utc_now()),
                            "cloud_provider": vec_cloud,
                            "account_scope": vec_scope,
                            "traffic_type": "cloud_api",
                            "traffic_kind": vec["traffic_kind"],
                            "is_synthetic": True,
                            "client_ip": evt.get("sourceIPAddress", "203.0.113.10"),
                            "principal": (evt.get("userIdentity") or {}).get("arn") or vec.get("principal") or "actor",
                            "method": "POST",
                            "target_host": evt.get("eventSource", vec["service"]),
                            "path": "/",
                            "service": vec["service"],
                            "operation": evt.get("eventName", vec["operation"]),
                            "user_agent": evt.get("userAgent", "sdk"),
                            "aws_region": evt.get("awsRegion", "global"),
                            "event_obj": evt,
                        }
                        dyn_res = evaluate_live_event(
                            dyn_conn,
                            proxy_like,
                            mode="observe",
                            learn_baseline=False,
                            static_rules=[],
                        )
                        for m in dyn_res.get("matched_dynamic") or []:
                            rname = str(m.get("rule_name") or m.get("rule_id") or "dynamic")
                            if rname not in dyn_hits:
                                dyn_hits.append(rname)

                    sigma_ok = bool(matched_before)
                    dyn_ok = bool(dyn_hits)
                    if sigma_ok:
                        vec_before_hits += 1
                    else:
                        evaded_events.extend(events)
                    if dyn_ok:
                        vec_dyn_hits += 1

                    eval_items.append(
                        {
                            "variant_id": variant.variant_id,
                            "variant_set": variant.variant_set,
                            "factor_levels": dict(variant.factor_levels),
                            "factor_supported": supported_ok,
                            "execution_mode": "synthetic",
                            "sigma_before": sigma_ok,
                            "dynamic_detected": dyn_ok,
                            "matched_before": matched_before,
                            "events": events,
                        }
                    )

                supported_count = len(eval_items)
                if vec_cloud == "gcp":
                    gcp_total += supported_count
                elif vec_cloud == "azure":
                    azure_total += supported_count
                else:
                    aws_total += supported_count
                before_detected_total += vec_before_hits
                dynamic_detected_total += vec_dyn_hits

                res_entry = {
                    "vector_id": vec["vector_id"],
                    "cloud_provider": vec_cloud,
                    "account_scope": vec_scope,
                    "source_origin": vec["source_origin"],
                    "source_detail": vec["source_detail"],
                    "traffic_kind": vec["traffic_kind"],
                    "technique_id": technique.technique_id,
                    "execution_mode": "synthetic",
                    "ruleset_version": before_ruleset_label,
                    "name": vec["name"],
                    "service": vec["service"],
                    "operation": vec["operation"],
                    "target_resource": vec["target_resource"],
                    "variants_tested": supported_count,
                    "unsupported_skipped": unsupported_skipped,
                    "before_detected": vec_before_hits,
                    "after_detected": vec_before_hits,
                    "before_rate": round((vec_before_hits / supported_count) * 100.0, 1) if supported_count else 0.0,
                    "after_rate": round((vec_before_hits / supported_count) * 100.0, 1) if supported_count else 0.0,
                    "dynamic_detected": vec_dyn_hits,
                    "evaded_before": supported_count - vec_before_hits,
                    "evaded_after": supported_count - vec_before_hits,
                    "validation_status": "covered" if vec_before_hits == supported_count else "gap_detected",
                    "unsupported_factor_notes": sorted(set(unsupported_notes))[:5],
                    "sample_evasions": [
                        {
                            "variant_id": item["variant_id"],
                            "variant_set": item["variant_set"],
                            "factor_levels": item["factor_levels"],
                        }
                        for item in eval_items
                        if not item["sigma_before"]
                    ][:5],
                    "hardened_rule": None,
                }

                if auto_enhance and (supported_count - vec_before_hits) > 0:
                    created = _write_closed_loop_sigma_rule(vec, evaded_events)
                    generated_rules.append(created)
                    res_entry["hardened_rule"] = created

                vector_results.append(res_entry)
                aws_generated_records.append((res_entry, eval_items))

            else:
                # HTTP / Web-App evasion verification across 5 mutations
                probes = _http_variants_for_vector(vec)
                dyn_hits_count = 0
                evaded_samples: list[dict[str, Any]] = []
                for probe in probes:
                    parsed = parse_request(
                        method=probe["method"],
                        url_or_path=probe["path"],
                        headers={"host": probe["host"], "user-agent": probe["user_agent"]},
                        body=b"",
                        client_ip="203.0.113.55",
                        target_host_override=probe["host"],
                    )
                    parsed["is_synthetic"] = True
                    dyn_res = evaluate_live_event(
                        dyn_conn,
                        parsed,
                        mode="observe",
                        learn_baseline=False,
                    )
                    detected = bool(dyn_res.get("matched_dynamic")) or float(dyn_res.get("risk_score") or 0.0) >= 40.0
                    if detected:
                        dyn_hits_count += 1
                    else:
                        evaded_samples.append(
                            {
                                "variant_id": probe["variant_label"],
                                "variant_set": "http_probe",
                                "factor_levels": {"mutation": probe["factor_note"], "path": probe["path"]},
                            }
                        )
                http_total += len(probes)
                before_detected_total += dyn_hits_count
                dynamic_detected_total += dyn_hits_count
                rate = round((dyn_hits_count / len(probes)) * 100.0, 1) if probes else 0.0
                vector_results.append(
                    {
                        "vector_id": vec["vector_id"],
                        "cloud_provider": "unknown",
                        "account_scope": "",
                        "source_origin": vec["source_origin"],
                        "source_detail": vec["source_detail"],
                        "traffic_kind": "http_app",
                        "technique_id": vec["technique_id"],
                        "execution_mode": "synthetic",
                        "ruleset_version": "dynamic-rules",
                        "name": vec["name"],
                        "service": "http_app",
                        "operation": vec["operation"],
                        "target_resource": vec["target_resource"],
                        "variants_tested": len(probes),
                        "before_detected": dyn_hits_count,
                        "after_detected": dyn_hits_count,
                        "before_rate": rate,
                        "after_rate": rate,
                        "dynamic_detected": dyn_hits_count,
                        "evaded_before": len(probes) - dyn_hits_count,
                        "evaded_after": len(probes) - dyn_hits_count,
                        "validation_status": "covered" if dyn_hits_count == len(probes) else "gap_detected",
                        "unsupported_factor_notes": [],
                        "sample_evasions": evaded_samples[:5],
                        "hardened_rule": None,
                    }
                )
    finally:
        dyn_conn.close()

    after_detected_total = before_detected_total
    if auto_enhance and generated_rules:
        after_rules = _load_rules_for_versions(["baseline-v1", "multicloud-v1", "enhanced-v1", "custom-v1"])
        after_detected_total = sum(
            res_entry["before_detected"]
            for res_entry in vector_results
            if res_entry["traffic_kind"] == "http_app"
        )
        for res_entry, eval_items in aws_generated_records:
            vec_cloud = str(res_entry.get("cloud_provider") or "aws").lower()
            hits_after = 0
            still_evaded: list[dict[str, Any]] = []
            for item in eval_items:
                matched_after = False
                for evt in item["events"]:
                    if _match_any(after_rules, evt, cloud_provider=vec_cloud):
                        matched_after = True
                        break
                if matched_after:
                    hits_after += 1
                else:
                    still_evaded.append(
                        {
                            "variant_id": item["variant_id"],
                            "variant_set": item["variant_set"],
                            "factor_levels": item["factor_levels"],
                        }
                    )
            total_v = max(len(eval_items), 1)
            res_entry["after_detected"] = hits_after
            res_entry["after_rate"] = round((hits_after / total_v) * 100.0, 1)
            res_entry["evaded_after"] = len(eval_items) - hits_after
            res_entry["validation_status"] = "hardened" if (len(eval_items) - hits_after) == 0 and res_entry.get("hardened_rule") else ("covered" if (len(eval_items) - hits_after) == 0 else "gap_remaining")
            if still_evaded:
                res_entry["sample_evasions"] = still_evaded[:5]
            after_detected_total += hits_after

    cloud_variants = aws_total + gcp_total + azure_total
    total_tested = cloud_variants + http_total
    before_rate = round((before_detected_total / total_tested) * 100.0, 1) if total_tested else 0.0
    after_rate = round((after_detected_total / total_tested) * 100.0, 1) if total_tested else 0.0

    report = {
        "loop_run_id": loop_run_id,
        "executed_at": _utc_now(),
        "mode": preview["mode"],
        "cloud_provider": preview["cloud_provider"],
        "auto_enhance": bool(auto_enhance),
        "include_pairwise": bool(include_pairwise),
        "summary": {
            "vectors_tested": len(vector_results),
            "aws_variants_tested": aws_total,
            "gcp_variants_tested": gcp_total,
            "azure_variants_tested": azure_total,
            "http_variants_tested": http_total,
            "total_variants_tested": total_tested,
            "before_detected": before_detected_total,
            "after_detected": after_detected_total,
            "before_rate": before_rate,
            "after_rate": after_rate,
            "improvement_pct": round(after_rate - before_rate, 1),
            "dynamic_detected": dynamic_detected_total,
            "rules_generated": len(generated_rules),
        },
        "vectors": vector_results,
        "generated_rules": generated_rules,
    }
    _save_last_closed_loop_report(report)
    return report
