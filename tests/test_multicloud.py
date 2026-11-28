"""Comprehensive tests for Multi-Cloud Identity Shield (AWS, GCP, Azure, SIEM Export & Security)."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from identity_shield import cli, config, ops_cli, settings
from identity_shield.clouds import (
    CANONICAL_SCHEMA_VERSION,
    CanonicalEvent,
    classify_traffic,
    detect_and_normalize_audit_payload,
    list_provider_capabilities,
)
from identity_shield.clouds.factors import check_factor_support
from identity_shield.db.connection import connect
from identity_shield.db.init import ensure_tables, init_db
from identity_shield.detect import dynamic, pysigma_backend, replay as detect_replay
from identity_shield.detect.policy import evaluate_policy
from identity_shield.detect.rules import Rule, load_sigma_text
from identity_shield.detect.siem_export import SIEM_TARGETS, export_rule_to_siem, export_sigma_yaml_to_siem
from identity_shield.integrations import get_external_tools_status, parse_scoutsuite_inventory
from identity_shield.proxy import parser as proxy_parser
from identity_shield.proxy.server import PROXY_RUNTIME
from identity_shield.proxy.tls import TlsCertAuthority
from identity_shield.runner.synthetic import multicloud_synthetic_events
from identity_shield.variants.closed_loop import preview_closed_loop_vectors, run_closed_loop
from identity_shield.variants.generator import GenerationOptions, generate_for_technique
from identity_shield.variants.loader import Technique, load_catalogue
from identity_shield.web import app as web_app
from tests.test_security_hardening import _raw_asgi


@pytest.fixture
def mc_env(tmp_path, monkeypatch):
    db_path = tmp_path / "mc_test.db"
    cfg_path = tmp_path / "workspace_config.json"
    overrides_path = tmp_path / "attack_overrides.json"
    init_db(db_path, drop=True)
    monkeypatch.setenv("IDENTITY_SHIELD_DB", str(db_path))
    monkeypatch.setenv("IDENTITY_SHIELD_CONFIG", str(cfg_path))
    monkeypatch.setenv("IDENTITY_SHIELD_ATTACK_OVERRIDES", str(overrides_path))
    monkeypatch.setattr(config, "DEFAULT_DB", db_path)
    monkeypatch.setattr(config, "DATA", tmp_path)
    monkeypatch.setattr(web_app, "NON_LOCAL_BIND", False)
    monkeypatch.delenv("IDENTITY_SHIELD_REQUIRE_TOKEN", raising=False)
    PROXY_RUNTIME.stop()
    try:
        yield {"db": db_path, "tmp": tmp_path, "cfg": cfg_path}
    finally:
        PROXY_RUNTIME.stop()


def test_cloud_traffic_classifier_and_conflicts():
    # AWS SigV4 + endpoint
    r_aws = classify_traffic(
        method="POST",
        url_or_path="/",
        headers={
            "Host": "iam.amazonaws.com",
            "Authorization": "AWS4-HMAC-SHA256 Credential=AKIA1234567890ABCDEF/20261127/eu-west-1/iam/aws4_request",
        },
        body=b"Action=ListUsers&Version=2010-05-08",
    )
    assert r_aws.cloud_provider == "aws"
    assert r_aws.traffic_type == "cloud_api"
    assert r_aws.legacy_traffic_kind == "aws_api"
    assert r_aws.confidence == "high"
    # Never expose raw access keys in classification text
    assert "AKIA1234567890ABCDEF" not in r_aws.reason

    # GCP REST + headers (no auth token required)
    r_gcp = classify_traffic(
        method="POST",
        url_or_path="/v1/projects/prod-101/serviceAccounts/svc@prod-101.iam.gserviceaccount.com/keys",
        headers={"Host": "iam.googleapis.com", "X-Goog-User-Project": "prod-101"},
    )
    assert r_gcp.cloud_provider == "gcp"
    assert r_gcp.traffic_type == "cloud_api"
    assert r_gcp.legacy_traffic_kind == "gcp_api"
    assert r_gcp.detected_service == "iam"

    # Azure ARM path + KeyVault
    r_az = classify_traffic(
        method="PUT",
        url_or_path="/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Authorization/roleAssignments/ra1?api-version=2022-04-01",
        headers={"Host": "management.azure.com", "X-Ms-Client-Request-Id": "123"},
    )
    assert r_az.cloud_provider == "azure"
    assert r_az.traffic_type == "cloud_api"
    assert r_az.legacy_traffic_kind == "azure_api"

    # Conflicting multi-cloud headers on unknown custom host -> stays conservative unknown
    r_conflict = classify_traffic(
        method="GET",
        url_or_path="/custom/api",
        headers={"Host": "custom-proxy.internal", "X-Amz-Date": "20261127T000000Z", "X-Goog-User-Project": "proj-1"},
    )
    assert r_conflict.cloud_provider == "unknown"
    assert r_conflict.confidence == "low"
    assert set(r_conflict.conflicting_providers) == {"aws", "gcp"}

    # Generic web app vs CONNECT tunnel separation
    r_web = classify_traffic(method="GET", url_or_path="/.env", headers={"Host": "portal.corp.local"})
    assert r_web.cloud_provider == "unknown"
    assert r_web.traffic_type == "http_app"

    r_tun = classify_traffic(
        method="CONNECT",
        url_or_path="storage.googleapis.com:443",
        headers={"Host": "storage.googleapis.com:443"},
        is_connect=True,
    )
    assert r_tun.cloud_provider == "gcp"
    assert r_tun.traffic_type == "connect_tunnel"
    assert r_tun.legacy_traffic_kind == "connect_tunnel"


def test_multicloud_normalization_and_redaction():
    aws_raw = {
        "eventVersion": "1.09",
        "eventID": "aws-ev-1",
        "eventTime": "2026-11-27T05:00:00Z",
        "eventSource": "iam.amazonaws.com",
        "eventName": "CreateAccessKey",
        "awsRegion": "eu-west-1",
        "sourceIPAddress": "203.0.113.10",
        "userAgent": "aws-cli/2.15.30",
        "recipientAccountId": "111122223333",
        "userIdentity": {"type": "IAMUser", "arn": "arn:aws:iam::111122223333:user/alice"},
        "requestParameters": {"access_key": "AKIA1234567890ABCDEF"},
    }
    gcp_admin_raw = {
        "insertId": "gcp-ev-1",
        "logName": "projects/my-gcp-proj/logs/cloudaudit.googleapis.com%2Factivity",
        "timestamp": "2026-11-27T05:01:00Z",
        "protoPayload": {
            "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
            "serviceName": "iam.googleapis.com",
            "methodName": "google.iam.admin.v1.CreateServiceAccountKey",
            "resourceName": "projects/my-gcp-proj/serviceAccounts/ops@my-gcp-proj.iam.gserviceaccount.com",
            "authenticationInfo": {
                "principalEmail": "ops@my-gcp-proj.iam.gserviceaccount.com",
                "token": "ya29.super_secret_oauth_token_1234567",
            },
            "requestMetadata": {"callerIp": "198.51.100.4", "callerSuppliedUserAgent": "gcloud/490.0.0"},
        },
        "resource": {"type": "service_account", "labels": {"project_id": "my-gcp-proj", "location": "global"}},
    }
    gcp_policy_denied = {
        "insertId": "gcp-ev-2",
        "logName": "projects/my-gcp-proj/logs/cloudaudit.googleapis.com%2Fpolicy",
        "timestamp": "2026-11-27T05:01:30Z",
        "protoPayload": {
            "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
            "serviceName": "secretmanager.googleapis.com",
            "methodName": "google.cloud.secretmanager.v1.SecretManagerService.AccessSecretVersion",
            "status": {"code": 7, "message": "PERMISSION_DENIED"},
            "authorizationInfo": [{"permission": "secretmanager.versions.access", "granted": False}],
        },
    }
    azure_activity = {
        "eventDataId": "az-act-1",
        "time": "2026-11-27T05:02:00Z",
        "operationName": {"value": "Microsoft.Authorization/roleAssignments/write"},
        "caller": "deployer@contoso.com",
        "callerIpAddress": "192.0.2.88",
        "resourceId": "/subscriptions/sub-abc/resourceGroups/rg-prod/providers/Microsoft.Authorization/roleAssignments/ra-1",
        "tenantId": "tenant-123",
        "category": {"value": "Administrative"},
        "status": {"value": "Succeeded"},
    }
    entra_signin = {
        "id": "az-si-1",
        "createdDateTime": "2026-11-27T05:03:00Z",
        "userPrincipalName": "alice@contoso.com",
        "ipAddress": "192.0.2.90",
        "clientAppUsed": "Browser",
        "conditionalAccessStatus": "notApplied",
        "status": {"errorCode": 50126, "failureReason": "Invalid username or password"},
        "location": {"countryOrRegion": "US"},
        "tenantId": "tenant-123",
    }
    entra_audit = {
        "id": "az-au-1",
        "activityDateTime": "2026-11-27T05:04:00Z",
        "activityDisplayName": "Add service principal credentials",
        "category": "ApplicationManagement",
        "result": "success",
        "initiatedBy": {"user": {"userPrincipalName": "admin@contoso.com", "ipAddress": "198.51.100.77"}},
        "targetResources": [{"id": "spn-99", "displayName": "billing-spn"}],
        "tenantId": "tenant-123",
    }

    c_aws = detect_and_normalize_audit_payload(aws_raw)[0]
    assert c_aws.schema_version == CANONICAL_SCHEMA_VERSION
    assert c_aws.cloud_provider == "aws"
    assert c_aws.account_scope == "111122223333"
    assert "AKIA1234567890ABCDEF" not in json.dumps(c_aws.to_dict())

    gcp_events = detect_and_normalize_audit_payload({"entries": [gcp_admin_raw, gcp_policy_denied]})
    assert len(gcp_events) == 2
    assert gcp_events[0].source_type == "gcp_admin_activity"
    assert gcp_events[0].account_scope == "my-gcp-proj"
    assert "ya29.super_secret" not in json.dumps(gcp_events[0].to_dict())
    assert gcp_events[1].source_type == "gcp_policy_denied"
    assert gcp_events[1].outcome == "denied"

    az_events = detect_and_normalize_audit_payload({"value": [azure_activity, entra_signin, entra_audit]})
    assert [e.source_type for e in az_events] == ["azure_activity", "entra_signin", "entra_audit"]
    assert az_events[0].account_scope == "sub-abc"
    assert az_events[1].outcome == "error"
    assert az_events[2].resource == "billing-spn"


def test_database_legacy_migration_is_idempotent_and_preserves_data(tmp_path):
    legacy_db = tmp_path / "legacy_v0.db"
    raw_conn = sqlite3.connect(legacy_db)
    raw_conn.executescript(
        """
        CREATE TABLE lab_run (
          run_id TEXT PRIMARY KEY, started_at TEXT NOT NULL, ended_at TEXT,
          aws_account_id TEXT NOT NULL, region TEXT NOT NULL, git_sha TEXT,
          ruleset_version TEXT NOT NULL, collector_lag_ms INTEGER, notes TEXT
        );
        CREATE TABLE technique (
          technique_id TEXT PRIMARY KEY, name TEXT NOT NULL, tactic TEXT NOT NULL,
          executor TEXT NOT NULL, executor_ref TEXT, event_names TEXT NOT NULL,
          requires_data_events INTEGER NOT NULL DEFAULT 0, success_check TEXT NOT NULL,
          required_actions TEXT NOT NULL
        );
        CREATE TABLE variant (
          variant_id TEXT PRIMARY KEY, technique_id TEXT NOT NULL, variant_set TEXT NOT NULL,
          factor_levels TEXT NOT NULL, seed INTEGER NOT NULL, spec_sha256 TEXT NOT NULL, notes TEXT
        );
        CREATE TABLE trial (
          trial_id TEXT PRIMARY KEY, run_id TEXT NOT NULL, variant_id TEXT NOT NULL,
          repetition INTEGER NOT NULL, window_start TEXT NOT NULL, window_end TEXT,
          attack_succeeded INTEGER, attack_evidence TEXT, variant_changed INTEGER,
          variant_diff TEXT, error TEXT
        );
        CREATE TABLE fixture (
          fixture_key TEXT PRIMARY KEY, technique_id TEXT, flavour TEXT NOT NULL,
          path TEXT NOT NULL, expected_detected INTEGER
        );
        CREATE TABLE event (
          event_id TEXT PRIMARY KEY, trial_id TEXT, fixture_key TEXT,
          event_time TEXT NOT NULL, received_at TEXT NOT NULL, event_source TEXT,
          event_name TEXT, aws_region TEXT, source_ip TEXT, user_agent TEXT,
          user_identity_type TEXT, user_identity_arn TEXT, error_code TEXT, raw TEXT NOT NULL
        );
        CREATE TABLE ruleset (
          ruleset_version TEXT PRIMARY KEY, created_at TEXT NOT NULL, frozen_at TEXT,
          description TEXT, source TEXT
        );
        CREATE TABLE principal_profile (
          principal TEXT PRIMARY KEY, known_user_agents TEXT NOT NULL DEFAULT '[]',
          known_regions TEXT NOT NULL DEFAULT '[]', known_services TEXT NOT NULL DEFAULT '[]',
          known_operations TEXT NOT NULL DEFAULT '[]', known_hours TEXT NOT NULL DEFAULT '[]',
          request_count INTEGER NOT NULL DEFAULT 0, last_seen TEXT NOT NULL
        );
        INSERT INTO principal_profile VALUES ('alice', '["boto3"]', '["eu-west-1"]', '["s3"]', '["GetObject"]', '[10]', 5, '2026-11-26T00:00:00Z');
        INSERT INTO event VALUES ('legacy-ev-1', NULL, NULL, '2026-11-26T00:00:00Z', '2026-11-26T00:00:01Z', 's3.amazonaws.com', 'GetObject', 'eu-west-1', '1.2.3.4', 'boto3', 'IAMUser', 'arn:aws:iam::1:user/alice', NULL, '{}');
        """
    )
    raw_conn.commit()
    raw_conn.close()

    # Apply additive migrations twice (idempotent)
    init_db(legacy_db)
    init_db(legacy_db)

    conn = connect(legacy_db)
    try:
        ev = conn.execute("SELECT cloud_provider, event_name FROM event WHERE event_id = 'legacy-ev-1'").fetchone()
        assert ev["cloud_provider"] == "aws"
        assert ev["event_name"] == "GetObject"

        prof = conn.execute("SELECT profile_key, principal, request_count, cold_start_complete FROM principal_profile WHERE principal = 'alice'").fetchone()
        assert prof["profile_key"] == "aws::alice"
        assert prof["request_count"] == 5
        assert prof["cold_start_complete"] == 1

        # Cross-cloud identical principal names stay isolated without collision
        dynamic.update_principal_profile(
            conn,
            {"cloud_provider": "gcp", "account_scope": "proj-x", "principal": "alice", "service": "iam.googleapis.com", "operation": "ListRoles"},
        )
        dynamic.update_principal_profile(
            conn,
            {"cloud_provider": "azure", "account_scope": "tenant-y", "principal": "alice", "service": "Microsoft.EntraID", "operation": "UserSignIn"},
        )
        conn.commit()
        rows = conn.execute("SELECT profile_key, cloud_provider FROM principal_profile WHERE principal = 'alice' ORDER BY cloud_provider").fetchall()
        assert [(r["profile_key"], r["cloud_provider"]) for r in rows] == [
            ("aws::alice", "aws"),
            ("azure:tenant-y:alice", "azure"),
            ("gcp:proj-x:alice", "gcp"),
        ]
        versions = [r[0] for r in conn.execute("SELECT version FROM schema_migration ORDER BY version").fetchall()]
        assert versions == [1, 2, 3]
    finally:
        conn.close()


def test_multicloud_sigma_behavioral_isolation_and_policy(mc_env):
    # All starter GCP and Azure Sigma rules compile via pySigma when available and match reference parser
    for cloud_dir in (config.CONF / "rules" / "gcp", config.CONF / "rules" / "azure"):
        files = sorted(p for p in cloud_dir.iterdir() if p.suffix == ".yml")
        assert len(files) == 5
        if pysigma_backend.PYSIGMA_AVAILABLE:
            rep = pysigma_backend.compile_corpus(cloud_dir)
            assert rep.compile_rate == 1.0

    # Policy layer keeps gcp/azure observe-only by default even when global mode='block'
    pol_gcp = evaluate_policy(
        cloud_provider="gcp",
        traffic_type="cloud_api",
        proxy_mode="block",
        block_threshold=70.0,
        matched_static=[{"rule_id": "gcp-1", "level": "high"}],
        matched_dynamic=[],
    )
    assert pol_gcp.effective_mode == "observe"
    assert pol_gcp.action_taken == "alerted"

    pol_gcp_block = evaluate_policy(
        cloud_provider="gcp",
        traffic_type="cloud_api",
        proxy_mode="block",
        block_threshold=70.0,
        matched_static=[{"rule_id": "gcp-1", "level": "high"}],
        matched_dynamic=[],
        provider_policies={"gcp": "block"},
    )
    assert pol_gcp_block.action_taken == "blocked"

    # Single low finding never auto-blocks below threshold
    pol_low = evaluate_policy(
        cloud_provider="aws",
        traffic_type="cloud_api",
        proxy_mode="block",
        block_threshold=70.0,
        matched_static=[{"rule_id": "aws-low", "level": "low"}],
        matched_dynamic=[],
    )
    assert pol_low.action_taken == "alerted"

    # CONNECT tunnel without TLS reports observed metadata-only
    pol_conn = evaluate_policy(
        cloud_provider="azure",
        traffic_type="connect_tunnel",
        proxy_mode="block",
        block_threshold=70.0,
        matched_static=[],
        matched_dynamic=[],
        inspection_capable=False,
    )
    assert pol_conn.policy_decision == "observed"

    # Synthetic poisoning guard + cold-start safety
    conn = connect(mc_env["db"])
    try:
        res_syn = dynamic.evaluate_live_event(
            conn,
            {
                "cloud_provider": "gcp",
                "account_scope": "proj-syn",
                "principal": "syn-actor",
                "service": "storage.googleapis.com",
                "operation": "storage.buckets.get",
                "user_agent": "curl/8.4.0",
                "aws_region": "global",
                "is_synthetic": True,
                "event_obj": {"cloudProvider": "gcp", "synthetic": True, "eventName": "storage.buckets.get"},
            },
            learn_baseline=True,
        )
        assert res_syn["cold_start"] is True
        assert conn.execute("SELECT COUNT(*) FROM principal_profile WHERE principal = 'syn-actor'").fetchone()[0] == 0
    finally:
        conn.close()


def test_multicloud_variants_closed_loop_and_siem_export(mc_env):
    # Unsupported provider factor combos are honestly detected
    ok_aws, unsup_aws = check_factor_support("aws", {"network_origin": "alternate_endpoint"})
    assert ok_aws and not unsup_aws
    ok_gcp, unsup_gcp = check_factor_support("gcp", {"network_origin": "alternate_endpoint"})
    assert not ok_gcp and unsup_gcp

    # Synthetic multi-cloud generation
    cat = load_catalogue()
    gcp_tech = Technique(
        technique_id="T1530.GCP01",
        name="GCP Storage Read",
        tactic="collection",
        executor="synthetic",
        executor_ref=None,
        event_names=("storage.objects.get",),
        required_actions=("storage.objects.get",),
        requires_data_events=True,
        excluded_levels={},
        baseline_levels={},
        success_check={},
    )
    variants, _ = generate_for_technique(gcp_tech, cat, GenerationOptions(holdout_per_technique=2, include_pairwise=False))
    events = multicloud_synthetic_events(gcp_tech, variants[0], cloud_provider="gcp", account_scope="proj-sec", run_id="r1", start="2026-11-27T05:00:00Z")
    assert events[0]["protoPayload"]["methodName"] == "storage.objects.get"
    assert events[0]["synthetic"] is True

    # SIEM export across all 4 targets
    gcp_rule = load_sigma_text((config.CONF / "rules" / "gcp" / "gcp-T1098.001-sa-key-create.yml").read_text(encoding="utf-8"))
    out_gcp = export_rule_to_siem(gcp_rule, "gcp_logging")
    assert out_gcp["supported"] and out_gcp["valid"]
    assert "CreateServiceAccountKey" in out_gcp["query"]

    out_secops = export_rule_to_siem(gcp_rule, "gcp_secops")
    assert out_secops["supported"] and "rule " in out_secops["query"]

    az_rule = load_sigma_text((config.CONF / "rules" / "azure" / "azure-T1098.003-role-assignment-write.yml").read_text(encoding="utf-8"))
    out_kql = export_rule_to_siem(az_rule, "azure_sentinel")
    assert out_kql["supported"] and "AzureActivity" in out_kql["query"] and "| where " in out_kql["query"]

    aws_rule = load_sigma_text((config.CONF / "rules" / "baseline" / "T1098.001-create-access-key.yml").read_text(encoding="utf-8"))
    out_cw = export_rule_to_siem(aws_rule, "aws_cloudwatch")
    assert out_cw["supported"] and "| filter " in out_cw["query"]

    # Cross-cloud mismatch warning + unsupported threshold count reporting
    mismatch = export_rule_to_siem(aws_rule, "azure_sentinel")
    assert mismatch["warnings"]

    unsup_yaml = """
title: Two of Them Unsupported
id: deadbeef-0000-0000-0000-000000000001
logsource:
  product: aws
  service: cloudtrail
detection:
  s1:
    eventName: ListUsers
  s2:
    eventName: ListRoles
  s3:
    eventName: GetObject
  condition: 2 of s*
"""
    unsup_out = export_sigma_yaml_to_siem(unsup_yaml, "aws_cloudwatch")
    assert unsup_out["supported"] is False
    assert unsup_out["unsupported_conditions"]


def test_tls_ca_guard_and_multicloud_api_and_cli_parity(mc_env):
    # TLS inspector handles missing openssl cleanly and never leaks private keys
    tls = TlsCertAuthority(ca_dir=mc_env["tmp"] / "ca", which_fn=lambda _b: None)
    assert tls.ensure_ca()["ready"] is False
    assert tls.is_passthrough_host("login.microsoftonline.com") is True
    st = tls.status(enabled=False)
    assert st["ca_private_key_in_db"] is False
    with pytest.raises(ValueError, match="Unsafe"):
        tls.issue_host_cert("bad host;rm")

    # Lazy tool status includes gcloud, az, scout without failing when missing
    tools = get_external_tools_status(which_fn=lambda _b: None)
    tool_ids = {t["id"] for t in tools["tools"]}
    assert {"stratus", "cloudfox", "pacu", "gcloud", "az", "scout"}.issubset(tool_ids)

    tok = web_app.get_session_token()
    auth = [(b"authorization", f"Bearer {tok}".encode("utf-8"))]

    # Provider capability & ingest endpoints
    r_clouds = _raw_asgi("GET", "/api/clouds", headers=auth)
    assert r_clouds.status_code == 200
    assert {p["provider"] for p in r_clouds.json()["providers"]} == {"aws", "gcp", "azure"}

    r_ing = _raw_asgi(
        "POST",
        "/api/clouds/ingest",
        payload={
            "cloud_provider": "gcp",
            "events": [
                {
                    "insertId": "gcp-ing-1",
                    "logName": "projects/p-sec/logs/cloudaudit.googleapis.com%2Factivity",
                    "timestamp": "2026-11-27T06:00:00Z",
                    "protoPayload": {
                        "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
                        "serviceName": "iam.googleapis.com",
                        "methodName": "google.iam.admin.v1.CreateServiceAccountKey",
                        "status": {"code": 7},
                    },
                    "resource": {"labels": {"project_id": "p-sec"}},
                }
            ],
        },
        headers=auth,
    )
    assert r_ing.status_code == 200
    assert r_ing.json()["by_cloud"]["gcp"] == 1

    # Import ScoutSuite multi-cloud inventory
    r_sc = _raw_asgi(
        "POST",
        "/api/tools/scoutsuite/import",
        payload={
            "inventory": {
                "provider_code": "gcp",
                "project_id": "p-sec",
                "buckets": ["p-sec-sensitive-gcs"],
                "secrets": ["prod-api-token"],
            }
        },
        headers=auth,
    )
    assert r_sc.status_code == 200
    assert r_sc.json()["inventory"]["cloud_provider"] == "gcp"

    # Run closed-loop scoped to GCP only
    r_cl = _raw_asgi(
        "POST",
        "/api/closed-loop/run",
        payload={"mode": "from_resources", "cloud_provider": "gcp", "auto_enhance": True},
        headers=auth,
    )
    assert r_cl.status_code == 200
    assert r_cl.json()["summary"]["gcp_variants_tested"] > 0

    # Filtered logs endpoint + SIEM export endpoint
    r_logs = _raw_asgi("GET", "/api/logs?cloud_provider=gcp", headers=auth)
    assert r_logs.status_code == 200
    assert all(e["cloud_provider"] == "gcp" for e in r_logs.json()["events"])

    r_siem = _raw_asgi(
        "POST",
        "/api/siem/export",
        payload={"yaml_content": (config.CONF / "rules" / "azure" / "azure-T1555.006-keyvault-secret-access.yml").read_text(encoding="utf-8"), "target": "azure_sentinel"},
        headers=auth,
    )
    assert r_siem.status_code == 200
    assert "SecretGet" in r_siem.json()["query"]

    # Live multi-cloud simulator via proxy + filtering
    r_sim = _raw_asgi("POST", "/api/proxy/simulate", payload={"scenario": "multicloud_mixed"}, headers=auth)
    assert r_sim.status_code == 200
    PROXY_RUNTIME.stop()

    r_px_az = _raw_asgi("GET", "/api/proxy/events?cloud_provider=azure", headers=auth)
    assert r_px_az.status_code == 200
    assert r_px_az.json()["count"] >= 2

    # CLI parity checks
    az_log_file = mc_env["tmp"] / "az_audit.json"
    az_log_file.write_text(
        json.dumps(
            {
                "value": [
                    {
                        "eventDataId": "az-cli-1",
                        "time": "2026-11-27T06:05:00Z",
                        "operationName": {"value": "Microsoft.Authorization/roleAssignments/write"},
                        "resourceId": "/subscriptions/sub-cli/providers/Microsoft.Authorization/roleAssignments/r1",
                        "caller": "cli@contoso.com",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    assert cli.main(["logs", "ingest", "--file", str(az_log_file), "--cloud", "azure", "--db", str(mc_env["db"])]) == 0
    assert cli.main(["dynamic", "loop", "--mode", "from_resources", "--cloud", "gcp", "--preview", "--db", str(mc_env["db"])]) == 0
    assert cli.main(["dynamic", "siem-export", "--rule-id", "5f0b7a1e-1c2d-4a3b-9e8f-0a1b2c3d4e05", "--ruleset", "baseline-v1", "--target", "aws_cloudwatch", "--db", str(mc_env["db"])]) == 0


def test_independent_audit_remediations_multicloud_and_siem(mc_env, capsys):
    """Regression coverage for mixed-cloud auto ingest, enhancer preservation, closed-loop raw match, Sentinel KQL, and attack parity."""
    from identity_shield.clouds import detect_and_normalize_audit_payload, list_providers, register_provider, registry as cloud_reg
    from identity_shield.detect import enhancer as detect_enhancer
    from identity_shield.detect.rules import load_sigma_text
    from identity_shield.detect.siem_export import export_rule_to_siem, export_sigma_yaml_to_siem
    from identity_shield.db.migrations import apply_migrations
    from identity_shield.variants import closed_loop
    import sqlite3

    # 1. Mixed-cloud auto ingestion preserves GCP + Azure Entra + AWS records together
    mixed = [
        {"protoPayload": {"serviceName": "iam.googleapis.com", "methodName": "CreateServiceAccountKey", "status": {"code": 0}}, "resource": {"labels": {"project_id": "p-mix"}}},
        {"id": "entra-mix-1", "createdDateTime": "2026-11-27T01:00:00Z", "userPrincipalName": "u@contoso.com", "conditionalAccessStatus": "notApplied", "status": {"errorCode": 0}},
        {"eventVersion": "1.09", "eventSource": "sts.amazonaws.com", "eventName": "GetCallerIdentity", "eventTime": "2026-11-27T01:02:00Z", "awsRegion": "us-east-1"},
    ]
    norm = detect_and_normalize_audit_payload(mixed, cloud_provider="auto")
    assert [e.cloud_provider for e in norm] == ["gcp", "azure", "aws"]

    # 2. Nested dict Azure caller coerces cleanly to string principal & GCP integer code=7 stays unredacted
    az_dict_caller = detect_and_normalize_audit_payload(
        {"operationName": {"value": "Microsoft.Authorization/roleAssignments/write"}, "caller": {"upn": "alice@contoso.com"}, "resourceId": "/subscriptions/sub-1/rg"},
        cloud_provider="azure",
    )[0]
    assert isinstance(az_dict_caller.principal, str) and az_dict_caller.principal == "alice@contoso.com"

    gcp_denied = detect_and_normalize_audit_payload(
        {"protoPayload": {"serviceName": "iam.googleapis.com", "methodName": "google.iam.admin.v1.CreateServiceAccountKey", "status": {"code": 7}}},
        cloud_provider="gcp",
    )[0]
    sa_rule = load_sigma_text((config.CONF / "rules" / "gcp" / "gcp-T1098.001-sa-key-create.yml").read_text(encoding="utf-8"))
    assert sa_rule.matches(gcp_denied.to_sigma_event()) is False

    # 3. Rule Enhancer preserves non-AWS logsource.product
    conn = connect(mc_env["db"])
    try:
        detect_replay.load_ruleset(conn, "gcp-baseline-v1")
        gcp_row = conn.execute("SELECT rule_id FROM rule WHERE ruleset_version = 'gcp-baseline-v1' LIMIT 1").fetchone()
        enh = detect_enhancer.build_enhanced_rule(conn, gcp_row["rule_id"])
        assert "product: gcp" in enh["enhanced_yaml"]
        assert "product: aws" not in enh["enhanced_yaml"]
    finally:
        conn.close()

    # 4. Closed-loop hardened GCP rule matches raw native GCP Audit JSON and skips unsupported alternate_endpoint
    gen_rule = closed_loop._write_closed_loop_sigma_rule(
        {"cloud_provider": "gcp", "service": "storage.googleapis.com", "operation": "storage.objects.get", "technique_id": "T1530.GCP01", "tactic": "collection"},
        [{"eventSource": "storage.googleapis.com", "eventName": "storage.objects.get"}],
    )
    loaded_cl = load_sigma_text(Path(gen_rule["path"]).read_text(encoding="utf-8"), path=gen_rule["path"])
    assert loaded_cl.matches({"protoPayload": {"serviceName": "storage.googleapis.com", "methodName": "storage.objects.get"}}) is True

    # 5. SIEM exporter uses AWSCloudTrail columns for Sentinel & escapes '/' in regexes
    aws_rule = load_sigma_text((config.CONF / "rules" / "baseline" / "T1098.001-create-access-key.yml").read_text(encoding="utf-8"))
    sent_aws = export_rule_to_siem(aws_rule, "azure_sentinel")
    assert "AWSCloudTrail" in sent_aws["query"]
    assert "EventName" in sent_aws["query"]
    assert "ResourceProviderValue" not in sent_aws["query"]

    slash_yaml = "title: Slash Rx\nid: 00000000-0000-0000-0000-000000000777\nlogsource:\n  product: gcp\n  service: gcp.audit\ndetection:\n  sel:\n    protoPayload.methodName|re: 'projects/.*/secrets/.*'\n  condition: sel\nlevel: medium\n"
    cw_slash = export_sigma_yaml_to_siem(slash_yaml, "aws_cloudwatch")
    sec_slash = export_sigma_yaml_to_siem(slash_yaml, "gcp_secops")
    assert r"projects\/.*\/secrets\/.*" in cw_slash["query"]
    assert r"projects\/.*\/secrets\/.*" in sec_slash["query"]

    # 6. Multi-cloud techniques & cloud_provider filters surfaced across API & CLI + register_provider available
    assert "aws" in list_providers() and callable(register_provider)
    assert callable(cloud_reg.register_provider)
    r_atk_gcp = _raw_asgi("GET", "/api/attacks?cloud_provider=gcp", headers={"x-identity-shield-token": web_app.get_session_token()})
    assert r_atk_gcp.status_code == 200
    assert any(a["technique_id"] == "T1098.GCP01" for a in r_atk_gcp.json()["attacks"])
    r_rules_gcp = _raw_asgi("GET", "/api/rules?cloud_provider=gcp", headers={"x-identity-shield-token": web_app.get_session_token()})
    assert r_rules_gcp.status_code == 200
    assert r_rules_gcp.json()["rules"] and all(r["cloud_provider"] == "gcp" for r in r_rules_gcp.json()["rules"])
    assert ops_cli.attacks_main(["list", "--cloud", "azure", "--json"]) == 0
    assert any(a["technique_id"] == "T1078.AZ04" for a in json.loads(capsys.readouterr().out)["attacks"])

    # 7. Ultra-old legacy alert schema without fixture_key migrates cleanly
    old_db = sqlite3.connect(":memory:")
    old_db.row_factory = sqlite3.Row
    old_db.executescript(
        "CREATE TABLE alert (alert_id TEXT PRIMARY KEY, rule_id TEXT, event_id TEXT, trial_id TEXT, emitted_at TEXT);"
        "CREATE TABLE event (event_id TEXT PRIMARY KEY, trial_id TEXT, fixture_key TEXT, raw_hash TEXT, event_time TEXT, received_at TEXT, event_source TEXT, event_name TEXT, aws_region TEXT, source_ip TEXT, user_agent TEXT, user_identity_type TEXT, user_identity_arn TEXT, error_code TEXT, raw TEXT);"
        "CREATE TABLE principal_profile (principal TEXT PRIMARY KEY, known_user_agents TEXT, known_regions TEXT, known_services TEXT, known_operations TEXT, known_hours TEXT, request_count INTEGER, last_seen TEXT);"
    )
    apply_migrations(old_db)
    assert "fixture_key" in {r["name"] for r in old_db.execute("PRAGMA table_info(alert)").fetchall()}
    old_db.close()


def test_multicloud_bugfixes_enhancer_scoping_and_normalizers(mc_env):
    from identity_shield.detect import enhancer

    conn = connect(mc_env["db"])
    try:
        # 1. Enhancer filename isolation across AWS/GCP/Azure + provider-aware NO_ERROR_FILTER
        detect_replay.load_ruleset(conn, "multicloud-v1")
        enh_res = enhancer.enhance_entire_ruleset(
            conn,
            source_ruleset="multicloud-v1",
            target_ruleset="enhanced-v1",
        )
        saved_names = sorted(Path(item["saved_path"]).name for item in enh_res["saved"])
        assert enh_res["rules_generated"] >= 18
        assert any(name.startswith("enhanced-gcp-") for name in saved_names)
        assert any(name.startswith("enhanced-azure-") for name in saved_names)
        assert any(name.startswith("enhanced-t") for name in saved_names)

        gcp_with_err = {
            "rule_id": "gcp-err-check",
            "native_id": "gcp-err-check",
            "ruleset_version": "multicloud-v1",
            "technique_id": "T1098.GCP01",
            "loader": "sigma",
            "title": "GCP Err Filter",
            "body": (
                "title: GCP Err\nlogsource:\n  product: gcp\n  service: gcp.audit\n"
                "detection:\n  sel:\n    protoPayload.methodName: google.iam.admin.v1.CreateServiceAccountKey\n"
                "  filter_errors:\n    protoPayload.status.code: 7\n  condition: sel and not filter_errors\nlevel: high\n"
            ),
        }
        audit_gcp = enhancer.audit_rule(conn, gcp_with_err)
        assert "NO_ERROR_FILTER" not in {w["code"] for w in audit_gcp["weaknesses"]}

        gcp_no_err = {
            **gcp_with_err,
            "rule_id": "gcp-no-err-check",
            "native_id": "gcp-no-err-check",
            "body": (
                "title: GCP No Err\nlogsource:\n  product: gcp\n  service: gcp.audit\n"
                "detection:\n  sel:\n    protoPayload.methodName: google.iam.admin.v1.CreateServiceAccountKey\n"
                "  condition: sel\nlevel: high\n"
            ),
        }
        audit_gcp_missing = enhancer.audit_rule(conn, gcp_no_err)
        err_weak = [w for w in audit_gcp_missing["weaknesses"] if w["code"] == "NO_ERROR_FILTER"]
        assert err_weak and "protoPayload.status.code" in err_weak[0]["fix"]

        # 2. Cross-account dynamic baseline isolation (proj-a never leaks into proj-b)
        for idx in range(3):
            dynamic.evaluate_live_event(
                conn,
                {
                    "cloud_provider": "gcp",
                    "account_scope": "proj-a",
                    "principal": "scoped-alice@example.com",
                    "service": "storage.googleapis.com",
                    "operation": "storage.buckets.get",
                    "user_agent": "google-cloud-sdk/1.0",
                    "aws_region": "us-central1",
                    "timestamp": f"2026-11-27T12:0{idx}:00Z",
                    "event_obj": {"cloudProvider": "gcp", "eventName": "storage.buckets.get"},
                },
                learn_baseline=True,
            )
        res_proj_b = dynamic.evaluate_live_event(
            conn,
            {
                "cloud_provider": "gcp",
                "account_scope": "proj-b",
                "principal": "scoped-alice@example.com",
                "service": "secretmanager.googleapis.com",
                "operation": "google.cloud.secretmanager.v1.SecretManagerService.AccessSecretVersion",
                "user_agent": "curl/8.4.0",
                "aws_region": "europe-west1",
                "timestamp": "2026-11-27T12:10:00Z",
                "event_obj": {"cloudProvider": "gcp", "eventName": "AccessSecretVersion"},
            },
            learn_baseline=False,
        )
        assert res_proj_b["cold_start"] is True
        assert "DYN-DRIFT-001" not in {r["rule_id"] for r in res_proj_b["matched_dynamic"]}

        # 3. Dynamic replay keeps full dotted service names for GCP/Azure sensitive_services
        conn.execute(
            "INSERT INTO lab_run(run_id, started_at, aws_account_id, region, ruleset_version, synthetic) VALUES (?,?,?,?,?,?)",
            ("run-mc-dyn", "2026-11-27T10:00:00Z", "000000000000", "global", "multicloud-v1", 1),
        )
        conn.execute(
            "INSERT OR IGNORE INTO technique(technique_id, name, tactic, executor, executor_ref, event_names, requires_data_events, success_check, required_actions) VALUES (?,?,?,?,?,?,?,?,?)",
            ("T1530.GCP01", "GCP Storage Read", "collection", "synthetic", None, '["storage.objects.get"]', 0, "{}", "[]"),
        )
        conn.execute(
            "INSERT INTO variant(variant_id, technique_id, variant_set, factor_levels, seed, spec_sha256) VALUES (?,?,?,?,?,?)",
            ("var-ben-gcp", "T1530.GCP01", "benign", "{}", 1, "sha-ben"),
        )
        conn.execute(
            "INSERT INTO variant(variant_id, technique_id, variant_set, factor_levels, seed, spec_sha256) VALUES (?,?,?,?,?,?)",
            ("var-atk-gcp", "T1530.GCP01", "baseline", "{}", 2, "sha-atk"),
        )
        conn.execute(
            "INSERT INTO trial(trial_id, run_id, variant_id, repetition, window_start) VALUES (?,?,?,?,?)",
            ("tr-ben-gcp", "run-mc-dyn", "var-ben-gcp", 1, "2026-11-27T10:00:00Z"),
        )
        conn.execute(
            "INSERT INTO trial(trial_id, run_id, variant_id, repetition, window_start) VALUES (?,?,?,?,?)",
            ("tr-atk-gcp", "run-mc-dyn", "var-atk-gcp", 1, "2026-11-27T11:00:00Z"),
        )
        for i in range(3):
            conn.execute(
                """
                INSERT INTO event(
                    event_id, trial_id, event_time, received_at, cloud_provider, account_scope,
                    source_type, event_source, event_name, aws_region, source_ip, user_agent,
                    user_identity_type, user_identity_arn, error_code, raw
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    f"ev-gcp-ben-{i}",
                    "tr-ben-gcp",
                    f"2026-11-27T10:0{i}:00Z",
                    f"2026-11-27T10:0{i}:01Z",
                    "gcp",
                    "proj-replay",
                    "gcp_audit",
                    "storage.googleapis.com",
                    "storage.buckets.list",
                    "us-central1",
                    "10.10.0.5",
                    "google-cloud-sdk/1.0",
                    "ServiceAccount",
                    "replay-sa@proj-replay.iam.gserviceaccount.com",
                    "",
                    json.dumps({"cloudProvider": "gcp"}),
                ),
            )
        conn.execute(
            """
            INSERT INTO event(
                event_id, trial_id, event_time, received_at, cloud_provider, account_scope,
                source_type, event_source, event_name, aws_region, source_ip, user_agent,
                user_identity_type, user_identity_arn, error_code, raw
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                "ev-gcp-atk-secret",
                "tr-atk-gcp",
                "2026-11-27T11:05:00Z",
                "2026-11-27T11:05:01Z",
                "gcp",
                "proj-replay",
                "gcp_audit",
                "secretmanager.googleapis.com",
                "google.cloud.secretmanager.v1.SecretManagerService.AccessSecretVersion",
                "us-central1",
                "10.10.0.5",
                "google-cloud-sdk/1.0",
                "ServiceAccount",
                "replay-sa@proj-replay.iam.gserviceaccount.com",
                "",
                json.dumps({"cloudProvider": "gcp"}),
            ),
        )
        conn.commit()
        dyn_rep = dynamic.run_dynamic_replay(conn, run_id="run-mc-dyn")
        assert dyn_rep["dynamic_alerts"] >= 1
        drift_rows = conn.execute("SELECT summary FROM dynamic_alert WHERE source = 'batch' AND rule_id = 'DYN-DRIFT-001'").fetchall()
        assert any("first-time sensitive service=secretmanager.googleapis.com" in r["summary"] for r in drift_rows)

        # 4. Closed-loop alert vector mapping for GCP operations & denied error codes
        conn.execute(
            """
            INSERT INTO event(
                event_id, trial_id, event_time, received_at, cloud_provider, account_scope,
                source_type, event_source, event_name, aws_region, source_ip, user_agent,
                user_identity_type, user_identity_arn, error_code, raw
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                "ev-gcp-denied-gcs",
                "tr-atk-gcp",
                "2026-11-27T11:06:00Z",
                "2026-11-27T11:06:01Z",
                "gcp",
                "proj-replay",
                "gcp_audit",
                "storage.googleapis.com",
                "storage.objects.get",
                "us-central1",
                "10.10.0.5",
                "curl/8.4.0",
                "ServiceAccount",
                "replay-sa@proj-replay.iam.gserviceaccount.com",
                "PERMISSION_DENIED",
                json.dumps({"cloudProvider": "gcp"}),
            ),
        )
        conn.commit()
        prev = preview_closed_loop_vectors(conn, mode="from_alerts", cloud_provider="gcp")
        assert any(v["technique_id"] == "T1530.GCP01" for v in prev["vectors"])

        # 5. Dict-typed scalar field coercion in GCP & Azure normalizers
        gcp_norm = detect_and_normalize_audit_payload(
            {
                "protoPayload": {
                    "serviceName": "iam.googleapis.com",
                    "methodName": "google.iam.admin.v1.CreateServiceAccountKey",
                    "authenticationInfo": {"principalEmail": {"email": "sa@proj.iam.gserviceaccount.com"}},
                },
                "resource": {"type": "project", "labels": {"project_id": "proj-1"}},
            }
        )
        assert gcp_norm[0].principal == "sa@proj.iam.gserviceaccount.com"

        az_si_norm = detect_and_normalize_audit_payload(
            {
                "time": "2026-11-27T01:00:00Z",
                "category": "SignInLogs",
                "tenantId": {"id": "tenant-1"},
                "userPrincipalName": {"value": "alice@contoso.com"},
                "status": {"errorCode": 0},
            }
        )
        assert az_si_norm[0].principal == "alice@contoso.com"
        assert az_si_norm[0].account_scope == "tenant-1"

        az_au_norm = detect_and_normalize_audit_payload(
            {
                "activityDateTime": "2026-11-27T01:00:00Z",
                "category": "AuditLogs",
                "activityDisplayName": {"value": "Add service principal credentials"},
                "initiatedBy": {"user": {"userPrincipalName": {"upn": "admin@contoso.com"}}},
                "result": "success",
            }
        )
        assert az_au_norm[0].principal == "admin@contoso.com"
        assert az_au_norm[0].operation == "Add service principal credentials"
    finally:
        conn.close()


def _der_len(data: bytes) -> bytes:
    ln = len(data)
    if ln < 0x80:
        return bytes([ln])
    raw = ln.to_bytes((ln.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def _der_tlv(tag: int, body: bytes) -> bytes:
    return bytes([tag]) + _der_len(body) + body


def _der_int(val: int) -> bytes:
    raw = val.to_bytes(max(1, (val.bit_length() + 8) // 8), "big")
    return _der_tlv(0x02, raw)


def test_multicloud_live_connections_siem_pull_and_census(mc_env, monkeypatch):
    import base64
    from types import SimpleNamespace
    from identity_shield import service
    from identity_shield.clouds import connect as cloud_connect

    settings.RUNTIME_SESSION.clear()
    try:
        # 1. Construct a synthetic RSA PKCS#8 key in RAM (no PEM literal in repo) and verify in-RAM RS256 signing
        p = 0xD7E9A1B3C5D7E9A1B3C5D7E9A1B3C5D7E9A1B3C5D7E9A1B3C5D7E9A1B3C5D7E9A1B3C5D7E9A1B3C5D7E9A1B3C5D7E9D3
        q = 0xE1F3A5B7C9D1E3F5A7B9C1D3E5F7A9B1C3D5E7F9A1B3C5D7E9F1A3B5C7D9E1F3A5B7C9D1E3F5A7B9C1D3E5F7A9B1C3E7
        n = p * q
        e = 65537
        # Use fixed d for deterministic PKCS#8 structure check (k >= 64 bytes -> ps_len >= 8)
        d = 0x123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF1
        rsa_seq = _der_tlv(0x30, _der_int(0) + _der_int(n) + _der_int(e) + _der_int(d))
        alg_seq = _der_tlv(0x30, b"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00")
        pkcs8 = _der_tlv(0x30, _der_int(0) + alg_seq + _der_tlv(0x04, rsa_seq))
        b64 = base64.b64encode(pkcs8).decode("ascii")
        syn_pem = "\n".join(["-----BEGIN " + "PRIVATE KEY-----", b64, "-----END " + "PRIVATE KEY-----"])
        jwt_tok = cloud_connect.sign_rs256_jwt_in_memory({"iss": "sa@test-proj.iam.gserviceaccount.com"}, syn_pem)
        assert len(jwt_tok.split(".")) == 3

        # 2. Mock outbound cloud HTTP + CLI binaries across GCP and Azure auth, SIEM log pull & census
        az_claims = base64.urlsafe_b64encode(
            json.dumps({"tid": "tenant-org-1", "upn": "secops@contoso.com", "appid": "app-001"}).encode("utf-8")
        ).rstrip(b"=").decode("ascii")
        az_jwt = f"hdr.{az_claims}.sig"

        def fake_which(name: str):
            return f"/usr/bin/{name}" if name in {"gcloud", "az"} else None

        def fake_run(cmd, **kwargs):
            s = " ".join(str(x) for x in cmd)
            if "gcloud" in s and "print-access-token" in s:
                return SimpleNamespace(returncode=0, stdout="gcp-cli-tok-secret\n", stderr="")
            if "gcloud" in s and "get-value project" in s:
                return SimpleNamespace(returncode=0, stdout="gcp-org-proj\n", stderr="")
            if "gcloud" in s and "get-value account" in s:
                return SimpleNamespace(returncode=0, stdout="admin@example.com\n", stderr="")
            if "gcloud" in s and "configurations list" in s:
                return SimpleNamespace(returncode=0, stdout=json.dumps([{"name": "default", "is_active": True, "properties": {"core": {"account": "admin@example.com", "project": "gcp-org-proj"}}}]), stderr="")
            if "az" in s and "ms-graph" in s:
                return SimpleNamespace(returncode=0, stdout=json.dumps({"accessToken": "az-graph-tok-secret"}), stderr="")
            if "az" in s and "get-access-token" in s:
                return SimpleNamespace(returncode=0, stdout=json.dumps({"accessToken": az_jwt, "tenant": "tenant-org-1", "subscription": "sub-101"}), stderr="")
            if "az" in s and "account show" in s:
                return SimpleNamespace(returncode=0, stdout=json.dumps({"id": "sub-101", "name": "Prod Sub", "tenantId": "tenant-org-1", "user": {"name": "secops@contoso.com"}}), stderr="")
            if "az" in s and "account list" in s:
                return SimpleNamespace(returncode=0, stdout=json.dumps([{"id": "sub-101", "name": "Prod Sub", "tenantId": "tenant-org-1", "isDefault": True, "state": "Enabled"}]), stderr="")
            return SimpleNamespace(returncode=1, stdout="", stderr="unrecognized")

        def fake_http(method: str, url: str, headers, body: bytes | None = None):
            if "iamcredentials.googleapis.com" in url:
                return 200, {"accessToken": "gcp-imp-tok-secret", "expireTime": "2026-11-28T12:00:00Z"}
            if "oauth2.googleapis.com/tokeninfo" in url:
                return 200, {"email": "siem@gcp-org-proj.iam.gserviceaccount.com", "scope": "https://www.googleapis.com/auth/cloud-platform", "expires_in": "3599"}
            if "oauth2.googleapis.com/token" in url or "sts.googleapis.com/v1/token" in url:
                return 200, {"access_token": "gcp-oauth-tok-secret", "expires_in": 3600}
            if "organizations:search" in url or "/v1/organizations/" in url:
                return 200, {"organizations": [{"name": "organizations/99887766", "displayName": "Org Nine"}], "displayName": "Org Nine"}
            if "cloudresourcemanager.googleapis.com/v1/projects/gcp-org-proj" in url:
                return 200, {"projectId": "gcp-org-proj", "name": "GCP Org Project", "lifecycleState": "ACTIVE"}
            if "cloudresourcemanager.googleapis.com/v1/projects" in url:
                return 200, {"projects": [{"projectId": "gcp-org-proj", "name": "GCP Org Project", "lifecycleState": "ACTIVE"}]}
            if "logging.googleapis.com/v2/entries:list" in url:
                return 200, {
                    "entries": [
                        {
                            "insertId": "gcp-live-sa-key-01",
                            "timestamp": "2026-11-28T04:00:00Z",
                            "logName": "projects/gcp-org-proj/logs/cloudaudit.googleapis.com%2Factivity",
                            "resource": {"type": "service_account", "labels": {"project_id": "gcp-org-proj"}},
                            "protoPayload": {
                                "serviceName": "iam.googleapis.com",
                                "methodName": "google.iam.admin.v1.CreateServiceAccountKey",
                                "authenticationInfo": {"principalEmail": "attacker@gcp-org-proj.iam.gserviceaccount.com"},
                                "requestMetadata": {"callerIp": "203.0.113.88", "callerSuppliedUserAgent": "curl/8.4.0"},
                            },
                        }
                    ]
                }
            if "iam.googleapis.com/v1/projects/" in url:
                return 200, {"accounts": [{"email": "siem@gcp-org-proj.iam.gserviceaccount.com"}]}
            if "storage.googleapis.com/storage/v1/b" in url:
                return 200, {"items": [{"name": "prod-gcp-audit-bucket"}]}
            if "secretmanager.googleapis.com/v1/projects/" in url:
                return 200, {"secrets": [{"name": "projects/gcp-org-proj/secrets/db-master"}]}
            if "169.254.169.254/metadata/identity" in url:
                return 200, {"access_token": az_jwt, "expires_in": 3599}
            if "login.microsoftonline.com" in url:
                return 200, {"access_token": az_jwt, "expires_in": 3599}
            if "/providers/Microsoft.Management/managementGroups" in url:
                return 200, {"value": [{"name": "org-root-mg", "properties": {"displayName": "Root MG"}}]}
            if "/providers/Microsoft.Insights/eventtypes/management/values" in url:
                return 200, {
                    "value": [
                        {
                            "eventDataId": "az-live-rbac-01",
                            "eventTimestamp": "2026-11-28T04:05:00Z",
                            "operationName": {"value": "Microsoft.Authorization/roleAssignments/write"},
                            "status": {"value": "Succeeded"},
                            "caller": "spn-attacker@contoso.com",
                            "resourceId": "/subscriptions/sub-101/resourceGroups/rg-prod",
                        }
                    ]
                }
            if "graph.microsoft.com/v1.0/auditLogs" in url:
                return 200, {"value": []}
            if "/providers/Microsoft.KeyVault/vaults" in url:
                return 200, {"value": [{"name": "kv-prod-secrets"}]}
            if "/providers/Microsoft.Storage/storageAccounts" in url:
                return 200, {"value": [{"name": "stprodaudit"}]}
            if "/resourcegroups" in url or "/providers/Microsoft.Compute/virtualMachines" in url:
                return 200, {"value": [{"name": "rg-or-vm-prod"}]}
            if "management.azure.com/subscriptions" in url:
                return 200, {
                    "subscriptionId": "sub-101",
                    "displayName": "Prod Sub",
                    "tenantId": "tenant-org-1",
                    "state": "Enabled",
                    "value": [{"subscriptionId": "sub-101", "displayName": "Prod Sub", "tenantId": "tenant-org-1", "state": "Enabled"}],
                }
            raise AssertionError(f"Unexpected mocked URL: {method} {url}")

        monkeypatch.setattr(cloud_connect.shutil, "which", fake_which)
        monkeypatch.setattr(cloud_connect.subprocess, "run", fake_run)
        monkeypatch.setattr(cloud_connect, "_default_https_json", fake_http)
        monkeypatch.setattr(cloud_connect, "_default_https_bytes", lambda *a, **k: (200, "{}"))

        # Test all GCP auth modes (org + single)
        for mode_payload in (
            {"auth_mode": "gcloud_adc", "scope": "organization"},
            {"auth_mode": "impersonate_sa", "service_account": "siem@gcp-org-proj.iam.gserviceaccount.com", "project_id": "gcp-org-proj", "scope": "single_project"},
            {"auth_mode": "service_account_json", "service_account_json": {"client_email": "siem@gcp-org-proj.iam.gserviceaccount.com", "private_key": syn_pem, "project_id": "gcp-org-proj"}, "scope": "single_project"},
            {"auth_mode": "workload_identity", "audience": "//iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/p/providers/o", "subject_token": "oidc-jwt-secret", "project_id": "gcp-org-proj", "scope": "single_project"},
            {"auth_mode": "in_memory_token", "access_token": "ya29.secret-gcp", "project_id": "gcp-org-proj", "scope": "organization"},
        ):
            res_g = cloud_connect.verify_and_connect_gcp(mode_payload, http_fn=fake_http, runner_fn=fake_run)
            assert res_g["identity"]["project_id"] == "gcp-org-proj"

        # Test all Azure auth modes (org + single)
        for az_payload in (
            {"auth_mode": "az_cli", "scope": "organization"},
            {"auth_mode": "service_principal", "tenant_id": "tenant-org-1", "client_id": "app-001", "client_secret": "az-client-secret-ram", "scope": "organization"},
            {"auth_mode": "oidc_federated", "tenant_id": "tenant-org-1", "client_id": "app-001", "federated_token": "fed-oidc-jwt", "scope": "single_subscription", "subscription_id": "sub-101"},
            {"auth_mode": "managed_identity", "scope": "single_subscription", "subscription_id": "sub-101"},
            {"auth_mode": "in_memory_token", "access_token": az_jwt, "graph_token": "graph-ram-secret", "scope": "organization"},
        ):
            res_a = cloud_connect.verify_and_connect_azure(az_payload, http_fn=fake_http, runner_fn=fake_run)
            assert res_a["identity"]["tenant_id"] == "tenant-org-1"

        # Connect GCP + Azure through Web Control Plane API and verify secret isolation
        tok = web_app.get_session_token()
        r_gcp = _raw_asgi(
            "POST",
            "/api/connect/gcp",
            payload={"auth_mode": "in_memory_token", "access_token": "ya29.secret-gcp", "project_id": "gcp-org-proj", "scope": "organization"},
            headers={"x-identity-shield-token": tok},
        )
        assert r_gcp.status_code == 200
        assert r_gcp.json()["connected"] is True
        assert r_gcp.json()["identity"]["organization_id"] == "99887766"

        r_az = _raw_asgi(
            "POST",
            "/api/connect/azure",
            payload={"auth_mode": "service_principal", "tenant_id": "tenant-org-1", "client_id": "app-001", "client_secret": "super-secret-client", "scope": "organization"},
            headers={"x-identity-shield-token": tok},
        )
        assert r_az.status_code == 200
        assert r_az.json()["connected"] is True
        assert r_az.json()["identity"]["management_groups_accessible"] == 1

        st_json = _raw_asgi("GET", "/api/state").json()
        assert st_json["connections"]["gcp"]["connected"] is True
        assert st_json["connections"]["azure"]["connected"] is True
        dumped_state = json.dumps(st_json)
        assert "ya29.secret-gcp" not in dumped_state
        assert "super-secret-client" not in dumped_state
        assert az_jwt not in dumped_state
        ws_text = settings.workspace_config_path().read_text(encoding="utf-8")
        assert "ya29.secret-gcp" not in ws_text
        assert "super-secret-client" not in ws_text

        # Templates include AWS, GCP & Azure single/org templates
        tpls = _raw_asgi("GET", "/api/connect/templates").json()["templates"]
        assert {"single-account", "organization", "gcp-single", "gcp-organization", "azure-single", "azure-organization"} <= set(tpls.keys())

        # Live Cloud SIEM Pull ingests real GCP + Azure audit entries and detects alerts automatically
        r_pull = _raw_asgi(
            "POST",
            "/api/clouds/pull",
            payload={"cloud_provider": "connected", "hours": 24, "replay_rules": True},
            headers={"x-identity-shield-token": tok},
        )
        assert r_pull.status_code == 200
        pull_out = r_pull.json()
        assert pull_out["ingested_by_cloud"]["gcp"] == 1
        assert pull_out["ingested_by_cloud"]["azure"] == 1
        assert pull_out["replay_stats"]["multicloud-v1"] >= 2

        # Live Multi-Cloud Census feeds Closed-Loop from_resources vectors
        r_cen = _raw_asgi(
            "POST",
            "/api/clouds/census",
            payload={"cloud_provider": "connected"},
            headers={"x-identity-shield-token": tok},
        )
        assert r_cen.status_code == 200
        cen = r_cen.json()
        assert "prod-gcp-audit-bucket" in cen["clouds"]["gcp"]["buckets"]
        assert "kv-prod-secrets" in cen["clouds"]["azure"]["key_vaults"]

        conn = connect(mc_env["db"])
        try:
            prev_res = preview_closed_loop_vectors(conn, mode="from_resources", cloud_provider="gcp")
            assert any(v["target_resource"] == "prod-gcp-audit-bucket" for v in prev_res["vectors"])
        finally:
            conn.close()

        # Multi-cloud Cloud Archive (GCS & Azure Blob) works via connected tokens
        gcs_arch = service.archive_telemetry_to_cloud({"provider": "gcp", "bucket": "prod-gcp-audit-bucket"}, db_path=mc_env["db"])
        az_arch = service.archive_telemetry_to_cloud({"provider": "azure", "storage_account": "stprodaudit", "container": "siem-logs"}, db_path=mc_env["db"])
        assert gcs_arch["uri"].startswith("gs://prod-gcp-audit-bucket/")
        assert "stprodaudit.blob.core.windows.net" in az_arch["uri"]
    finally:
        settings.RUNTIME_SESSION.clear()


def test_multicloud_lab_attacks_variants_and_campaigns_parity(mc_env, monkeypatch, capsys):
    """Verify 3-cloud parity across Lab Resources, Doctor, Discover, Attacks, Variants, and Campaigns."""
    import time
    from identity_shield import service
    from identity_shield.clouds import connect as mc_conn

    variants_dir = mc_env["tmp"] / "variants"
    variants_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(config, "VARIANTS_DIR", variants_dir)
    monkeypatch.setenv("IDENTITY_SHIELD_VARIANTS_DIR", str(variants_dir))
    settings.RUNTIME_SESSION.clear()

    tok = web_app.get_session_token()
    hdrs = {"x-identity-shield-token": tok}

    # Connect mock GCP + Azure runtime sessions cleanly (RAM only)
    def fake_http(method: str, url: str, headers=None, body=None):
        if "tokeninfo" in url:
            return 200, {"email": "secops@prod.iam.gserviceaccount.com", "expires_in": "3600"}
        if "cloudresourcemanager.googleapis.com/v1/projects" in url:
            return 200, {"projects": [{"projectId": "prod-gcp-101"}]}
        if "storage.googleapis.com/storage/v1/b" in url:
            return 200, {"items": [{"name": "gcp-crown-bucket"}]}
        if "iam.googleapis.com" in url:
            return 200, {"accounts": [{"email": "app@prod-gcp-101.iam.gserviceaccount.com", "displayName": "App SA"}]}
        if "secretmanager.googleapis.com" in url:
            return 200, {"secrets": [{"name": "projects/prod-gcp-101/secrets/prod-api-key"}]}
        if "logging.googleapis.com" in url and "/sinks" in url:
            return 200, {"sinks": [{"name": "org-siem-sink", "destination": "storage.googleapis.com/gcp-crown-bucket"}]}
        if "login.microsoftonline.com" in url:
            return 200, {"access_token": "az-arm-tok", "expires_in": 3600}
        if "management.azure.com/subscriptions" in url and "/providers/" not in url and "/resourcegroups" not in url:
            return 200, {"value": [{"subscriptionId": "sub-1111-2222", "displayName": "Prod Sub", "state": "Enabled"}]}
        if "/providers/Microsoft.KeyVault/vaults" in url:
            return 200, {"value": [{"name": "kv-prod-01", "id": "/subscriptions/sub-1111-2222/resourceGroups/rg-sec/providers/Microsoft.KeyVault/vaults/kv-prod-01", "location": "eastus"}]}
        if "/resourcegroups" in url:
            return 200, {"value": [{"name": "rg-sec", "location": "eastus"}]}
        if "graph.microsoft.com" in url:
            return 200, {"value": [{"appId": "app-1", "displayName": "Security App"}]}
        return 200, {"value": []}

    monkeypatch.setattr(mc_conn, "_default_https_json", fake_http)
    try:
        assert _raw_asgi("POST", "/api/connect/gcp", payload={"auth_mode": "in_memory_token", "project_id": "prod-gcp-101", "access_token": "ya29.test"}, headers=hdrs).status_code == 200
        assert _raw_asgi("POST", "/api/connect/azure", payload={"auth_mode": "service_principal", "tenant_id": "ten-1", "client_id": "app-1", "client_secret": "sec-1"}, headers=hdrs).status_code == 200

        # 1. Bind & CLI-bind GCP + Azure target resources
        r_res = _raw_asgi(
            "POST",
            "/api/lab/resources",
            payload={"gcp_project_id": "prod-gcp-101", "gcp_bucket": "gcp-crown-bucket", "azure_subscription_id": "sub-1111-2222", "azure_key_vault": "kv-prod-01"},
            headers=hdrs,
        )
        assert r_res.status_code == 200
        assert r_res.json()["resources"]["gcp_bucket"] == "gcp-crown-bucket"
        assert ops_cli.config_main(["bind", "--gcp-secret", "prod-api-key", "--azure-rg", "rg-sec"]) == 0
        _ = capsys.readouterr()
        assert settings.get_resources().gcp_secret_name == "prod-api-key"
        assert settings.get_resources().azure_resource_group == "rg-sec"

        # 2. Lab Doctor + Discover work independently for GCP and Azure
        doc_gcp = _raw_asgi("POST", "/api/lab/doctor", payload={"cloud_provider": "gcp"}, headers=hdrs)
        doc_az = _raw_asgi("POST", "/api/lab/doctor", payload={"cloud_provider": "azure"}, headers=hdrs)
        doc_all = _raw_asgi("POST", "/api/lab/doctor", payload={"cloud_provider": "all"}, headers=hdrs)
        assert doc_gcp.status_code == 200 and doc_gcp.json()["ok"] is True
        assert doc_az.status_code == 200 and doc_az.json()["ok"] is True
        assert "gcp" in doc_all.json()["by_cloud"] and "azure" in doc_all.json()["by_cloud"]

        disc_gcp = _raw_asgi("POST", "/api/lab/census", payload={"cloud_provider": "gcp"}, headers=hdrs)
        disc_az = _raw_asgi("POST", "/api/lab/census", payload={"cloud_provider": "azure"}, headers=hdrs)
        assert disc_gcp.status_code == 200 and disc_gcp.json()["inventory"]["buckets"][0]["name"] == "gcp-crown-bucket"
        assert disc_az.status_code == 200 and disc_az.json()["inventory"]["key_vaults"][0]["name"] == "kv-prod-01"

        # 3. Custom GCP attack generates 5-factor variants & keeps default load_catalogue AWS-8 clean when include_multicloud=False
        r_add = _raw_asgi(
            "POST",
            "/api/attacks",
            payload={
                "cloud_provider": "gcp",
                "technique_id": "T1555.GCP09",
                "name": "Custom GCP Secret Grab",
                "tactic": "credential-access",
                "service": "secretmanager.googleapis.com",
                "operation": "AccessSecretVersion",
                "event_names": "google.cloud.secretmanager.v1.SecretManagerService.AccessSecretVersion",
                "sync_variants": True,
            },
            headers=hdrs,
        )
        assert r_add.status_code == 200, r_add.text
        var_gcp = _raw_asgi("GET", "/api/variants?cloud_provider=gcp&limit=200", headers=hdrs)
        var_az = _raw_asgi("GET", "/api/variants?cloud_provider=azure&limit=200", headers=hdrs)
        assert var_gcp.status_code == 200 and any(v["technique_id"] == "T1555.GCP09" for v in var_gcp.json()["variants"])
        assert var_az.status_code == 200 and any(v["technique_id"] == "T1555.AZ06" for v in var_az.json()["variants"])
        # Built-in AWS-only load_catalogue preserves its 8 core techniques cleanly
        aws_only_ids = {t.technique_id for t in load_catalogue(include_overrides=False).techniques}
        assert len(aws_only_ids) == 8

        # 4. Run Synthetic Multi-Cloud Campaign for GCP + Azure and verify SQLite events + Sigma detections + Analytics
        r_camp = _raw_asgi(
            "POST",
            "/api/campaigns/run",
            payload={
                "synthetic": True,
                "cloud_provider": "all",
                "techniques": ["T1098.GCP01", "T1555.AZ06"],
                "sets": ["baseline", "ofat"],
                "ruleset": "multicloud-v1",
            },
            headers=hdrs,
        )
        assert r_camp.status_code == 200, r_camp.text
        job_id = r_camp.json()["job_id"]
        job = {}
        for _ in range(80):
            job = _raw_asgi("GET", f"/api/jobs/{job_id}", headers=hdrs).json()
            if job.get("status") != "running":
                break
            time.sleep(0.05)
        assert job.get("status") == "completed", job

        logs_gcp = _raw_asgi("GET", "/api/logs?cloud_provider=gcp&alerts_only=true", headers=hdrs).json()
        logs_az = _raw_asgi("GET", "/api/logs?cloud_provider=azure&alerts_only=true", headers=hdrs).json()
        assert len(logs_gcp["events"]) >= 1
        assert len(logs_az["events"]) >= 1

        an_gcp = _raw_asgi("GET", "/api/analytics?ruleset=multicloud-v1&cloud_provider=gcp", headers=hdrs).json()
        assert an_gcp["summary"]["overall"]["detected"] >= 1
    finally:
        settings.RUNTIME_SESSION.clear()
