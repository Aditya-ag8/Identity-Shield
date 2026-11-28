"""Tests for Closed-Loop Alert/Resource -> 5-Factor Variant Engine & Lazy Tool Adapters."""

from __future__ import annotations

import json
import subprocess
import uuid
from types import SimpleNamespace

import pytest

from identity_shield import cli, config, service, settings
from identity_shield.db.connection import connect
from identity_shield.db.init import init_db
from identity_shield.integrations import (
    ALLOWED_PACU_MODULES,
    MAX_CLOUDFOX_BYTES,
    get_external_tools_status,
    load_cloudfox_inventory_file,
    parse_cloudfox_inventory,
    run_cloudfox_recon,
    run_pacu_recon,
)
from identity_shield.proxy.server import PROXY_RUNTIME
from identity_shield.variants.closed_loop import (
    load_cloudfox_inventory,
    preview_closed_loop_vectors,
    run_closed_loop,
)
from identity_shield.web import app as web_app
from tests.test_security_hardening import _raw_asgi


@pytest.fixture
def loop_env(tmp_path, monkeypatch):
    db_path = tmp_path / "loop_test.db"
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
        yield {"db": db_path, "tmp": tmp_path}
    finally:
        PROXY_RUNTIME.stop()


def _insert_sample_proxy_alerts(db_path):
    conn = connect(db_path)
    try:
        # 1. AWS API suspicious alert (not in default baseline-v1 rules -> exposes gap then gets auto-hardened)
        conn.execute(
            """
            INSERT INTO proxy_event (
              proxy_event_id, timestamp, traffic_kind, mode, action_taken,
              client_ip, principal, method, target_host, path, service, operation,
              user_agent, aws_region, params_json, status_code, latency_ms,
              risk_score, matched_static, matched_dynamic, event_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "px-test-aws-001",
                "2026-11-27T04:00:00Z",
                "aws_api",
                "observe",
                "alerted",
                "203.0.113.19",
                "arn:aws:iam::111122223333:user/suspect-ci",
                "POST",
                "secretsmanager.eu-west-1.amazonaws.com",
                "/",
                "secretsmanager",
                "GetSecretValue",
                "python-requests/2.32.0",
                "eu-west-1",
                json.dumps({"secretId": "prod/db/master"}),
                200,
                12.0,
                78.5,
                json.dumps([]),
                json.dumps([{"rule_id": "dyn-ua-drift", "rule_name": "Agent Drift"}]),
                json.dumps(
                    {
                        "eventID": uuid.uuid4().hex[:32],
                        "eventTime": "2026-11-27T04:00:00Z",
                        "eventSource": "secretsmanager.amazonaws.com",
                        "eventName": "GetSecretValue",
                    }
                ),
            ),
        )
        # 2. HTTP Web App suspicious probe alert
        conn.execute(
            """
            INSERT INTO proxy_event (
              proxy_event_id, timestamp, traffic_kind, mode, action_taken,
              client_ip, principal, method, target_host, path, service, operation,
              user_agent, aws_region, params_json, status_code, latency_ms,
              risk_score, matched_static, matched_dynamic, event_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "px-test-http-001",
                "2026-11-27T04:01:00Z",
                "http_app",
                "block",
                "blocked",
                "198.51.100.77",
                "ip:198.51.100.77",
                "GET",
                "portal.internal",
                "/.env",
                "http_app",
                "SensitiveProbe",
                "curl/8.4.0",
                "eu-west-1",
                json.dumps({}),
                403,
                4.0,
                85.0,
                json.dumps([]),
                json.dumps([{"rule_id": "dyn-app-probe", "rule_name": "Sensitive Path Probe"}]),
                json.dumps({"eventID": uuid.uuid4().hex[:32], "eventName": "SensitiveProbe"}),
            ),
        )
        conn.commit()
    finally:
        conn.close()


def test_lazy_tools_status_and_pacu_allowlist(tmp_path):
    st_none = get_external_tools_status(which_fn=lambda _b: None)
    assert st_none["lazy_mode"] is True
    assert st_none["installed_count"] == 0
    assert len(st_none["tools"]) >= 8

    st_partial = get_external_tools_status(which_fn=lambda b: f"/usr/bin/{b}" if b in {"stratus", "cloudfox"} else None)
    assert st_partial["installed_count"] == 2

    # Unconditionally block destructive or unallowlisted Pacu modules
    for bad_mod in ("iam__privesc_scan", "ec2__backdoor_ec2_sec_groups", "iam__enum_permissions; rm -rf /"):
        with pytest.raises(ValueError, match="not allowed"):
            run_pacu_recon(bad_mod)

    with pytest.raises(ValueError, match="Invalid profile"):
        run_pacu_recon("iam__enum_permissions", profile="--evil-flag")

    # Missing binary fails gracefully without throwing or slowing down
    absent = run_pacu_recon("iam__enum_permissions", which_fn=lambda _b: None)
    assert absent["ok"] is False
    assert absent["installed"] is False

    # Valid allowlisted execution invokes subprocess with shell=False and redacts secrets in output
    recorded = {}

    def fake_run(cmd, **kwargs):
        recorded["cmd"] = cmd
        recorded["kwargs"] = kwargs
        return subprocess.CompletedProcess(
            cmd,
            0,
            stdout="Scanned IAM AKIA1234567890ABCDEF cleanly",
            stderr="",
        )

    ok_res = run_pacu_recon(
        "iam__enum_permissions",
        profile="audit-ro",
        proxy_url="http://127.0.0.1:8888",
        which_fn=lambda _b: "/usr/local/bin/pacu",
        runner=fake_run,
    )
    assert ok_res["ok"] is True
    assert recorded["kwargs"]["shell"] is False
    assert "AKIA1234567890ABCDEF" not in ok_res["stdout"]
    assert "<redacted-aws-key>" in ok_res["stdout"]

    # CloudFox absent + mocked execution
    cf_absent = run_cloudfox_recon(which_fn=lambda _b: None)
    assert cf_absent["ok"] is False
    assert cf_absent["installed"] is False


def test_cloudfox_inventory_parser_and_security_guards(tmp_path):
    raw = {
        "buckets": [{"BucketName": "prod-data-lake"}, "staging-logs"],
        "iam_users": [{"UserName": "deploy-bot", "access_key": "AKIA1234567890ABCDEF"}],
        "iam_roles": [{"RoleName": "AppAdminRole"}],
        "ec2_instances": [{"InstanceId": "i-0abc1234567890def"}],
        "lambdas": [{"FunctionName": "billing-sync"}],
        "secrets": [{"SecretName": "rds/prod/password"}],
        "sqs_queues": ["https://sqs.eu-west-1.amazonaws.com/111122223333/events"],
    }
    parsed = parse_cloudfox_inventory(raw)
    assert parsed["total_resources"] == 8
    assert parsed["suggested_bindings"]["data_bucket"] == "prod-data-lake"
    assert parsed["suggested_bindings"]["test_user_name"] == "deploy-bot"
    assert parsed["suggested_bindings"]["admin_role_name"] == "AppAdminRole"
    assert parsed["suggested_bindings"]["instance_id"] == "i-0abc1234567890def"

    # Reject empty / malformed / oversized payloads
    with pytest.raises(ValueError, match="Invalid CloudFox JSON"):
        parse_cloudfox_inventory("{bad json")

    oversized = "{" + (" " * (MAX_CLOUDFOX_BYTES + 64)) + "}"
    with pytest.raises(ValueError, match="limit"):
        parse_cloudfox_inventory(oversized)

    # Reject traversal and wrong file extensions
    with pytest.raises(ValueError, match="traversal"):
        load_cloudfox_inventory_file("../secret.json", base_dir=tmp_path)

    txt_file = tmp_path / "notes.txt"
    txt_file.write_text("{}", encoding="utf-8")
    with pytest.raises(ValueError, match=".json"):
        load_cloudfox_inventory_file(str(txt_file), base_dir=tmp_path)

    good_file = tmp_path / "cf.json"
    good_file.write_text(json.dumps(raw), encoding="utf-8")
    loaded = load_cloudfox_inventory_file("cf.json", base_dir=tmp_path)
    assert loaded["counts"]["secrets"] == 1


def test_closed_loop_all_three_modes_and_auto_hardening(loop_env):
    db_path = loop_env["db"]
    _insert_sample_proxy_alerts(db_path)

    # Bind a resource + import CloudFox secrets inventory
    settings.update_resources(
        {
            "region": "eu-west-1",
            "data_bucket": "custom-crown-bucket",
            "test_user_name": "custom-operator",
        }
    )
    cf_inv = parse_cloudfox_inventory(
        {
            "buckets": ["cf-analytics-bucket"],
            "secrets": ["cf-prod-db-secret"],
            "lambdas": ["cf-worker-fn"],
        }
    )

    conn = connect(db_path)
    try:
        dyn_alerts_before = conn.execute("SELECT COUNT(*) FROM dynamic_alert").fetchone()[0]

        prev_alerts = preview_closed_loop_vectors(conn, mode="from_alerts", cloudfox_inventory=cf_inv)
        assert prev_alerts["mode"] == "from_alerts"
        assert prev_alerts["counts"]["from_alerts"] == 2
        assert prev_alerts["counts"]["from_resources"] == 0
        assert {v["traffic_kind"] for v in prev_alerts["vectors"]} == {"aws_api", "http_app"}

        prev_res = preview_closed_loop_vectors(conn, mode="from_resources", cloudfox_inventory=cf_inv)
        assert prev_res["mode"] == "from_resources"
        assert prev_res["counts"]["from_alerts"] == 0
        assert prev_res["counts"]["from_resources"] >= 3
        assert any(v["service"] == "secretsmanager" for v in prev_res["vectors"])

        prev_both = preview_closed_loop_vectors(conn, mode="both", cloudfox_inventory=cf_inv)
        assert prev_both["counts"]["from_alerts"] == 2
        assert prev_both["counts"]["from_resources"] >= 3

        # Run full closed loop with auto-hardening
        report = run_closed_loop(
            conn,
            mode="both",
            include_pairwise=False,
            auto_enhance=True,
            limit=8,
            cloudfox_inventory=cf_inv,
        )
        sm = report["summary"]
        assert sm["vectors_tested"] >= 4
        assert sm["aws_variants_tested"] > 0
        assert sm["http_variants_tested"] == 5
        assert sm["rules_generated"] >= 1
        assert sm["after_rate"] >= sm["before_rate"]
        assert (loop_env["tmp"] / "rules" / "enhanced").is_dir()

        # Verify closed-loop HTTP/synthetic probes did not pollute live dynamic_alert table
        dyn_alerts_after = conn.execute("SELECT COUNT(*) FROM dynamic_alert").fetchone()[0]
        assert dyn_alerts_after == dyn_alerts_before
    finally:
        conn.close()


def test_closed_loop_api_and_cli_parity(loop_env, monkeypatch):
    db_path = loop_env["db"]
    _insert_sample_proxy_alerts(db_path)
    tok = web_app.get_session_token()
    auth = [(b"authorization", f"Bearer {tok}".encode("utf-8"))]

    # Cross-origin browser POST without CSRF token blocked (403)
    r_csrf = _raw_asgi(
        "POST",
        "/api/closed-loop/run",
        payload={"mode": "both"},
        headers=[(b"origin", b"http://127.0.0.1:8501")],
    )
    assert r_csrf.status_code == 403

    # Remote/strict mode unauthenticated mutation rejected (401)
    monkeypatch.setattr(web_app, "NON_LOCAL_BIND", True)
    r_unauth = _raw_asgi("POST", "/api/closed-loop/run", payload={"mode": "both"}, client_host="203.0.113.5")
    assert r_unauth.status_code == 401
    monkeypatch.setattr(web_app, "NON_LOCAL_BIND", False)

    # Tool status endpoint
    r_tools = _raw_asgi("GET", "/api/tools/status", headers=auth)
    assert r_tools.status_code == 200
    assert r_tools.json()["lazy_mode"] is True

    # Import CloudFox JSON via API
    r_imp = _raw_asgi(
        "POST",
        "/api/tools/cloudfox/import",
        payload={
            "json_text": json.dumps({"buckets": ["api-cf-bucket"], "secrets": ["api-cf-secret"]}),
            "apply_bindings": True,
        },
        headers=auth,
    )
    assert r_imp.status_code == 200
    assert r_imp.json()["inventory"]["counts"]["buckets"] == 1
    assert settings.get_resources().data_bucket == "api-cf-bucket"
    assert load_cloudfox_inventory() is not None

    # Blocked Pacu module returns 400
    r_pacu_bad = _raw_asgi(
        "POST",
        "/api/tools/pacu/recon",
        payload={"module": "iam__privesc_scan"},
        headers=auth,
    )
    assert r_pacu_bad.status_code == 400

    # Closed-loop preview & run via API
    r_prev = _raw_asgi("GET", "/api/closed-loop/preview?mode=from_alerts", headers=auth)
    assert r_prev.status_code == 200
    assert r_prev.json()["mode"] == "from_alerts"

    r_run = _raw_asgi(
        "POST",
        "/api/closed-loop/run",
        payload={"mode": "both", "auto_enhance": True, "limit": 4},
        headers=auth,
    )
    assert r_run.status_code == 200
    body = r_run.json()
    assert body["summary"]["vectors_tested"] >= 2
    assert body["summary"]["after_rate"] >= body["summary"]["before_rate"]

    # CLI parity checks
    assert cli.main(["config", "tools", "--mode", "status"]) == 0
    assert cli.main(["dynamic", "loop", "--mode", "both", "--preview", "--db", str(db_path)]) == 0
