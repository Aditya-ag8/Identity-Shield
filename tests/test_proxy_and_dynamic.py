"""End-to-end tests for Live Security Proxy, Adaptive Rule Enhancer, Dynamic Detection Engine, and CLI parity."""

from __future__ import annotations

import http.client
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from identity_shield import config, ops_cli, settings
from identity_shield.db.connection import connect
from identity_shield.db.init import ensure_tables, init_db
from identity_shield.detect import dynamic, enhancer, replay
from identity_shield.proxy.server import PROXY_RUNTIME
from identity_shield.runner import orchestrator
from identity_shield.web.app import app
from test_control_plane_and_parity import _AsgiHarness


@pytest.fixture
def isolated_env(tmp_path, monkeypatch):
    db_path = tmp_path / "proxy_test.db"
    cfg_path = tmp_path / "workspace_config.json"
    overrides_path = tmp_path / "attack_overrides.json"
    variants_dir = tmp_path / "variants"
    variants_dir.mkdir(parents=True, exist_ok=True)

    init_db(db_path, drop=True)
    monkeypatch.setenv("IDENTITY_SHIELD_DB", str(db_path))
    monkeypatch.setenv("IDENTITY_SHIELD_CONFIG", str(cfg_path))
    monkeypatch.setenv("IDENTITY_SHIELD_ATTACK_OVERRIDES", str(overrides_path))
    monkeypatch.setattr(config, "DEFAULT_DB", db_path)
    monkeypatch.setattr(config, "VARIANTS_DIR", variants_dir)
    monkeypatch.setattr(config, "DATA", tmp_path)
    settings.RUNTIME_SESSION.clear()
    PROXY_RUNTIME.stop()
    try:
        yield {
            "db": db_path,
            "cfg": cfg_path,
            "tmp": tmp_path,
        }
    finally:
        PROXY_RUNTIME.stop()


class _EchoUpstreamHandler(BaseHTTPRequestHandler):
    requests_received: list[str] = []

    def _handle(self) -> None:
        self.__class__.requests_received.append(f"{self.command} {self.path}")
        body = json.dumps({"ok": True, "path": self.path, "method": self.command}).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        self._handle()

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        if length > 0:
            self.rfile.read(length)
        self._handle()

    def log_message(self, format: str, *args) -> None:  # noqa: A002
        return


def _start_upstream() -> tuple[HTTPServer, threading.Thread, str]:
    _EchoUpstreamHandler.requests_received = []
    srv = HTTPServer(("127.0.0.1", 0), _EchoUpstreamHandler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    host, port = srv.server_address[:2]
    return srv, t, f"http://{host}:{port}"


def _send_http(host: str, port: int, method: str, path: str, headers: dict[str, str], body: bytes = b""):
    conn = http.client.HTTPConnection(host, port, timeout=10)
    conn.request(method, path, body=body or None, headers=headers)
    resp = conn.getresponse()
    raw = resp.read().decode("utf-8", errors="replace")
    out = {
        "status": resp.status,
        "action": resp.getheader("X-Identity-Shield-Action") or "",
        "risk": float(resp.getheader("X-Identity-Shield-Risk") or "0"),
        "body": raw,
    }
    conn.close()
    return out


def test_live_proxy_forwarding_drift_velocity_sequence_and_blocking(isolated_env):
    upstream_srv, _ut, upstream_url = _start_upstream()
    try:
        settings.update_proxy_config(
            {
                "host": "127.0.0.1",
                "port": 0,
                "mode": "observe",
                "upstream_url": upstream_url,
                "block_risk_threshold": 5.0,
                "learn_baseline": True,
                "ruleset_version": "baseline-v1",
            }
        )
        st = PROXY_RUNTIME.start(db_path=isolated_env["db"], host="127.0.0.1", port=0)
        assert st["running"] is True
        host, port = st["host"], int(st["port"])

        # 1. Clean baseline requests establish profile (Boto3 + eu-west-1 + s3)
        #    Send 3 clean requests to cross min_baseline_events=3 for DYN-DRIFT-001
        clean_headers = {
            "Authorization": "AWS4-HMAC-SHA256 Credential=AKIABUILDER01/20261126/eu-west-1/s3/aws4_request",
            "User-Agent": "Boto3/1.34.49 Python/3.11.9",
        }
        for _ in range(3):
            r_clean = _send_http(host, port, "GET", "/app-public-assets", clean_headers)
            assert r_clean["status"] == 200
            assert r_clean["action"] == "allowed"
        assert len(_EchoUpstreamHandler.requests_received) == 3

        # 2. Same key suddenly switches to curl in us-east-1 doing IAM discovery burst -> CreateAccessKey
        attack_headers = {
            "Authorization": "AWS4-HMAC-SHA256 Credential=AKIABUILDER01/20261126/us-east-1/iam/aws4_request",
            "User-Agent": "curl/8.4.0",
            "Content-Type": "application/x-www-form-urlencoded",
        }
        actions = [
            "ListUsers",
            "ListRoles",
            "ListAccessKeys",
            "GetAccountAuthorizationDetails",
            "CreateAccessKey",
        ]
        last_res = None
        for act in actions:
            last_res = _send_http(
                host,
                port,
                "POST",
                "/",
                attack_headers,
                body=f"Action={act}&Version=2010-05-08".encode("utf-8"),
            )
            assert last_res["status"] == 200  # Observe mode forwards and alerts
            assert last_res["action"] == "alerted"
        assert last_res is not None and last_res["risk"] >= 5.0

        # Verify dynamic alerts fired for Drift, Velocity Burst, and Sequence Chain
        conn = connect(isolated_env["db"])
        try:
            rule_ids = {
                r["rule_id"]
                for r in conn.execute("SELECT rule_id FROM dynamic_alert WHERE source = 'proxy'").fetchall()
            }
            assert "DYN-DRIFT-001" in rule_ids
            assert "DYN-VEL-001" in rule_ids
            assert "DYN-SEQ-001" in rule_ids

            # Baseline profile MUST NOT be poisoned by curl/us-east-1 attack traffic
            prof = conn.execute(
                "SELECT * FROM principal_profile WHERE principal = 'AKIABUILDER01'"
            ).fetchone()
            assert prof is not None
            assert "Boto3/1.34.49 Python/3.11.9" in json.loads(prof["known_user_agents"])
            assert "curl/8.4.0" not in json.loads(prof["known_user_agents"])
        finally:
            conn.close()

        # 3. Switch to inline Block mode (HTTP 403) and test Cloud Web App path traversal
        settings.update_proxy_config({"mode": "block", "block_risk_threshold": 60.0})
        forwarded_before = len(_EchoUpstreamHandler.requests_received)
        blocked = _send_http(
            host,
            port,
            "GET",
            "/api/files?name=../../etc/passwd",
            {"User-Agent": "curl/8.4.0", "X-Identity-User": "scanner"},
        )
        assert blocked["status"] == 403
        assert blocked["action"] == "blocked"
        blocked_json = json.loads(blocked["body"])
        assert blocked_json["blocked_by"] == "Identity Shield Live Proxy"
        assert blocked_json["risk_score"] >= 60.0
        # Blocked request MUST NOT reach upstream server
        assert len(_EchoUpstreamHandler.requests_received) == forwarded_before
    finally:
        upstream_srv.shutdown()
        upstream_srv.server_close()


def test_proxy_api_endpoints_and_simulator_and_cli_parity(isolated_env):
    client = _AsgiHarness(app)

    r_state = client.get("/api/state")
    assert r_state.status_code == 200
    assert "proxy" in r_state.json()
    assert "proxy_status" in r_state.json()

    r_cfg = client.put(
        "/api/proxy/config",
        json={"host": "127.0.0.1", "port": 0, "mode": "observe", "ruleset_version": "baseline-v1"},
    )
    assert r_cfg.status_code == 200
    assert r_cfg.json()["config"]["mode"] == "observe"

    r_sim = client.post("/api/proxy/simulate", json={"scenario": "mixed"})
    assert r_sim.status_code == 200
    sim_data = r_sim.json()
    assert sim_data["sent_count"] >= 11
    assert sim_data["status"]["running"] is True
    assert sim_data["status"]["stats"]["aws_events"] >= 5
    assert sim_data["status"]["stats"]["app_events"] >= 5

    r_ev = client.get("/api/proxy/events?alerts_only=true")
    assert r_ev.status_code == 200
    assert r_ev.json()["count"] >= 4

    r_app = client.get("/api/proxy/events?traffic_kind=http_app")
    assert r_app.status_code == 200
    assert r_app.json()["count"] >= 5
    app_dyn_ids = {
        hit["rule_id"]
        for ev in r_app.json()["events"]
        for hit in ev["matched_dynamic"]
    }
    assert "DYN-APP-001" in app_dyn_ids

    r_prof = client.get("/api/dynamic/profiles")
    assert r_prof.status_code == 200
    assert r_prof.json()["count"] >= 1

    r_stop = client.post("/api/proxy/stop", json={})
    assert r_stop.status_code == 200
    assert r_stop.json()["running"] is False

    # CLI parity checks
    assert ops_cli.proxy_main(["status", "--db", str(isolated_env["db"])]) == 0
    assert ops_cli.proxy_main(["events", "--kind", "http_app", "--db", str(isolated_env["db"]), "--json"]) == 0
    assert ops_cli.proxy_main(["clear", "--db", str(isolated_env["db"])]) == 0


def test_rule_audit_adaptive_enhancer_and_dynamic_rules_crud_and_replay(isolated_env):
    from identity_shield.contracts import Variant as VContract
    from identity_shield.variants.loader import load_catalogue

    client = _AsgiHarness(app)

    # Seed realistic batch trial run so enhancer can inspect missed variants too
    assert client.post("/api/variants/generate", json={}).status_code == 200
    variants_t1530 = client.get("/api/variants?technique_id=T1530").json()["variants"][:8]
    variants_t1087 = client.get("/api/variants?technique_id=T1087.004").json()["variants"][:8]
    v_objs = [
        VContract(
            variant_id=row["variant_id"],
            technique_id=row["technique_id"],
            variant_set=row["variant_set"],
            factor_levels=row["factor_levels"],
            seed=row["seed"],
            spec_sha256=row["spec_sha256"],
        )
        for row in (variants_t1530 + variants_t1087)
    ]

    conn = connect(isolated_env["db"])
    try:
        camp = orchestrator.run_campaign(
            conn,
            run_id="batch-enhance-test",
            variants=v_objs,
            catalogue=load_catalogue(),
            account_id="123456789012",
            region="eu-west-1",
            synthetic=True,
        )
        assert camp.succeeded > 0
    finally:
        conn.close()

    assert client.post("/api/rules/replay", json={"ruleset_version": "baseline-v1"}).status_code == 200
    res_run = {"trials": camp.succeeded}

    # 1. Audit baseline-v1 for hardcoded patterns
    r_audit = client.get("/api/rules/audit?ruleset=baseline-v1")
    assert r_audit.status_code == 200
    audit = r_audit.json()
    assert audit["total_rules"] >= 4
    assert audit["weak_rules"] >= 1
    weakest = min(audit["rules"], key=lambda x: x["health_score"])

    # 2. Preview single rule enhancement
    r_prev = client.post("/api/rules/enhance/preview", json={"rule_id": weakest["rule_id"]})
    assert r_prev.status_code == 200
    prev = r_prev.json()
    assert "(Enhanced)" in prev["enhanced_title"]
    assert len(prev["fixes_applied"]) >= 1

    # 3. Auto-enhance full baseline-v1 -> enhanced-v1 without mutating frozen ruleset
    r_all = client.post(
        "/api/rules/enhance/all",
        json={"source_ruleset": "baseline-v1", "target_ruleset": "enhanced-v1"},
    )
    assert r_all.status_code == 200
    enh_res = r_all.json()
    assert enh_res["target_ruleset"] == "enhanced-v1"
    assert enh_res["rules_generated"] >= 4

    enhanced_dir = isolated_env["tmp"] / "rules" / "enhanced"
    assert enhanced_dir.exists()
    assert len(list(enhanced_dir.glob("*.yml"))) >= 4

    r_an = client.get("/api/analytics?ruleset=enhanced-v1")
    assert r_an.status_code == 200
    assert r_an.json()["ruleset"] == "enhanced-v1"
    assert r_an.json()["compare_target"] == "enhanced-v1"

    # 4. Dynamic rule CRUD + toggle + batch replay
    r_dyn_add = client.post(
        "/api/dynamic/rules",
        json={
            "rule_id": "DYN-TEST-BURST",
            "name": "Test S3 Burst",
            "kind": "velocity",
            "severity": "high",
            "window_seconds": 120,
            "threshold": 2,
            "config": {"services": ["s3", "iam"]},
        },
    )
    assert r_dyn_add.status_code == 200
    assert r_dyn_add.json()["rule_id"] == "DYN-TEST-BURST"

    r_toggle = client.patch("/api/dynamic/rules/DYN-TEST-BURST", json={"enabled": False})
    assert r_toggle.status_code == 200
    assert r_toggle.json()["enabled"] is False

    r_rep = client.post("/api/dynamic/replay", json={})
    assert r_rep.status_code == 200
    assert r_rep.json()["events_scanned"] >= res_run["trials"]

    r_alerts = client.get("/api/dynamic/alerts?source=batch")
    assert r_alerts.status_code == 200
    assert r_alerts.json()["count"] >= 0

    r_del = client.delete("/api/dynamic/rules/DYN-TEST-BURST")
    assert r_del.status_code == 200
    assert r_del.json()["deleted"] is True

    # CLI parity for dynamic subcommands
    assert ops_cli.dynamic_main(["list", "--db", str(isolated_env["db"])]) == 0
    assert ops_cli.dynamic_main(["audit", "--ruleset", "baseline-v1", "--db", str(isolated_env["db"])]) == 0
    assert ops_cli.dynamic_main(["replay", "--db", str(isolated_env["db"])]) == 0


def test_self_hosted_storage_linking_export_and_s3_archive(isolated_env, monkeypatch):
    from aws_fakes import FakeClient, FakeSession
    from identity_shield import service

    client = _AsgiHarness(app)
    monkeypatch.delenv("IDENTITY_SHIELD_DB", raising=False)

    # Reject remote Postgres/MySQL URI cleanly rather than breaking sqlite3
    r_bad = client.put("/api/storage", json={"db_path": "postgresql://user:pw@db/shield"})
    assert r_bad.status_code == 400
    assert "SQLite" in r_bad.json()["error"]

    # Link a custom organization SQLite DB path on mounted/local storage
    org_db = isolated_env["tmp"] / "org_warehouse" / "org_shield.db"
    r_link = client.put(
        "/api/storage",
        json={
            "db_path": str(org_db),
            "max_proxy_events": 25000,
            "archive_s3_bucket": "org-security-telemetry",
            "archive_s3_prefix": "proxy-archive/",
        },
    )
    assert r_link.status_code == 200, r_link.text
    assert org_db.exists()
    assert service.resolve_db_path() == org_db.resolve()
    assert r_link.json()["db"]["linked_custom_db"] is True

    # Simulate traffic directly into newly linked DB & export portable JSONL
    r_sim = client.post("/api/proxy/simulate", json={"scenario": "baseline"})
    assert r_sim.status_code == 200
    PROXY_RUNTIME.stop()

    r_exp = client.get("/api/storage/export")
    assert r_exp.status_code == 200
    lines = [json.loads(line) for line in r_exp.text.strip().splitlines() if line.strip()]
    assert len(lines) >= 4
    assert any(row.get("record_type") == "proxy_event" for row in lines)

    # Test S3 archive upload using in-memory FakeSession (no external AWS call)
    s3_fake = FakeClient({"put_object": {"ETag": '"abc123"'}})
    fake_sess = FakeSession({"s3": s3_fake})
    settings.RUNTIME_SESSION.set_connection(
        descriptor=settings.get_connection_descriptor(),
        boto_session=fake_sess,
        classification={"organization_status": "standalone", "effective_scope": "single_account"},
        caller_arn="arn:aws:iam::123456789012:user/admin",
        account_id="123456789012",
    )
    r_arch = client.post("/api/storage/archive", json={})
    assert r_arch.status_code == 200, r_arch.text
    arch = r_arch.json()
    assert arch["archived"] is True
    assert arch["bucket"] == "org-security-telemetry"
    assert arch["records"] >= 4
    assert len(s3_fake.calls) == 1

    # CLI parity for config storage + export
    out_jsonl = isolated_env["tmp"] / "exported.jsonl"
    assert ops_cli.config_main(["storage", "--max-proxy-events", "10000"]) == 0
    assert ops_cli.config_main(["export", "--output", str(out_jsonl)]) == 0
    assert out_jsonl.exists() and out_jsonl.stat().st_size > 0
