"""Security regression tests for Auth, CSRF, Host validation, SSRF, Traversal, Secret Redaction, and DoS guards."""

from __future__ import annotations

import asyncio
import http.client
import json
from types import SimpleNamespace
from urllib.parse import urlsplit

import pytest

from identity_shield import config, service, settings
from identity_shield.db.init import init_db
from identity_shield.lab import provision
from identity_shield.proxy import parser as proxy_parser
from identity_shield.proxy.server import PROXY_RUNTIME
from identity_shield.web import app as web_app


def _raw_asgi(
    method: str,
    url: str,
    *,
    payload: dict | None = None,
    raw_body: bytes | None = None,
    headers: list[tuple[bytes, bytes]] | None = None,
    client_host: str = "127.0.0.1",
) -> SimpleNamespace:
    split = urlsplit(url)
    body_bytes = raw_body if raw_body is not None else (json.dumps(payload).encode("utf-8") if payload is not None else b"")
    req_headers: list[tuple[bytes, bytes]] = [(b"host", b"127.0.0.1:8501")]
    if payload is not None and raw_body is None:
        req_headers.append((b"content-type", b"application/json"))
    if headers:
        if isinstance(headers, dict):
            headers = [(str(k).encode("utf-8"), str(v).encode("utf-8")) for k, v in headers.items()]
        # Replace host if caller supplied custom host
        custom_names = {k.lower() for k, _ in headers}
        req_headers = [(k, v) for k, v in req_headers if k.lower() not in custom_names]
        req_headers.extend(headers)

    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": method.upper(),
        "scheme": "http",
        "path": split.path,
        "raw_path": split.path.encode("ascii"),
        "query_string": split.query.encode("ascii"),
        "headers": req_headers,
        "client": (client_host, 54321),
        "server": ("127.0.0.1", 8501),
    }
    sent = False
    status = 500
    resp_headers: dict[str, str] = {}
    resp_body: list[bytes] = []

    async def receive():
        nonlocal sent
        if not sent:
            sent = True
            return {"type": "http.request", "body": body_bytes, "more_body": False}
        return {"type": "http.disconnect"}

    async def send(message):
        nonlocal status
        if message["type"] == "http.response.start":
            status = message["status"]
            for hk, hv in message.get("headers") or []:
                resp_headers[hk.decode("latin1").lower()] = hv.decode("latin1")
        elif message["type"] == "http.response.body":
            resp_body.append(message.get("body", b""))

    asyncio.run(web_app.app(scope, receive, send))
    text = b"".join(resp_body).decode("utf-8", errors="replace")
    return SimpleNamespace(
        status_code=status,
        headers=resp_headers,
        text=text,
        json=lambda: json.loads(text) if text else {},
    )


@pytest.fixture
def sec_env(tmp_path, monkeypatch):
    db_path = tmp_path / "sec_test.db"
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
    monkeypatch.delenv("IDENTITY_SHIELD_ALLOW_PUBLIC_PROXY", raising=False)
    PROXY_RUNTIME.stop()
    try:
        yield {"db": db_path, "tmp": tmp_path}
    finally:
        PROXY_RUNTIME.stop()


def test_web_security_headers_csrf_host_and_token_auth(sec_env, monkeypatch):
    # 1. Local GET / returns HTML with security headers + seamless local meta CSRF token
    r_idx = _raw_asgi("GET", "/")
    assert r_idx.status_code == 200
    assert r_idx.headers["x-content-type-options"] == "nosniff"
    assert r_idx.headers["x-frame-options"] == "DENY"
    assert r_idx.headers["referrer-policy"] == "no-referrer"
    csp = r_idx.headers["content-security-policy"]
    assert "script-src 'self'" in csp
    assert "'unsafe-inline'" not in csp.split("script-src", 1)[1].split(";", 1)[0]
    assert web_app.get_session_token() in r_idx.text

    # 2. Cross-site Origin & Sec-Fetch-Site CSRF blocked (403)
    r_evil_orig = _raw_asgi(
        "POST",
        "/api/db/reset",
        payload={},
        headers=[(b"origin", b"https://evil.example")],
    )
    assert r_evil_orig.status_code == 403

    r_sfs = _raw_asgi(
        "POST",
        "/api/cli/exec",
        payload={"command": "lab doctor"},
        headers=[(b"sec-fetch-site", b"cross-site")],
    )
    assert r_sfs.status_code == 403

    # 3. Same-Origin browser POST missing CSRF token blocked (403)
    r_no_csrf = _raw_asgi(
        "POST",
        "/api/db/reset",
        payload={},
        headers=[(b"origin", b"http://127.0.0.1:8501")],
    )
    assert r_no_csrf.status_code == 403

    # 4. HTML form simple CSRF with text/plain Content-Type blocked (415)
    r_form = _raw_asgi(
        "POST",
        "/api/cli/exec",
        raw_body=b'{"command":"lab doctor"}',
        headers=[(b"content-type", b"text/plain")],
    )
    assert r_form.status_code == 415

    # 5. DNS Rebinding invalid Host header blocked (403)
    r_rebind = _raw_asgi(
        "GET",
        "/api/state",
        headers=[(b"host", b"evil-rebind.com:8501")],
    )
    assert r_rebind.status_code == 403

    # 6. Cache-Control: no-store on API JSON
    r_api = _raw_asgi("GET", "/api/state")
    assert r_api.status_code == 200
    assert r_api.headers["cache-control"] == "no-store"

    # 7. Non-localhost / strict mode requires valid Bearer or X-Identity-Shield-Token
    monkeypatch.setattr(web_app, "NON_LOCAL_BIND", True)
    r_remote_noauth = _raw_asgi("GET", "/api/state", client_host="203.0.113.5")
    assert r_remote_noauth.status_code == 401
    r_remote_idx = _raw_asgi("GET", "/", client_host="203.0.113.5")
    assert web_app.get_session_token() not in r_remote_idx.text

    r_remote_ok = _raw_asgi(
        "GET",
        "/api/state",
        client_host="203.0.113.5",
        headers=[(b"authorization", f"Bearer {web_app.get_session_token()}".encode("utf-8"))],
    )
    assert r_remote_ok.status_code == 200


def test_proxy_ssrf_imds_body_limits_and_mock_status_guard(sec_env):
    # Public bind refused by default
    with pytest.raises(ValueError, match="non-loopback"):
        settings.update_proxy_config({"host": "0.0.0.0"})

    # IMDS upstream refused at config time
    with pytest.raises(ValueError, match="169.254"):
        settings.update_proxy_config({"upstream_url": "http://169.254.169.254/latest/meta-data/"})

    settings.update_proxy_config({"host": "127.0.0.1", "port": 0, "mode": "observe", "upstream_url": ""})
    st = PROXY_RUNTIME.start(db_path=sec_env["db"], host="127.0.0.1", port=0)
    host, port = st["host"], int(st["port"])

    # Forward proxy SSRF to AWS IMDS blocked with 403
    conn = http.client.HTTPConnection(host, port, timeout=10)
    conn.request("GET", "http://169.254.169.254/latest/meta-data/iam/security-credentials/")
    resp = conn.getresponse()
    body = resp.read().decode("utf-8", errors="replace")
    conn.close()
    assert resp.status == 403
    assert "SSRF Guard" in body

    # Forward proxy self-SSRF to Control Plane port blocked with 403
    conn = http.client.HTTPConnection(host, port, timeout=10)
    conn.request("GET", "http://127.0.0.1:8501/api/state")
    resp2 = conn.getresponse()
    resp2.read()
    conn.close()
    assert resp2.status == 403

    # Oversized Content-Length rejected cleanly with 413
    conn = http.client.HTTPConnection(host, port, timeout=10)
    conn.putrequest("POST", "/api/upload")
    conn.putheader("Content-Length", str(5 * 1024 * 1024))
    conn.endheaders()
    resp3 = conn.getresponse()
    resp3.read()
    conn.close()
    assert resp3.status == 413

    # Non-loopback client cannot spoof X-Mock-Status (tested via unit inspect + remote socket check)
    conn = http.client.HTTPConnection(host, port, timeout=10)
    conn.request("GET", "/api/login", headers={"X-Mock-Status": "invalid-status"})
    resp4 = conn.getresponse()
    resp4.read()
    conn.close()
    assert resp4.status == 200


def test_path_traversal_secret_redaction_and_cli_constraints(sec_env):
    # Path traversal blocked in rule deletion, saving, and storage linking
    with pytest.raises(ValueError, match="Invalid rule filename"):
        service.delete_custom_sigma_rule("../enhanced/evil.yml", db_path=sec_env["db"])

    with pytest.raises(ValueError, match="Invalid rule filename"):
        service.save_custom_sigma_rule(filename="../../evil.yml", yaml_content="title: x\ndetection:\n  sel:\n    eventName: x\n  condition: sel", db_path=sec_env["db"])

    with pytest.raises(ValueError, match="traversal"):
        settings.update_storage_config({"db_path": "../escape.db"})

    with pytest.raises(ValueError, match=".db"):
        settings.update_storage_config({"db_path": str(sec_env["tmp"] / "authorized_keys")})

    # CLI Console restricts unsafe subcommands & external --db overrides
    with pytest.raises(ValueError, match="disabled"):
        service.execute_cli_command("ui --host 0.0.0.0", db_path=sec_env["db"])
    with pytest.raises(ValueError, match="Live Proxy"):
        service.execute_cli_command("proxy start", db_path=sec_env["db"])
    with pytest.raises(ValueError, match="--db"):
        service.execute_cli_command("attacks list --db /tmp/other.db", db_path=sec_env["db"])

    # Terraform variable validation blocks invalid variable identifiers / newlines
    with pytest.raises(ValueError, match="Invalid Terraform variable"):
        provision._var_args({"bad-key;rm": "1"})
    with pytest.raises(ValueError, match="control character"):
        provision._var_args({"region": "eu-west-1\nevil"})

    # Secret / password / token redaction in proxy parser
    rec = proxy_parser.parse_request(
        method="POST",
        url_or_path="/api/login?token=supersecret99&name=../../etc/passwd",
        headers={"Content-Type": "application/json", "User-Agent": "curl/8.4.0"},
        body=json.dumps({"username": "alice", "password": "MyPassword!", "api_key": "sk-secret-123"}).encode("utf-8"),
        client_ip="127.0.0.1",
    )
    assert "supersecret99" not in rec["path"]
    assert "supersecret99" not in rec["params_json"]
    assert "MyPassword!" not in rec["params_json"]
    assert "sk-secret-123" not in rec["params_json"]
    assert "MyPassword!" not in rec["event_json"]
    assert "[REDACTED]" in rec["params_json"]
    assert "../../etc/passwd" in rec["params_json"]  # Preserved for traversal detection


def test_audit_security_connect_ssrf_host_preserve_and_redaction(sec_env):
    """Regression coverage for CONNECT UnboundLocalError fix, alternate SSRF notations, signed Host preservation, redaction, and DoS caps."""
    import http.server
    import socket
    import threading
    from identity_shield.clouds.redaction import redact_mapping, redact_query_string, redact_text
    from identity_shield.proxy.server import _ssrf_block_reason

    # 1. Extended SSRF vectors (metadata hostnames, octal/decimal IPv4, CGNAT, IPv4-mapped IPv6)
    for bad_host in ("metadata.google.internal", "0177.0.0.1", "2130706433", "100.64.0.1", "::ffff:169.254.169.254"):
        assert _ssrf_block_reason(bad_host, 80, allow_local_upstream=False, self_port=8888) is not None

    # 2. Query/text redaction scrubs sig=, key=AIza..., X-Amz-Signature=, access_token= while keeping JSON S3 key / status.code
    red_q = redact_query_string("Action=GetObject&sig=secretSig&key=AIzaSyDummyGoogleKey1234567890&X-Amz-Signature=deadbeef")
    assert "secretSig" not in red_q and "AIzaSyDummyGoogleKey1234567890" not in red_q and "deadbeef" not in red_q
    red_t = redact_text("access_token=secretTok123 AIzaSyDummyGoogleKey1234567890 X-Amz-Signature=deadbeef sig=s123")
    assert "secretTok123" not in red_t and "AIzaSyDummyGoogleKey1234567890" not in red_t and "deadbeef" not in red_t
    kept = redact_mapping({"requestParameters": {"bucketName": "b1", "key": "finance/q4.csv"}, "status": {"code": 7}})
    assert kept["requestParameters"]["key"] == "finance/q4.csv" and kept["status"]["code"] == 7

    # 3. Web Control Plane DoS guard (>5 MiB Content-Length -> 413), ::ffff:127.0.0.1 loopback, and lab up guard
    r_big = _raw_asgi(
        "POST",
        "/api/attacks",
        raw_body=b"{}",
        headers=[
            (b"content-type", b"application/json"),
            (b"content-length", str(6 * 1024 * 1024).encode("ascii")),
            (b"x-identity-shield-token", web_app.get_session_token().encode("utf-8")),
        ],
    )
    assert r_big.status_code == 413

    r_v6_local = _raw_asgi("GET", "/api/state", client_host="::ffff:127.0.0.1")
    assert r_v6_local.status_code == 200

    with pytest.raises(ValueError, match="Lab Setup UI"):
        service.execute_cli_command("lab up --yes", db_path=sec_env["db"])

    # 4. Live CONNECT SSRF block & signed Host header preservation on cloud_api forwarding
    seen_host = {}

    class _EchoHandler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            seen_host["host"] = self.headers.get("Host")
            _ = self.rfile.read(int(self.headers.get("Content-Length") or "0"))
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, *args):
            pass

    up_srv = http.server.HTTPServer(("127.0.0.1", 0), _EchoHandler)
    up_port = up_srv.server_address[1]
    threading.Thread(target=up_srv.serve_forever, daemon=True).start()
    try:
        settings.update_proxy_config({"host": "127.0.0.1", "port": 0, "mode": "observe", "upstream_url": f"http://127.0.0.1:{up_port}", "rewrite_host": True})
        st = PROXY_RUNTIME.start(db_path=sec_env["db"], host="127.0.0.1", port=0)
        ph, pp = st["host"], int(st["port"])

        # Live CONNECT to IMDS must return 403 cleanly (not crash with UnboundLocalError)
        with socket.create_connection((ph, pp), timeout=5) as s:
            s.sendall(b"CONNECT 169.254.169.254:443 HTTP/1.1\r\nHost: 169.254.169.254:443\r\n\r\n")
            resp_txt = s.recv(1024).decode("utf-8", errors="replace")
        assert "403" in resp_txt

        # Signed AWS API request keeps signed Host header across proxy
        conn = http.client.HTTPConnection(ph, pp, timeout=5)
        conn.request(
            "POST",
            "/",
            body=b"Action=GetCallerIdentity",
            headers={
                "Host": "sts.us-east-1.amazonaws.com",
                "Authorization": "AWS4-HMAC-SHA256 Credential=AKIABUILDER01/20261127/us-east-1/sts/aws4_request, SignedHeaders=host, Signature=abcd",
            },
        )
        r_aws = conn.getresponse()
        r_aws.read()
        conn.close()
        assert r_aws.status == 200
        assert seen_host.get("host") == "sts.us-east-1.amazonaws.com"
    finally:
        PROXY_RUNTIME.stop()
        up_srv.shutdown()
        up_srv.server_close()


def test_cli_bridge_subcommands_ipv6_connect_and_ssrf_fields(sec_env):
    import socket
    from identity_shield.db.connection import connect

    # 1. Web CLI command bridge succeeds cleanly for non-DB and DB subcommands without arg injection errors
    for cmd in ("lab doctor", "proxy config --mode observe", "attacks list", "logs events --limit 5"):
        res = service.execute_cli_command(cmd, db_path=sec_env["db"])
        assert res["returncode"] == 0, f"{cmd} failed: {res['stderr']}"

    for bad_cmd in ("attacks list; whoami", "attacks list && whoami", "attacks list | findstr x"):
        with pytest.raises(ValueError, match="Shell chaining"):
            service.execute_cli_command(bad_cmd, db_path=sec_env["db"])

    # 2. Bracketed IPv6 CONNECT parsing preserves full IPv6 host + port
    parsed_v6 = proxy_parser.parse_connect_tunnel(authority="[::ffff:169.254.169.254]:443", headers={})
    assert parsed_v6["target_host"] == "::ffff:169.254.169.254"
    assert json.loads(parsed_v6["params_json"])["port"] == "443"

    # 3. Live CONNECT to bracketed IPv6 IMDS is blocked (403) and HTTP SSRF block records policy fields
    settings.update_proxy_config({"host": "127.0.0.1", "port": 0, "mode": "observe", "upstream_url": ""})
    st = PROXY_RUNTIME.start(db_path=sec_env["db"], host="127.0.0.1", port=0)
    ph, pp = st["host"], int(st["port"])
    try:
        with socket.create_connection((ph, pp), timeout=5) as s:
            s.sendall(b"CONNECT [::ffff:169.254.169.254]:443 HTTP/1.1\r\nHost: [::ffff:169.254.169.254]:443\r\n\r\n")
            resp_v6 = s.recv(1024).decode("utf-8", errors="replace")
        assert "403" in resp_v6

        conn = http.client.HTTPConnection(ph, pp, timeout=5)
        conn.request("GET", "http://169.254.169.254/latest/meta-data/", headers={"Host": "169.254.169.254"})
        r_imds = conn.getresponse()
        r_imds.read()
        conn.close()
        assert r_imds.status == 403

        db = connect(sec_env["db"])
        try:
            row = db.execute(
                "SELECT action_taken, policy_decision, policy_reason FROM proxy_event WHERE target_host = '169.254.169.254' ORDER BY rowid DESC LIMIT 1"
            ).fetchone()
            assert row is not None
            assert row["action_taken"] == "blocked"
            assert row["policy_decision"] == "blocked"
            assert "SSRF guard" in str(row["policy_reason"] or "")
        finally:
            db.close()
    finally:
        PROXY_RUNTIME.stop()
