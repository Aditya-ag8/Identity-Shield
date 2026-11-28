"""Inline Live Security Proxy Server (`proxy/server.py`).

Intercepts traffic between clients/SDKs and Cloud Web Apps or AWS APIs:
1. Evaluates each request against static Sigma rules + Dynamic Behavioral rules.
2. Persists telemetry to SQLite (`proxy_event`, `dynamic_alert`, `principal_profile`).
3. Streams events live to UI subscribers via SSE.
4. Forwards clean/observed requests upstream (or responds locally when no upstream
   is configured) and blocks with HTTP 403 when `mode == 'block'` and
   `risk_score >= block_risk_threshold`.
"""

from __future__ import annotations

import http.client
import ipaddress
import json
import os
import queue
import re
import select
import socket
import ssl
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Iterator, Mapping
from urllib.parse import urlsplit

from identity_shield import settings
from identity_shield.db.connection import connect
from identity_shield.db.init import ensure_tables
from identity_shield.detect import dynamic
from identity_shield.proxy import parser as proxy_parser
from identity_shield.proxy.tls import TlsCertAuthority


MAX_PROXY_BODY_BYTES = 2 * 1024 * 1024  # 2 MiB inline inspection cap
_ALLOWED_MOCK_STATUSES = {200, 201, 204, 400, 401, 403, 404, 500}
_CGNAT_NET = ipaddress.ip_network("100.64.0.0/10")
_AWS_IPV6_IMDS_NET = ipaddress.ip_network("fd00:ec2::/32")
_BLOCKED_METADATA_HOSTS = frozenset(
    {
        "169.254.169.254",
        "169.254.170.2",
        "100.100.100.200",
        "fd00:ec2::254",
        "metadata",
        "metadata.goog",
        "metadata.google.internal",
        "instance-data",
    }
)
_ALT_IPV4_RE = re.compile(r"^[0-9a-fA-FxX.]+$")


def _parse_ip_literal(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        ip = ipaddress.ip_address(host)
        return getattr(ip, "ipv4_mapped", None) or ip
    except ValueError:
        pass
    if _ALT_IPV4_RE.fullmatch(host):
        try:
            packed = socket.inet_aton(host)
            return ipaddress.IPv4Address(packed)
        except OSError:
            pass
    return None


def _ssrf_block_reason(
    host: str | None,
    port: int | None,
    *,
    allow_local_upstream: bool = False,
    self_port: int | None = None,
) -> str | None:
    """Block SSRF against cloud IMDS, metadata hostnames, alternate IP notations, and internal ports."""
    clean_host = str(host or "").strip().strip("[]").rstrip(".").lower()
    if not clean_host:
        return "missing upstream host"

    if clean_host in _BLOCKED_METADATA_HOSTS or clean_host.endswith(".metadata.google.internal"):
        return f"blocked cloud metadata host {clean_host}"
    if not allow_local_upstream and (
        clean_host in {"localhost", "localhost.localdomain"}
        or clean_host.endswith((".internal", ".local", ".localhost"))
    ):
        return f"blocked internal hostname SSRF target {clean_host}"

    literal_ip = _parse_ip_literal(clean_host)
    if literal_ip is not None:
        ips = [literal_ip]
    else:
        try:
            infos = socket.getaddrinfo(clean_host, port or 80, type=socket.SOCK_STREAM)
            ips = []
            for item in infos:
                raw_ip = ipaddress.ip_address(item[4][0].split("%", 1)[0])
                ips.append(getattr(raw_ip, "ipv4_mapped", None) or raw_ip)
        except Exception:
            ips = []

    for ip in ips:
        if ip.is_link_local or ip.is_multicast or ip.is_unspecified or ip in _AWS_IPV6_IMDS_NET or ip in _CGNAT_NET:
            return f"blocked link-local/reserved/metadata target {ip}"
        if not allow_local_upstream and (ip.is_private or ip.is_loopback or ip.is_reserved):
            return f"blocked internal/private SSRF target {ip}"
        if allow_local_upstream and ip.is_loopback:
            if port in {8501, self_port}:
                return f"blocked self-SSRF against local control-plane/proxy port {port}"
    return None


class _ProxyHTTPServer(ThreadingHTTPServer):
    allow_reuse_address = os.name != "nt"
    daemon_threads = True

    def __init__(self, server_address, RequestHandlerClass, runtime: "LiveSecurityProxy"):
        self.runtime = runtime
        super().__init__(server_address, RequestHandlerClass)


class _ProxyHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        return  # Keep stdout clean; events go to SQLite + SSE stream

    def do_CONNECT(self) -> None:
        self.server.runtime.handle_connect(self)  # type: ignore[attr-defined]

    def _handle_http(self) -> None:
        self.server.runtime.handle_http(self)  # type: ignore[attr-defined]

    do_GET = _handle_http
    do_POST = _handle_http
    do_PUT = _handle_http
    do_DELETE = _handle_http
    do_PATCH = _handle_http
    do_HEAD = _handle_http
    do_OPTIONS = _handle_http


class LiveSecurityProxy:
    """Thread-safe lifecycle & streaming controller for the live proxy."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._server: _ProxyHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._db_path: Path | None = None
        self._subscribers: list[queue.Queue[dict[str, Any] | None]] = []
        self._started_at: str | None = None

    def is_running(self) -> bool:
        with self._lock:
            return self._server is not None

    def address(self) -> tuple[str, int] | None:
        with self._lock:
            if self._server is None:
                return None
            host, port = self._server.server_address[:2]
            return str(host), int(port)

    def start(
        self,
        *,
        db_path: Path | None = None,
        host: str | None = None,
        port: int | None = None,
        persist_config: bool = True,
    ) -> dict[str, Any]:
        with self._lock:
            if self._server is not None:
                return self.status_unlocked()
            cfg = settings.get_proxy_config()
            bind_host = host or cfg.host or "127.0.0.1"
            if bind_host.lower() not in {"127.0.0.1", "localhost", "::1"} and os.environ.get("IDENTITY_SHIELD_ALLOW_PUBLIC_PROXY") != "1":
                raise ValueError(
                    f"Refusing non-loopback proxy bind host {bind_host!r} without IDENTITY_SHIELD_ALLOW_PUBLIC_PROXY=1"
                )
            bind_port = int(cfg.port if port is None else port)
            self._db_path = db_path
            server = _ProxyHTTPServer((bind_host, bind_port), _ProxyHandler, self)
            self._server = server
            self._started_at = dynamic._utc_now()
            actual_port = int(server.server_address[1])
            if persist_config:
                settings.update_proxy_config({"host": bind_host, "port": actual_port})

            thread = threading.Thread(target=server.serve_forever, daemon=True)
            self._thread = thread
            thread.start()
            return self.status_unlocked()

    def stop(self) -> dict[str, Any]:
        with self._lock:
            server = self._server
            self._server = None
            self._thread = None
            self._started_at = None
            for q in self._subscribers:
                q.put(None)
        if server is not None:
            server.shutdown()
            server.server_close()
        return self.status()

    def status_unlocked(self) -> dict[str, Any]:
        cfg = settings.get_proxy_config()
        addr = self._server.server_address[:2] if self._server else (cfg.host, cfg.port)
        tls_info = TlsCertAuthority().status(
            enabled=cfg.tls_intercept_enabled,
            passthrough_hosts=cfg.tls_passthrough_hosts,
        )
        return {
            "running": self._server is not None,
            "host": str(addr[0]),
            "port": int(addr[1]),
            "listen_url": f"http://{addr[0]}:{int(addr[1])}",
            "started_at": self._started_at,
            "tls": tls_info,
            "config": cfg.to_dict(),
        }

    def status(self) -> dict[str, Any]:
        with self._lock:
            return self.status_unlocked()

    def subscribe(self) -> Iterator[str]:
        q: queue.Queue[dict[str, Any] | None] = queue.Queue()
        with self._lock:
            self._subscribers.append(q)
        try:
            yield f"data: {json.dumps({'type': 'status', 'status': self.status()})}\n\n"
            while True:
                try:
                    item = q.get(timeout=15)
                except queue.Empty:
                    yield ": keepalive\n\n"
                    continue
                if item is None:
                    yield f"data: {json.dumps({'type': 'closed'})}\n\n"
                    break
                yield f"data: {json.dumps({'type': 'event', 'event': item})}\n\n"
        finally:
            with self._lock:
                if q in self._subscribers:
                    self._subscribers.remove(q)

    def _publish(self, event_row: dict[str, Any]) -> None:
        with self._lock:
            subs = list(self._subscribers)
        for q in subs:
            q.put(event_row)

    def _open_conn(self):
        from identity_shield import service

        path = service.ensure_database(self._db_path)
        conn = connect(path)
        ensure_tables(conn)
        return conn

    def _persist_and_publish(self, record: dict[str, Any], eval_res: dict[str, Any]) -> dict[str, Any]:
        conn = self._open_conn()
        cloud_provider = str(record.get("cloud_provider") or eval_res.get("cloud_provider") or "unknown")
        account_scope = str(record.get("account_scope") or eval_res.get("account_scope") or "")
        traffic_type = str(record.get("traffic_type") or eval_res.get("traffic_type") or "http_app")
        policy_decision = str(eval_res.get("policy_decision") or eval_res["action_taken"])
        policy_reason = str(eval_res.get("policy_reason") or "")
        cfg = settings.get_proxy_config()
        try:
            conn.execute(
                """
                INSERT INTO proxy_event (
                    proxy_event_id, timestamp, cloud_provider, account_scope,
                    traffic_type, traffic_kind, classification_confidence, classification_reason,
                    mode, action_taken, policy_decision, policy_reason,
                    client_ip, principal, method, target_host, path, service,
                    operation, user_agent, aws_region, params_json, status_code,
                    latency_ms, risk_score, matched_static, matched_dynamic, event_json
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(proxy_event_id) DO UPDATE SET
                    status_code=excluded.status_code,
                    latency_ms=excluded.latency_ms,
                    action_taken=excluded.action_taken,
                    policy_decision=excluded.policy_decision,
                    policy_reason=excluded.policy_reason
                """,
                (
                    record["proxy_event_id"],
                    record["timestamp"],
                    cloud_provider,
                    account_scope,
                    traffic_type,
                    record["traffic_kind"],
                    str(record.get("classification_confidence") or "high"),
                    str(record.get("classification_reason") or ""),
                    record["mode"],
                    eval_res["action_taken"],
                    policy_decision,
                    policy_reason,
                    record["client_ip"],
                    record["principal"],
                    record["method"],
                    record["target_host"],
                    record["path"],
                    record["service"],
                    record["operation"],
                    record["user_agent"],
                    record["aws_region"],
                    record["params_json"],
                    record.get("status_code"),
                    record.get("latency_ms"),
                    eval_res["risk_score"],
                    json.dumps(eval_res["matched_static"]),
                    json.dumps(eval_res["matched_dynamic"]),
                    record["event_json"],
                ),
            )
            all_hits: list[dict[str, Any]] = []
            for s in eval_res["matched_static"]:
                all_hits.append(
                    {
                        "rule_id": s["rule_id"],
                        "rule_name": s["title"],
                        "severity": s["level"],
                        "summary": f"Static rule matched on {record['operation']}",
                        "evidence": {"technique_id": s.get("technique_id"), "cloud_provider": cloud_provider},
                    }
                )
            all_hits.extend(eval_res["matched_dynamic"])
            if all_hits:
                dynamic.record_dynamic_alerts(
                    conn,
                    source="proxy",
                    ref_id=record["proxy_event_id"],
                    timestamp=record["timestamp"],
                    principal=str(record["principal"]),
                    hits=all_hits,
                    action_taken=eval_res["action_taken"],
                    cloud_provider=cloud_provider,
                    account_scope=account_scope,
                    ruleset_version=cfg.ruleset_version,
                )
            max_keep = int(settings.get_storage_config().max_proxy_events or 0)
            if max_keep > 0:
                total_rows = conn.execute("SELECT COUNT(*) FROM proxy_event").fetchone()[0]
                if total_rows > max_keep:
                    excess = total_rows - max_keep
                    conn.execute(
                        "DELETE FROM proxy_event WHERE rowid IN (SELECT rowid FROM proxy_event ORDER BY timestamp ASC, rowid ASC LIMIT ?)",
                        (excess,),
                    )
            conn.commit()
        finally:
            conn.close()

        summary_row = {
            "proxy_event_id": record["proxy_event_id"],
            "timestamp": record["timestamp"],
            "cloud_provider": cloud_provider,
            "account_scope": account_scope,
            "traffic_type": traffic_type,
            "traffic_kind": record["traffic_kind"],
            "classification_confidence": record.get("classification_confidence") or "high",
            "classification_reason": record.get("classification_reason") or "",
            "mode": record["mode"],
            "action_taken": eval_res["action_taken"],
            "policy_decision": policy_decision,
            "policy_reason": policy_reason,
            "client_ip": record["client_ip"],
            "principal": record["principal"],
            "method": record["method"],
            "target_host": record["target_host"],
            "path": record["path"],
            "service": record["service"],
            "operation": record["operation"],
            "user_agent": record["user_agent"],
            "aws_region": record["aws_region"],
            "status_code": record.get("status_code"),
            "latency_ms": record.get("latency_ms"),
            "risk_score": eval_res["risk_score"],
            "matched_static": eval_res["matched_static"],
            "matched_dynamic": eval_res["matched_dynamic"],
        }
        self._publish(summary_row)
        return summary_row

    def inspect_synthetic_or_direct(self, record: dict[str, Any]) -> dict[str, Any]:
        """Run evaluation and persistence for a pre-parsed proxy record."""
        cfg = settings.get_proxy_config()
        record = dict(record)
        record["mode"] = cfg.mode
        conn = self._open_conn()
        try:
            eval_res = dynamic.evaluate_live_event(
                conn,
                record,
                ruleset_version=cfg.ruleset_version,
                mode=cfg.mode,
                block_threshold=cfg.block_risk_threshold,
                learn_baseline=cfg.learn_baseline,
                provider_policies=cfg.provider_policies,
                inspection_capable=(record.get("traffic_type") != "connect_tunnel"),
            )
            conn.commit()
        finally:
            conn.close()
        return self._persist_and_publish(record, eval_res)

    def handle_http(self, handler: _ProxyHandler) -> None:
        started = time.perf_counter()
        raw_cl = handler.headers.get("Content-Length")
        try:
            content_len = int(raw_cl) if raw_cl is not None else 0
        except ValueError:
            handler.send_error(400, "Invalid Content-Length")
            return
        if content_len < 0:
            handler.send_error(400, "Negative Content-Length")
            return
        if content_len > MAX_PROXY_BODY_BYTES:
            handler.send_error(413, "Request payload exceeds 2 MiB inspection limit")
            return
        body = handler.rfile.read(content_len) if content_len > 0 else b""
        client_ip = handler.client_address[0] if handler.client_address else "127.0.0.1"
        cfg = settings.get_proxy_config()

        headers_dict = {k: v for k, v in handler.headers.items()}
        # Determine forward vs reverse target
        raw_target = handler.path
        is_forward_url = raw_target.startswith(("http://", "https://"))
        upstream_url = ""
        if is_forward_url:
            upstream_url = raw_target
        elif cfg.upstream_url:
            base = cfg.upstream_url.rstrip("/")
            rel = raw_target if raw_target.startswith("/") else f"/{raw_target}"
            upstream_url = f"{base}{rel}"

        parsed_upstream = urlsplit(upstream_url) if upstream_url else None
        record = proxy_parser.parse_request(
            method=handler.command,
            url_or_path=upstream_url or raw_target,
            headers=headers_dict,
            body=body,
            client_ip=client_ip,
            target_host_override=parsed_upstream.netloc if parsed_upstream and parsed_upstream.netloc else None,
        )
        record["mode"] = cfg.mode

        # SSRF guard BEFORE forwarding (blocks AWS IMDS 169.254.169.254, private IPs, control-plane self-SSRF)
        if parsed_upstream and parsed_upstream.scheme in {"http", "https"}:
            addr = self.address()
            up_port = parsed_upstream.port or (443 if parsed_upstream.scheme == "https" else 80)
            ssrf_err = _ssrf_block_reason(
                parsed_upstream.hostname,
                up_port,
                allow_local_upstream=not is_forward_url,
                self_port=addr[1] if addr else None,
            )
            if ssrf_err:
                record["status_code"] = 403
                record["latency_ms"] = round((time.perf_counter() - started) * 1000, 2)
                ssrf_eval = {
                    "matched_static": [],
                    "matched_dynamic": [
                        {
                            "rule_id": "PROXY-SSRF-001",
                            "rule_name": "Proxy SSRF / Metadata Guard",
                            "kind": "app_anomaly",
                            "severity": "critical",
                            "summary": ssrf_err,
                            "evidence": {"target": upstream_url},
                        }
                    ],
                    "risk_score": 100.0,
                    "action_taken": "blocked",
                    "policy_decision": "blocked",
                    "policy_reason": f"SSRF guard blocked HTTP forwarding ({ssrf_err}).",
                }
                self._persist_and_publish(record, ssrf_eval)
                payload = json.dumps(
                    {
                        "blocked_by": "Identity Shield Live Proxy (SSRF Guard)",
                        "reason": ssrf_err,
                        "proxy_event_id": record["proxy_event_id"],
                    },
                    indent=2,
                ).encode("utf-8")
                handler.send_response(403, "Forbidden")
                handler.send_header("Content-Type", "application/json")
                handler.send_header("Content-Length", str(len(payload)))
                handler.send_header("X-Identity-Shield-Action", "blocked")
                handler.end_headers()
                handler.wfile.write(payload)
                return

        # Evaluate BEFORE forwarding so we can block high-risk traffic inline
        conn = self._open_conn()
        try:
            eval_res = dynamic.evaluate_live_event(
                conn,
                record,
                ruleset_version=cfg.ruleset_version,
                mode=cfg.mode,
                block_threshold=cfg.block_risk_threshold,
                learn_baseline=cfg.learn_baseline,
                provider_policies=cfg.provider_policies,
                inspection_capable=True,
            )
            conn.commit()
        finally:
            conn.close()

        if eval_res["action_taken"] == "blocked":
            record["status_code"] = 403
            record["latency_ms"] = round((time.perf_counter() - started) * 1000, 2)
            self._persist_and_publish(record, eval_res)
            payload = json.dumps(
                {
                    "blocked_by": "Identity Shield Live Proxy",
                    "proxy_event_id": record["proxy_event_id"],
                    "risk_score": eval_res["risk_score"],
                    "matched_static": eval_res["matched_static"],
                    "matched_dynamic": eval_res["matched_dynamic"],
                },
                indent=2,
            ).encode("utf-8")
            handler.send_response(403, "Forbidden")
            handler.send_header("Content-Type", "application/json")
            handler.send_header("Content-Length", str(len(payload)))
            handler.send_header("X-Identity-Shield-Action", "blocked")
            handler.end_headers()
            handler.wfile.write(payload)
            return

        # Forward to upstream if configured or absolute HTTP proxy URL supplied
        if upstream_url and parsed_upstream and parsed_upstream.scheme in {"http", "https"}:
            # Preserve client Host header on forward proxy calls & signed cloud_api requests (e.g. AWS SigV4)
            eff_rewrite_host = bool(cfg.rewrite_host) and (not is_forward_url) and (record.get("traffic_type") != "cloud_api")
            status, resp_headers, resp_body = self._forward_http(
                method=handler.command,
                parsed_url=parsed_upstream,
                headers=headers_dict,
                body=body,
                rewrite_host=eff_rewrite_host,
            )
            record["status_code"] = status
            record["latency_ms"] = round((time.perf_counter() - started) * 1000, 2)
            self._persist_and_publish(record, eval_res)

            handler.send_response(status)
            for hk, hv in resp_headers.items():
                if hk.lower() in {"transfer-encoding", "connection", "content-length"}:
                    continue
                handler.send_header(hk, hv)
            handler.send_header("Content-Length", str(len(resp_body)))
            handler.send_header("X-Identity-Shield-Action", eval_res["action_taken"])
            handler.send_header("X-Identity-Shield-Risk", str(eval_res["risk_score"]))
            handler.end_headers()
            if handler.command.upper() != "HEAD":
                handler.wfile.write(resp_body)
            return

        # Standalone capture/echo response when no upstream target is configured
        forced_status = 200
        if client_ip in {"127.0.0.1", "::1", "::ffff:127.0.0.1"} and headers_dict.get("X-Mock-Status"):
            try:
                cand = int(headers_dict["X-Mock-Status"])
                if cand in _ALLOWED_MOCK_STATUSES:
                    forced_status = cand
            except ValueError:
                forced_status = 200
        record["status_code"] = forced_status
        record["latency_ms"] = round((time.perf_counter() - started) * 1000, 2)
        self._persist_and_publish(record, eval_res)

        payload = json.dumps(
            {
                "ok": True,
                "proxy_mode": cfg.mode,
                "action_taken": eval_res["action_taken"],
                "risk_score": eval_res["risk_score"],
                "service": record["service"],
                "operation": record["operation"],
                "matched_static": [m["rule_id"] for m in eval_res["matched_static"]],
                "matched_dynamic": [m["rule_id"] for m in eval_res["matched_dynamic"]],
            },
            indent=2,
        ).encode("utf-8")
        handler.send_response(forced_status)
        handler.send_header("Content-Type", "application/json")
        handler.send_header("Content-Length", str(len(payload)))
        handler.send_header("X-Identity-Shield-Action", eval_res["action_taken"])
        handler.send_header("X-Identity-Shield-Risk", str(eval_res["risk_score"]))
        handler.end_headers()
        if handler.command.upper() != "HEAD":
            handler.wfile.write(payload)

    def _forward_http(
        self,
        *,
        method: str,
        parsed_url,
        headers: Mapping[str, str],
        body: bytes,
        rewrite_host: bool,
    ) -> tuple[int, dict[str, str], bytes]:
        host = parsed_url.hostname or "127.0.0.1"
        port = parsed_url.port or (443 if parsed_url.scheme == "https" else 80)
        path = parsed_url.path or "/"
        if parsed_url.query:
            path = f"{path}?{parsed_url.query}"

        out_headers = {}
        for k, v in headers.items():
            kl = k.lower()
            if kl in {"proxy-connection", "connection", "content-length", "x-mock-status"}:
                continue
            if kl == "host" and rewrite_host:
                out_headers[k] = parsed_url.netloc
            else:
                out_headers[k] = v
        if rewrite_host:
            out_headers["Host"] = parsed_url.netloc

        try:
            if parsed_url.scheme == "https":
                conn = http.client.HTTPSConnection(host, port, timeout=15, context=ssl.create_default_context())
            else:
                conn = http.client.HTTPConnection(host, port, timeout=15)
            conn.request(method, path, body=body or None, headers=out_headers)
            resp = conn.getresponse()
            resp_body = resp.read()
            resp_headers = {k: v for k, v in resp.getheaders()}
            status = resp.status
            conn.close()
            return status, resp_headers, resp_body
        except Exception as exc:  # noqa: BLE001
            err_body = json.dumps({"proxy_upstream_error": f"{type(exc).__name__}: {exc}"}).encode("utf-8")
            return 502, {"Content-Type": "application/json"}, err_body

    def handle_connect(self, handler: _ProxyHandler) -> None:
        started = time.perf_counter()
        client_ip = handler.client_address[0] if handler.client_address else "127.0.0.1"
        cfg = settings.get_proxy_config()
        record = proxy_parser.parse_connect_tunnel(
            authority=handler.path,
            headers={k: v for k, v in handler.headers.items()},
            client_ip=client_ip,
        )
        record["mode"] = cfg.mode

        host, _, port_str = handler.path.partition(":")
        if host.startswith("[") and "]" in handler.path:
            bracket_host, _, rest = handler.path.partition("]")
            host = bracket_host[1:]
            port_str = rest.lstrip(":")
        try:
            port = int(port_str or 443)
        except ValueError:
            handler.send_error(400, "Invalid CONNECT authority port")
            return
        if port < 1 or port > 65535:
            handler.send_error(400, "Invalid CONNECT authority port")
            return

        addr = self.address()
        ssrf_err = _ssrf_block_reason(
            host,
            port,
            allow_local_upstream=False,
            self_port=addr[1] if addr else None,
        )

        if ssrf_err:
            record["status_code"] = 403
            record["latency_ms"] = round((time.perf_counter() - started) * 1000, 2)
            ssrf_eval = {
                "matched_static": [],
                "matched_dynamic": [
                    {
                        "rule_id": "PROXY-SSRF-001",
                        "rule_name": "Proxy SSRF / Metadata Guard",
                        "kind": "app_anomaly",
                        "severity": "critical",
                        "summary": ssrf_err,
                        "evidence": {"target": handler.path},
                    }
                ],
                "risk_score": 100.0,
                "action_taken": "blocked",
                "policy_decision": "blocked",
                "policy_reason": f"SSRF guard blocked CONNECT tunnel ({ssrf_err}).",
            }
            self._persist_and_publish(record, ssrf_eval)
            handler.send_error(403, f"Blocked by Identity Shield Live Proxy ({ssrf_err})")
            return

        conn = self._open_conn()
        try:
            eval_res = dynamic.evaluate_live_event(
                conn,
                record,
                ruleset_version=cfg.ruleset_version,
                mode=cfg.mode,
                block_threshold=cfg.block_risk_threshold,
                learn_baseline=False,
                provider_policies=cfg.provider_policies,
                inspection_capable=False,
                explicit_tunnel_block=False,
            )
            conn.commit()
        finally:
            conn.close()

        if eval_res["action_taken"] == "blocked":
            record["status_code"] = 403
            record["latency_ms"] = round((time.perf_counter() - started) * 1000, 2)
            self._persist_and_publish(record, eval_res)
            handler.send_error(403, "Blocked by Identity Shield Live Proxy")
            return

        try:
            upstream = socket.create_connection((host, port), timeout=10)
        except Exception as exc:  # noqa: BLE001
            record["status_code"] = 502
            record["latency_ms"] = round((time.perf_counter() - started) * 1000, 2)
            self._persist_and_publish(record, eval_res)
            handler.send_error(502, f"Tunnel failed: {exc}")
            return

        record["status_code"] = 200
        record["latency_ms"] = round((time.perf_counter() - started) * 1000, 2)
        self._persist_and_publish(record, eval_res)

        handler.send_response(200, "Connection Established")
        handler.end_headers()

        sockets = [handler.connection, upstream]
        try:
            while True:
                readable, _, _ = select.select(sockets, [], [], 30)
                if not readable:
                    break
                for sock in readable:
                    other = upstream if sock is handler.connection else handler.connection
                    data = sock.recv(8192)
                    if not data:
                        return
                    other.sendall(data)
        except OSError:
            pass
        finally:
            upstream.close()


PROXY_RUNTIME = LiveSecurityProxy()
