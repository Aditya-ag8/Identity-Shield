"""Starlette REST & SSE backend for the Identity Shield Web Control Plane."""

from __future__ import annotations

import asyncio
import hmac
import json
import os
import secrets
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from starlette.applications import Starlette
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, Response, StreamingResponse
from starlette.routing import Mount, Route
from starlette.staticfiles import StaticFiles

from identity_shield import service, settings
from identity_shield.proxy.server import PROXY_RUNTIME

STATIC_DIR = Path(__file__).resolve().parent / "static"

SESSION_TOKEN: str = os.environ.get("IDENTITY_SHIELD_API_TOKEN") or secrets.token_urlsafe(24)
NON_LOCAL_BIND: bool = False
_LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1", "::ffff:127.0.0.1", "testserver"}
MAX_WEB_BODY_BYTES = 5 * 1024 * 1024  # 5 MiB cap for Control Plane JSON payloads


class _PayloadTooLarge(ValueError):
    """Raised when a Control Plane JSON request exceeds MAX_WEB_BODY_BYTES."""


def get_session_token() -> str:
    return os.environ.get("IDENTITY_SHIELD_API_TOKEN") or SESSION_TOKEN


def is_strict_auth_required() -> bool:
    return NON_LOCAL_BIND or os.environ.get("IDENTITY_SHIELD_REQUIRE_TOKEN") == "1"


def _host_without_port(raw_host: str) -> str:
    h = (raw_host or "").strip().lower()
    if h.startswith("["):
        return h.split("]", 1)[0][1:]
    return h.split(":", 1)[0]


def _provided_token(request: Request) -> str:
    auth = request.headers.get("authorization") or ""
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    hdr = (request.headers.get("x-identity-shield-token") or "").strip()
    if hdr:
        return hdr
    return (request.query_params.get("token") or "").strip()


class SecurityMiddleware(BaseHTTPMiddleware):
    """Enforces host validation, CSRF protection, optional token auth, and security headers."""

    async def dispatch(self, request: Request, call_next):
        strict = is_strict_auth_required()
        client_host = (request.client.host if request.client else "127.0.0.1") or "127.0.0.1"
        is_loopback_client = client_host in {"127.0.0.1", "::1", "::ffff:127.0.0.1", "testclient"}

        raw_cl = request.headers.get("content-length")
        if raw_cl:
            try:
                if int(raw_cl) > MAX_WEB_BODY_BYTES:
                    return JSONResponse({"error": "Request body exceeds 5 MiB limit"}, status_code=413)
            except ValueError:
                return JSONResponse({"error": "Invalid Content-Length header"}, status_code=400)

        req_host = _host_without_port(request.headers.get("host") or "")
        if not strict and req_host and req_host not in _LOOPBACK_HOSTS:
            return JSONResponse({"error": f"Blocked invalid Host header {req_host!r}"}, status_code=403)

        sec_fetch = (request.headers.get("sec-fetch-site") or "").lower()
        if sec_fetch == "cross-site":
            return JSONResponse({"error": "Blocked cross-site request"}, status_code=403)

        origin = request.headers.get("origin") or ""
        if origin:
            orig_parsed = urlsplit(origin)
            hdr_host = (request.headers.get("host") or "").lower()
            if orig_parsed.netloc.lower() != hdr_host:
                return JSONResponse({"error": "Blocked CSRF Origin mismatch"}, status_code=403)

        path = request.url.path
        if path.startswith("/api/") and path != "/api/auth/verify":
            expected = get_session_token()
            provided = _provided_token(request)
            token_ok = bool(provided) and hmac.compare_digest(provided, expected)

            # Remote clients or non-localhost bind always require valid bearer/session token
            if strict or not is_loopback_client:
                if not token_ok:
                    return JSONResponse({"error": "Authentication required"}, status_code=401)

            # Browser requests (sending Origin) or state-changing API calls must satisfy CSRF/JSON rules
            if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
                if origin and not token_ok:
                    return JSONResponse({"error": "Invalid or missing CSRF token"}, status_code=403)
                ctype = (request.headers.get("content-type") or "").lower()
                if ctype and "application/json" not in ctype:
                    return JSONResponse({"error": "Content-Type must be application/json"}, status_code=415)

        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; connect-src 'self'; object-src 'none'; "
            "frame-ancestors 'none'; base-uri 'self'"
        )
        if path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
        return response


def _json_error(exc: Exception, status_code: int = 400) -> JSONResponse:
    code = 413 if isinstance(exc, _PayloadTooLarge) else status_code
    return JSONResponse(
        {"error": f"{type(exc).__name__}: {exc}"},
        status_code=code,
    )


async def _body(request: Request) -> dict[str, Any]:
    raw = await request.body()
    if len(raw) > MAX_WEB_BODY_BYTES:
        raise _PayloadTooLarge(f"Request payload exceeds {MAX_WEB_BODY_BYTES // (1024 * 1024)} MiB limit")
    if not raw:
        return {}
    return json.loads(raw.decode("utf-8"))


async def index(request: Request) -> HTMLResponse:
    html = (STATIC_DIR / "index.html").read_text(encoding="utf-8")
    client_host = (request.client.host if request.client else "127.0.0.1") or "127.0.0.1"
    loopback_req = client_host in {"127.0.0.1", "::1", "::ffff:127.0.0.1", "testclient"}
    # Embed CSRF/session token cleanly into <meta> only for seamless loopback UI launches
    injected_token = "" if (is_strict_auth_required() or not loopback_req) else get_session_token()
    meta_tag = f'<meta name="is-token" content="{injected_token}" />'
    html = html.replace("</head>", f"  {meta_tag}\n</head>", 1)
    return HTMLResponse(html)


async def api_auth_verify(request: Request) -> JSONResponse:
    try:
        payload = await _body(request)
        tok = str(payload.get("token") or _provided_token(request) or "").strip()
        if tok and hmac.compare_digest(tok, get_session_token()):
            return JSONResponse({"authenticated": True})
        return JSONResponse({"authenticated": False, "error": "Invalid token"}, status_code=401)
    except Exception as exc:  # noqa: BLE001
        return _json_error(exc, 400)


async def api_state(_request: Request) -> JSONResponse:
    db = service.db_health()
    cfg = settings.load_workspace_config()
    return JSONResponse(
        {
            "db": db,
            "connection": settings.RUNTIME_SESSION.status(),
            "thresholds": cfg["thresholds"],
            "resources": cfg["resources"],
            "proxy": cfg["proxy"],
            "storage": cfg["storage"],
            "proxy_status": service.proxy_status(),
            "profiles": service.list_local_aws_profiles(),
            "jobs": service.JOBS.list_jobs(),
        }
    )


async def api_profiles(_request: Request) -> JSONResponse:
    return JSONResponse({"profiles": service.list_local_aws_profiles()})


async def api_templates(_request: Request) -> JSONResponse:
    return JSONResponse({"templates": service.customer_onboarding_templates()})


async def api_connect(request: Request) -> JSONResponse:
    try:
        payload = await _body(request)
        res = await asyncio.to_thread(service.connect_aws, payload)
        return JSONResponse(res)
    except Exception as exc:  # noqa: BLE001
        return _json_error(exc, 400)


async def api_disconnect(_request: Request) -> JSONResponse:
    return JSONResponse(service.disconnect_aws())


async def api_lab_doctor(_request: Request) -> JSONResponse:
    try:
        res = await asyncio.to_thread(service.run_lab_doctor)
        return JSONResponse(res)
    except Exception as exc:  # noqa: BLE001
        return _json_error(exc, 500)


async def api_lab_census(_request: Request) -> JSONResponse:
    try:
        res = await asyncio.to_thread(service.run_live_resource_probe)
        return JSONResponse(res)
    except Exception as exc:  # noqa: BLE001
        return _json_error(exc, 500)


async def api_lab_resources(request: Request) -> JSONResponse:
    try:
        payload = await _body(request)
        updated = settings.update_resources(payload)
        return JSONResponse({"resources": updated.to_dict()})
    except Exception as exc:  # noqa: BLE001
        return _json_error(exc, 400)


async def api_lab_plan(request: Request) -> JSONResponse:
    try:
        payload = await _body(request)
        res = await asyncio.to_thread(service.terraform_plan_preview, payload.get("variables"))
        return JSONResponse(res)
    except Exception as exc:  # noqa: BLE001
        return _json_error(exc, 500)


async def api_lab_up(request: Request) -> JSONResponse:
    try:
        payload = await _body(request)
        job_id = service.start_lab_up_job(payload.get("variables"))
        return JSONResponse({"job_id": job_id})
    except Exception as exc:  # noqa: BLE001
        return _json_error(exc, 400)


async def api_lab_down(request: Request) -> JSONResponse:
    try:
        payload = await _body(request)
        job_id = service.start_lab_down_job(check_only=bool(payload.get("check_only", False)))
        return JSONResponse({"job_id": job_id})
    except Exception as exc:  # noqa: BLE001
        return _json_error(exc, 400)


async def api_attacks_list(request: Request) -> JSONResponse:
    try:
        cloud = request.query_params.get("cloud_provider") or ""
        return JSONResponse(service.list_attacks_overview(cloud_provider=cloud))
    except Exception as exc:  # noqa: BLE001
        return _json_error(exc, 500)


async def api_attacks_add(request: Request) -> JSONResponse:
    try:
        payload = await _body(request)
        res = await asyncio.to_thread(
            service.add_custom_attack,
            payload,
            sync_variants=bool(payload.get("sync_variants", True)),
        )
        return JSONResponse(res)
    except Exception as exc:  # noqa: BLE001
        return _json_error(exc, 400)


async def api_attacks_toggle(request: Request) -> JSONResponse:
    try:
        tid = request.path_params["technique_id"]
        payload = await _body(request)
        res = await asyncio.to_thread(
            service.toggle_attack,
            tid,
            bool(payload.get("enabled", True)),
            sync_variants=bool(payload.get("sync_variants", True)),
        )
        return JSONResponse(res)
    except Exception as exc:  # noqa: BLE001
        return _json_error(exc, 400)


async def api_attacks_delete(request: Request) -> JSONResponse:
    try:
        tid = request.path_params["technique_id"]
        res = await asyncio.to_thread(service.delete_attack, tid)
        return JSONResponse(res)
    except Exception as exc:  # noqa: BLE001
        return _json_error(exc, 400)


async def api_variants(request: Request) -> JSONResponse:
    try:
        q = request.query_params
        res = service.get_variants_view(
            technique_id=q.get("technique_id") or None,
            variant_set=q.get("variant_set") or None,
            cloud_provider=q.get("cloud_provider") or "",
            limit=int(q.get("limit") or 200),
        )
        return JSONResponse(res)
    except Exception as exc:  # noqa: BLE001
        return _json_error(exc, 500)


async def api_variants_generate(request: Request) -> JSONResponse:
    try:
        payload = await _body(request)
        res = await asyncio.to_thread(
            service.generate_all_variants,
            master_seed=int(payload.get("master_seed") or 2026),
            holdout_per_technique=int(payload.get("holdout_per_technique") or 3),
            include_pairwise=bool(payload.get("include_pairwise", True)),
        )
        return JSONResponse(res)
    except Exception as exc:  # noqa: BLE001
        return _json_error(exc, 400)


async def api_campaigns_run(request: Request) -> JSONResponse:
    try:
        payload = await _body(request)
        job_id = service.start_campaign_job(payload)
        return JSONResponse({"job_id": job_id})
    except Exception as exc:  # noqa: BLE001
        return _json_error(exc, 400)


async def api_job_status(request: Request) -> JSONResponse:
    job = service.JOBS.get_job(request.path_params["job_id"])
    if not job:
        return JSONResponse({"error": "Job not found"}, status_code=404)
    return JSONResponse(job)


async def api_job_stream(request: Request) -> StreamingResponse:
    job_id = request.path_params["job_id"]
    return StreamingResponse(
        service.JOBS.stream_logs(job_id),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


async def api_analytics(request: Request) -> JSONResponse:
    try:
        q = request.query_params
        res = service.get_analytics_payload(
            ruleset=q.get("ruleset") or "baseline-v1",
            run_id=q.get("run_id") or None,
            cloud_provider=q.get("cloud_provider") or "",
        )
        return JSONResponse(res)
    except Exception as exc:  # noqa: BLE001
        return _json_error(exc, 500)


async def api_rules(request: Request) -> JSONResponse:
    try:
        cloud = request.query_params.get("cloud_provider") or ""
        return JSONResponse(service.list_rules_view(cloud_provider=cloud))
    except Exception as exc:  # noqa: BLE001
        return _json_error(exc, 500)


async def api_rules_custom_save(request: Request) -> JSONResponse:
    try:
        payload = await _body(request)
        res = await asyncio.to_thread(
            service.save_custom_sigma_rule,
            filename=str(payload.get("filename") or ""),
            yaml_content=str(payload.get("yaml") or ""),
        )
        return JSONResponse(res)
    except Exception as exc:  # noqa: BLE001
        return _json_error(exc, 400)


async def api_rules_custom_delete(request: Request) -> JSONResponse:
    try:
        name = request.path_params["name"]
        res = await asyncio.to_thread(service.delete_custom_sigma_rule, name)
        return JSONResponse(res)
    except Exception as exc:  # noqa: BLE001
        return _json_error(exc, 400)


async def api_rules_replay(request: Request) -> JSONResponse:
    try:
        payload = await _body(request)
        res = await asyncio.to_thread(
            service.replay_rules,
            ruleset_version=payload.get("ruleset_version") or None,
        )
        return JSONResponse({"replay": res})
    except Exception as exc:  # noqa: BLE001
        return _json_error(exc, 400)


async def api_thresholds_get(_request: Request) -> JSONResponse:
    return JSONResponse({"thresholds": settings.get_thresholds().to_dict()})


async def api_thresholds_put(request: Request) -> JSONResponse:
    try:
        payload = await _body(request)
        updated = settings.update_thresholds(payload)
        return JSONResponse({"thresholds": updated.to_dict()})
    except Exception as exc:  # noqa: BLE001
        return _json_error(exc, 400)


async def api_logs(request: Request) -> JSONResponse:
    try:
        q = request.query_params
        res = service.get_logs_view(
            search=q.get("search") or "",
            run_id=q.get("run_id") or None,
            cloud_provider=q.get("cloud_provider") or "",
            alerts_only=q.get("alerts_only") == "true",
            limit=int(q.get("limit") or 300),
        )
        return JSONResponse(res)
    except Exception as exc:  # noqa: BLE001
        return _json_error(exc, 500)


async def api_cli_exec(request: Request) -> JSONResponse:
    try:
        payload = await _body(request)
        res = await asyncio.to_thread(
            service.execute_cli_command,
            str(payload.get("command") or ""),
            db_path=service.resolve_db_path(),
        )
        return JSONResponse(res)
    except Exception as exc:  # noqa: BLE001
        return _json_error(exc, 400)


async def api_db_reset(_request: Request) -> JSONResponse:
    try:
        return JSONResponse(service.reset_database())
    except Exception as exc:  # noqa: BLE001
        return _json_error(exc, 500)


async def api_proxy_status(_request: Request) -> JSONResponse:
    try:
        return JSONResponse(service.proxy_status())
    except Exception as exc:  # noqa: BLE001
        return _json_error(exc, 500)


async def api_proxy_start(request: Request) -> JSONResponse:
    try:
        payload = await _body(request)
        res = await asyncio.to_thread(
            service.start_proxy_server,
            host=payload.get("host") or None,
            port=int(payload["port"]) if payload.get("port") not in (None, "") else None,
        )
        return JSONResponse(res)
    except Exception as exc:  # noqa: BLE001
        return _json_error(exc, 400)


async def api_proxy_stop(_request: Request) -> JSONResponse:
    try:
        res = await asyncio.to_thread(service.stop_proxy_server)
        return JSONResponse(res)
    except Exception as exc:  # noqa: BLE001
        return _json_error(exc, 500)


async def api_proxy_config(request: Request) -> JSONResponse:
    try:
        payload = await _body(request)
        return JSONResponse(service.update_proxy_settings(payload))
    except Exception as exc:  # noqa: BLE001
        return _json_error(exc, 400)


async def api_proxy_events(request: Request) -> JSONResponse:
    try:
        q = request.query_params
        return JSONResponse(
            service.list_proxy_events(
                search=q.get("search") or "",
                alerts_only=q.get("alerts_only") in {"1", "true", "yes"},
                traffic_kind=q.get("traffic_kind") or "",
                cloud_provider=q.get("cloud_provider") or "",
                limit=int(q.get("limit") or 100),
            )
        )
    except Exception as exc:  # noqa: BLE001
        return _json_error(exc, 500)


async def api_proxy_stream(_request: Request) -> StreamingResponse:
    return StreamingResponse(
        PROXY_RUNTIME.subscribe(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


async def api_proxy_simulate(request: Request) -> JSONResponse:
    try:
        payload = await _body(request)
        res = await asyncio.to_thread(
            service.simulate_proxy_traffic,
            scenario=str(payload.get("scenario") or "mixed"),
        )
        return JSONResponse(res)
    except Exception as exc:  # noqa: BLE001
        return _json_error(exc, 400)


async def api_proxy_clear(_request: Request) -> JSONResponse:
    try:
        return JSONResponse(service.clear_proxy_events())
    except Exception as exc:  # noqa: BLE001
        return _json_error(exc, 500)


async def api_rules_audit(request: Request) -> JSONResponse:
    try:
        ruleset = request.query_params.get("ruleset") or "baseline-v1"
        return JSONResponse(await asyncio.to_thread(service.audit_ruleset_view, ruleset_version=ruleset))
    except Exception as exc:  # noqa: BLE001
        return _json_error(exc, 400)


async def api_rules_enhance_preview(request: Request) -> JSONResponse:
    try:
        payload = await _body(request)
        rule_id = str(payload.get("rule_id") or "")
        return JSONResponse(await asyncio.to_thread(service.preview_rule_enhancement, rule_id))
    except Exception as exc:  # noqa: BLE001
        return _json_error(exc, 400)


async def api_rules_enhance_apply(request: Request) -> JSONResponse:
    try:
        payload = await _body(request)
        res = await asyncio.to_thread(
            service.apply_enhanced_rule_service,
            filename=str(payload.get("filename") or ""),
            yaml_content=str(payload.get("yaml") or ""),
            target_ruleset=str(payload.get("target_ruleset") or "enhanced-v1"),
            replay=bool(payload.get("replay", True)),
        )
        return JSONResponse(res)
    except Exception as exc:  # noqa: BLE001
        return _json_error(exc, 400)


async def api_rules_enhance_all(request: Request) -> JSONResponse:
    try:
        payload = await _body(request)
        res = await asyncio.to_thread(
            service.enhance_ruleset_service,
            source_ruleset=str(payload.get("source_ruleset") or "baseline-v1"),
            target_ruleset=str(payload.get("target_ruleset") or "enhanced-v1"),
        )
        return JSONResponse(res)
    except Exception as exc:  # noqa: BLE001
        return _json_error(exc, 400)


async def api_dynamic_rules(request: Request) -> JSONResponse:
    try:
        enabled_only = request.query_params.get("enabled_only") in {"1", "true", "yes"}
        return JSONResponse(service.list_dynamic_rules_view(enabled_only=enabled_only))
    except Exception as exc:  # noqa: BLE001
        return _json_error(exc, 500)


async def api_dynamic_rules_save(request: Request) -> JSONResponse:
    try:
        payload = await _body(request)
        return JSONResponse(service.save_dynamic_rule_service(payload))
    except Exception as exc:  # noqa: BLE001
        return _json_error(exc, 400)


async def api_dynamic_rules_toggle(request: Request) -> JSONResponse:
    try:
        rule_id = request.path_params["rule_id"]
        payload = await _body(request)
        return JSONResponse(service.toggle_dynamic_rule_service(rule_id, bool(payload.get("enabled", True))))
    except Exception as exc:  # noqa: BLE001
        return _json_error(exc, 400)


async def api_dynamic_rules_delete(request: Request) -> JSONResponse:
    try:
        rule_id = request.path_params["rule_id"]
        return JSONResponse(service.delete_dynamic_rule_service(rule_id))
    except Exception as exc:  # noqa: BLE001
        return _json_error(exc, 400)


async def api_dynamic_alerts(request: Request) -> JSONResponse:
    try:
        q = request.query_params
        return JSONResponse(
            service.list_dynamic_alerts_view(
                source=q.get("source") or "",
                cloud_provider=q.get("cloud_provider") or "",
                limit=int(q.get("limit") or 100),
            )
        )
    except Exception as exc:  # noqa: BLE001
        return _json_error(exc, 500)


async def api_dynamic_profiles(request: Request) -> JSONResponse:
    try:
        q = request.query_params
        limit = int(q.get("limit") or 50)
        cloud_provider = q.get("cloud_provider") or ""
        return JSONResponse(service.list_principal_profiles_view(cloud_provider=cloud_provider, limit=limit))
    except Exception as exc:  # noqa: BLE001
        return _json_error(exc, 500)


async def api_dynamic_replay(request: Request) -> JSONResponse:
    try:
        payload = await _body(request)
        res = await asyncio.to_thread(
            service.run_dynamic_replay_service,
            run_id=payload.get("run_id") or None,
        )
        return JSONResponse(res)
    except Exception as exc:  # noqa: BLE001
        return _json_error(exc, 400)


async def api_storage_get(_request: Request) -> JSONResponse:
    try:
        return JSONResponse(service.get_storage_status())
    except Exception as exc:  # noqa: BLE001
        return _json_error(exc, 500)


async def api_storage_put(request: Request) -> JSONResponse:
    try:
        payload = await _body(request)
        return JSONResponse(await asyncio.to_thread(service.update_storage_link, payload))
    except Exception as exc:  # noqa: BLE001
        return _json_error(exc, 400)


async def api_storage_export(request: Request) -> Response:
    try:
        limit = int(request.query_params.get("limit") or 5000)
        res = await asyncio.to_thread(service.export_telemetry_jsonl, limit=limit)
        return Response(
            content=res["jsonl"],
            media_type="application/x-ndjson",
            headers={"Content-Disposition": "attachment; filename=identity-shield-telemetry.jsonl"},
        )
    except Exception as exc:  # noqa: BLE001
        return _json_error(exc, 400)


async def api_storage_archive(request: Request) -> JSONResponse:
    try:
        payload = await _body(request)
        res = await asyncio.to_thread(
            service.archive_telemetry_to_s3,
            bucket=payload.get("bucket") or None,
            prefix=payload.get("prefix") or None,
        )
        return JSONResponse(res)
    except Exception as exc:  # noqa: BLE001
        return _json_error(exc, 400)


async def api_tools_status(_request: Request) -> JSONResponse:
    try:
        return JSONResponse(service.external_tools_status_service())
    except Exception as exc:  # noqa: BLE001
        return _json_error(exc, 500)


async def api_tools_cloudfox_import(request: Request) -> JSONResponse:
    try:
        payload = await _body(request)
        res = await asyncio.to_thread(service.import_cloudfox_service, payload)
        return JSONResponse(res)
    except Exception as exc:  # noqa: BLE001
        return _json_error(exc, 400)


async def api_tools_cloudfox_run(request: Request) -> JSONResponse:
    try:
        payload = await _body(request)
        res = await asyncio.to_thread(service.run_cloudfox_recon_service, payload)
        return JSONResponse(res)
    except Exception as exc:  # noqa: BLE001
        return _json_error(exc, 400)


async def api_tools_pacu_recon(request: Request) -> JSONResponse:
    try:
        payload = await _body(request)
        res = await asyncio.to_thread(service.run_pacu_recon_service, payload)
        return JSONResponse(res)
    except Exception as exc:  # noqa: BLE001
        return _json_error(exc, 400)


async def api_closed_loop_preview(request: Request) -> JSONResponse:
    try:
        q = request.query_params
        mode = str(q.get("mode") or "both")
        limit = int(q.get("limit") or 8)
        cloud_provider = str(q.get("cloud_provider") or "all")
        res = await asyncio.to_thread(
            service.preview_closed_loop_service,
            mode=mode,
            limit=limit,
            cloud_provider=cloud_provider,
        )
        return JSONResponse(res)
    except Exception as exc:  # noqa: BLE001
        return _json_error(exc, 400)


async def api_closed_loop_run(request: Request) -> JSONResponse:
    try:
        payload = await _body(request)
        res = await asyncio.to_thread(
            service.run_closed_loop_service,
            mode=str(payload.get("mode") or "both"),
            include_pairwise=bool(payload.get("include_pairwise", False)),
            auto_enhance=bool(payload.get("auto_enhance", True)),
            limit=int(payload.get("limit") or 6),
            cloud_provider=str(payload.get("cloud_provider") or "all"),
        )
        return JSONResponse(res)
    except Exception as exc:  # noqa: BLE001
        return _json_error(exc, 400)


async def api_clouds_status(_request: Request) -> JSONResponse:
    try:
        return JSONResponse(service.multicloud_status_service())
    except Exception as exc:  # noqa: BLE001
        return _json_error(exc, 500)


async def api_clouds_ingest(request: Request) -> JSONResponse:
    try:
        payload = await _body(request)
        res = await asyncio.to_thread(service.ingest_cloud_logs_service, payload)
        return JSONResponse(res)
    except Exception as exc:  # noqa: BLE001
        return _json_error(exc, 400)


async def api_tools_scoutsuite_import(request: Request) -> JSONResponse:
    try:
        payload = await _body(request)
        res = await asyncio.to_thread(service.import_scoutsuite_service, payload)
        return JSONResponse(res)
    except Exception as exc:  # noqa: BLE001
        return _json_error(exc, 400)


async def api_siem_export(request: Request) -> JSONResponse:
    try:
        payload = await _body(request)
        res = await asyncio.to_thread(service.export_siem_rule_service, payload)
        return JSONResponse(res)
    except KeyError as exc:
        return _json_error(exc, 404)
    except Exception as exc:  # noqa: BLE001
        return _json_error(exc, 400)


routes = [
    Route("/", index, methods=["GET"]),
    Route("/api/auth/verify", api_auth_verify, methods=["POST"]),
    Route("/api/state", api_state, methods=["GET"]),
    Route("/api/connect/profiles", api_profiles, methods=["GET"]),
    Route("/api/connect/templates", api_templates, methods=["GET"]),
    Route("/api/connect", api_connect, methods=["POST"]),
    Route("/api/connect/disconnect", api_disconnect, methods=["POST"]),
    Route("/api/lab/doctor", api_lab_doctor, methods=["POST"]),
    Route("/api/lab/census", api_lab_census, methods=["POST"]),
    Route("/api/lab/resources", api_lab_resources, methods=["POST"]),
    Route("/api/lab/plan", api_lab_plan, methods=["POST"]),
    Route("/api/lab/up", api_lab_up, methods=["POST"]),
    Route("/api/lab/down", api_lab_down, methods=["POST"]),
    Route("/api/attacks", api_attacks_list, methods=["GET"]),
    Route("/api/attacks", api_attacks_add, methods=["POST"]),
    Route("/api/attacks/{technique_id}", api_attacks_toggle, methods=["PATCH"]),
    Route("/api/attacks/{technique_id}", api_attacks_delete, methods=["DELETE"]),
    Route("/api/variants", api_variants, methods=["GET"]),
    Route("/api/variants/generate", api_variants_generate, methods=["POST"]),
    Route("/api/campaigns/run", api_campaigns_run, methods=["POST"]),
    Route("/api/jobs/{job_id}", api_job_status, methods=["GET"]),
    Route("/api/jobs/{job_id}/stream", api_job_stream, methods=["GET"]),
    Route("/api/analytics", api_analytics, methods=["GET"]),
    Route("/api/rules", api_rules, methods=["GET"]),
    Route("/api/rules/custom", api_rules_custom_save, methods=["POST"]),
    Route("/api/rules/custom/{name}", api_rules_custom_delete, methods=["DELETE"]),
    Route("/api/rules/replay", api_rules_replay, methods=["POST"]),
    Route("/api/rules/audit", api_rules_audit, methods=["GET"]),
    Route("/api/rules/enhance/preview", api_rules_enhance_preview, methods=["POST"]),
    Route("/api/rules/enhance/apply", api_rules_enhance_apply, methods=["POST"]),
    Route("/api/rules/enhance/all", api_rules_enhance_all, methods=["POST"]),
    Route("/api/dynamic/rules", api_dynamic_rules, methods=["GET"]),
    Route("/api/dynamic/rules", api_dynamic_rules_save, methods=["POST"]),
    Route("/api/dynamic/rules/{rule_id}", api_dynamic_rules_toggle, methods=["PATCH"]),
    Route("/api/dynamic/rules/{rule_id}", api_dynamic_rules_delete, methods=["DELETE"]),
    Route("/api/dynamic/alerts", api_dynamic_alerts, methods=["GET"]),
    Route("/api/dynamic/profiles", api_dynamic_profiles, methods=["GET"]),
    Route("/api/dynamic/replay", api_dynamic_replay, methods=["POST"]),
    Route("/api/proxy/status", api_proxy_status, methods=["GET"]),
    Route("/api/proxy/start", api_proxy_start, methods=["POST"]),
    Route("/api/proxy/stop", api_proxy_stop, methods=["POST"]),
    Route("/api/proxy/config", api_proxy_config, methods=["PUT"]),
    Route("/api/proxy/events", api_proxy_events, methods=["GET"]),
    Route("/api/proxy/stream", api_proxy_stream, methods=["GET"]),
    Route("/api/proxy/simulate", api_proxy_simulate, methods=["POST"]),
    Route("/api/proxy/clear", api_proxy_clear, methods=["POST"]),
    Route("/api/thresholds", api_thresholds_get, methods=["GET"]),
    Route("/api/thresholds", api_thresholds_put, methods=["PUT"]),
    Route("/api/storage", api_storage_get, methods=["GET"]),
    Route("/api/storage", api_storage_put, methods=["PUT"]),
    Route("/api/storage/export", api_storage_export, methods=["GET"]),
    Route("/api/storage/archive", api_storage_archive, methods=["POST"]),
    Route("/api/tools/status", api_tools_status, methods=["GET"]),
    Route("/api/tools/cloudfox/import", api_tools_cloudfox_import, methods=["POST"]),
    Route("/api/tools/cloudfox/run", api_tools_cloudfox_run, methods=["POST"]),
    Route("/api/tools/scoutsuite/import", api_tools_scoutsuite_import, methods=["POST"]),
    Route("/api/tools/pacu/recon", api_tools_pacu_recon, methods=["POST"]),
    Route("/api/clouds", api_clouds_status, methods=["GET"]),
    Route("/api/clouds/ingest", api_clouds_ingest, methods=["POST"]),
    Route("/api/siem/export", api_siem_export, methods=["POST"]),
    Route("/api/closed-loop/preview", api_closed_loop_preview, methods=["GET"]),
    Route("/api/closed-loop/run", api_closed_loop_run, methods=["POST"]),
    Route("/api/logs", api_logs, methods=["GET"]),
    Route("/api/cli/exec", api_cli_exec, methods=["POST"]),
    Route("/api/db/reset", api_db_reset, methods=["POST"]),
    Mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static"),
]

app = Starlette(routes=routes)
app.add_middleware(SecurityMiddleware)
