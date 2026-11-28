"""CLI parity commands for Attack Studio, Threshold/Resource Config, Logs, and Web UI."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from identity_shield import service, settings


def attacks_main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="identity-shield attacks")
    sub = parser.add_subparsers(dest="action", required=True)

    p_list = sub.add_parser("list", help="list all available, disabled, and custom attacks")
    p_list.add_argument("--cloud", default="all", choices=["all", "aws", "gcp", "azure"])
    p_list.add_argument("--db", default=None)
    p_list.add_argument("--json", action="store_true")

    p_show = sub.add_parser("show", help="inspect full definition and Sigma rule mappings for an attack")
    p_show.add_argument("technique_id")
    p_show.add_argument("--db", default=None)
    p_show.add_argument("--json", action="store_true")

    p_add = sub.add_parser("add", help="add a custom attack technique and regenerate variants")
    p_add.add_argument("--id", required=True, dest="technique_id", help="e.g. T1538 or T9001.custom")
    p_add.add_argument("--name", required=True)
    p_add.add_argument("--tactic", default="discovery")
    p_add.add_argument("--events", required=True, help="comma-separated CloudTrail event names")
    p_add.add_argument("--service", default="sts", help="AWS boto3 service name (e.g. ec2, iam, s3, sts)")
    p_add.add_argument("--operation", default="get_caller_identity", help="boto3 client method name")
    p_add.add_argument("--kwargs", default="{}", help="JSON kwargs dict for the API operation")
    p_add.add_argument("--actions", default="", help="comma-separated IAM actions (optional)")
    p_add.add_argument("--requires-data-events", action="store_true")
    p_add.add_argument("--notes", default="")
    p_add.add_argument("--no-sync", action="store_true")
    p_add.add_argument("--db", default=None)
    p_add.add_argument("--json", action="store_true")

    for verb in ("enable", "disable", "remove"):
        p_t = sub.add_parser(verb, help=f"{verb} an attack technique")
        p_t.add_argument("technique_id")
        p_t.add_argument("--no-sync", action="store_true")
        p_t.add_argument("--db", default=None)
        p_t.add_argument("--json", action="store_true")

    args = parser.parse_args(argv)
    db = service.resolve_db_path(args.db)

    if args.action == "list":
        data = service.list_attacks_overview(db, cloud_provider=args.cloud)
        if args.json:
            print(json.dumps(data, indent=2))
            return 0
        print(f"{'ID':<14} {'CLOUD':<6} {'STATUS':<10} {'LIVE READY':<12} {'VARIANTS':>8}  {'TACTIC':<20} NAME")
        print("-" * 100)
        for a in data["attacks"]:
            status = "ENABLED" if a["enabled"] else "DISABLED"
            live = "READY" if a["live_capability"]["available"] else "GATED"
            cp = str(a.get("cloud_provider") or "aws").upper()
            suffix = " [custom]" if a["custom"] else ""
            print(
                f"{a['technique_id']:<14} {cp:<6} {status:<10} {live:<12} {a['variant_count']:>8}  "
                f"{a['tactic']:<20} {a['name']}{suffix}"
            )
        return 0

    if args.action == "show":
        data = service.list_attacks_overview(db)
        match = next((a for a in data["attacks"] if a["technique_id"].upper() == args.technique_id.upper()), None)
        if not match:
            print(f"unknown technique: {args.technique_id}", file=sys.stderr)
            return 1
        if args.json:
            print(json.dumps(match, indent=2))
        else:
            print(f"{match['technique_id']} — {match['name']} ({match['tactic']})")
            print(f"  enabled:          {match['enabled']}  (custom={match['custom']})")
            print(f"  executor:         {match['executor']} ({match['executor_ref']})")
            print(f"  events:           {', '.join(match['event_names'])}")
            print(f"  required actions: {', '.join(match['required_actions'])}")
            print(f"  live capability:  {match['live_capability']['available']} — {match['live_capability']['reason']}")
            print(f"  mapped rules:     {len(match['mapped_rules'])}")
            for r in match["mapped_rules"]:
                print(f"    - [{r['ruleset_version']}] {r['native_id']}: {r['title']}")
        return 0

    if args.action == "add":
        try:
            kwargs_obj = json.loads(args.kwargs or "{}")
        except json.JSONDecodeError as exc:
            print(f"invalid --kwargs JSON: {exc}", file=sys.stderr)
            return 2
        res = service.add_custom_attack(
            {
                "technique_id": args.technique_id,
                "name": args.name,
                "tactic": args.tactic,
                "event_names": args.events,
                "service": args.service,
                "operation": args.operation,
                "kwargs": kwargs_obj,
                "required_actions": args.actions,
                "requires_data_events": args.requires_data_events,
                "notes": args.notes,
            },
            db_path=db,
            sync_variants=not args.no_sync,
        )
        if args.json:
            print(json.dumps(res, indent=2))
        else:
            print(f"added custom attack {res['attack']['technique_id']} ({res['attack']['name']})")
            if res.get("variant_sync"):
                print(f"variants synchronized: {res['variant_sync'].get('variants_total')} total")
        return 0

    if args.action in ("enable", "disable"):
        res = service.toggle_attack(args.technique_id, args.action == "enable", db_path=db, sync_variants=not args.no_sync)
        if args.json:
            print(json.dumps(res, indent=2))
        else:
            print(f"{args.technique_id} -> {'ENABLED' if args.action == 'enable' else 'DISABLED'}")
        return 0

    if args.action == "remove":
        res = service.delete_attack(args.technique_id, db_path=db, sync_variants=not args.no_sync)
        if args.json:
            print(json.dumps(res, indent=2))
        else:
            verb = "deleted custom attack" if res.get("deleted_custom") else "disabled built-in attack"
            print(f"{verb}: {args.technique_id}")
        return 0

    return 0


def config_main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="identity-shield config")
    sub = parser.add_subparsers(dest="action", required=True)

    p_show = sub.add_parser("show", help="display thresholds, bound resources, and active connection profile")
    p_show.add_argument("--json", action="store_true")

    p_thresh = sub.add_parser("thresholds", help="update cost, detection, or latency thresholds")
    p_thresh.add_argument("--budget-usd", type=float, default=None)
    p_thresh.add_argument("--min-detection-rate", type=float, default=None)
    p_thresh.add_argument("--max-evasion-rate", type=float, default=None)
    p_thresh.add_argument("--max-false-alarm-rate", type=float, default=None)
    p_thresh.add_argument("--max-ingest-lag-ms", type=int, default=None)
    p_thresh.add_argument("--enable-data-events", choices=["true", "false"], default=None)
    p_thresh.add_argument("--enable-instance", choices=["true", "false"], default=None)
    p_thresh.add_argument("--allowed-regions", default=None, help="comma-separated AWS regions")
    p_thresh.add_argument("--json", action="store_true")

    p_bind = sub.add_parser("bind", help="bind target client AWS resources for live testing")
    p_bind.add_argument("--region", default=None)
    p_bind.add_argument("--bucket", default=None)
    p_bind.add_argument("--key", default=None)
    p_bind.add_argument("--trail-name", default=None)
    p_bind.add_argument("--queue-url", default=None)
    p_bind.add_argument("--instance-id", default=None)
    p_bind.add_argument("--test-user", default=None)
    p_bind.add_argument("--admin-role", default=None)
    p_bind.add_argument("--json", action="store_true")

    p_conn = sub.add_parser("connect", help="test and save AWS connection descriptor (Profile, AssumeRole, or Env)")
    p_conn.add_argument("--mode", choices=["profile", "assume_role", "env_default"], default="profile")
    p_conn.add_argument("--profile", default="lab")
    p_conn.add_argument("--role-arn", default="")
    p_conn.add_argument("--external-id", default="")
    p_conn.add_argument("--region", default="eu-west-1")
    p_conn.add_argument("--scope", choices=["single_account", "organization"], default="single_account")
    p_conn.add_argument("--json", action="store_true")

    p_cgcp = sub.add_parser("connect-gcp", help="connect & verify GCP account/project or whole GCP Organization")
    p_cgcp.add_argument("--mode", choices=["gcloud_adc", "impersonate_sa", "in_memory_token", "workload_identity"], default="gcloud_adc")
    p_cgcp.add_argument("--project", default="")
    p_cgcp.add_argument("--organization", default="")
    p_cgcp.add_argument("--service-account", default="")
    p_cgcp.add_argument("--region", default="us-central1")
    p_cgcp.add_argument("--scope", choices=["single_project", "organization"], default="single_project")
    p_cgcp.add_argument("--gcloud-config", default="")
    p_cgcp.add_argument("--json", action="store_true")

    p_caz = sub.add_parser("connect-azure", help="connect & verify Azure subscription or whole Entra/Org tenant")
    p_caz.add_argument("--mode", choices=["az_cli", "service_principal", "managed_identity", "in_memory_token"], default="az_cli")
    p_caz.add_argument("--tenant-id", default="")
    p_caz.add_argument("--subscription-id", default="")
    p_caz.add_argument("--management-group", default="")
    p_caz.add_argument("--client-id", default="")
    p_caz.add_argument("--location", default="eastus")
    p_caz.add_argument("--scope", choices=["single_subscription", "organization"], default="single_subscription")
    p_caz.add_argument("--json", action="store_true")

    p_stor = sub.add_parser("storage", help="link self-hosted database file path, retention cap, or S3 archive bucket")
    p_stor.add_argument("--db-path", default=None, help="custom SQLite file path (pass empty string '' to reset default)")
    p_stor.add_argument("--max-proxy-events", type=int, default=None)
    p_stor.add_argument("--archive-bucket", default=None)
    p_stor.add_argument("--archive-prefix", default=None)

    p_exp = sub.add_parser("export", help="export captured proxy & dynamic telemetry as JSONL")
    p_exp.add_argument("--output", default=None, help="write JSONL to file path instead of stdout")
    p_exp.add_argument("--limit", type=int, default=5000)
    p_exp.add_argument("--db", default=None)

    p_tools = sub.add_parser("tools", help="inspect optional tools (Stratus/CloudFox/Pacu) or import CloudFox JSON")
    p_tools.add_argument("--mode", choices=["status", "import-cloudfox", "cloudfox", "pacu"], default="status")
    p_tools.add_argument("--file", default=None, help="CloudFox JSON file to import")
    p_tools.add_argument("--apply-bindings", action="store_true", help="apply suggested resource bindings from CloudFox")
    p_tools.add_argument("--module", default="iam__enum_permissions", help="allowlisted read-only Pacu module")
    p_tools.add_argument("--profile", default=None)
    p_tools.add_argument("--region", default=None)
    p_tools.add_argument("--proxy-url", default=None)

    args = parser.parse_args(argv)

    if args.action == "show":
        cfg = settings.load_workspace_config()
        if args.json:
            print(json.dumps(cfg, indent=2))
        else:
            print(json.dumps(cfg, indent=2))
        return 0

    if args.action == "thresholds":
        updates: dict[str, Any] = {}
        if args.budget_usd is not None:
            updates["budget_usd"] = args.budget_usd
        if args.min_detection_rate is not None:
            updates["min_detection_rate"] = args.min_detection_rate
        if args.max_evasion_rate is not None:
            updates["max_evasion_rate"] = args.max_evasion_rate
        if args.max_false_alarm_rate is not None:
            updates["max_false_alarm_rate"] = args.max_false_alarm_rate
        if args.max_ingest_lag_ms is not None:
            updates["max_ingest_lag_ms"] = args.max_ingest_lag_ms
        if args.enable_data_events is not None:
            updates["enable_data_events"] = args.enable_data_events == "true"
        if args.enable_instance is not None:
            updates["enable_instance"] = args.enable_instance == "true"
        if args.allowed_regions is not None:
            updates["allowed_regions"] = [r.strip() for r in args.allowed_regions.split(",") if r.strip()]
        updated = settings.update_thresholds(updates)
        print(json.dumps(updated.to_dict(), indent=2))
        return 0

    if args.action == "bind":
        updates = {}
        mapping = {
            "region": args.region,
            "data_bucket": args.bucket,
            "data_key": args.key,
            "trail_name": args.trail_name,
            "queue_url": args.queue_url,
            "instance_id": args.instance_id,
            "test_user_name": args.test_user,
            "admin_role_name": args.admin_role,
        }
        for k, v in mapping.items():
            if v is not None:
                updates[k] = v
        updated = settings.update_resources(updates)
        print(json.dumps(updated.to_dict(), indent=2))
        return 0

    if args.action == "connect":
        res = service.connect_aws(
            {
                "auth_mode": args.mode,
                "profile_name": args.profile,
                "role_arn": args.role_arn,
                "external_id": args.external_id,
                "region": args.region,
                "scope": args.scope,
            }
        )
        print(json.dumps(res, indent=2))
        return 0

    if args.action == "connect-gcp":
        import os

        res = service.connect_gcp(
            {
                "auth_mode": args.mode,
                "project_id": args.project,
                "organization_id": args.organization,
                "service_account": args.service_account,
                "region": args.region,
                "scope": args.scope,
                "gcloud_config": args.gcloud_config,
                "access_token": os.environ.get("IDENTITY_SHIELD_GCP_TOKEN", ""),
            }
        )
        print(json.dumps(res, indent=2))
        return 0

    if args.action == "connect-azure":
        import os

        res = service.connect_azure(
            {
                "auth_mode": args.mode,
                "tenant_id": args.tenant_id,
                "subscription_id": args.subscription_id,
                "management_group_id": args.management_group,
                "client_id": args.client_id,
                "location": args.location,
                "scope": args.scope,
                "client_secret": os.environ.get("IDENTITY_SHIELD_AZURE_CLIENT_SECRET", ""),
                "access_token": os.environ.get("IDENTITY_SHIELD_AZURE_TOKEN", ""),
            }
        )
        print(json.dumps(res, indent=2))
        return 0
        updates: dict[str, Any] = {}
        if args.db_path is not None:
            updates["db_path"] = args.db_path
        if args.max_proxy_events is not None:
            updates["max_proxy_events"] = args.max_proxy_events
        if args.archive_bucket is not None:
            updates["archive_s3_bucket"] = args.archive_bucket
        if args.archive_prefix is not None:
            updates["archive_s3_prefix"] = args.archive_prefix
        res = service.update_storage_link(updates) if updates else service.get_storage_status()
        print(json.dumps(res, indent=2))
        return 0

    if args.action == "export":
        res = service.export_telemetry_jsonl(
            db_path=service.resolve_db_path(args.db),
            limit=args.limit,
        )
        if args.output:
            out_path = Path(args.output).expanduser().resolve()
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(res["jsonl"], encoding="utf-8")
            print(json.dumps({"exported": res["records"], "output": str(out_path)}, indent=2))
        else:
            print(res["jsonl"], end="")
        return 0

    if args.action == "tools":
        if args.mode == "status":
            print(json.dumps(service.external_tools_status_service(), indent=2))
            return 0
        if args.mode == "import-cloudfox":
            if not args.file:
                raise SystemExit("--file is required with --mode import-cloudfox")
            print(
                json.dumps(
                    service.import_cloudfox_service(
                        {"path": args.file, "apply_bindings": bool(args.apply_bindings)}
                    ),
                    indent=2,
                )
            )
            return 0
        if args.mode == "cloudfox":
            print(
                json.dumps(
                    service.run_cloudfox_recon_service(
                        {"profile": args.profile, "region": args.region}
                    ),
                    indent=2,
                )
            )
            return 0
        if args.mode == "pacu":
            print(
                json.dumps(
                    service.run_pacu_recon_service(
                        {
                            "module": args.module,
                            "profile": args.profile,
                            "proxy_url": args.proxy_url,
                        }
                    ),
                    indent=2,
                )
            )
            return 0

    return 0


def logs_main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="identity-shield logs")
    sub = parser.add_subparsers(dest="kind", required=True)

    p_ev = sub.add_parser("events", help="inspect captured AWS/GCP/Azure events")
    p_ev.add_argument("--search", default="")
    p_ev.add_argument("--run-id", default=None)
    p_ev.add_argument("--cloud", default="", choices=["", "all", "aws", "gcp", "azure"])
    p_ev.add_argument("--alerts-only", action="store_true")
    p_ev.add_argument("--limit", type=int, default=50)
    p_ev.add_argument("--db", default=None)
    p_ev.add_argument("--json", action="store_true")

    p_ing = sub.add_parser("ingest", help="ingest AWS CloudTrail, GCP Audit, or Azure Activity/Entra JSON logs")
    p_ing.add_argument("--file", required=True, help="JSON or NDJSON log file path")
    p_ing.add_argument("--cloud", default="auto", choices=["auto", "aws", "gcp", "azure"])
    p_ing.add_argument("--db", default=None)

    p_pull = sub.add_parser("pull", help="pull live audit logs from connected AWS, GCP, and/or Azure clouds into SIEM")
    p_pull.add_argument("--cloud", default="connected", choices=["connected", "all", "aws", "gcp", "azure"])
    p_pull.add_argument("--hours", type=int, default=24)
    p_pull.add_argument("--limit", type=int, default=100)
    p_pull.add_argument("--no-replay", action="store_true")
    p_pull.add_argument("--db", default=None)

    p_tr = sub.add_parser("trials", help="inspect trial execution logs")
    p_tr.add_argument("--limit", type=int, default=50)
    p_tr.add_argument("--db", default=None)
    p_tr.add_argument("--json", action="store_true")

    args = parser.parse_args(argv)
    db = service.resolve_db_path(args.db)
    if args.kind == "ingest":
        src = Path(args.file).expanduser().resolve()
        if ".." in Path(args.file).parts or not src.is_file():
            raise SystemExit(f"Invalid or missing log file: {args.file}")
        res = service.ingest_cloud_logs_service(
            {"json_text": src.read_text(encoding="utf-8"), "cloud_provider": args.cloud},
            db_path=db,
        )
        print(json.dumps(res, indent=2))
        return 0

    if args.kind == "pull":
        res = service.pull_cloud_siem_logs_service(
            {
                "cloud_provider": args.cloud,
                "hours": args.hours,
                "limit": args.limit,
                "replay_rules": not bool(args.no_replay),
            },
            db_path=db,
        )
        print(json.dumps(res, indent=2))
        return 0

    data = service.get_logs_view(
        db_path=db,
        search=getattr(args, "search", ""),
        run_id=getattr(args, "run_id", None),
        cloud_provider=getattr(args, "cloud", ""),
        alerts_only=bool(getattr(args, "alerts_only", False)),
        limit=args.limit,
    )
    if args.json:
        print(json.dumps(data[args.kind if args.kind == "events" else "trial_logs"], indent=2))
        return 0

    if args.kind == "events":
        rows = data["events"]
        print(f"{'EVENT TIME':<22} {'EVENT NAME':<28} {'SOURCE':<22} {'IP':<16} RULES")
        print("-" * 105)
        for ev in rows:
            print(
                f"{(ev['event_time'] or '')[:20]:<22} {(ev['event_name'] or '')[:27]:<28} "
                f"{(ev['event_source'] or '')[:21]:<22} {(ev['source_ip'] or '')[:15]:<16} "
                f"{ev['matched_rules'] or '-'}"
            )
    else:
        rows = data["trial_logs"][: args.limit]
        print(f"{'TRIAL ID':<38} {'TECHNIQUE':<11} {'OK':<5} {'DIFF':<6} ERROR")
        print("-" * 92)
        for t in rows:
            ok = "yes" if t["attack_succeeded"] == 1 else ("no" if t["attack_succeeded"] == 0 else "-")
            diff = "yes" if t["variant_changed"] == 1 else ("no" if t["variant_changed"] == 0 else "-")
            print(
                f"{t['trial_id'][:37]:<38} {t['technique_id']:<11} {ok:<5} {diff:<6} "
                f"{(t['error'] or '')[:30]}"
            )
    return 0


def ui_main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="identity-shield ui", description="Launch the Identity Shield Control Plane Web UI")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8501)
    parser.add_argument("--db", default=None)
    args = parser.parse_args(argv)

    import os
    import uvicorn
    from identity_shield.web import app as web_app

    if args.db:
        os.environ["IDENTITY_SHIELD_DB"] = str(service.resolve_db_path(args.db))
    service.ensure_database()

    is_local = args.host.strip().lower() in {"127.0.0.1", "localhost", "::1"}
    web_app.NON_LOCAL_BIND = not is_local
    print(f"Identity Shield Control Plane running at http://{args.host}:{args.port}")
    if not is_local or os.environ.get("IDENTITY_SHIELD_REQUIRE_TOKEN") == "1":
        print(f"Access Token required for Control Plane UI/API: {web_app.get_session_token()}")
    uvicorn.run("identity_shield.web.app:app", host=args.host, port=args.port, log_level="warning")
    return 0


def proxy_main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="identity-shield proxy", description="Manage the Live Security Proxy")
    sub = parser.add_subparsers(dest="action", required=True)

    p_st = sub.add_parser("status", help="show proxy status and traffic counts")
    p_st.add_argument("--db", default=None)
    p_st.add_argument("--json", action="store_true")

    p_start = sub.add_parser("start", help="start live proxy (blocking until Ctrl+C)")
    p_start.add_argument("--host", default=None)
    p_start.add_argument("--port", type=int, default=None)
    p_start.add_argument("--mode", choices=["observe", "block"], default=None)
    p_start.add_argument("--upstream", default=None)
    p_start.add_argument("--ruleset", default=None)
    p_start.add_argument("--db", default=None)

    p_cfg = sub.add_parser("config", help="update proxy configuration")
    p_cfg.add_argument("--host", default=None)
    p_cfg.add_argument("--port", type=int, default=None)
    p_cfg.add_argument("--mode", choices=["observe", "block"], default=None)
    p_cfg.add_argument("--upstream", default=None)
    p_cfg.add_argument("--ruleset", default=None)
    p_cfg.add_argument("--block-threshold", type=float, default=None)
    p_cfg.add_argument("--learn-baseline", choices=["true", "false"], default=None)

    p_ev = sub.add_parser("events", help="list captured proxy events")
    p_ev.add_argument("--search", default="")
    p_ev.add_argument("--alerts-only", action="store_true")
    p_ev.add_argument("--kind", default="", choices=["", "aws_api", "gcp_api", "azure_api", "http_app", "connect_tunnel"])
    p_ev.add_argument("--limit", type=int, default=50)
    p_ev.add_argument("--db", default=None)
    p_ev.add_argument("--json", action="store_true")

    p_sim = sub.add_parser("simulate", help="send realistic baseline and attack HTTP requests through proxy")
    p_sim.add_argument("--scenario", default="mixed", choices=["baseline", "aws_attack", "gcp_attack", "azure_attack", "webapp_attack", "mixed", "multicloud_mixed"])
    p_sim.add_argument("--db", default=None)
    p_sim.add_argument("--json", action="store_true")

    p_clr = sub.add_parser("clear", help="clear proxy event log")
    p_clr.add_argument("--db", default=None)

    args = parser.parse_args(argv)
    db = service.resolve_db_path(getattr(args, "db", None))

    if args.action == "status":
        st = service.proxy_status(db_path=db)
        if args.json:
            print(json.dumps(st, indent=2))
        else:
            print(f"running={st['running']} listen={st['listen_url']} mode={st['config']['mode']} ruleset={st['config']['ruleset_version']}")
            print(f"events={st['stats']['total_events']} alerted={st['stats']['alerted_events']} blocked={st['stats']['blocked_events']}")
        return 0

    if args.action == "config":
        updates: dict[str, Any] = {}
        if args.host is not None:
            updates["host"] = args.host
        if args.port is not None:
            updates["port"] = args.port
        if args.mode is not None:
            updates["mode"] = args.mode
        if args.upstream is not None:
            updates["upstream_url"] = args.upstream
        if args.ruleset is not None:
            updates["ruleset_version"] = args.ruleset
        if args.block_threshold is not None:
            updates["block_risk_threshold"] = args.block_threshold
        if args.learn_baseline is not None:
            updates["learn_baseline"] = args.learn_baseline == "true"
        res = service.update_proxy_settings(updates)
        print(json.dumps(res["config"], indent=2))
        return 0

    if args.action == "start":
        updates: dict[str, Any] = {}
        if args.mode is not None:
            updates["mode"] = args.mode
        if args.upstream is not None:
            updates["upstream_url"] = args.upstream
        if args.ruleset is not None:
            updates["ruleset_version"] = args.ruleset
        if updates:
            service.update_proxy_settings(updates)
        st = service.start_proxy_server(db_path=db, host=args.host, port=args.port)
        print(f"Identity Shield Live Proxy listening on {st['listen_url']} (mode={st['config']['mode']})")
        import time

        try:
            while True:
                time.sleep(1.0)
        except KeyboardInterrupt:
            service.stop_proxy_server(db_path=db)
            print("Proxy stopped.")
        return 0

    if args.action == "events":
        data = service.list_proxy_events(
            db_path=db,
            search=args.search,
            alerts_only=bool(args.alerts_only),
            traffic_kind=args.kind,
            limit=args.limit,
        )
        if args.json:
            print(json.dumps(data, indent=2))
            return 0
        print(f"{'TIME':<22} {'KIND':<10} {'ACTION':<9} {'RISK':<6} {'SERVICE/OP':<28} PRINCIPAL")
        print("-" * 100)
        for ev in data["events"]:
            op = f"{ev['service']}.{ev['operation']}"
            print(
                f"{str(ev['timestamp'])[:20]:<22} {ev['traffic_kind']:<10} {ev['action_taken']:<9} "
                f"{float(ev['risk_score']):<6.1f} {op[:27]:<28} {str(ev['principal'])[:32]}"
            )
        return 0

    if args.action == "simulate":
        res = service.simulate_proxy_traffic(db_path=db, scenario=args.scenario)
        if args.json:
            print(json.dumps(res, indent=2))
        else:
            print(f"Sent {res['sent_count']} requests through {res['status']['listen_url']} (scenario={args.scenario})")
            for req in res["requests"]:
                print(f"  {req['method']:<5} {req['path']:<36} -> HTTP {req['status']} [{req['action'] or 'allowed'} risk={req['risk'] or '0'}]")
        return 0

    if args.action == "clear":
        res = service.clear_proxy_events(db_path=db)
        print(json.dumps(res, indent=2))
        return 0

    return 0


def dynamic_main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="identity-shield dynamic", description="Manage dynamic behavioral rules & rule enhancement")
    sub = parser.add_subparsers(dest="action", required=True)

    p_ls = sub.add_parser("list", help="list dynamic behavioral rules")
    p_ls.add_argument("--db", default=None)
    p_ls.add_argument("--json", action="store_true")

    p_en = sub.add_parser("enable", help="enable a dynamic rule")
    p_en.add_argument("rule_id")
    p_en.add_argument("--db", default=None)

    p_dis = sub.add_parser("disable", help="disable a dynamic rule")
    p_dis.add_argument("rule_id")
    p_dis.add_argument("--db", default=None)

    p_add = sub.add_parser("add", help="add or update a dynamic behavioral rule")
    p_add.add_argument("--id", dest="rule_id", default=None)
    p_add.add_argument("--name", required=True)
    p_add.add_argument("--kind", required=True, choices=["velocity", "sequence", "drift", "app_anomaly"])
    p_add.add_argument("--severity", default="medium", choices=["low", "medium", "high", "critical"])
    p_add.add_argument("--window", type=int, default=60)
    p_add.add_argument("--threshold", type=int, default=3)
    p_add.add_argument("--config", default="{}")
    p_add.add_argument("--description", default="")
    p_add.add_argument("--db", default=None)

    p_del = sub.add_parser("delete", help="delete a dynamic rule")
    p_del.add_argument("rule_id")
    p_del.add_argument("--db", default=None)

    p_rep = sub.add_parser("replay", help="run dynamic behavioral detection against captured CloudTrail batch events")
    p_rep.add_argument("--run-id", default=None)
    p_rep.add_argument("--db", default=None)

    p_al = sub.add_parser("alerts", help="list fired dynamic behavioral alerts")
    p_al.add_argument("--source", default="", choices=["", "proxy", "batch"])
    p_al.add_argument("--limit", type=int, default=50)
    p_al.add_argument("--db", default=None)
    p_al.add_argument("--json", action="store_true")

    p_pr = sub.add_parser("profiles", help="list learned per-principal baselines")
    p_pr.add_argument("--db", default=None)
    p_pr.add_argument("--json", action="store_true")

    p_au = sub.add_parser("audit", help="audit static rules for hardcoded patterns and blind spots")
    p_au.add_argument("--ruleset", default="baseline-v1")
    p_au.add_argument("--db", default=None)
    p_au.add_argument("--json", action="store_true")

    p_eh = sub.add_parser("enhance", help="auto-enhance static rules into enhanced-v1 and replay")
    p_eh.add_argument("--ruleset", default="baseline-v1")
    p_eh.add_argument("--target", default="enhanced-v1")
    p_eh.add_argument("--db", default=None)
    p_eh.add_argument("--json", action="store_true")

    p_lp = sub.add_parser("loop", help="run Closed-Loop 5-Factor Alert/Resource -> Variant -> Harden engine")
    p_lp.add_argument(
        "--mode",
        choices=["from_alerts", "from_resources", "both", "alerts", "resources"],
        default="both",
        help="vector source: flagged alerts, discovered resources, or both",
    )
    p_lp.add_argument("--cloud", default="all", choices=["all", "aws", "gcp", "azure"])
    p_lp.add_argument("--limit", type=int, default=6)
    p_lp.add_argument("--pairwise", action="store_true", help="include full pairwise 5-factor combinations")
    p_lp.add_argument("--no-enhance", action="store_true", help="skip auto-generating hardened rules for misses")
    p_lp.add_argument("--preview", action="store_true", help="list discovered vectors without running variants")
    p_lp.add_argument("--db", default=None)
    p_lp.add_argument("--json", action="store_true")

    p_siem = sub.add_parser("siem-export", help="export a Sigma rule to CloudWatch Insights, GCP Logging/SecOps, or Sentinel KQL")
    p_siem.add_argument("--rule-id", required=True, help="native rule id or full rule_id")
    p_siem.add_argument("--ruleset", default="")
    p_siem.add_argument("--target", default="aws_cloudwatch", choices=["aws_cloudwatch", "gcp_logging", "gcp_secops", "azure_sentinel"])
    p_siem.add_argument("--db", default=None)
    p_siem.add_argument("--json", action="store_true")

    args = parser.parse_args(argv)
    db = service.resolve_db_path(getattr(args, "db", None))

    if args.action == "list":
        data = service.list_dynamic_rules_view(db_path=db)
        if args.json:
            print(json.dumps(data, indent=2))
            return 0
        print(f"{'RULE ID':<16} {'KIND':<13} {'SEV':<9} {'WIN/THR':<10} {'ON':<4} NAME")
        print("-" * 90)
        for r in data["rules"]:
            wt = f"{r['window_seconds']}s/{r['threshold']}"
            print(f"{r['rule_id']:<16} {r['kind']:<13} {r['severity']:<9} {wt:<10} {'yes' if r['enabled'] else 'no':<4} {r['name']}")
        return 0

    if args.action in {"enable", "disable"}:
        res = service.toggle_dynamic_rule_service(args.rule_id, args.action == "enable", db_path=db)
        print(json.dumps(res, indent=2))
        return 0

    if args.action == "add":
        res = service.save_dynamic_rule_service(
            {
                "rule_id": args.rule_id,
                "name": args.name,
                "kind": args.kind,
                "severity": args.severity,
                "window_seconds": args.window,
                "threshold": args.threshold,
                "config": args.config,
                "description": args.description,
            },
            db_path=db,
        )
        print(json.dumps(res, indent=2))
        return 0

    if args.action == "delete":
        print(json.dumps(service.delete_dynamic_rule_service(args.rule_id, db_path=db), indent=2))
        return 0

    if args.action == "replay":
        print(json.dumps(service.run_dynamic_replay_service(db_path=db, run_id=args.run_id), indent=2))
        return 0

    if args.action == "alerts":
        data = service.list_dynamic_alerts_view(db_path=db, source=args.source, limit=args.limit)
        if args.json:
            print(json.dumps(data, indent=2))
            return 0
        for a in data["alerts"]:
            print(f"[{a['severity']}] {a['rule_id']} ({a['source']}) {a['principal']} -> {a['summary']}")
        return 0

    if args.action == "profiles":
        data = service.list_principal_profiles_view(db_path=db)
        print(json.dumps(data, indent=2))
        return 0

    if args.action == "audit":
        data = service.audit_ruleset_view(db_path=db, ruleset_version=args.ruleset)
        if args.json:
            print(json.dumps(data, indent=2))
            return 0
        print(f"Ruleset {data['ruleset_version']}: {data['total_rules']} rules, {data['weak_rules']} weak, avg health {data['average_health_score']}")
        for r in data["rules"]:
            codes = ", ".join(w["code"] for w in r["weaknesses"]) or "healthy"
            print(f"  {r['technique_id']:<10} {r['health_score']:>3}/100  {r['title'][:36]:<36}  [{codes}]")
        return 0

    if args.action == "enhance":
        data = service.enhance_ruleset_service(
            source_ruleset=args.ruleset,
            target_ruleset=args.target,
            db_path=db,
        )
        print(json.dumps(data, indent=2))
        return 0

    if args.action == "loop":
        if args.preview:
            data = service.preview_closed_loop_service(
                mode=args.mode,
                limit=args.limit,
                cloud_provider=args.cloud,
                db_path=db,
            )
            print(json.dumps(data, indent=2))
            return 0
        report = service.run_closed_loop_service(
            mode=args.mode,
            include_pairwise=bool(args.pairwise),
            auto_enhance=not bool(args.no_enhance),
            limit=args.limit,
            cloud_provider=args.cloud,
            db_path=db,
        )
        if args.json:
            print(json.dumps(report, indent=2))
            return 0
        sm = report["summary"]
        print(
            f"Closed-Loop ({report['mode']} · {report.get('cloud_provider', 'all')}): {sm['vectors_tested']} vectors | "
            f"Before {sm['before_rate']}% -> After {sm['after_rate']}% | "
            f"Rules added: {sm['rules_generated']}"
        )
        return 0

    if args.action == "siem-export":
        res = service.export_siem_rule_service(
            {
                "rule_id": args.rule_id,
                "ruleset_version": args.ruleset,
                "target": args.target,
            },
            db_path=db,
        )
        if args.json:
            print(json.dumps(res, indent=2))
            return 0
        print(res.get("query") or "")
        for w in res.get("warnings") or []:
            print(f"# warning: {w}")
        return 0

    return 0
