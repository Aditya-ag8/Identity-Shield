"""Runner command line.

    identity-shield runner campaign --synthetic --yes
    identity-shield runner campaign --synthetic --set baseline --technique T1530
    identity-shield runner preflight --variant-id T1530-ofat-000
    identity-shield runner collect --trial-id ...
    identity-shield runner sweep --run-id ...

Live campaigns require ``--yes``. The synthetic rehearsal is clearly labelled
and never needs AWS credentials.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from identity_shield import config
from identity_shield.contracts import Variant, read_variants
from identity_shield.runner import orchestrator, preflight, sweeper
from identity_shield.runner.models import TrialContext
from identity_shield.variants.benign import generate_benign, load_benign
from identity_shield.variants.loader import load_catalogue


def _now_run_id(prefix: str) -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"{prefix}-{stamp}"


def _connect(path):
    from identity_shield.db.connection import connect

    return connect(path)


def _load_file(path: Path, *, include_holdout: bool) -> list[Variant]:
    if not path.exists():
        return []
    return read_variants(path, include_holdout=include_holdout)


def _catalogue_techniques(catalogue, names: list[str] | None):
    wanted = {name.upper() for name in names or []}
    return tuple(
        technique
        for technique in catalogue.techniques
        if not wanted or technique.technique_id in wanted
    )


def _select(
    catalogue,
    *,
    sets: list[str],
    techniques: list[str] | None,
    include_holdout: bool,
) -> list[Variant]:
    attack_sets = {"baseline", "ofat", "pairwise", "holdout"}
    benign = "benign" in sets
    wanted = set(sets)
    if "all" in wanted or "visible" in wanted:
        wanted |= {"baseline", "ofat", "pairwise"}
    if include_holdout:
        wanted.add("holdout")
    wanted &= attack_sets

    variants: list[Variant] = []
    if wanted:
        path = config.VARIANTS_DIR / "variants.jsonl"
        variants.extend(
            variant
            for variant in _load_file(path, include_holdout=include_holdout)
            if variant.variant_set in wanted
            and (
                not techniques
                or variant.technique_id in {name.upper() for name in techniques}
            )
        )
    if benign:
        path = config.VARIANTS_DIR / "benign.jsonl"
        rows = _load_file(path, include_holdout=True)
        if not rows:
            rows = list(
                generate_benign(
                    catalogue,
                    activities=load_benign(),
                )
            )
            from identity_shield.contracts import write_variants

            write_variants(path, rows)
        variants.extend(
            variant
            for variant in rows
            if not techniques
            or variant.technique_id in {name.upper() for name in techniques}
        )
    return variants


def _persist(conn, variants: list[Variant], catalogue) -> None:
    if not variants:
        return
    from identity_shield.variants.cli import persist

    persist(conn, variants, catalogue, prune=False)


def _run_summary(conn, run_id: str) -> dict[str, Any]:
    rows = conn.execute(
        """
        SELECT v.variant_set, COUNT(*) AS trials,
               SUM(CASE WHEN t.attack_succeeded = 1 THEN 1 ELSE 0 END) AS succeeded,
               SUM(CASE WHEN t.variant_changed = 1 THEN 1 ELSE 0 END) AS changed,
               SUM(CASE WHEN t.error IS NOT NULL THEN 1 ELSE 0 END) AS errors
        FROM trial t JOIN variant v ON v.variant_id = t.variant_id
        WHERE t.run_id = ? GROUP BY v.variant_set ORDER BY v.variant_set
        """,
        (run_id,),
    ).fetchall()
    return {
        "run_id": run_id,
        "sets": {row["variant_set"]: dict(row) for row in rows},
    }


def _campaign(args) -> int:
    catalogue = load_catalogue()
    if args.synthetic:
        variants = _select(
            catalogue,
            sets=args.set or ["all"],
            techniques=args.technique,
            include_holdout=False,
        )
    else:
        if not args.yes:
            print("refusing to run a live campaign without --yes", file=sys.stderr)
            return 2
        variants = _select(
            catalogue,
            sets=args.set or ["all"],
            techniques=args.technique,
            include_holdout=False,
        )

    if not variants:
        print("no variants selected; run `identity-shield variants generate` first", file=sys.stderr)
        return 2

    run_id = args.run_id or _now_run_id("sim" if args.synthetic else "run")
    conn = _connect(args.db)
    try:
        _persist(conn, variants, catalogue)
        session = None
        if not args.synthetic:
            from identity_shield.lab.aws import LabSession

            session = LabSession(
                region_name=args.region, profile_name=args.profile or None
            )
            if not session.has_credentials():
                print(
                    f"no AWS credentials found for profile {args.profile!r}",
                    file=sys.stderr,
                )
                return 2
        lab = {
            "queue_url": args.queue_url,
            "trail_name": args.trail_name,
            "data_bucket": args.bucket,
            "data_key": args.key,
            "instance_id": args.instance_id,
            "test_user_name": args.test_user,
            "admin_role_name": args.admin_role,
            "aws_profile": args.profile,
            "ruleset_version": args.ruleset,
        }
        result = orchestrator.run_campaign(
            conn,
            run_id=run_id,
            variants=variants,
            catalogue=catalogue,
            account_id=args.account_id or "123456789012",
            region=args.region,
            repetitions=args.repetitions,
            synthetic=args.synthetic,
            session=session,
            lab=lab,
            force=args.force,
        )
        summary = _run_summary(conn, run_id)
        if args.replay:
            from identity_shield.detect import replay

            for ruleset in (args.ruleset, "improved-v1"):
                try:
                    loaded = replay.load_ruleset(conn, ruleset)
                    replay.run_replay(conn, loaded)
                except KeyError:
                    continue
        if args.json:
            print(json.dumps({**result.to_dict(), **summary, "synthetic": args.synthetic}, indent=2))
        else:
            print(f"run:        {run_id}")
            print(f"provenance: {'SYNTHETIC REHEARSAL' if args.synthetic else 'live lab'}")
            print(f"trials:     {result.trials}")
            print(f"verified:   {result.succeeded}")
            print(f"errors:     {len(result.errors)}")
            print()
            for set_name, row in summary["sets"].items():
                print(
                    f"  {set_name:<10} trials={row['trials']:>4} "
                    f"verified={row['succeeded']:>4} changed={row['changed']:>4} "
                    f"errors={row['errors']:>4}"
                )
            if result.errors:
                print("\nfirst errors:", file=sys.stderr)
                for error in result.errors[:8]:
                    print(f"  {error}", file=sys.stderr)
        return 0
    finally:
        conn.close()


def _preflight_cmd(args) -> int:
    catalogue = load_catalogue()
    conn = _connect(args.db)
    try:
        variants = _load_file(config.VARIANTS_DIR / "variants.jsonl", include_holdout=False)
        variant = next((row for row in variants if row.variant_id == args.variant_id), None)
        if variant is None:
            print(f"unknown variant {args.variant_id!r}; generate variants first", file=sys.stderr)
            return 2
        technique = catalogue.technique(variant.technique_id)
        from identity_shield.lab.aws import LabSession

        session = (
            None
            if args.synthetic
            else LabSession(region_name=args.region, profile_name=args.profile or None)
        )
        if session is not None and not session.has_credentials():
            print("no AWS credentials found", file=sys.stderr)
            return 2
        ctx = TrialContext(
            run_id=args.run_id or _now_run_id("preflight"),
            variant=variant,
            technique=technique,
            repetition=1,
            account_id=args.account_id or "123456789012",
            region=args.region,
            lab={
                "trail_name": args.trail_name,
                "queue_url": args.queue_url,
                "test_user_name": args.test_user,
                "admin_role_name": args.admin_role,
                "data_bucket": args.bucket,
                "instance_id": args.instance_id,
            },
            synthetic=args.synthetic,
            session=session,
        )
        report = preflight.run_preflight(ctx)
        if args.json:
            print(json.dumps(report.to_dict(), indent=2))
        else:
            for check in report.checks:
                print(f"{check.status:<5} {check.name:<18} {check.detail}")
            print("ready" if report.ok else "NOT READY")
        return 0 if report.ok else 1
    finally:
        conn.close()


def _collect(args) -> int:
    from identity_shield.lab.aws import LabSession
    from identity_shield.runner.collector import CloudTrailCollector

    session = LabSession(region_name=args.region, profile_name=args.profile or None)
    if not session.has_credentials():
        print("no AWS credentials found", file=sys.stderr)
        return 2
    collector = CloudTrailCollector(
        session.client("sqs", region_name=args.region),
        session.client("s3", region_name=args.region),
        args.queue_url,
    )
    conn = _connect(args.db)
    try:
        result = collector.collect(
            conn,
            trial_id=args.trial_id,
            start=args.start,
            end=args.end,
            expected_event_names=args.event or (),
            timeout=args.timeout,
        )
    finally:
        conn.close()
    payload = {
        "events": result.events,
        "expected_seen": result.expected_seen,
        "missing": result.missing,
        "timed_out": result.timed_out,
        "messages": result.messages,
        "error": result.error,
    }
    print(json.dumps(payload, indent=2))
    return 0 if not result.timed_out and not result.error else 1


def _sweep(args) -> int:
    from identity_shield.lab.aws import LabSession

    session = LabSession(region_name=args.region, profile_name=args.profile or None)
    if not session.has_credentials():
        print("no AWS credentials found", file=sys.stderr)
        return 2
    residue = sweeper.find_residue(session, run_id=args.run_id, region=args.region)
    print(json.dumps({"run_id": args.run_id, "residue": residue, "ok": not residue}, indent=2))
    return 0 if not residue else 1


def _add_common(parser) -> None:
    parser.add_argument("--db", default=None)
    parser.add_argument("--region", default="eu-west-1")
    parser.add_argument("--json", action="store_true")


def _add_campaign(commands) -> None:
    parser = commands.add_parser("campaign", help="run selected variants")
    _add_common(parser)
    parser.add_argument("--run-id", default=None)
    parser.add_argument("--set", action="append", choices=["all", "visible", "baseline", "ofat", "pairwise", "holdout", "benign"])
    parser.add_argument("--technique", action="append")
    parser.add_argument("--repetitions", type=int, default=1)
    parser.add_argument("--synthetic", action="store_true", help="offline rehearsal; no AWS calls")
    parser.add_argument("--yes", action="store_true")
    parser.add_argument("--force", action="store_true", help="overwrite an existing trial")
    parser.add_argument("--replay", action="store_true", default=True)
    parser.add_argument("--no-replay", action="store_false", dest="replay")
    parser.add_argument("--account-id", default=None)
    parser.add_argument("--queue-url", default=None)
    parser.add_argument("--trail-name", default="identity-shield-trail")
    parser.add_argument("--bucket", default="is-lab-crown-jewels")
    parser.add_argument("--key", default="finance/approved.csv")
    parser.add_argument("--instance-id", default=None)
    parser.add_argument("--test-user", default="is-test-user")
    parser.add_argument("--admin-role", default="is-admin-role")
    parser.add_argument("--profile", default="lab")
    parser.add_argument("--ruleset", default="baseline-v1")
    parser.set_defaults(handler=_campaign)


def _add_preflight(commands) -> None:
    parser = commands.add_parser("preflight", help="check one variant before running it")
    _add_common(parser)
    parser.add_argument("--variant-id", required=True)
    parser.add_argument("--run-id", default=None)
    parser.add_argument("--account-id", default=None)
    parser.add_argument("--queue-url", default=None)
    parser.add_argument("--trail-name", default="identity-shield-trail")
    parser.add_argument("--bucket", default="is-lab-crown-jewels")
    parser.add_argument("--instance-id", default=None)
    parser.add_argument("--test-user", default="is-test-user")
    parser.add_argument("--admin-role", default="is-admin-role")
    parser.add_argument("--profile", default="lab")
    parser.add_argument("--synthetic", action="store_true")
    parser.set_defaults(handler=_preflight_cmd)


def _add_collect(commands) -> None:
    parser = commands.add_parser("collect", help="consume CloudTrail objects from SQS for one trial window")
    _add_common(parser)
    parser.add_argument("--queue-url", required=True)
    parser.add_argument("--trial-id", required=True)
    parser.add_argument("--start", required=True)
    parser.add_argument("--end", required=True)
    parser.add_argument("--event", action="append")
    parser.add_argument("--timeout", type=int, default=120)
    parser.add_argument("--profile", default="lab")
    parser.set_defaults(handler=_collect)


def _add_sweep(commands) -> None:
    parser = commands.add_parser("sweep", help="find tagged residue for a run")
    _add_common(parser)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--profile", default="lab")
    parser.set_defaults(handler=_sweep)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="identity-shield runner")
    commands = parser.add_subparsers(dest="command", required=True)
    _add_campaign(commands)
    _add_preflight(commands)
    _add_collect(commands)
    _add_sweep(commands)
    args = parser.parse_args(argv)
    try:
        return args.handler(args)
    except Exception as exc:  # noqa: BLE001 - CLI boundary
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
