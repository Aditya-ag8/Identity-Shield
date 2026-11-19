"""Analysis command line.

    identity-shield analyse summary
    identity-shield analyse misses --out data/findings.json
    identity-shield analyse diff
    identity-shield analyse report
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from identity_shield import config
from identity_shield.analysis import misses, outcomes, report
from identity_shield.contracts import ContractError, write_findings, write_json


def _pct(value: float | int | None) -> str:
    return "n/a" if value is None else f"{float(value):.1%}"


def _connect(path):
    from identity_shield.db.connection import connect

    return connect(path)


def _maybe_replay(conn, versions: list[str]) -> None:
    from identity_shield.detect import replay

    for version in versions:
        try:
            loaded = replay.load_ruleset(conn, version)
            replay.run_replay(conn, loaded)
        except KeyError:
            print(f"warning: ruleset {version!r} is not registered", file=sys.stderr)


def _summary(args) -> int:
    conn = _connect(args.db)
    try:
        if args.replay:
            _maybe_replay(conn, [args.ruleset, args.improved])
        summary = outcomes.summarise(conn, args.ruleset, run_id=args.run)
        try:
            paired = outcomes.paired(conn, args.ruleset, args.improved, run_id=args.run)
        except Exception:  # noqa: BLE001
            paired = None
        false_alarms = outcomes.false_alarms(conn, args.ruleset, run_id=args.run)
    finally:
        conn.close()

    if args.json:
        print(json.dumps({"summary": summary, "paired": paired, "false_alarms": false_alarms}, indent=2))
        return 0

    overall = summary["overall"]
    print(f"ruleset:        {args.ruleset}")
    print(f"run:            {args.run or 'all runs'}")
    print(f"provenance:     {summary['provenance']['live_trials']} live, "
          f"{summary['provenance']['synthetic_trials']} synthetic")
    print(f"valid trials:   {overall['valid']}")
    print(f"detected:       {overall['detected']} ({_pct(overall['detection_rate'])}, "
          f"Wilson {_pct(overall['wilson_low'])}-{_pct(overall['wilson_high'])})")
    print(f"evasion:        {_pct(overall['evasion_rate'])}")
    print(f"invalid:        {overall['invalid_or_unverified']}")
    print()
    print(f"{'technique':<12} {'valid':>6} {'detected':>9} {'evasion':>8}")
    for technique, entry in summary["techniques"].items():
        print(f"{technique:<12} {entry['valid']:>6} {entry['detected']:>9} "
              f"{_pct(entry['evasion_rate']):>8}")
    if paired:
        test = paired["mcnemar"]
        print()
        print(f"paired:         {paired['pairs']} trials, delta {paired['delta']:+.1%}, "
              f"McNemar p={test['p_value']:.4g} "
              f"(baseline-only {test['baseline_only']}, improved-only {test['improved_only']})")
    print(f"benign:         {false_alarms['alerted']}/{false_alarms['trials']} alerted "
          f"({_pct(false_alarms['rate'])})")
    return 0


def _misses(args) -> int:
    from identity_shield.variants.loader import load_catalogue

    conn = _connect(args.db)
    try:
        if args.replay:
            _maybe_replay(conn, [args.ruleset])
        artifact = misses.build(
            conn,
            load_catalogue(),
            args.ruleset,
            run_id=args.run,
            include_holdout=args.include_holdout,
        )
    finally:
        conn.close()
    path = Path(args.out) if args.out else config.DATA / "findings.json"
    write_findings(path, artifact)
    if args.json:
        print(json.dumps(artifact.to_dict(), indent=2))
    else:
        print(f"findings: {len(artifact.findings)}")
        print(f"written:  {path}")
        for finding in artifact.findings[:10]:
            print(f"  {finding.technique_id} {finding.variant_id}: {finding.rationale[:120]}")
    return 0


def _diff(args) -> int:
    conn = _connect(args.db)
    try:
        if args.replay:
            _maybe_replay(conn, [args.ruleset, args.improved])
        diff = outcomes.rule_diff(conn, args.ruleset, args.improved)
    finally:
        conn.close()
    if args.json:
        print(json.dumps(diff, indent=2))
    else:
        print(f"baseline: {diff['counts']['baseline']} rules")
        print(f"improved: {diff['counts']['improved']} rules")
        print(f"added:    {len(diff['added'])}")
        for row in diff["added"]:
            print(f"  + {row['native_id']} {row['title']}")
        print(f"removed:  {len(diff['removed'])}")
        for row in diff["removed"]:
            print(f"  - {row['native_id']} {row['title']}")
    return 0


def _report(args) -> int:
    from identity_shield.variants.loader import load_catalogue

    conn = _connect(args.db)
    try:
        if args.replay:
            _maybe_replay(conn, [args.ruleset, args.improved])
        bundle = report.build(
            conn,
            load_catalogue(),
            ruleset=args.ruleset,
            improved=args.improved,
            run_id=args.run,
            include_holdout=args.include_holdout,
        )
    finally:
        conn.close()
    directory = Path(args.out_dir) if args.out_dir else config.DATA
    markdown_path, json_path = report.write(bundle, directory=directory)
    if args.json:
        print(json.dumps({key: value for key, value in bundle.items() if key != "markdown"}, indent=2))
    else:
        print(f"report: {markdown_path}")
        print(f"json:   {json_path}")
        print(f"provenance: {bundle['provenance']['live_trials']} live, "
              f"{bundle['provenance']['synthetic_trials']} synthetic")
        print(f"baseline detection: {_pct(bundle['baseline']['overall']['detection_rate'])}")
        if bundle.get("improved"):
            print(f"improved detection: {_pct(bundle['improved']['overall']['detection_rate'])}")
    return 0


def _add_common(parser) -> None:
    parser.add_argument("--db", default=None)
    parser.add_argument("--ruleset", default="baseline-v1")
    parser.add_argument("--improved", default="improved-v1")
    parser.add_argument("--run", default=None, help="limit to one run_id")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--replay", action="store_true", default=True)
    parser.add_argument("--no-replay", action="store_false", dest="replay")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="identity-shield analyse")
    commands = parser.add_subparsers(dest="command", required=True)

    summary_parser = commands.add_parser("summary", help="detection and evasion rates")
    _add_common(summary_parser)
    summary_parser.set_defaults(handler=_summary)

    misses_parser = commands.add_parser("misses", help="write findings.json for missed variants")
    _add_common(misses_parser)
    misses_parser.add_argument("--out", default=None)
    misses_parser.add_argument("--include-holdout", action="store_true")
    misses_parser.set_defaults(handler=_misses)

    diff_parser = commands.add_parser("diff", help="compare baseline and improved rule sets")
    _add_common(diff_parser)
    diff_parser.set_defaults(handler=_diff)

    report_parser = commands.add_parser("report", help="write report.md and report.json")
    _add_common(report_parser)
    report_parser.add_argument("--out-dir", default=None)
    report_parser.add_argument("--include-holdout", action="store_true")
    report_parser.set_defaults(handler=_report)

    args = parser.parse_args(argv)
    try:
        return args.handler(args)
    except ContractError as exc:
        print(f"contract error: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:  # noqa: BLE001 - CLI boundary
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
