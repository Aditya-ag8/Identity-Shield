"""Performance harness.

The user-visible question is "why does this take 20 minutes?". This command
answers it with a number instead of a guess. It runs the complete offline
pipeline against a throwaway database and prints a per-stage budget.

The live AWS stages are excluded on purpose; they are bounded by AWS, not by
this code.
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Callable

from identity_shield import config


def _timed(name: str, function: Callable[[], Any]) -> tuple[str, float, Any]:
    started = time.perf_counter()
    result = function()
    return name, time.perf_counter() - started, result


def run_benchmark(*, repetitions: int = 1) -> dict[str, Any]:
    from identity_shield.analysis import outcomes, report
    from identity_shield.contracts import write_variants
    from identity_shield.db.connection import connect
    from identity_shield.db.init import init_db
    from identity_shield.detect import loader, replay
    from identity_shield.runner import orchestrator
    from identity_shield.variants.benign import generate_benign
    from identity_shield.variants.cli import persist
    from identity_shield.variants.generator import generate
    from identity_shield.variants.loader import load_catalogue

    stages: list[dict[str, Any]] = []

    with tempfile.TemporaryDirectory(prefix="identity-shield-bench-") as directory:
        root = Path(directory)
        db = root / "bench.db"
        variants_path = root / "variants.jsonl"
        catalogue = load_catalogue()

        def stage(name: str, function: Callable[[], Any]) -> Any:
            label, seconds, result = _timed(name, function)
            stages.append({"stage": label, "seconds": round(seconds, 4)})
            return result

        stage("init", lambda: init_db(db, drop=True))
        conn = connect(db)
        try:
            stage("load techniques", lambda: loader.load_techniques(conn))
            stage("load fixtures", lambda: loader.load_fixtures(conn))
            loaded = stage("load ruleset", lambda: replay.load_ruleset(conn, "baseline-v1"))
            stage("fixture replay", lambda: replay.run_replay(conn, loaded))
            generated = stage("generate 332 variants", lambda: generate(catalogue))
            stage("write variants", lambda: write_variants(variants_path, generated.variants))
            stage("persist variants", lambda: persist(conn, list(generated.variants), catalogue))
            benign = stage("generate benign", lambda: list(generate_benign(catalogue)))
            stage("persist benign", lambda: persist(conn, benign, catalogue))
            visible = [
                variant
                for variant in generated.variants
                if variant.variant_set in {"baseline", "ofat", "pairwise"}
            ]
            campaign = stage(
                "synthetic campaign (visible)",
                lambda: orchestrator.run_campaign(
                    conn,
                    run_id="bench-run",
                    variants=visible,
                    catalogue=catalogue,
                    account_id="123456789012",
                    region="eu-west-1",
                    repetitions=repetitions,
                    synthetic=True,
                ),
            )
            stage("replay baseline", lambda: replay.run_replay(conn, replay.load_ruleset(conn, "baseline-v1")))
            stage("replay improved", lambda: replay.run_replay(conn, replay.load_ruleset(conn, "improved-v1")))
            stage("summarise", lambda: outcomes.summarise(conn, "baseline-v1", run_id="bench-run"))
            bundle = stage("report", lambda: report.build(conn, catalogue, run_id="bench-run"))
            stage("write report", lambda: report.write(bundle, directory=root))
        finally:
            conn.close()

    total = sum(row["seconds"] for row in stages)
    return {
        "stages": stages,
        "total_seconds": round(total, 4),
        "trials": campaign.trials,
        "artefacts": len(generated.variants) + len(benign),
        "repetitions": repetitions,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="identity-shield bench")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--budget", type=float, default=30.0, help="fail if total seconds exceed this")
    parser.add_argument("--repetitions", type=int, default=1)
    args = parser.parse_args(argv)

    result = run_benchmark(repetitions=args.repetitions)
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"{'stage':<32} {'seconds':>10}")
        print("-" * 44)
        for row in result["stages"]:
            print(f"{row['stage']:<32} {row['seconds']:>10.3f}")
        print("-" * 44)
        print(f"{'total':<32} {result['total_seconds']:>10.3f}")
        print(f"trials: {result['trials']}  artefacts: {result['artefacts']}")
        print(f"budget: {args.budget:.1f}s -> "
              f"{'PASS' if result['total_seconds'] <= args.budget else 'FAIL'}")

    return 0 if result["total_seconds"] <= args.budget else 1


if __name__ == "__main__":
    sys.exit(main())
