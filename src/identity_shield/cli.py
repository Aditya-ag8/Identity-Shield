"""Single entry point for the M0 workflow.

    identity-shield init
    identity-shield load --reset
    identity-shield replay --ruleset baseline-v1
    identity-shield compile --db data/identity_shield.db
    identity-shield demo          # init + load + replay, in order
"""

from __future__ import annotations

import argparse
import sys
from typing import Callable


def _init(argv: list[str]) -> int:
    from identity_shield.db.init import main

    return main(argv)


def _load(argv: list[str]) -> int:
    from identity_shield.detect.loader import main

    return main(argv)


def _replay(argv: list[str]) -> int:
    from identity_shield.detect.replay import main

    return main(argv)


def _compile(argv: list[str]) -> int:
    from identity_shield.detect.pysigma_backend import main

    return main(argv)


def _demo(argv: list[str]) -> int:
    import time

    from identity_shield.db.init import main as db_main
    from identity_shield.detect.loader import main as loader_main
    from identity_shield.detect.replay import main as replay_main

    full = "--full" in argv
    steps: list[tuple[str, Callable[[list[str]], int], list[str]]] = [
        ("init", db_main, ["--drop"]),
        ("load", loader_main, []),
        ("replay", replay_main, ["--ruleset", "baseline-v1"]),
    ]
    if full:
        from identity_shield.analysis.cli import main as analyse_main
        from identity_shield.runner.cli import main as runner_main
        from identity_shield.variants.cli import main as variants_main

        steps += [
            ("variants", variants_main, ["generate", "--db", "data/identity_shield.db"]),
            ("benign", variants_main, ["benign", "--db", "data/identity_shield.db"]),
            (
                "rehearsal",
                runner_main,
                [
                    "campaign",
                    "--synthetic",
                    "--yes",
                    "--set",
                    "all",
                    "--set",
                    "benign",
                    "--db",
                    "data/identity_shield.db",
                ],
            ),
            (
                "report",
                analyse_main,
                ["report", "--db", "data/identity_shield.db"],
            ),
        ]

    started = time.perf_counter()
    timings: list[tuple[str, float]] = []
    for name, function, arguments in steps:
        print(f"\n=== {name} ===")
        step_started = time.perf_counter()
        code = function(arguments)
        timings.append((name, time.perf_counter() - step_started))
        if code != 0:
            return code
    elapsed = time.perf_counter() - started
    print("\n=== timing ===")
    for name, duration in timings:
        print(f"  {name:<12} {duration:6.2f}s")
    print(f"  {'total':<12} {elapsed:6.2f}s")
    return 0


def _variants(argv: list[str]) -> int:
    from identity_shield.variants.cli import main

    return main(argv)


def _lab(argv: list[str]) -> int:
    from identity_shield.lab.cli import main

    return main(argv)


def _runner(argv: list[str]) -> int:
    from identity_shield.runner.cli import main

    return main(argv)


def _analyse(argv: list[str]) -> int:
    from identity_shield.analysis.cli import main

    return main(argv)


def _bench(argv: list[str]) -> int:
    from identity_shield.bench import main

    return main(argv)


def _attacks(argv: list[str]) -> int:
    from identity_shield.ops_cli import attacks_main

    return attacks_main(argv)


def _config(argv: list[str]) -> int:
    from identity_shield.ops_cli import config_main

    return config_main(argv)


def _logs(argv: list[str]) -> int:
    from identity_shield.ops_cli import logs_main

    return logs_main(argv)


def _ui(argv: list[str]) -> int:
    from identity_shield.ops_cli import ui_main

    return ui_main(argv)


def _proxy(argv: list[str]) -> int:
    from identity_shield.ops_cli import proxy_main

    return proxy_main(argv)


def _dynamic(argv: list[str]) -> int:
    from identity_shield.ops_cli import dynamic_main

    return dynamic_main(argv)


COMMANDS: dict[str, Callable[[list[str]], int]] = {
    "init": _init,
    "load": _load,
    "replay": _replay,
    "compile": _compile,
    "demo": _demo,
    "variants": _variants,
    "lab": _lab,
    "runner": _runner,
    "analyse": _analyse,
    "bench": _bench,
    "attacks": _attacks,
    "config": _config,
    "logs": _logs,
    "proxy": _proxy,
    "dynamic": _dynamic,
    "ui": _ui,
}


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)

    parser = argparse.ArgumentParser(
        prog="identity-shield",
        description="Detection-robustness testing for AWS CloudTrail rules.",
    )
    parser.add_argument("command", choices=sorted(COMMANDS), help="what to do")
    parser.add_argument("args", nargs=argparse.REMAINDER, help="passed to the subcommand")
    parsed = parser.parse_args(argv)

    return COMMANDS[parsed.command](parsed.args)


if __name__ == "__main__":
    sys.exit(main())
