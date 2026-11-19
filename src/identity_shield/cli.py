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
    from identity_shield.db.init import main as db_main
    from identity_shield.detect.loader import main as loader_main
    from identity_shield.detect.replay import main as replay_main

    steps: list[tuple[str, Callable[[list[str]], int], list[str]]] = [
        ("init", db_main, ["--drop"]),
        ("load", loader_main, []),
        ("replay", replay_main, ["--ruleset", "baseline-v1"]),
    ]
    for name, function, arguments in steps:
        print(f"\n=== {name} ===")
        code = function(arguments)
        if code != 0:
            return code
    return 0


def _variants(argv: list[str]) -> int:
    from identity_shield.variants.cli import main

    return main(argv)


def _lab(argv: list[str]) -> int:
    from identity_shield.lab.cli import main

    return main(argv)


COMMANDS: dict[str, Callable[[list[str]], int]] = {
    "init": _init,
    "load": _load,
    "replay": _replay,
    "compile": _compile,
    "demo": _demo,
    "variants": _variants,
    "lab": _lab,
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
