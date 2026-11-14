"""Load technique definitions and CloudTrail fixtures into SQLite.

    python -m identity_shield.detect.loader [--db PATH] [--reset]

Fixture layout::

    fixtures/cloudtrail/<TECHNIQUE_ID>/<flavour>.json
    fixtures/manifest.yaml        # fixture_key -> expected_detected

``flavour`` is one of ``catch``, ``obvious``, ``hard`` or ``benign``. The flavour
is our own expectation, not a property of CloudTrail: ``catch`` means "a
reasonable round-1 rule should fire here", ``hard`` means "we expect this to be
missed". The manifest records that expectation so the test suite can assert
against it.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

import yaml

from identity_shield import config
from identity_shield.db.connection import connect
from identity_shield.detect.parser import iter_events, normalize

TECHNIQUE_COLUMNS = (
    "technique_id",
    "name",
    "tactic",
    "executor",
    "executor_ref",
    "event_names",
    "requires_data_events",
    "success_check",
    "required_actions",
)


def load_techniques(conn, path: Path | None = None) -> int:
    path = path or config.TECHNIQUES_YAML
    document = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    entries = document.get("techniques") or []

    placeholders = ", ".join("?" for _ in TECHNIQUE_COLUMNS)
    updates = ", ".join(f"{column}=excluded.{column}" for column in TECHNIQUE_COLUMNS[1:])
    sql = (
        f"INSERT INTO technique ({', '.join(TECHNIQUE_COLUMNS)}) VALUES ({placeholders}) "
        f"ON CONFLICT(technique_id) DO UPDATE SET {updates}"
    )

    for entry in entries:
        values = (
            entry["technique_id"],
            entry["name"],
            entry["tactic"],
            entry["executor"],
            entry.get("executor_ref"),
            json.dumps(entry.get("event_names") or []),
            int(bool(entry.get("requires_data_events"))),
            json.dumps(entry.get("success_check") or {}),
            json.dumps(entry.get("required_actions") or []),
        )
        conn.execute(sql, values)

    conn.commit()
    return len(entries)


def load_manifest(path: Path | None = None) -> dict[str, int | None]:
    path = path or config.FIXTURE_MANIFEST
    if not path.exists():
        return {}
    document = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    fixtures = document.get("fixtures") or {}
    return {str(key): value for key, value in fixtures.items()}


def discover_fixtures(root: Path | None = None) -> list[tuple[Path, str, str, str]]:
    """Return (path, fixture_key, technique_id, flavour)."""
    root = root or config.FIXTURE_ROOT
    found: list[tuple[Path, str, str, str]] = []
    for path in sorted(root.rglob("*.json*")):
        if not path.is_file():
            continue
        technique_id = path.parent.name
        flavour = path.stem.split(".")[0]
        found.append((path, f"{technique_id}/{flavour}", technique_id, flavour))
    return found


def load_fixtures(conn, root: Path | None = None, manifest: dict[str, int | None] | None = None) -> dict[str, int]:
    root = root or config.FIXTURE_ROOT
    manifest = load_manifest() if manifest is None else manifest

    known = {row["technique_id"] for row in conn.execute("SELECT technique_id FROM technique")}
    expected_keys = set(manifest)
    seen_keys: set[str] = set()

    fixtures = 0
    events = 0
    warnings: list[str] = []

    for path, fixture_key, technique_id, flavour in discover_fixtures(root):
        if technique_id not in known:
            warnings.append(f"{path}: technique {technique_id!r} is not in techniques.yaml")
            technique_ref: str | None = None
        else:
            technique_ref = technique_id

        expected = manifest.get(fixture_key)
        if fixture_key not in expected_keys:
            warnings.append(f"{path}: no manifest entry, expected_detected left NULL")
        seen_keys.add(fixture_key)

        conn.execute(
            """
            INSERT INTO fixture (fixture_key, technique_id, flavour, path, expected_detected)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(fixture_key) DO UPDATE SET
                technique_id=excluded.technique_id,
                flavour=excluded.flavour,
                path=excluded.path,
                expected_detected=excluded.expected_detected
            """,
            (fixture_key, technique_ref, flavour, str(path.relative_to(config.ROOT)), expected),
        )
        fixtures += 1

        for event in iter_events(path):
            row = normalize(event)
            conn.execute(
                """
                INSERT INTO event (event_id, fixture_key, event_time, received_at,
                                   event_source, event_name, aws_region, source_ip,
                                   user_agent, user_identity_type, user_identity_arn,
                                   error_code, raw)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(event_id) DO UPDATE SET fixture_key=excluded.fixture_key
                """,
                (row.event_id, fixture_key, *row.as_tuple()[1:]),
            )
            events += 1

    for missing in sorted(expected_keys - seen_keys):
        warnings.append(f"manifest entry {missing!r} has no fixture file")

    conn.commit()
    return {"fixtures": fixtures, "events": events, "warnings": warnings}


def reset_fixtures(conn) -> None:
    conn.execute("DELETE FROM alert")
    conn.execute("DELETE FROM event WHERE trial_id IS NULL")
    conn.execute("DELETE FROM fixture")
    conn.commit()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Load techniques and CloudTrail fixtures.")
    parser.add_argument("--db", default=None)
    parser.add_argument("--reset", action="store_true", help="clear fixtures and events first")
    args = parser.parse_args(argv)

    conn = connect(args.db)
    try:
        technique_count = load_techniques(conn)
        if args.reset:
            reset_fixtures(conn)
        stats = load_fixtures(conn)
    finally:
        conn.close()

    print(f"techniques: {technique_count}")
    print(f"fixtures:   {stats['fixtures']}")
    print(f"events:     {stats['events']}")
    for warning in stats["warnings"]:
        print(f"warning: {warning}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
