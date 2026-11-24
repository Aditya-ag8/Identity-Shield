"""Create or reset the Identity Shield database.

    python -m identity_shield.db.init [--db PATH] [--drop]
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from identity_shield import config
from identity_shield.db.connection import connect, connect_path


def init_db(path: str | Path | None = None, drop: bool = False) -> Path:
    resolved = connect_path(path)
    schema = config.SCHEMA_SQL.read_text(encoding="utf-8")

    if drop and resolved.exists():
        conn = connect(resolved)
        conn.close()
        for suffix in ("", "-wal", "-shm"):
            candidate = Path(str(resolved) + suffix)
            if candidate.exists():
                candidate.unlink()
        resolved = connect_path(path)

    conn = connect(resolved)
    try:
        # Additive migrations for databases created before the column existed.
        # The schema file itself cannot do this because CREATE TABLE IF NOT
        # EXISTS leaves an old table untouched, and the trial view references
        # the column.
        tables = {
            row["name"]
            for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
        }
        if "lab_run" in tables:
            columns = {row["name"] for row in conn.execute("PRAGMA table_info(lab_run)")}
            if "synthetic" not in columns:
                conn.execute(
                    "ALTER TABLE lab_run ADD COLUMN synthetic INTEGER NOT NULL DEFAULT 0"
                )
        if "ruleset" in tables:
            columns = {row["name"] for row in conn.execute("PRAGMA table_info(ruleset)")}
            if "manifest_sha256" not in columns:
                conn.execute(
                    "ALTER TABLE ruleset ADD COLUMN manifest_sha256 TEXT"
                )
            if "git_sha" not in columns:
                conn.execute(
                    "ALTER TABLE ruleset ADD COLUMN git_sha TEXT"
                )
        conn.executescript(schema)
        conn.commit()
    finally:
        conn.close()
    return resolved


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Create or reset the Identity Shield database.")
    parser.add_argument("--db", default=None, help="database path (default: data/identity_shield.db)")
    parser.add_argument("--drop", action="store_true", help="delete the existing database first")
    args = parser.parse_args(argv)

    resolved = init_db(args.db, drop=args.drop)
    print(f"database ready: {resolved}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
