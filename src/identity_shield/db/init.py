"""Create or reset the Identity Shield database.

    python -m identity_shield.db.init [--db PATH] [--drop]
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from identity_shield import config
from identity_shield.db.connection import connect, connect_path
from identity_shield.db.migrations import apply_migrations


def init_db(path: str | Path | None = None, drop: bool = False) -> Path:
    resolved = connect_path(path)

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
        apply_migrations(conn)
    finally:
        conn.close()
    return resolved


def ensure_tables(conn) -> None:
    """Idempotently apply any newly added schema tables and migrations onto an open connection."""
    apply_migrations(conn)


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
