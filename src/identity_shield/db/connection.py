from __future__ import annotations

import sqlite3
from pathlib import Path

from identity_shield import config


def connect_path(path: str | Path | None = None) -> Path:
    resolved = config.resolve_db(path)
    resolved.parent.mkdir(parents=True, exist_ok=True)
    return resolved


def connect(path: str | Path | None = None) -> sqlite3.Connection:
    """Open the database with the pragmas the schema relies on.

    ``synchronous=NORMAL`` is safe with WAL and removes an fsync per commit,
    which is the difference between a replay that takes seconds and one that
    takes minutes once the event table grows. The database is disposable lab
    output, not accounting data.
    """
    resolved = connect_path(path)
    conn = sqlite3.connect(resolved, timeout=30.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 30000")
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA synchronous = NORMAL")
    conn.execute("PRAGMA temp_store = MEMORY")
    conn.execute("PRAGMA cache_size = -64000")
    return conn
