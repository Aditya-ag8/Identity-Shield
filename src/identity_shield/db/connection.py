from __future__ import annotations

import sqlite3
from pathlib import Path

from identity_shield import config


def connect_path(path: str | Path | None = None) -> Path:
    resolved = config.resolve_db(path)
    resolved.parent.mkdir(parents=True, exist_ok=True)
    return resolved


def connect(path: str | Path | None = None) -> sqlite3.Connection:
    """Open the database with the pragmas the schema relies on."""
    resolved = connect_path(path)
    conn = sqlite3.connect(resolved)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn
