"""Idempotent, additive multi-cloud SQLite schema migrations."""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from typing import Any

from identity_shield import config

LATEST_SCHEMA_VERSION = 3


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _tables(conn: sqlite3.Connection) -> set[str]:
    return {
        row[0]
        for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
    }


def _columns(conn: sqlite3.Connection, table: str) -> dict[str, tuple[Any, ...]]:
    return {
        row[1]: tuple(row)
        for row in conn.execute(f"PRAGMA table_info({table})")
    }


def _add_column_if_missing(
    conn: sqlite3.Connection,
    tables: set[str],
    table: str,
    column: str,
    ddl_type: str,
) -> bool:
    if table not in tables:
        return False
    cols = _columns(conn, table)
    if column in cols:
        return False
    conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {ddl_type}")
    return True


def _upgrade_principal_profile_pk(conn: sqlite3.Connection) -> bool:
    """Non-destructively upgrade legacy principal_profile (PK=principal) to PK=profile_key."""
    tables = _tables(conn)
    if "principal_profile" not in tables:
        return False
    cols = _columns(conn, "principal_profile")
    # PRAGMA table_info row[5] is pk index (>0 means part of primary key)
    pk_cols = [name for name, row in cols.items() if int(row[5] or 0) > 0]
    if pk_cols == ["profile_key"]:
        return False

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS principal_profile_v3 (
          profile_key         TEXT PRIMARY KEY,
          cloud_provider      TEXT NOT NULL DEFAULT 'aws',
          account_scope       TEXT NOT NULL DEFAULT '',
          principal           TEXT NOT NULL,
          known_user_agents   TEXT NOT NULL DEFAULT '[]',
          known_regions       TEXT NOT NULL DEFAULT '[]',
          known_services      TEXT NOT NULL DEFAULT '[]',
          known_operations    TEXT NOT NULL DEFAULT '[]',
          known_hours         TEXT NOT NULL DEFAULT '[]',
          request_count       INTEGER NOT NULL DEFAULT 0,
          cold_start_complete INTEGER NOT NULL DEFAULT 0,
          last_seen           TEXT NOT NULL,
          UNIQUE (cloud_provider, account_scope, principal)
        )
        """
    )
    has_provider = "cloud_provider" in cols
    has_scope = "account_scope" in cols
    has_cold = "cold_start_complete" in cols

    prov_expr = "COALESCE(NULLIF(cloud_provider, ''), 'aws')" if has_provider else "'aws'"
    scope_expr = "COALESCE(account_scope, '')" if has_scope else "''"
    cold_expr = (
        "CASE WHEN request_count >= 3 OR COALESCE(cold_start_complete, 0) = 1 THEN 1 ELSE 0 END"
        if has_cold
        else "CASE WHEN request_count >= 3 THEN 1 ELSE 0 END"
    )
    conn.execute(
        f"""
        INSERT OR IGNORE INTO principal_profile_v3 (
          profile_key, cloud_provider, account_scope, principal,
          known_user_agents, known_regions, known_services, known_operations,
          known_hours, request_count, cold_start_complete, last_seen
        )
        SELECT
          {prov_expr} || ':' || {scope_expr} || ':' || principal,
          {prov_expr},
          {scope_expr},
          principal,
          known_user_agents,
          known_regions,
          known_services,
          known_operations,
          known_hours,
          request_count,
          {cold_expr},
          last_seen
        FROM principal_profile
        """
    )
    conn.execute("DROP TABLE principal_profile")
    conn.execute("ALTER TABLE principal_profile_v3 RENAME TO principal_profile")
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_principal_profile_lookup ON principal_profile(cloud_provider, account_scope, principal)"
    )
    return True


def _record_migration(conn: sqlite3.Connection, version: int, name: str) -> None:
    conn.execute(
        """
        INSERT OR IGNORE INTO schema_migration (version, name, applied_at)
        VALUES (?, ?, ?)
        """,
        (version, name, _utc_now()),
    )


def apply_migrations(conn: sqlite3.Connection) -> list[int]:
    """Run all additive schema migrations cleanly and idempotently. Returns newly recorded versions."""
    tables = _tables(conn)

    # 1. Pre-schema ALTERs on legacy tables BEFORE schema.sql creates new multi-cloud indexes.
    _add_column_if_missing(conn, tables, "lab_run", "synthetic", "INTEGER NOT NULL DEFAULT 0")
    _add_column_if_missing(conn, tables, "ruleset", "manifest_sha256", "TEXT")
    _add_column_if_missing(conn, tables, "ruleset", "git_sha", "TEXT")

    _add_column_if_missing(conn, tables, "event", "cloud_provider", "TEXT NOT NULL DEFAULT 'aws'")
    _add_column_if_missing(conn, tables, "event", "account_scope", "TEXT NOT NULL DEFAULT ''")
    _add_column_if_missing(conn, tables, "event", "source_type", "TEXT NOT NULL DEFAULT 'cloudtrail'")
    _add_column_if_missing(conn, tables, "event", "schema_version", "TEXT NOT NULL DEFAULT '1.0'")

    _add_column_if_missing(conn, tables, "alert", "fixture_key", "TEXT")
    _add_column_if_missing(conn, tables, "alert", "cloud_provider", "TEXT NOT NULL DEFAULT 'aws'")

    _add_column_if_missing(conn, tables, "proxy_event", "cloud_provider", "TEXT NOT NULL DEFAULT 'unknown'")
    _add_column_if_missing(conn, tables, "proxy_event", "account_scope", "TEXT NOT NULL DEFAULT ''")
    _add_column_if_missing(conn, tables, "proxy_event", "traffic_type", "TEXT NOT NULL DEFAULT 'http_app'")
    _add_column_if_missing(conn, tables, "proxy_event", "classification_confidence", "TEXT NOT NULL DEFAULT 'high'")
    _add_column_if_missing(conn, tables, "proxy_event", "classification_reason", "TEXT NOT NULL DEFAULT ''")
    _add_column_if_missing(conn, tables, "proxy_event", "policy_decision", "TEXT NOT NULL DEFAULT 'allowed'")
    _add_column_if_missing(conn, tables, "proxy_event", "policy_reason", "TEXT NOT NULL DEFAULT ''")

    _add_column_if_missing(conn, tables, "dynamic_alert", "cloud_provider", "TEXT NOT NULL DEFAULT 'aws'")
    _add_column_if_missing(conn, tables, "dynamic_alert", "account_scope", "TEXT NOT NULL DEFAULT ''")
    _add_column_if_missing(conn, tables, "dynamic_alert", "ruleset_version", "TEXT")

    # 2. If legacy principal_profile existed with single-column PK, upgrade preserving all rows.
    if "principal_profile" in tables:
        _add_column_if_missing(conn, tables, "principal_profile", "profile_key", "TEXT")
        _add_column_if_missing(conn, tables, "principal_profile", "cloud_provider", "TEXT NOT NULL DEFAULT 'aws'")
        _add_column_if_missing(conn, tables, "principal_profile", "account_scope", "TEXT NOT NULL DEFAULT ''")
        _add_column_if_missing(conn, tables, "principal_profile", "cold_start_complete", "INTEGER NOT NULL DEFAULT 0")
        _upgrade_principal_profile_pk(conn)

    # Backfill proxy_event cloud_provider on legacy rows where empty/'unknown' for aws_api
    tables = _tables(conn)
    if "proxy_event" in tables:
        conn.execute(
            """
            UPDATE proxy_event
            SET cloud_provider = 'aws',
                traffic_type = 'cloud_api'
            WHERE traffic_kind = 'aws_api' AND (cloud_provider = 'unknown' OR cloud_provider = '')
            """
        )

    # 3. Apply CREATE TABLE IF NOT EXISTS / CREATE INDEX IF NOT EXISTS idempotently
    conn.executescript(config.SCHEMA_SQL.read_text(encoding="utf-8"))

    # 4. Track migration versions cleanly
    existing_versions = {
        row[0]
        for row in conn.execute("SELECT version FROM schema_migration").fetchall()
    }
    applied_now: list[int] = []
    specs = (
        (1, "core_lab_and_ruleset_manifests"),
        (2, "multicloud_event_proxy_alert_columns_and_technique_map"),
        (3, "scoped_principal_profile_identity_isolation"),
    )
    for ver, name in specs:
        if ver not in existing_versions:
            _record_migration(conn, ver, name)
            applied_now.append(ver)

    conn.commit()
    return applied_now
