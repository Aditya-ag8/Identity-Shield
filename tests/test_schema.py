from __future__ import annotations

import sqlite3

import pytest

from identity_shield.db.connection import connect
from identity_shield.db.init import init_db

EXPECTED_TABLES = {
    "lab_run",
    "technique",
    "variant",
    "trial",
    "fixture",
    "event",
    "ruleset",
    "rule",
    "alert",
    "rule_compile",
}

EXPECTED_VIEWS = {"v_fixture_outcome"}


def _objects(conn, kind):
    return {
        row[0]
        for row in conn.execute("SELECT name FROM sqlite_master WHERE type = ?", (kind,))
    }


def test_schema_creates_all_objects(db_path):
    init_db(db_path, drop=True)
    conn = connect(db_path)
    try:
        assert EXPECTED_TABLES <= _objects(conn, "table")
        assert EXPECTED_VIEWS <= _objects(conn, "view")
    finally:
        conn.close()


def test_init_is_idempotent(db_path):
    init_db(db_path, drop=True)
    init_db(db_path)
    conn = connect(db_path)
    try:
        assert EXPECTED_TABLES <= _objects(conn, "table")
    finally:
        conn.close()


def test_foreign_keys_are_enforced(db_path):
    init_db(db_path, drop=True)
    conn = connect(db_path)
    try:
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                "INSERT INTO variant (variant_id, technique_id, variant_set, factor_levels, seed, spec_sha256)"
                " VALUES ('v1', 'T9999.999', 'baseline', '{}', 0, 'x')"
            )
    finally:
        conn.close()


def test_variant_set_is_constrained(db_path):
    init_db(db_path, drop=True)
    conn = connect(db_path)
    try:
        conn.execute(
            "INSERT INTO technique (technique_id, name, tactic, executor, event_names,"
            " success_check, required_actions) VALUES ('T1', 't', 'discovery', 'boto3', '[]', '{}', '[]')"
        )
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                "INSERT INTO variant (variant_id, technique_id, variant_set, factor_levels, seed, spec_sha256)"
                " VALUES ('v1', 'T1', 'nonsense', '{}', 0, 'x')"
            )
    finally:
        conn.close()


def test_fixture_outcome_view_reflects_alerts(conn):
    from identity_shield.detect import replay

    loaded = replay.load_ruleset(conn, "baseline-v1")
    replay.run_replay(conn, loaded)

    rows = {row["fixture_key"]: row for row in conn.execute("SELECT * FROM v_fixture_outcome")}
    assert rows["T1098.001/catch"]["detected"] == 1
    assert rows["T1098.001/hard"]["detected"] == 0
    assert rows["T1098.001/catch"]["fired_rules"]
