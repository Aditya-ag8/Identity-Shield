from __future__ import annotations

from identity_shield.detect import replay


def test_ruleset_loads_pysigma_and_python_rules(conn):
    loaded = replay.load_ruleset(conn, "baseline-v1")
    assert loaded.rules
    assert loaded.statuses.get("pysigma", 0) >= 8
    assert any(rule.loader == "python" for rule in loaded.rules)
    assert loaded.compile_rate == 1.0


def test_every_fixture_meets_its_expectation(conn):
    loaded = replay.load_ruleset(conn, "baseline-v1")
    stats = replay.run_replay(conn, loaded)
    assert stats["events"] == 24
    assert stats["alerts"] > 0

    summary = replay.fixture_summary(conn, loaded.version)
    assert len(summary) == 24

    mismatches = [
        (row["fixture_key"], row["expected_detected"], row["detected"])
        for row in summary
        if row["expected_detected"] is not None and row["detected"] != row["expected_detected"]
    ]
    assert not mismatches


def test_replay_is_idempotent(conn):
    loaded = replay.load_ruleset(conn, "baseline-v1")
    first = replay.run_replay(conn, loaded)
    second = replay.run_replay(conn, loaded)
    assert first["alerts"] == second["alerts"]
    count = conn.execute("SELECT COUNT(*) FROM alert").fetchone()[0]
    assert count == first["alerts"]


def test_unknown_ruleset_is_rejected(conn):
    import pytest

    with pytest.raises(KeyError):
        replay.load_ruleset(conn, "does-not-exist")


def test_alert_links_back_to_the_rule_that_fired(conn):
    loaded = replay.load_ruleset(conn, "baseline-v1")
    replay.run_replay(conn, loaded)

    rows = conn.execute(
        """
        SELECT r.native_id, r.loader, COUNT(*) AS alerts
        FROM alert a JOIN rule r ON r.rule_id = a.rule_id
        GROUP BY r.rule_id ORDER BY alerts DESC
        """
    ).fetchall()
    assert rows
    assert {row["loader"] for row in rows} <= {"pysigma", "fallback", "python"}
