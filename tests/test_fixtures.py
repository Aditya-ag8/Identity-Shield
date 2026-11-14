from __future__ import annotations

import json

import pytest

from identity_shield import config
from identity_shield.detect import loader
from identity_shield.detect.parser import extract_events


def test_techniques_are_loaded(conn):
    ids = {row["technique_id"] for row in conn.execute("SELECT technique_id FROM technique")}
    assert ids == {
        "T1087.004",
        "T1526",
        "T1580",
        "T1078.004",
        "T1098.001",
        "T1098.003",
        "T1552.005",
        "T1530",
    }


def test_every_manifest_entry_has_a_fixture(conn):
    manifest = loader.load_manifest()
    keys = {row["fixture_key"] for row in conn.execute("SELECT fixture_key FROM fixture")}
    assert set(manifest) == keys


def test_fixture_directories_belong_to_a_known_technique(conn):
    unknown = [
        row["fixture_key"]
        for row in conn.execute(
            "SELECT fixture_key FROM fixture WHERE technique_id IS NULL"
        )
    ]
    assert not unknown


@pytest.mark.parametrize("path", sorted(config.FIXTURE_ROOT.rglob("*.json")), ids=lambda p: p.parent.name + "/" + p.stem)
def test_fixture_is_a_parseable_cloudtrail_event(path):
    payload = json.loads(path.read_text(encoding="utf-8"))
    events = extract_events(payload)
    assert len(events) == 1, "each M0 fixture holds exactly one event"

    event = events[0]
    for field in ("eventID", "eventTime", "eventName", "eventSource", "userIdentity"):
        assert event.get(field), f"{path.name} missing {field}"

    assert event["eventTime"].endswith("Z")
    assert event["userIdentity"].get("type")
    assert event["userIdentity"].get("arn")


def test_flavours_are_known(conn):
    flavours = {row["flavour"] for row in conn.execute("SELECT DISTINCT flavour FROM fixture")}
    assert flavours <= {"catch", "obvious", "hard", "benign"}
    assert flavours == {"catch", "obvious", "hard"}


def test_each_technique_has_the_three_flavours(conn):
    rows = conn.execute(
        "SELECT technique_id, COUNT(*) AS n FROM fixture GROUP BY technique_id"
    ).fetchall()
    assert len(rows) == 8
    assert all(row["n"] == 3 for row in rows)
