from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("streamlit")

from streamlit.testing.v1 import AppTest  # noqa: E402

from identity_shield.db.connection import connect  # noqa: E402
from identity_shield.db.init import init_db  # noqa: E402
from identity_shield.detect import loader, replay  # noqa: E402
from identity_shield.runner import orchestrator  # noqa: E402
from identity_shield.variants.benign import generate_benign, load_benign  # noqa: E402
from identity_shield.variants.cli import persist  # noqa: E402
from identity_shield.variants.generator import GenerationOptions, generate_for_technique  # noqa: E402
from identity_shield.variants.loader import load_catalogue  # noqa: E402

APP = Path(__file__).resolve().parents[1] / "dashboard" / "app.py"


@pytest.fixture
def populated_db(tmp_path, monkeypatch):
    path = tmp_path / "dashboard.db"
    init_db(path, drop=True)
    conn = connect(path)
    try:
        loader.load_techniques(conn)
        loader.load_fixtures(conn)
        loaded = replay.load_ruleset(conn, "baseline-v1")
        replay.run_replay(conn, loaded)
    finally:
        conn.close()
    monkeypatch.setenv("IDENTITY_SHIELD_DB", str(path))
    return path


def test_dashboard_renders_without_exceptions(populated_db):
    app = AppTest.from_file(str(APP), default_timeout=60)
    app.run()
    assert not app.exception, [str(item) for item in app.exception]
    assert app.title or app.header


def test_dashboard_explains_an_empty_database(tmp_path, monkeypatch):
    monkeypatch.setenv("IDENTITY_SHIELD_DB", str(tmp_path / "missing.db"))
    app = AppTest.from_file(str(APP), default_timeout=60)
    app.run()
    assert not app.exception, [str(item) for item in app.exception]
    assert app.error, "expected a helpful error instead of a blank page"


def test_dashboard_renders_a_synthetic_campaign(tmp_path, monkeypatch):
    path = tmp_path / "campaign.db"
    init_db(path, drop=True)
    conn = connect(path)
    try:
        loader.load_techniques(conn)
        loader.load_fixtures(conn)
        catalogue = load_catalogue()
        technique = catalogue.technique("T1530")
        variants, _ = generate_for_technique(
            technique, catalogue, GenerationOptions(include_pairwise=False)
        )
        variants = [row for row in variants if row.variant_set != "holdout"]
        benign = list(
            generate_benign(
                catalogue,
                activities=tuple(
                    activity
                    for activity in load_benign()
                    if activity.technique_id == "T1530"
                ),
            )
        )
        persist(conn, variants, catalogue, prune=False)
        persist(conn, benign, catalogue, prune=False)
        orchestrator.run_campaign(
            conn,
            run_id="dash-run",
            variants=list(variants) + benign,
            catalogue=catalogue,
            account_id="123456789012",
            region="eu-west-1",
            synthetic=True,
        )
        replay.run_replay(conn, replay.load_ruleset(conn, "baseline-v1"))
        replay.run_replay(conn, replay.load_ruleset(conn, "improved-v1"))
    finally:
        conn.close()

    monkeypatch.setenv("IDENTITY_SHIELD_DB", str(path))
    app = AppTest.from_file(str(APP), default_timeout=60)
    app.run()
    assert not app.exception, [str(item) for item in app.exception]
    assert app.title or app.header
    assert any("Synthetic" in str(item.value) for item in app.warning)
