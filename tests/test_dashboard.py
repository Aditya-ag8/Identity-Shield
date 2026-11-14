from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("streamlit")

from streamlit.testing.v1 import AppTest  # noqa: E402

from identity_shield.db.connection import connect  # noqa: E402
from identity_shield.db.init import init_db  # noqa: E402
from identity_shield.detect import loader, replay  # noqa: E402

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
