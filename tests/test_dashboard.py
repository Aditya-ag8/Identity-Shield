from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("streamlit")

from streamlit.testing.v1 import AppTest  # noqa: E402

APP = Path(__file__).resolve().parents[1] / "dashboard" / "app.py"


def test_dashboard_renders_without_exceptions():
    """Smoke test: the app must not raise against a populated database.

    Requires `identity-shield demo` (or init+load+replay) to have been run, since
    the app reads the default database path.
    """
    app = AppTest.from_file(str(APP), default_timeout=30)
    app.run()
    assert not app.exception, [str(item) for item in app.exception]
    assert app.title or app.header
