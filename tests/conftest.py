from __future__ import annotations

import pytest

from identity_shield.db.connection import connect
from identity_shield.db.init import init_db
from identity_shield.detect import loader


@pytest.fixture
def db_path(tmp_path):
    return tmp_path / "identity_shield_test.db"


@pytest.fixture
def conn(db_path):
    init_db(db_path, drop=True)
    connection = connect(db_path)
    loader.load_techniques(connection)
    loader.load_fixtures(connection)
    try:
        yield connection
    finally:
        connection.close()
