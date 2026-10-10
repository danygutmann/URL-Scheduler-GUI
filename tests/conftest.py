import os
import tempfile

_temporary_data = tempfile.TemporaryDirectory(prefix="url-scheduler-tests-")
os.environ.update({
    "APP_AUTH_ENABLED": "false",
    "APP_DATA_DIR": _temporary_data.name,
    "APP_SESSION_SECRET": "test-session-secret-that-is-long-enough",
    "APP_ENCRYPTION_KEY": "m5HbA1yn-cyp7dMSxP6g8onTTlpVSuaSSUi5Wi7o8q0=",
    "APP_RESPONSE_PREVIEW_BYTES": "128",
})

import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker

from app import database
from app.models import Base


@pytest.fixture()
def db(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite:///{tmp_path / 'test.db'}", connect_args={"check_same_thread": False})

    @event.listens_for(engine, "connect")
    def enable_foreign_keys(connection, _record):
        connection.execute("PRAGMA foreign_keys=ON")

    Base.metadata.create_all(engine)
    maker = sessionmaker(bind=engine, expire_on_commit=False)
    monkeypatch.setattr(database, "engine", engine)
    monkeypatch.setattr(database, "SessionLocal", maker)
    yield engine
    engine.dispose()
