"""Pytest fixtures and environment bootstrap.

Environment variables must be set before `app.config.settings` is first
imported (it is lru_cached).
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

_TMP = Path(tempfile.mkdtemp(prefix="xtester-test-"))

os.environ.setdefault("APP_ENV", "test")
os.environ.setdefault("DATABASE_URL", f"sqlite:///{_TMP}/test.db")
os.environ.setdefault("AUDIT_LOG_DIR", str(_TMP / "audit"))
os.environ.setdefault("SECRET_KEY", "test-secret-key-that-is-long-enough-123456")
os.environ.setdefault("BOOTSTRAP_ADMIN_USERNAME", "admin")
os.environ.setdefault("BOOTSTRAP_ADMIN_PASSWORD", "ChangeMe_Strong_Pass_2026!")
os.environ.setdefault("ALLOWED_TARGET_HOSTS", "localhost,127.0.0.1,lab,*.lab.local,172.16.*")
os.environ.setdefault("CELERY_TASK_ALWAYS_EAGER", "1")
os.environ.setdefault("RATE_LIMIT_PER_MINUTE", "1000")

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.config import settings  # noqa: E402
from app.db.session import SessionLocal, engine  # noqa: E402


@pytest.fixture()
def db():
    from app.db import models  # noqa: F401

    models.Base.metadata.create_all(bind=engine)
    session = SessionLocal()
    yield session
    session.close()


@pytest.fixture()
def client():
    from app.main import app

    with TestClient(app) as c:
        yield c


@pytest.fixture()
def admin_headers(client):
    res = client.post(
        "/api/auth/login",
        json={"username": settings.bootstrap_admin_username,
              "password": settings.bootstrap_admin_password},
    )
    assert res.status_code == 200, res.text
    token = res.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture(scope="session")
def tdir() -> Path:
    return _TMP