"""Database engine, session management and schema bootstrap."""
from __future__ import annotations

from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker, Session

from app.config import settings
from app.db.models import Base

_engine = None
_SessionLocal: sessionmaker | None = None


def _make_engine():
    connect_args = {}
    if settings.database_url.startswith("sqlite"):
        connect_args = {"check_same_thread": False}

    engine = create_engine(
        settings.database_url,
        pool_pre_ping=True,
        connect_args=connect_args,
    )

    if settings.database_url.startswith("sqlite"):

        @event.listens_for(engine, "connect")
        def _fk_pragma(dbapi_connection, connection_record):
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.close()

    return engine


def init_db() -> None:
    global _engine, _SessionLocal
    if _engine is None:
        _engine = _make_engine()
    Base.metadata.create_all(_engine)
    _SessionLocal = sessionmaker(bind=_engine, autoflush=False, expire_on_commit=False)


def get_engine():
    if _engine is None:
        init_db()
    return _engine


def SessionLocal() -> Session:
    if _SessionLocal is None:
        init_db()
    return _SessionLocal()


def db_session():
    """FastAPI dependency."""
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()