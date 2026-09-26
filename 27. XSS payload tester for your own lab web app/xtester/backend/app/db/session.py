"""Database session management (SQLAlchemy 2.0).

Production uses Postgres via DATABASE_URL; development defaults to SQLite.
"""

from __future__ import annotations

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.config import settings


class Base(DeclarativeBase):
    """Declarative base for all ORM models."""


connect_args = {}
if settings.database_url.startswith("sqlite"):
    connect_args["check_same_thread"] = False

engine = create_engine(
    settings.database_url,
    connect_args=connect_args,
    pool_pre_ping=True,
)

SessionLocal = sessionmaker(bind=engine, class_=Session, expire_on_commit=False)


def get_db():
    """FastAPI dependency yielding a scoped session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    """Create tables. Mirgations in production are handled by Alembic."""
    from app.db import models  # noqa: F401

    Base.metadata.create_all(bind=engine)