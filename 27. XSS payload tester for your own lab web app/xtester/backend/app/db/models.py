"""ORM models.

Schema designed so auth records (users / API keys) are stored as salted
hashes only (NIST SP 800-63B, ISO 27001 A.8.24), and scan results are
retention-tagged so an automated retention job can purge old data
(ISO 27001 A.8.13 / A.10.1.3).
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Enum, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.session import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Role(str, enum.Enum):
    viewer = "viewer"      # read-only: view scans / reports
    engineer = "engineer"  # run scans, manage targets
    admin = "admin"        # users, targets, config, audit, retention


class ScanStatus(str, enum.Enum):
    queued = "queued"
    running = "running"
    completed = "completed"
    failed = "failed"
    cancelled = "cancelled"


class FindingSeverity(str, enum.Enum):
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class ContextKind(str, enum.Enum):
    html = "html"
    attribute = "attribute"
    script = "script"
    url = "url"
    dom = "dom"


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))          # argon2id
    role: Mapped[Role] = mapped_column(Enum(Role), default=Role.viewer)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    must_change_password: Mapped[bool] = mapped_column(Boolean, default=False)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow
    )

    api_keys: Mapped[list["ApiKey"]] = relationship(back_populates="user", cascade="all, delete-orphan")
    scans: Mapped[list["Scan"]] = relationship(back_populates="owner")


class ApiKey(Base):
    __tablename__ = "api_keys"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    key_hash: Mapped[str] = mapped_column(String(128), unique=True, index=True)  # sha256(key)
    prefix: Mapped[str] = mapped_column(String(16))                              # xt_abc123...
    role_binding: Mapped[Role] = mapped_column(Enum(Role), default=Role.engineer)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    user: Mapped[User] = relationship(back_populates="api_keys")


class RefreshToken(Base):
    __tablename__ = "refresh_tokens"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    jti_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    user_agent: Mapped[str | None] = mapped_column(String(255))


class Target(Base):
    __tablename__ = "targets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    label: Mapped[str] = mapped_column(String(128))
    base_url: Mapped[str] = mapped_column(String(512), unique=True)
    host: Mapped[str] = mapped_column(String(255), index=True)
    approved_by: Mapped[str | None] = mapped_column(String(64))
    notes: Mapped[str | None] = mapped_column(Text)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    target_id: Mapped[int | None] = mapped_column(ForeignKey("targets.id"))
    scan_url: Mapped[str] = mapped_column(String(2048))
    context: Mapped[str] = mapped_column(String(16), default="auto")
    status: Mapped[ScanStatus] = mapped_column(Enum(ScanStatus), default=ScanStatus.queued)
    payload_count: Mapped[int] = mapped_column(Integer, default=0)
    executed_count: Mapped[int] = mapped_column(Integer, default=0)
    safe_count: Mapped[int] = mapped_column(Integer, default=0)
    max_severity: Mapped[FindingSeverity] = mapped_column(
        Enum(FindingSeverity), default=FindingSeverity.info
    )
    cvss_score: Mapped[float] = mapped_column(Float, default=0.0)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    retained_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    error: Mapped[str | None] = mapped_column(Text)
    report: Mapped["Report"] = relationship(back_populates="scan", uselist=False, cascade="all, delete-orphan")

    owner: Mapped[User] = relationship(back_populates="scans")


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id"), index=True)
    payload: Mapped[str] = mapped_column(Text)
    vector_name: Mapped[str] = mapped_column(String(128))
    vector_category: Mapped[str] = mapped_column(String(128))
    context: Mapped[ContextKind] = mapped_column(Enum(ContextKind))
    evasion: Mapped[str] = mapped_column(String(255))
    url: Mapped[str] = mapped_column(String(2048))
    verdict: Mapped[str] = mapped_column(String(32))          # executed / likely / suspicious / clean
    evidence: Mapped[str | None] = mapped_column(Text)        # JSON-encoded observations
    severity: Mapped[FindingSeverity] = mapped_column(Enum(FindingSeverity))
    cvss_score: Mapped[float] = mapped_column(Integer, default=0.0)
    poc: Mapped[str | None] = mapped_column(Text)             # self-contained repro URL
    remediation: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


class Report(Base):
    __tablename__ = "reports"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id"), unique=True)
    summary: Mapped[str | None] = mapped_column(Text)            # JSON
    security_headers: Mapped[str | None] = mapped_column(Text)   # JSON: observed headers
    csp_recommendation: Mapped[str | None] = mapped_column(Text)
    retained_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    scan: Mapped[Scan] = relationship(back_populates="report")


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    actor: Mapped[str | None] = mapped_column(String(128))
    actor_type: Mapped[str] = mapped_column(String(16), default="user")  # user | api_key | system
    action: Mapped[str] = mapped_column(String(64), index=True)
    outcome: Mapped[str] = mapped_column(String(16), default="success")  # success | failure
    resource: Mapped[str | None] = mapped_column(String(255))
    ip: Mapped[str | None] = mapped_column(String(45))
    details: Mapped[str | None] = mapped_column(Text)                    # JSON
    prev_hash: Mapped[str | None] = mapped_column(String(64))
    entry_hash: Mapped[str | None] = mapped_column(String(64), index=True)