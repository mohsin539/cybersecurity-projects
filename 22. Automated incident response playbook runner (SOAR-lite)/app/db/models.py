# SQLAlchemy models for SOAR-Lite.
from __future__ import annotations

import datetime as dt
import uuid

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy.types import JSON as SA_JSON


def _uuid() -> str:
    return str(uuid.uuid4())


def pk_column() -> Column:
    """String UUID primary key, portable across SQLite and Postgres."""
    return Column(String(36), primary_key=True, default=_uuid)


Base = declarative_base()


class User(Base):
    __tablename__ = "users"

    id = pk_column()
    username = Column(String(120), unique=True, nullable=False, index=True)
    email = Column(String(255), nullable=False, default="")
    password_hash = Column(String(255), nullable=False)
    role = Column(String(32), nullable=False, default="viewer")  # viewer|analyst|approver|author|admin|automation
    must_change_password = Column(Boolean, default=True)
    is_active = Column(Boolean, default=True)
    failed_login_attempts = Column(Integer, default=0)
    locked_until = Column(DateTime, nullable=True)
    last_login = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=dt.datetime.utcnow)


class Case(Base):
    __tablename__ = "cases"

    id = Column(Integer, primary_key=True, autoincrement=True)
    title = Column(String(512), nullable=False)
    severity = Column(Integer, default=3, index=True)
    status = Column(String(32), default="open", index=True)  # open|analyzing|contained|eradicated|recovered|closed
    # NIST SP 800-61 incident handling phase: preparation|detection|analysis|containment|eradication|recovery|post_incident
    nist_phase = Column(String(32), default="detection")
    assigned_to = Column(String(36), ForeignKey("users.id"), nullable=True)
    sla_breached = Column(Boolean, default=False)
    opened_at = Column(DateTime, default=dt.datetime.utcnow)
    updated_at = Column(DateTime, default=dt.datetime.utcnow, onupdate=dt.datetime.utcnow)
    contained_at = Column(DateTime, nullable=True)
    eradicated_at = Column(DateTime, nullable=True)
    recovered_at = Column(DateTime, nullable=True)
    closed_at = Column(DateTime, nullable=True)
    lessons = Column(Text, nullable=True)

    alerts = relationship("Alert", back_populates="case")
    timeline = relationship("CaseTimeline", back_populates="case", order_by="CaseTimeline.ts")
    evidence = relationship("Evidence", back_populates="case")


class Alert(Base):
    __tablename__ = "alerts"

    id = pk_column()
    external_id = Column(String(255), nullable=True)
    source = Column(String(64), nullable=False, index=True)
    category = Column(String(64), nullable=True, index=True)
    subcategory = Column(String(128), nullable=True)
    title = Column(String(512), nullable=False)
    description = Column(Text, nullable=True)
    vendor_severity = Column(String(16), nullable=True)  # critical|high|medium|low
    severity = Column(Integer, default=3)  # 1-5
    score = Column(Float, default=0.0)
    asset_id = Column(String(255), nullable=True, index=True)
    attack_tactic = Column(String(128), nullable=True)
    attack_technique = Column(String(128), nullable=True)
    indicators = Column(SA_JSON, default=list)
    raw_json = Column(SA_JSON, default=dict)
    canonical_hash = Column(String(64), index=True)
    is_duplicate_of = Column(String(36), nullable=True)
    status = Column(String(24), default="open", index=True)  # open|assigned|closed|suppressed
    case_id = Column(Integer, ForeignKey("cases.id"), nullable=True, index=True)
    redacted = Column(Boolean, default=False)
    created_at = Column(DateTime, default=dt.datetime.utcnow, index=True)

    case = relationship("Case", back_populates="alerts")


class CaseTimeline(Base):
    __tablename__ = "case_timeline"

    id = Column(Integer, primary_key=True, autoincrement=True)
    case_id = Column(Integer, ForeignKey("cases.id"), nullable=False, index=True)
    ts = Column(DateTime, default=dt.datetime.utcnow)
    actor = Column(String(120), nullable=True)
    event_type = Column(String(64), nullable=False)
    message = Column(Text, nullable=False)
    detail = Column(SA_JSON, default=dict)

    case = relationship("Case", back_populates="timeline")


class Evidence(Base):
    __tablename__ = "evidence"

    id = Column(Integer, primary_key=True, autoincrement=True)
    case_id = Column(Integer, ForeignKey("cases.id"), nullable=False, index=True)
    filename = Column(String(512), nullable=False)
    object_key = Column(String(1024), nullable=False)
    size = Column(Integer, default=0)
    sha256 = Column(String(64), nullable=False)
    collector = Column(String(120), nullable=True)
    collected_at = Column(DateTime, default=dt.datetime.utcnow)
    # `metadata` is reserved by SQLAlchemy declarative — persist as evidence_meta
    evidence_meta = Column(SA_JSON, default=dict, name="metadata")

    case = relationship("Case", back_populates="evidence")


class Playbook(Base):
    __tablename__ = "playbooks"
    __table_args__ = (UniqueConstraint("key", "version", name="uq_playbook_key_version"),)

    id = pk_column()
    key = Column(String(120), nullable=False, index=True)
    name = Column(String(255), nullable=False)
    version = Column(Integer, default=1)
    description = Column(Text, nullable=True)
    trigger = Column(SA_JSON, default=dict)
    spec = Column(SA_JSON, default=dict)
    compensations = Column(SA_JSON, default=list)
    risk = Column(String(16), default="medium")  # low|medium|high|critical
    status = Column(String(24), default="draft", index=True)  # draft|published|archived
    created_by = Column(String(36), ForeignKey("users.id"), nullable=True)
    previous_id = Column(String(36), nullable=True)
    created_at = Column(DateTime, default=dt.datetime.utcnow)
    published_at = Column(DateTime, nullable=True)


class ExecutionRun(Base):
    __tablename__ = "execution_runs"

    id = pk_column()
    case_id = Column(Integer, ForeignKey("cases.id"), nullable=True, index=True)
    alert_id = Column(String(36), ForeignKey("alerts.id"), nullable=True, index=True)
    playbook_id = Column(String(36), ForeignKey("playbooks.id"), nullable=False)
    parent_run_id = Column(String(36), nullable=True)
    status = Column(String(24), default="pending", index=True)  # pending|running|awaiting_approval|succeeded|failed|cancelled|compensated
    trigger_summary = Column(String(512), nullable=True)
    data = Column(SA_JSON, default=dict)
    current_step_id = Column(String(64), nullable=True)
    started_at = Column(DateTime, nullable=True)
    finished_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=dt.datetime.utcnow)

    steps = relationship("StepRun", back_populates="run", order_by="StepRun.id")


class StepRun(Base):
    __tablename__ = "step_runs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    run_id = Column(String(36), ForeignKey("execution_runs.id"), nullable=False, index=True)
    step_id = Column(String(64), nullable=False)
    step_type = Column(String(32), nullable=False)
    action = Column(String(255), nullable=True)
    if_expr = Column(Text, nullable=True)
    run_after = Column(SA_JSON, default=list)
    status = Column(String(24), default="queued", index=True)  # queued|running|succeeded|failed|skipped|awaiting_approval|compensated
    retries_done = Column(Integer, default=0)
    max_retries = Column(Integer, default=0)
    message = Column(Text, nullable=True)
    result = Column(SA_JSON, default=dict)
    idempotency_key = Column(String(64), index=True)
    started_at = Column(DateTime, nullable=True)
    finished_at = Column(DateTime, nullable=True)
    next_attempt_at = Column(DateTime, nullable=True)

    run = relationship("ExecutionRun", back_populates="steps")


class ApprovalRequest(Base):
    __tablename__ = "approval_requests"

    id = Column(Integer, primary_key=True, autoincrement=True)
    run_id = Column(String(36), ForeignKey("execution_runs.id"), nullable=False, index=True)
    step_id = Column(String(64), nullable=False)
    case_id = Column(Integer, ForeignKey("cases.id"), nullable=True, index=True)
    reason = Column(Text, nullable=True)
    status = Column(String(16), default="pending", index=True)  # pending|approved|denied
    requested_by = Column(String(120), nullable=True)
    decided_by = Column(String(36), ForeignKey("users.id"), nullable=True)
    decision_note = Column(Text, nullable=True)
    created_at = Column(DateTime, default=dt.datetime.utcnow)
    decided_at = Column(DateTime, nullable=True)


class Connector(Base):
    __tablename__ = "connectors"

    id = pk_column()
    name = Column(String(120), unique=True, nullable=False, index=True)
    conn_type = Column(String(64), nullable=False)  # generic_http|simulator|teams|slack
    base_url = Column(String(512), nullable=True)
    auth_type = Column(String(32), default="none")  # none|header_token|basic
    auth_secret_ref = Column(String(255), nullable=True)  # reference into SecretVault
    allowed_hosts = Column(SA_JSON, default=list)  # extra allowed host:port; default = base_url host
    extra = Column(SA_JSON, default=dict)
    enabled = Column(Boolean, default=True)
    created_at = Column(DateTime, default=dt.datetime.utcnow)


class SecretVault(Base):
    __tablename__ = "secret_vault"

    id = pk_column()
    name = Column(String(255), unique=True, nullable=False, index=True)
    ciphertext = Column(Text, nullable=False)
    key_id = Column(String(64), nullable=False)  # master-key version that encrypted it
    created_at = Column(DateTime, default=dt.datetime.utcnow)
    last_used_at = Column(DateTime, nullable=True)


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id = pk_column()
    seq = Column(Integer, index=True)
    ts = Column(DateTime, default=dt.datetime.utcnow, index=True)
    actor = Column(String(120), nullable=True)
    action = Column(String(64), nullable=False, index=True)
    resource_type = Column(String(64), nullable=True)
    resource_id = Column(String(128), nullable=True)
    ip = Column(String(64), nullable=True)
    detail = Column(SA_JSON, default=dict)
    prev_hash = Column(String(64), nullable=True)
    hash = Column(String(64), nullable=False)


class DeadLetter(Base):
    __tablename__ = "dead_letters"

    id = pk_column()
    source = Column(String(64), nullable=True)
    payload = Column(SA_JSON, default=dict)
    reason = Column(Text, nullable=True)
    created_at = Column(DateTime, default=dt.datetime.utcnow)


class Setting(Base):
    __tablename__ = "settings"

    key = Column(String(128), primary_key=True)
    value = Column(SA_JSON, nullable=False)
    updated_at = Column(DateTime, default=dt.datetime.utcnow, onupdate=dt.datetime.utcnow)


NIST_PHASES = [
    "preparation",
    "detection",
    "analysis",
    "containment",
    "eradication",
    "recovery",
    "post_incident",
]

ROLES = ["viewer", "analyst", "approver", "author", "admin", "automation"]