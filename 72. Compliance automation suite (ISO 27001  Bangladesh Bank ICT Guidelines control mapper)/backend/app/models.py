"""SQLAlchemy ORM models — mirrors architecture.md §6 Data Model & ERD."""
from sqlalchemy import (
    Column, Integer, String, Text, Float, Boolean, DateTime, ForeignKey,
    UniqueConstraint, Index, JSON,
)
from sqlalchemy.orm import relationship
from .database import Base, naive_utcnow


def utcnow():
    return naive_utcnow()


# ---------------------------------------------------------------------------
# Identity & Access
# ---------------------------------------------------------------------------
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    username = Column(String(80), unique=True, index=True, nullable=False)
    email = Column(String(160), unique=True, index=True, nullable=False)
    display_name = Column(String(160), nullable=False)
    password_hash = Column(String(255), nullable=False)          # PBKDF2-HMAC-SHA256
    role = Column(String(40), nullable=False, default="VIEWER")  # RBAC role
    mfa_enabled = Column(Boolean, default=True)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=utcnow)
    last_login = Column(DateTime, nullable=True)

    tickets = relationship("RemediationTicket", back_populates="assignee")


class AuditLog(Base):
    """Append-only, hash-chained audit trail (ISO A.8.15 / BB Ch-14)."""
    __tablename__ = "audit_logs"
    id = Column(Integer, primary_key=True)
    actor = Column(String(80), nullable=False)
    actor_role = Column(String(40), nullable=False)
    action = Column(String(120), nullable=False)
    entity_type = Column(String(60))
    entity_id = Column(Integer)
    detail = Column(JSON, default=dict)
    ip_address = Column(String(64))
    prev_hash = Column(String(64))          # SHA-256 of previous row
    row_hash = Column(String(64), unique=True)
    created_at = Column(DateTime, default=utcnow)


# ---------------------------------------------------------------------------
# Framework & Controls (canonical control object — CCO)
# ---------------------------------------------------------------------------
class Framework(Base):
    __tablename__ = "frameworks"
    id = Column(Integer, primary_key=True)
    code = Column(String(20), unique=True, nullable=False)   # ISO27001, BBICT2015, NISTCSF, OWASP2021
    name = Column(String(120), nullable=False)
    version = Column(String(40))
    publisher = Column(String(80))
    cadence = Column(String(40))
    is_active = Column(Boolean, default=True)

    controls = relationship("Control", back_populates="framework")


class Control(Base):
    __tablename__ = "controls"
    id = Column(Integer, primary_key=True)
    framework_id = Column(Integer, ForeignKey("frameworks.id"), index=True)
    code = Column(String(40), nullable=False)             # e.g. A.8.24 / CH-14 / PR.DS-1 / A02:2021
    title = Column(String(200), nullable=False)
    description = Column(Text)
    category = Column(String(80))                          # canonical category (DATA_PROTECTION …)
    intent = Column(String(40), default="MUST")            # MUST / SHOULD / MAY
    implementation_status = Column(String(30), default="NOT_ASSESSED")
    owner = Column(String(120))
    weight = Column(Float, default=1.0)                    # control importance weight
    last_assessed_at = Column(DateTime, nullable=True)
    UniqueConstraint("framework_id", "code", name="uq_fw_control")
    Index("ix_control_category", "category")

    framework = relationship("Framework", back_populates="controls")
    mappings = relationship("ControlMapping", foreign_keys="ControlMapping.source_id", back_populates="source")
    evidence_links = relationship("EvidenceLink", back_populates="control")
    risks = relationship("RiskPoint", back_populates="control")


class ControlMapping(Base):
    """1:N graph link across frameworks — canonical mapper output."""
    __tablename__ = "control_mappings"
    id = Column(Integer, primary_key=True)
    source_id = Column(Integer, ForeignKey("controls.id"), index=True)
    target_id = Column(Integer, ForeignKey("controls.id"), index=True)
    map_type = Column(String(20), default="EQUIVALENT")     # EQUIVALENT / RELATED / IMPLEMENTS
    rationale = Column(Text)
    created_at = Column(DateTime, default=utcnow)
    UniqueConstraint("source_id", "target_id", name="uq_mapping")

    source = relationship("Control", foreign_keys=[source_id], back_populates="mappings")
    target = relationship("Control", foreign_keys=[target_id])


class Asset(Base):
    __tablename__ = "assets"
    id = Column(Integer, primary_key=True)
    name = Column(String(160), index=True, nullable=False)
    asset_type = Column(String(40))                 # WEB_APP / API / DB / NETWORK / ENDPOINT
    environment = Column(String(20), default="PRODUCTION")
    classification = Column(String(30), default="INTERNAL")  # PUBLIC / INTERNAL / CONFIDENTIAL / RESTRICTED
    owner = Column(String(120))
    criticality = Column(Float, default=3.0)        # 1 (low) – 5 (critical)
    discovered_by = Column(String(40), default="CSPM")
    created_at = Column(DateTime, default=utcnow)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)

    scans = relationship("ScanResult", back_populates="asset")


class ScanResult(Base):
    __tablename__ = "scan_results"
    id = Column(Integer, primary_key=True)
    asset_id = Column(Integer, ForeignKey("assets.id"), index=True)
    scanner = Column(String(40), nullable=False)    # OWASP_ZAP / SONARQUBE / NESSUS / TRIVY / CHECKOV
    finding_type = Column(String(40))               # SAST / DAST / CSPM / SCA / INFRA
    title = Column(String(200))
    severity = Column(String(20))                   # CRITICAL / HIGH / MEDIUM / LOW / INFO
    cvss = Column(Float, default=0.0)
    status = Column(String(30), default="OPEN")
    raw = Column(JSON, default=dict)
    scanned_at = Column(DateTime, default=utcnow)

    asset = relationship("Asset", back_populates="scans")


class Evidence(Base):
    """Immutable (WORM) evidence artefact in the vault."""
    __tablename__ = "evidence"
    id = Column(Integer, primary_key=True)
    title = Column(String(200), nullable=False)
    artefact_type = Column(String(40))              # POLICY / LOG_EXPORT / SCAN_REPORT / CONFIG_BASELINE / SCREENSHOT / AUDIT
    source_system = Column(String(80))
    description = Column(Text)
    file_path = Column(String(400))                 # vault storage reference
    mime_type = Column(String(80))
    file_size = Column(Integer, default=0)
    sha256 = Column(String(64), index=True, nullable=False)
    chain_hash = Column(String(64))                 # hash-chain linkage into vault ledger
    assessment_id = Column(Integer, ForeignKey("assessments.id"), nullable=True)
    uploaded_by = Column(String(80))
    retention_days = Column(Integer, default=365)
    worm_locked = Column(Boolean, default=True)
    created_at = Column(DateTime, default=utcnow)

    links = relationship("EvidenceLink", back_populates="evidence")


class EvidenceLink(Base):
    """Ties one evidence artefact to many controls (overlap de-dup)."""
    __tablename__ = "evidence_links"
    id = Column(Integer, primary_key=True)
    evidence_id = Column(Integer, ForeignKey("evidence.id"), index=True)
    control_id = Column(Integer, ForeignKey("controls.id"), index=True)
    linked_by = Column(String(80))
    linked_at = Column(DateTime, default=utcnow)
    UniqueConstraint("evidence_id", "control_id", name="uq_evidence_control")

    evidence = relationship("Evidence", back_populates="links")
    control = relationship("Control", back_populates="evidence_links")


class Assessment(Base):
    __tablename__ = "assessments"
    id = Column(Integer, primary_key=True)
    name = Column(String(160), nullable=False)
    scope = Column(String(40), default="ANNUAL")     # CONTINUOUS / ANNUAL / QUARTERLY / RELEASE
    framework_code = Column(String(20))
    method = Column(String(20), default="AUTO")       # AUTO / QUESTIONNAIRE / HYBRID
    status = Column(String(30), default="IN_PROGRESS")  # PLANNED / IN_PROGRESS / COMPLETED / REVIEWED
    progress = Column(Float, default=0.0)
    result_score = Column(Float, nullable=True)       # overall score 0-100
    findings_count = Column(Integer, default=0)
    created_by = Column(String(80))
    created_at = Column(DateTime, default=utcnow)
    completed_at = Column(DateTime, nullable=True)

    decisions = relationship("AssessmentDecision", back_populates="assessment")


class AssessmentDecision(Base):
    __tablename__ = "assessment_decisions"
    id = Column(Integer, primary_key=True)
    assessment_id = Column(Integer, ForeignKey("assessments.id"), index=True)
    control_id = Column(Integer, ForeignKey("controls.id"), index=True)
    status = Column(String(30), default="NOT_APPLICABLE")  # COMPLIANT / PARTIAL / NON_COMPLIANT / NOT_ASSESSED / N/A
    evidence_ref = Column(String(80))
    note = Column(Text)
    scored_by = Column(String(80))
    decided_at = Column(DateTime, default=utcnow)
    UniqueConstraint("assessment_id", "control_id", name="uq_assess_dec")

    assessment = relationship("Assessment", back_populates="decisions")
    control = relationship("Control")


class RiskPoint(Base):
    __tablename__ = "risk_points"
    id = Column(Integer, primary_key=True)
    control_id = Column(Integer, ForeignKey("controls.id"), index=True)
    asset_id = Column(Integer, ForeignKey("assets.id"), nullable=True)
    title = Column(String(200), nullable=False)
    likelihood = Column(Float, default=3.0)          # 1-5
    impact = Column(Float, default=3.0)              # 1-5
    cvss = Column(Float, default=0.0)
    raw_score = Column(Float, nullable=True)
    residual_score = Column(Float, nullable=True)
    tier = Column(String(20), nullable=True)          # CRITICAL / HIGH / MEDIUM / LOW
    status = Column(String(30), default="OPEN")       # OPEN / MITIGATING / ACCEPTED / RESOLVED
    created_at = Column(DateTime, default=utcnow)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)

    control = relationship("Control", back_populates="risks")
    asset = relationship("Asset")


class RemediationTicket(Base):
    __tablename__ = "remediation_tickets"
    id = Column(Integer, primary_key=True)
    risk_id = Column(Integer, ForeignKey("risk_points.id"), nullable=True)
    control_id = Column(Integer, ForeignKey("controls.id"), nullable=True)
    title = Column(String(200), nullable=False)
    description = Column(Text)
    assignee_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    priority = Column(String(20), default="MEDIUM")
    status = Column(String(30), default="OPEN")        # OPEN / IN_PROGRESS / IN_REVIEW / RESOLVED
    sla_hours = Column(Integer, default=72)
    due_at = Column(DateTime, nullable=True)
    external_ticket = Column(String(40))
    created_at = Column(DateTime, default=utcnow)
    resolved_at = Column(DateTime, nullable=True)

    assignee = relationship("User", back_populates="tickets")


class Setting(Base):
    """Key/value store for platform state (see state.md)."""
    __tablename__ = "settings"
    id = Column(Integer, primary_key=True)
    key = Column(String(120), unique=True, index=True, nullable=False)
    value = Column(Text)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)