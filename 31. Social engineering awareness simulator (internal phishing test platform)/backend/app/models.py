from datetime import datetime

from sqlalchemy import (Boolean, DateTime, Float, ForeignKey, Integer, String,
                        Text)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    email: Mapped[str] = mapped_column(String(128), unique=True)
    full_name: Mapped[str] = mapped_column(String(128))
    hashed_password: Mapped[str] = mapped_column(String(256))
    role: Mapped[str] = mapped_column(String(32), default="analyst")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class Employee(Base):
    __tablename__ = "employees"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    employee_code: Mapped[str] = mapped_column(String(32), unique=True)
    full_name: Mapped[str] = mapped_column(String(128))
    email: Mapped[str] = mapped_column(String(128))
    phone: Mapped[str] = mapped_column(String(32), default="")
    branch: Mapped[str] = mapped_column(String(64))
    division: Mapped[str] = mapped_column(String(64))
    job_grade: Mapped[str] = mapped_column(String(16), default="G09")
    risk_weight: Mapped[float] = mapped_column(Float, default=1.0)
    opt_out: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    deliveries: Mapped[list["Delivery"]] = relationship(back_populates="employee")


class EmailTemplate(Base):
    __tablename__ = "email_templates"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(128))
    language: Mapped[str] = mapped_column(String(16), default="en")
    subject: Mapped[str] = mapped_column(String(256))
    body_html: Mapped[str] = mapped_column(Text)


class LandingPage(Base):
    __tablename__ = "landing_pages"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(128))
    title: Mapped[str] = mapped_column(String(256))
    body_html: Mapped[str] = mapped_column(Text)


class Campaign(Base):
    __tablename__ = "campaigns"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(128))
    vector: Mapped[str] = mapped_column(String(16), default="email")
    status: Mapped[str] = mapped_column(String(16), default="draft")
    branches: Mapped[str] = mapped_column(Text, default="[]")
    divisions: Mapped[str] = mapped_column(Text, default="[]")
    schedule_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_by: Mapped[int] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    approved_by: Mapped[int | None] = mapped_column(Integer, nullable=True)

    variants: Mapped[list["CampaignVariant"]] = relationship(
        back_populates="campaign", cascade="all, delete-orphan"
    )
    deliveries: Mapped[list["Delivery"]] = relationship(
        back_populates="campaign", cascade="all, delete-orphan"
    )


class CampaignVariant(Base):
    __tablename__ = "campaign_variants"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    campaign_id: Mapped[int] = mapped_column(ForeignKey("campaigns.id"))
    name: Mapped[str] = mapped_column(String(64))
    weight: Mapped[int] = mapped_column(Integer, default=1)
    email_template_id: Mapped[int | None] = mapped_column(
        ForeignKey("email_templates.id"), nullable=True
    )
    landing_page_id: Mapped[int | None] = mapped_column(
        ForeignKey("landing_pages.id"), nullable=True
    )

    campaign: Mapped["Campaign"] = relationship(back_populates="variants")
    email_template: Mapped["EmailTemplate | None"] = relationship()
    landing_page: Mapped["LandingPage | None"] = relationship()


class Delivery(Base):
    __tablename__ = "deliveries"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    campaign_id: Mapped[int] = mapped_column(ForeignKey("campaigns.id"))
    variant_id: Mapped[int] = mapped_column(ForeignKey("campaign_variants.id"))
    employee_id: Mapped[int] = mapped_column(ForeignKey("employees.id"))
    token: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    status: Mapped[str] = mapped_column(String(16), default="pending")
    sent_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    opened_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    clicked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    submitted_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    reported_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    campaign: Mapped["Campaign"] = relationship(back_populates="deliveries")
    variant: Mapped["CampaignVariant"] = relationship()
    employee: Mapped["Employee"] = relationship(back_populates="deliveries")

    @property
    def click_url(self) -> str:
        return "/t/c/" + self.token

    @property
    def open_url(self) -> str:
        return "/t/o/" + self.token


class Event(Base):
    __tablename__ = "events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    delivery_id: Mapped[int] = mapped_column(ForeignKey("deliveries.id"))
    employee_id: Mapped[int] = mapped_column(ForeignKey("employees.id"))
    campaign_id: Mapped[int] = mapped_column(ForeignKey("campaigns.id"))
    event_type: Mapped[str] = mapped_column(String(32))
    payload: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class Submission(Base):
    __tablename__ = "submissions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    delivery_id: Mapped[int] = mapped_column(ForeignKey("deliveries.id"))
    submitted_username: Mapped[str] = mapped_column(String(128))
    password_hash: Mapped[str] = mapped_column(String(256))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class RiskScore(Base):
    __tablename__ = "risk_scores"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    employee_id: Mapped[int] = mapped_column(ForeignKey("employees.id"))
    score: Mapped[float] = mapped_column(Float)
    snapshot: Mapped[str] = mapped_column(String(32), default="daily")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class Training(Base):
    __tablename__ = "trainings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    employee_id: Mapped[int] = mapped_column(ForeignKey("employees.id"))
    title: Mapped[str] = mapped_column(String(128))
    completed: Mapped[bool] = mapped_column(Boolean, default=False)
    score: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class ConsentRecord(Base):
    __tablename__ = "consent_records"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    employee_id: Mapped[int] = mapped_column(ForeignKey("employees.id"), unique=True)
    acknowledged: Mapped[bool] = mapped_column(Boolean, default=True)
    acknowledged_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    actor: Mapped[str] = mapped_column(String(64))
    action: Mapped[str] = mapped_column(String(64))
    target_type: Mapped[str] = mapped_column(String(32), default="")
    target_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    detail: Mapped[str] = mapped_column(Text, default="")
    ip: Mapped[str] = mapped_column(String(64), default="")
    prev_hash: Mapped[str] = mapped_column(String(64), default="")
    hash: Mapped[str] = mapped_column(String(64), unique=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class ReportBundle(Base):
    __tablename__ = "report_bundles"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(128))
    fmt: Mapped[str] = mapped_column(String(8))
    path: Mapped[str] = mapped_column(String(256))
    size: Mapped[int] = mapped_column(Integer, default=0)
    status: Mapped[str] = mapped_column(String(16), default="ready")
    created_by: Mapped[int] = mapped_column(Integer)
    url_token: Mapped[str] = mapped_column(String(64), unique=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)