"""Pydantic request/response schemas.

Every inbound field is validated (OWASP Top 10 A03 injection / A04 insecure
design); URLs are normalized and length-capped to prevent abuse.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

ContextStr = Literal["html", "attribute", "script", "url", "dom", "auto"]
Role = Literal["viewer", "engineer", "admin"]


class LoginRequest(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    password: str = Field(min_length=12, max_length=256)


class ChangePasswordRequest(BaseModel):
    old_password: str = Field(min_length=12, max_length=256)
    new_password: str = Field(min_length=12, max_length=256)


class CreateUserRequest(BaseModel):
    username: str = Field(min_length=3, max_length=64, pattern=r"^[a-zA-Z0-9_.-]+$")
    password: str = Field(min_length=12, max_length=256)
    role: Role = "viewer"
    enabled: bool = True


class CreateScanRequest(BaseModel):
    url: str = Field(min_length=5, max_length=2048)
    context: ContextStr = "auto"
    wait_ms: int | None = Field(default=None, ge=200, le=5000)

    @field_validator("url")
    @classmethod
    def _normalize_url(cls, v: str) -> str:
        v = v.strip()
        if not v.lower().startswith(("http://", "https://")):
            raise ValueError("url must start with http:// or https://")
        return v


class CreateApiKeyRequest(BaseModel):
    role_binding: Role = "engineer"
    expires_days: int = Field(default=30, ge=1, le=365)


class TargetCreate(BaseModel):
    label: str = Field(min_length=2, max_length=128)
    base_url: str = Field(min_length=5, max_length=512)
    notes: str | None = Field(default=None, max_length=2000)

    @field_validator("base_url")
    @classmethod
    def _url_must_be_absolute(cls, v: str) -> str:
        if not v.lower().startswith(("http://", "https://")):
            raise ValueError("base_url must start with http:// or https://")
        return v


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    username: str
    role: Role
    enabled: bool
    must_change_password: bool
    last_login_at: datetime | None
    created_at: datetime


class ScanOut(BaseModel):
    model_config = ConfigDict(from_attributes=True, populate_by_name=True)
    id: str
    url: str = Field(alias="scan_url", serialization_alias="url")
    context: str
    status: str
    payload_count: int
    executed_count: int
    safe_count: int
    max_severity: str
    cvss_score: float
    created_at: datetime
    finished_at: datetime | None


class ScanDetail(ScanOut):
    owner: str | None = None
    error: str | None = None
    findings: list["FindingOut"] = []


class FindingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    vector_name: str
    vector_category: str
    context: str
    evasion: str
    url: str
    verdict: str
    evidence: str | None
    severity: str
    cvss_score: float
    poc: str | None
    remediation: str | None
    payload: str


class AuditOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    ts: datetime
    actor: str | None
    actor_type: str
    action: str
    outcome: str
    resource: str | None
    ip: str | None
    details: str | None
    prev_hash: str | None
    entry_hash: str | None