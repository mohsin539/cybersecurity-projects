from datetime import datetime

from pydantic import BaseModel, EmailStr, Field, field_validator


class LoginIn(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    password: str = Field(min_length=8, max_length=128)

    @field_validator("username")
    @classmethod
    def strip_username(cls, v: str) -> str:
        return v.strip().lower()


class UserOut(BaseModel):
    id: int
    username: str
    email: EmailStr
    full_name: str
    role: str

    model_config = {"from_attributes": True}


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserOut


class EmployeeOut(BaseModel):
    id: int
    employee_code: str
    full_name: str
    email: EmailStr
    phone: str
    branch: str
    division: str
    job_grade: str
    risk_weight: float
    opt_out: bool

    model_config = {"from_attributes": True}


class EmployeeIn(BaseModel):
    employee_code: str = Field(min_length=2, max_length=32)
    full_name: str = Field(min_length=2, max_length=128)
    email: EmailStr
    phone: str = Field(default="", max_length=32)
    branch: str = Field(min_length=2, max_length=64)
    division: str = Field(default="", max_length=64)
    job_grade: str = Field(default="G09", max_length=16)
    risk_weight: float = Field(default=1.0, ge=0.5, le=3.0)
    opt_out: bool = False


class TemplateIn(BaseModel):
    name: str = Field(min_length=2, max_length=128)
    language: str = Field(default="en", max_length=16)
    subject: str = Field(min_length=2, max_length=256)
    body_html: str = Field(min_length=10)


class LandingPageIn(BaseModel):
    name: str = Field(min_length=2, max_length=128)
    title: str = Field(min_length=2, max_length=256)
    body_html: str = Field(min_length=10)


class TemplateOut(BaseModel):
    id: int
    name: str
    language: str
    subject: str
    body_html: str

    model_config = {"from_attributes": True}


class LandingPageOut(BaseModel):
    id: int
    name: str
    title: str
    body_html: str

    model_config = {"from_attributes": True}


class VariantIn(BaseModel):
    name: str = Field(min_length=2, max_length=64)
    weight: int = Field(default=1, ge=1, le=100)
    email_template_id: int | None = None
    landing_page_id: int | None = None


class CampaignIn(BaseModel):
    name: str = Field(min_length=2, max_length=128)
    vector: str = Field(default="email", pattern="^(email|sms|qr|vishing)$")
    schedule_at: datetime | None = None
    templates: list[int] = Field(default_factory=list)
    landing_pages: list[int] = Field(default_factory=list)
    branches: list[str] = Field(default_factory=list)
    divisions: list[str] = Field(default_factory=list)


class CampaignOut(BaseModel):
    id: int
    name: str
    vector: str
    status: str
    schedule_at: datetime | None
    created_at: datetime
    sent: int = 0
    opened: int = 0
    clicked: int = 0
    submitted: int = 0
    reported: int = 0

    model_config = {"from_attributes": True}


class DeliveryOut(BaseModel):
    id: int
    employee_code: str = ""
    full_name: str = ""
    branch: str = ""
    status: str
    open_url: str = ""
    click_url: str = ""
    sent_at: datetime | None
    opened_at: datetime | None
    clicked_at: datetime | None
    submitted_at: datetime | None
    reported_at: datetime | None

    model_config = {"from_attributes": True}


class EventOut(BaseModel):
    id: int
    employee_id: int
    campaign_id: int
    event_type: str
    payload: str
    created_at: datetime

    model_config = {"from_attributes": True}


class TrainingIn(BaseModel):
    employee_id: int
    title: str = Field(min_length=2, max_length=128)
    score: int = Field(ge=0, le=100)


class TrainingOut(BaseModel):
    id: int
    employee_id: int
    title: str
    completed: bool
    score: int
    created_at: datetime

    model_config = {"from_attributes": True}


class AuditLogOut(BaseModel):
    id: int
    actor: str
    action: str
    target_type: str
    target_id: int | None
    detail: str
    hash: str
    created_at: datetime

    model_config = {"from_attributes": True}


class ReportOut(BaseModel):
    id: int
    name: str
    fmt: str
    size: int
    status: str
    url_token: str
    created_at: datetime

    model_config = {"from_attributes": True}


class ReportRequest(BaseModel):
    fmt: str = Field(pattern="^(xlsx|csv|html)$")
    campaign_id: int | None = None


class DashboardOut(BaseModel):
    total_employees: int
    total_campaigns: int
    total_sent: int
    total_opened: int
    total_clicked: int
    total_submitted: int
    total_reported: int
    avg_se_index: float
    campaigns: list[CampaignOut]
    top_risk: list[dict]


class RiskRow(BaseModel):
    employee_code: str
    full_name: str
    branch: str
    se_index: float
    clicks: int
    submissions: int
    trainings_ok: bool