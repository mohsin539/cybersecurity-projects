"""Core application configuration loaded from environment / .env file.

Implements OWASP Top 10 A05 (security configuration): all security-relevant
knobs are centralized here, validated at startup, and fail closed on
invalid or insecure production values.
"""

from __future__ import annotations

import re
from functools import lru_cache
from typing import Literal

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

APP_ENV_VALUES = ("development", "test", "production")


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=(".env", "../../.env"),
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # --- application -------------------------------------------------------
    app_name: str = "xtester"
    app_env: Literal["development", "test", "production"] = "development"
    log_level: str = "INFO"
    public_base_url: str = "http://localhost:8000"

    # --- auth --------------------------------------------------------------
    secret_key: str = "dev-only-change-me"
    jwt_alg: str = Field(default="HS256", pattern=r"^HS(256|384|512)$")
    access_token_ttl_minutes: int = 15
    refresh_token_ttl_days: int = 7
    bootstrap_admin_username: str = "admin"
    bootstrap_admin_password: str = "change-me-strong-password"

    # --- database ----------------------------------------------------------
    database_url: str = "sqlite:///./data/xtester.db"

    # --- queue ---------------------------------------------------------------
    celery_broker_url: str = "redis://localhost:6379/0"
    celery_result_backend: str = "redis://localhost:6379/0"
    celery_task_always_eager: bool = False

    # --- scanner -----------------------------------------------------------
    scan_default_wait_ms: int = 800
    scan_max_payloads: int = 400
    scan_concurrency: int = 2
    scan_http_timeout: int = 15_000
    scan_allow_redirects: bool = True
    detector_min_confidence: float = 0.6

    # --- security controls ---------------------------------------------------
    rate_limit_per_minute: int = 60
    rate_limit_scans_per_day: int = 50
    audit_log_dir: str = "./data/audit"
    audit_enable_tamper_evidence: bool = True
    allowed_target_hosts: str = "localhost,127.0.0.1,172.16.*"
    require_https_for_non_local: bool = True

    @field_validator("app_env")
    @classmethod
    def _validate_env(cls, v: str) -> str:
        if v not in APP_ENV_VALUES:
            raise ValueError(f"app_env must be one of {APP_ENV_VALUES}")
        return v

    @field_validator("log_level")
    @classmethod
    def _validate_log_level(cls, v: str) -> str:
        if v.upper() not in ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"):
            raise ValueError(f"invalid LOG_LEVEL {v}")
        return v.upper()

    @model_validator(mode="after")
    def _validate_production_security(self) -> "Settings":
        env = self.app_env.lower()
        if env == "production":
            if len(self.secret_key) < 32 or self.secret_key in (
                "dev-only-change-me",
                "change-me-strong-password",
            ):
                raise ValueError("refusing to start in production with weak SECRET_KEY")
            if not self.audit_enable_tamper_evidence:
                raise ValueError("production requires tamper-evident audit logging")
            if "sqlite" in self.database_url:
                raise ValueError("production requires a real database (postgres)")
        return self

    # --- derived helpers -----------------------------------------------------
    @property
    def allowed_host_patterns(self) -> list[str]:
        return [p.strip().lower() for p in self.allowed_target_hosts.split(",") if p.strip()]

    def host_allowed(self, hostname: str) -> bool:
        """Allowlist enforcement (A.8.22/SC-7 style). Return True if a scan
        target host is permitted."""
        hostname = (hostname or "").strip().lower().rstrip(".")
        for pattern in self.allowed_host_patterns:
            pat = re.escape(pattern).replace(r"\*", r"[a-z0-9.\-]*")
            if re.fullmatch(pat, hostname):
                return True
        return False


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()