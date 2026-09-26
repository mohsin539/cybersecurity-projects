"""Central configuration.

Security defaults are conservative: auth required, security headers on,
rate limiting on. All knobs can be overridden via environment variables.
"""
from __future__ import annotations

import os
from functools import lru_cache

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    app_name: str = "SentinelGraph AD Attack Path Visualizer"
    version: str = "1.0.0"
    environment: str = "lab"  # lab | staging | production
    api_prefix: str = "/api/v1"
    log_level: str = "INFO"

    # ---- Auth / crypto -------------------------------------------------
    jwt_secret: str = Field(default_factory=lambda: os.environ.get("JWT_SECRET", ""))
    jwt_algorithm: str = "HS256"
    access_token_minutes: int = 15
    # Argon2id is preferred in prod; bcrypt chosen for lab portability.
    password_hash_scheme: str = "bcrypt"

    # ---- Neo4j ---------------------------------------------------------
    neo4j_enabled: bool = False  # false => in-memory lab store
    neo4j_uri: str = "bolt://localhost:7687"
    neo4j_user: str = "neo4j"
    neo4j_password: str = ""
    neo4j_database: str = "neo4j"

    # ---- Rate limiting -------------------------------------------------
    rate_limit_enabled: bool = True
    rate_limit_login: str = "5/minute"
    rate_limit_api: str = "120/minute"

    # ---- Scheduled re-scan (0 = disabled) --------------------------------
    rescan_interval_minutes: int = 0

    # ---- Compliance posture -------------------------------------------
    compliance_frameworks: tuple[str, ...] = (
        "owasp_top10_2021",
        "iso27001_2022",
        "nist_csf_20",
        "nist_80053_r5",
        "pci_dss_40",
        "cis_controls_v8",
    )

    @field_validator("jwt_secret")
    @classmethod
    def _secret_strength(cls, v: str) -> str:
        if v and len(v) < 32:
            raise ValueError(
                "JWT_SECRET must be >= 32 chars (NIST SP 800-63B / OWASP A02)"
            )
        return v

    model_config = {"env_file": ".env", "env_prefix": "SG_", "extra": "ignore"}


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
