"""Application configuration loaded from environment / .env."""
from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    app_name: str = "SOAR-Lite"
    app_env: str = "development"
    debug: bool = False
    log_level: str = "INFO"
    secret_key: str = "dev-insecure-secret-change-me"

    database_url: str = "sqlite:///./data/soarlite.db"

    host: str = "0.0.0.0"
    port: int = 8000
    base_url: str = "http://localhost:8000"
    cookie_secure: bool = False
    hsts_seconds: int = 0

    access_token_ttl_minutes: int = 480
    jwt_algorithm: str = "HS256"

    admin_username: str = "admin"
    admin_email: str = "admin@soarlite.local"
    admin_password: str = "ChangeMe!NoW1"
    admin_must_change_password: bool = True

    ingest_hmac_key: str = ""

    secrets_master_key: str = ""

    engine_poll_interval_seconds: float = 1.0
    enable_embedded_worker: bool = True
    max_active_runs: int = 50
    default_retries: int = 2
    default_retry_backoff_seconds: int = 2

    connector_egress_allowlist: str = "0.0.0.0/0"

    audit_retention_days: int = 0
    alert_retention_days: int = 0
    case_retention_days: int = 0

    redaction_keys: str = "email,email_address,sender_email,recipient_emails,phone,ssn,password,token,id_token"

    @property
    def is_production(self) -> bool:
        return self.app_env.lower() == "production"

    @property
    def redaction_key_set(self) -> set[str]:
        return {k.strip().lower() for k in self.redaction_keys.split(",") if k.strip()}


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()