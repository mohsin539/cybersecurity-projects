from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    app_name: str = "Social Engineering Awareness Simulator"
    database_url: str = "sqlite:///./seas.db"
    secret_key: str = "dev-only-secret-rotate-me-0123456789abcdef"
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 180

    seed_admin_username: str = "admin"
    seed_admin_password: str = "Admin@12345"
    seed_admin_email: str = "admin@example.com"

    cors_origins: str = "http://localhost:5173,http://127.0.0.1:5173"

    reports_dir: str = "services/reports"
    lure_base_url: str = "http://localhost:8000"


def get_settings() -> Settings:
    from functools import lru_cache

    @lru_cache
    def _cached() -> Settings:
        return Settings()

    return _cached()