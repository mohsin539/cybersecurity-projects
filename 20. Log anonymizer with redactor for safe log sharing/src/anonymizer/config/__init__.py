"""Runtime configuration for the anonymizer (env-driven, secure defaults)."""

import os
from dataclasses import dataclass


def _env_bool(name: str, default: bool = False) -> bool:
    return os.getenv(name, str(default)).lower() in ("1", "true", "yes", "on")


@dataclass
class RuntimeConfig:
    """Environment-driven configuration (12-factor)."""

    # Core
    policy_file: str = os.getenv("ANON_POLICY_FILE", "config/policies.yaml")
    detection_timeout_ms: int = int(os.getenv("ANON_DETECT_TIMEOUT", "500"))
    max_line_length: int = int(os.getenv("ANON_MAX_LINE_LEN", "100000"))

    # Security
    token_salt: str = os.getenv("ANON_TOKEN_SALT", "")
    require_approval: bool = _env_bool("ANON_REQUIRE_APPROVAL", True)
    audit_directory: str = os.getenv("ANON_AUDIT_DIR", "data/audit")

    # Output
    output_format: str = os.getenv("ANON_OUTPUT_FORMAT", "json")
    default_retention_days: int = int(os.getenv("ANON_RETENTION", "30"))

    # API
    api_host: str = os.getenv("ANON_API_HOST", "0.0.0.0")
    api_port: int = int(os.getenv("ANON_API_PORT", "8000"))
    allowed_origins: str = os.getenv("ANON_ALLOWED_ORIGINS", "*")


def load_config(env_prefix: str = "ANON_") -> RuntimeConfig:
    """Load configuration from environment (with safe fallbacks)."""
    return RuntimeConfig()
