"""Application settings schema + strict validation (NIST CM-6, ISO 27001 A.5.28).

Settings are an allow-listed schema: unknown keys are rejected (fail closed),
and every value is type-coerced and range-checked. Auth material is stored as a
salted SHA-256 hash, never the raw token (OWASP A02/A07).
"""

from __future__ import annotations

import hashlib
import secrets
from copy import deepcopy

from .validate import is_cidr

SETTINGS_SCHEMA = {
    # Network defaults
    "default_subnet": str,
    "default_listen_port": int,
    "default_mtu": int,
    "default_keepalive": int,
    "first_address_offset": int,
    # Behaviour
    "monitor_interval_sec": int,
    "snapshot_retention": int,
    "audit_retention_days": int,
    # Features
    "psk_enabled": bool,
    "auto_assign_ips": bool,
    # Security
    "auth_enabled": bool,
    "token_hash": str,
    "token_salt": str,
    "require_localhost_only": bool,
    "redact_secrets_in_logs": bool,
    # Backend
    "backend": str,  # auto | local | simulator | dry-run
    "conf_dir": str,
    "data_dir": str,
}

DEFAULTS: dict = {
    "default_subnet": "10.9.0.0/24",
    "default_listen_port": 51820,
    "default_mtu": 1420,
    "default_keepalive": 25,
    "first_address_offset": 1,
    "monitor_interval_sec": 5,
    "snapshot_retention": 10,
    "audit_retention_days": 90,
    "psk_enabled": True,
    "auto_assign_ips": True,
    "auth_enabled": True,
    "token_hash": "",
    "token_salt": "",
    "require_localhost_only": True,
    "redact_secrets_in_logs": True,
    "backend": "auto",
    "conf_dir": "confs",
    "data_dir": "data",
}


def get_defaults() -> dict:
    return deepcopy(DEFAULTS)


def clean_value(key: str, value):
    """Coerce a single value against its declared type. Raises ValueError."""
    expected = SETTINGS_SCHEMA[key]
    if expected is bool:
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            lowered = value.strip().lower()
            if lowered in ("1", "true", "yes", "on"):
                return True
            if lowered in ("0", "false", "no", "off"):
                return False
        raise ValueError(f"{key}: expected boolean")
    if expected is int:
        if isinstance(value, bool):
            raise ValueError(f"{key}: expected integer")
        try:
            return int(value)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"{key}: expected integer") from exc
    if expected is str:
        return str(value).strip()
    raise ValueError(f"{key}: unsupported schema type")


def validate_settings(raw: dict) -> tuple[dict, list[str]]:
    """Validate a dict of user-supplied settings.

    Returns (cleaned, errors). Unknown keys are an error (strict schema).
    """
    cleaned: dict = {k: v for k, v in DEFAULTS.items()}
    cleaned.update({k: None for k in raw})   # mark keys for validation
    errors: list[str] = []

    for key, value in raw.items():
        if key not in SETTINGS_SCHEMA:
            errors.append(f"unknown setting key: {key}")
            continue
        try:
            cleaned[key] = clean_value(key, value)
        except ValueError as exc:
            errors.append(str(exc))

    # Cross-field rules
    if cleaned["default_listen_port"] is not None:
        if not (0 < cleaned["default_listen_port"] < 65536):
            errors.append("default_listen_port must be 1-65535")
    if cleaned["default_mtu"] is not None:
        if not (576 <= int(cleaned["default_mtu"]) <= 65535):
            errors.append("default_mtu must be 576-65535")
    if cleaned["snapshot_retention"] is not None:
        if int(cleaned["snapshot_retention"]) < 1:
            errors.append("snapshot_retention must be >= 1")
    if cleaned["default_subnet"]:
        ok, msg = is_cidr(str(cleaned["default_subnet"]))
        if not ok:
            errors.append(msg)
    if cleaned["backend"] not in ("auto", "local", "simulator", "dry-run"):
        errors.append("backend must be auto|local|simulator|dry-run")

    for key in ("token_hash", "token_salt"):
        if cleaned[key] is None:
            cleaned[key] = ""

    # Hard-code the protected flags never scribed by the UI
    cleaned.pop("data_dir", None)
    cleaned["data_dir"] = DEFAULTS["data_dir"]

    return cleaned, errors


def hash_token(token: str, salt: str) -> str:
    digest = hashlib.sha256((salt + token).encode("utf-8")).digest()
    return digest.hex()


def new_token() -> tuple[str, str, str]:
    """Generate (token, salt, hash). Salt + salted hash are what get stored."""
    token = secrets.token_urlsafe(32)
    salt = secrets.token_hex(16)
    return token, salt, hash_token(token, salt)


def token_matches(settings: dict, candidate: str) -> bool:
    salt = settings.get("token_salt", "")
    expected = settings.get("token_hash", "")
    if not salt or not expected or not candidate:
        return False
    return secrets.compare_digest(hash_token(candidate, salt), expected)