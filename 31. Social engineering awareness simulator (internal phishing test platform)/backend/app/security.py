import hashlib
import hmac
import os
import secrets
from datetime import datetime, timedelta, timezone

import jwt

from .config import get_settings

PBKDF2_ITERATIONS = 600_000


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ITERATIONS)
    return salt.hex() + "$" + digest.hex()


def verify_password(password: str, stored: str) -> bool:
    try:
        salt_hex, digest_hex = stored.split("$", 1)
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(digest_hex)
    except (ValueError, AttributeError):
        return False
    actual = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ITERATIONS)
    return hmac.compare_digest(actual, expected)


def create_access_token(subject: int, role: str, username: str) -> str:
    settings = get_settings()
    expires = datetime.now(timezone.utc) + timedelta(
        minutes=settings.access_token_expire_minutes
    )
    payload = {"sub": str(subject), "role": role, "username": username, "exp": expires}
    return jwt.encode(payload, settings.secret_key, algorithm=settings.algorithm)


def decode_token(token: str) -> dict:
    settings = get_settings()
    return jwt.decode(token, settings.secret_key, algorithms=[settings.algorithm])


def hash_value(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def mask_username(value: str) -> str:
    if not value:
        return ""
    if len(value) <= 2:
        return "*" * len(value)
    return value[:1] + "*" * (len(value) - 2) + value[-1:]


def new_token() -> str:
    return secrets.token_urlsafe(32)


def audit_hash(prev_hash: str, payload: str) -> str:
    return hashlib.sha256((prev_hash + "|" + payload).encode()).hexdigest()