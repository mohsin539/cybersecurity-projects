"""JWT issuance / verification and refresh-token handling."""

from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timedelta, timezone

import jwt

from app.config import settings


def _now() -> datetime:
    return datetime.now(timezone.utc)


def create_access_token(user_id: int, username: str, role: str, jti: str | None = None) -> str:
    now = _now()
    payload = {
        "sub": str(user_id),
        "username": username,
        "role": role,
        "iat": now,
        "exp": now + timedelta(minutes=settings.access_token_ttl_minutes),
        "type": "access",
        "jti": jti or secrets.token_urlsafe(12),
    }
    return jwt.encode(payload, settings.secret_key, algorithm=settings.jwt_alg)


def create_refresh_token(user_id: int) -> tuple[str, str, datetime]:
    """Returns (jwt, jti_hash, expires_at). Only the jti hash is persisted."""
    jti = secrets.token_urlsafe(16)
    expires = _now() + timedelta(days=settings.refresh_token_ttl_days)
    payload = {
        "sub": str(user_id),
        "exp": expires,
        "iat": _now(),
        "type": "refresh",
        "jti": jti,
    }
    token = jwt.encode(payload, settings.secret_key, algorithm=settings.jwt_alg)
    return token, hash_refresh_jti(jti), expires


def decode_token(token: str, expected_type: str = "access") -> dict:
    opts = {"verify_aud": False, "verify_iss": False, "require": ["jti"]}
    return jwt.decode(token, settings.secret_key, algorithms=[settings.jwt_alg], options=opts)


def hash_refresh_jti(jti: str) -> str:
    return hashlib.sha256(jti.encode()).hexdigest()