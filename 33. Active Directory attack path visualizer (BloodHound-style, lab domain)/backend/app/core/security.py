"""Authentication & authorization primitives.

- Passwords: bcrypt via passlib (OWASP ASVS 2.4; Argon2id preferred in prod).
- Tokens:    short-lived signed JWTs (OWASP A07 / NIST SP 800-63B AAL2).
- RBAC:      analyst / auditor / admin roles enforced on every route.
"""
from __future__ import annotations

import secrets
import time
import uuid
from typing import Any

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt

from app.core.config import settings

_BCRYPT_OK = True
try:
    from passlib.context import CryptContext
    _pwd = CryptContext(schemes=["bcrypt"], deprecated="auto")
except Exception:  # pragma: no cover - fallback if bcrypt wheel missing
    _BCRYPT_OK = False
    import base64
    import hashlib

    class _Pbkdf2:
        def hash(self, p: str) -> str:
            salt = secrets.token_bytes(16)
            dk = hashlib.pbkdf2_hmac("sha256", p.encode(), salt, 600_000)
            return "pbkdf2$" + base64.b64encode(salt + dk).decode()

        def verify(self, p: str, h: str) -> bool:
            try:
                raw = base64.b64decode(h.split("$", 1)[1])
                salt, dk = raw[:16], raw[16:]
            except Exception:
                return False
            calc = hashlib.pbkdf2_hmac("sha256", p.encode(), salt, 600_000)
            return secrets.compare_digest(calc, dk)

    _pwd = _Pbkdf2()  # type: ignore[assignment]

HTTP_BEARER = HTTPBearer(auto_error=False)

# Lab accounts (RBAC demonstration). Production binds these to AD via LDAPS;
# service accounts are excluded from interactive logon per PCI DSS 8.2.2.
USERS: dict[str, dict[str, Any]] = {
    "admin": {"password": "ChangeMe!Lab2024", "role": "admin",
              "full_name": "Lab Administrator"},
    "analyst": {"password": "Analyst!Lab2024", "role": "analyst",
                "full_name": "Security Analyst"},
    "auditor": {"password": "Auditor!Lab2024", "role": "auditor",
                "full_name": "Compliance Auditor"},
}


def hash_password(password: str) -> str:
    return _pwd.hash(password)


def verify_password(password: str, hashed: str) -> bool:
    return _pwd.verify(password, hashed)


def create_access_token(subject: str, role: str) -> tuple[str, int]:
    now = int(time.time())
    exp = now + settings.access_token_minutes * 60
    payload = {
        "sub": subject,
        "role": role,
        "iat": now,
        "exp": exp,
        "jti": uuid.uuid4().hex,
        "iss": "sentinelgraph",
    }
    token = jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)
    return token, exp


def _unauth(detail: str = "Not authenticated") -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=detail,
        headers={"WWW-Authenticate": "Bearer"},
    )


def get_current_user(
    creds: HTTPAuthorizationCredentials | None = Depends(HTTP_BEARER),
) -> dict[str, Any]:
    if creds is None or creds.scheme.lower() != "bearer":
        raise _unauth()
    token = creds.credentials
    try:
        payload = jwt.decode(
            token, settings.jwt_secret,
            algorithms=[settings.jwt_algorithm],
            options={"require": ["exp", "sub", "role"]},
        )
    except JWTError:
        raise _unauth("Invalid or expired token")
    return {"username": payload["sub"], "role": payload["role"]}


def require_role(*allowed: str):
    def checker(user: dict[str, Any] = Depends(get_current_user)) -> dict[str, Any]:
        if user["role"] not in allowed:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient role for this operation",
            )
        return user
    return checker
