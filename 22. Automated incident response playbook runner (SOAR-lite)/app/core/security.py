"""Password hashing, JWT issuance/validation, role authorization, CSRF.

OWASP Top 10 alignment:
  - A2/A7: bcrypt (cost 12) password hashing + short-lived signed tokens
  - A1: central `require_perm` dependency enforcing RBAC on every endpoint
  - A5: deny-by-default permission matrix
"""
from __future__ import annotations

import datetime as dt
import secrets
import uuid
from typing import Optional

import bcrypt
import jwt
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.config import settings
from app.db.base import db_session
from app.db.models import User

TOKEN_COOKIE = "soarlite_token"
CSRF_COOKIE = "csrf_token"

ROLE_PERMISSIONS: dict[str, set[str]] = {
    "viewer": {"alerts.read", "cases.read", "cases.read_timeline", "reports.read", "evidence.read"},
    "analyst": {"alerts.read", "alerts.update", "cases.read", "cases.read_timeline", "cases.write",
                "cases.comment", "evidence.read", "evidence.create", "reports.read", "runs.read"},
    "approver": {"alerts.read", "cases.read", "cases.read_timeline", "approvals.read", "approvals.decide",
                 "evidence.read", "reports.read", "runs.read"},
    "author": {"alerts.read", "cases.read", "cases.read_timeline", "playbooks.read", "playbooks.write",
               "playbooks.publish", "reports.read", "runs.read", "runs.cancel", "replay", "evidence.read"},
    "admin": {
        "alerts.read", "alerts.update", "cases.read", "cases.read_timeline", "cases.write", "cases.comment",
        "evidence.read", "evidence.create", "reports.read", "runs.read", "runs.cancel", "replay",
        "playbooks.read", "playbooks.write", "playbooks.publish", "approvals.read", "approvals.decide",
        "users.manage", "audit.read", "audit.verify", "connectors.manage", "settings.manage",
        "retention.run", "ingest",
    },
    # Service account for machine-to-machine alert ingestion
    "automation": {"ingest"},
}


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode("utf-8")


def verify_password(password: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))
    except ValueError:
        return False


def create_access_token(user: User) -> str:
    now = dt.datetime.now(dt.timezone.utc)
    payload = {
        "sub": user.id,
        "username": user.username,
        "role": user.role,
        "jti": uuid.uuid4().hex,
        "iat": now,
        "exp": now + dt.timedelta(minutes=settings.access_token_ttl_minutes),
    }
    return jwt.encode(payload, settings.secret_key, algorithm=settings.jwt_algorithm)


def decode_token(token: str) -> Optional[dict]:
    try:
        return jwt.decode(token, settings.secret_key, algorithms=[settings.jwt_algorithm])
    except jwt.PyJWTError:
        return None


class _Bearer(HTTPBearer):
    def __init__(self) -> None:
        super().__init__(auto_error=False)


BEARER = _Bearer()


def _load_user(db: Session, user_id: str) -> Optional[User]:
    return db.get(User, user_id)


def get_current_user(
    request: Request,
    db: Session = Depends(db_session),
    credentials: HTTPAuthorizationCredentials | None = Depends(BEARER),
) -> User:
    token: Optional[str] = None
    if credentials is not None:
        token = credentials.credentials
    elif request.cookies.get(TOKEN_COOKIE):
        token = request.cookies.get(TOKEN_COOKIE)

    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")

    payload = decode_token(token)
    if payload is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token")

    user = _load_user(db, payload.get("sub", ""))
    if user is None or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User inactive or missing")
    return user


def _has_permission(user: User, permission: str) -> bool:
    perms = ROLE_PERMISSIONS.get(user.role, set())
    if user.role == "admin":
        perms = ROLE_PERMISSIONS["admin"]
    return permission in perms


def require_perm(permission: str):
    def dependency(user: User = Depends(get_current_user)) -> User:
        if not _has_permission(user, permission):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=f"Missing permission: {permission}")
        return user

    return dependency


def actor_name(user: User) -> str:
    return f"{user.username} ({user.role})"


def issue_csrf_token() -> str:
    return secrets.token_urlsafe(32)


def validate_csrf(request: Request) -> None:
    """Double-submit cookie CSRF check for browser UI mutations.

    Requests without the browser cookie (e.g. Bearer API clients) bypass CSRF.
    """
    cookie = request.cookies.get(CSRF_COOKIE)
    if cookie is None:
        return

    header = request.headers.get("X-CSRF-Token", "")
    if not header or not secrets.compare_digest(cookie, header):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="CSRF validation failed")