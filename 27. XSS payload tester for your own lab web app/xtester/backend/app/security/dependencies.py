"""FastAPI auth dependencies: JWT bearer, API key, optional web session.

Lookup is done by primary key fetched from a token's `sub` claim to avoid
DB hit on every keystroke only when caching could go stale; here we do the
safe thing and hit the DB on each authenticated request (cheap at this
scale and avoids stale-user / revocation-window issues: ISO 27001 A.9.2.6).
"""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import APIKeyHeader, HTTPAuthorizationCredentials, HTTPBearer

from app.db.session import get_db
from app.db.models import ApiKey, RefreshToken, Role, User
from app.security.audit import audit
from app.security.passwords import hash_key
from app.security.tokens import decode_token, hash_refresh_jti
from sqlalchemy.orm import Session

_bearer = HTTPBearer(auto_error=False)
_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


class Principal:
    """Authenticated identity (user or API key) with an effective role."""

    def __init__(self, user: User, via: str, role: Role | None = None):
        self.user = user
        self.via = via
        self.role = role or user.role

    @property
    def username(self) -> str:
        return self.user.username

    def audit_actor(self) -> str:
        return self.username

    def require(self, *roles: Role) -> None:
        if self.role not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="insufficient permissions (RBAC)",
            )


def _client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def get_principal(
    request: Request,
    creds: HTTPAuthorizationCredentials | None = Depends(_bearer),
    api_key: str | None = Depends(_api_key_header),
    db: Session = Depends(get_db),
) -> Principal:
    if creds and creds.scheme.lower() == "bearer":
        return _principal_from_jwt(request, creds.credentials, db)
    if api_key:
        return _principal_from_api_key(request, api_key, db)
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="missing or invalid credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )


def _principal_from_jwt(request: Request, token: str, db: Session) -> Principal:
    try:
        payload = decode_token(token, expected_type="access")
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid or expired token"
        )
    if payload.get("type") != "access":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="token type mismatch")
    user = db.get(User, int(payload["sub"]))
    if user is None or not user.enabled:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="account disabled")
    return Principal(user=user, via="jwt")


def _principal_from_api_key(request: Request, api_key: str, db: Session) -> Principal:
    record = db.query(ApiKey).filter(ApiKey.key_hash == hash_key(api_key)).first()
    if record is None or not record.enabled:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid API key")
    exp = record.expires_at
    if exp and exp.tzinfo is None:
        exp = exp.replace(tzinfo=timezone.utc)
    if exp and exp < datetime.now(timezone.utc):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="API key expired")
    user = db.get(User, record.user_id)
    if user is None or not user.enabled:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="account disabled")
    record.last_used_at = datetime.now(timezone.utc)
    db.add(record)
    db.commit()
    return Principal(user=user, via="api_key", role=record.role_binding)


def get_current_user(request: Request, principal: Principal = Depends(get_principal)) -> Principal:
    return principal


def refresh_principal_for_rotation(request: Request, db: Session) -> tuple[User, str]:
    """Used during POST /auth/refresh. Reads the httpOnly refresh cookie,
    validates the JWT and that its jti is not revoked."""
    cookie = request.cookies.get("xt_refresh")
    if not cookie:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="missing refresh cookie")
    try:
        payload = decode_token(cookie, expected_type="refresh")
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid refresh token")
    if payload.get("type") != "refresh":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="token type mismatch")
    stored = (
        db.query(RefreshToken)
        .filter(RefreshToken.jti_hash == hash_refresh_jti(payload["jti"]))
        .first()
    )
    if stored is None or stored.revoked:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="refresh token revoked")
    user = db.get(User, int(payload["sub"]))
    if user is None or not user.enabled:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="account disabled")
    # rotate
    _ = stored
    db.delete(stored)
    db.commit()
    return user, cookie


def audit_failed_auth(request: Request, reason: str) -> None:
    audit.record(
        "auth.failed",
        actor=None,
        outcome="failure",
        resource="auth",
        ip=_client_ip(request),
        details={"reason": reason},
        severity="warning",
    )


def client_ip(request: Request) -> str:
    return _client_ip(request)