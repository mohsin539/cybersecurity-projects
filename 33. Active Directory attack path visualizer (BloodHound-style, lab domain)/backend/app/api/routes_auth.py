"""Auth endpoints: login (rate-limited), me, logout. JWT bearer."""
from __future__ import annotations

import secrets

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field

from app.api.deps import rate_limit_login
from app.core import audit
from app.core.config import settings
from app.core.errors import ApiError
from app.core.security import (
    USERS, create_access_token, get_current_user, verify_password,
)

router = APIRouter(prefix="/auth", tags=["auth"])


class LoginIn(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=128)


def _check_password(plain: str, stored: str) -> bool:
    """Hashed when a hash is configured; constant-time compare for the
    seeded lab accounts (plaintext by design, lab profile only)."""
    if "$" in stored:  # passlib hash format e.g. bcrypt$...
        return verify_password(plain, stored)
    return secrets.compare_digest(plain, stored)


@router.post("/login")
def login(body: LoginIn, request: Request,
          _: None = Depends(rate_limit_login)) -> dict:
    user = USERS.get(body.username)
    if not user or not _check_password(body.password, user["password"]):
        audit.record("auth.login", actor=body.username, outcome="failure",
                     severity="warn", ip=request.client.host
                     if request.client else "")
        raise ApiError(401, "BAD_CREDENTIALS", "Invalid username or password")
    token, exp = create_access_token(body.username, user["role"])
    audit.record("auth.login", actor=body.username, outcome="success")
    return {
        "access_token": token,
        "token_type": "bearer",
        "expires_at": exp,
        "role": user["role"],
        "full_name": user["full_name"],
        "token_minutes": settings.access_token_minutes,
    }


@router.get("/me")
def me(user: dict = Depends(get_current_user)) -> dict:
    return user


@router.post("/logout")
def logout(user: dict = Depends(get_current_user)) -> dict:
    audit.record("auth.logout", actor=user["username"])
    # Stateless JWT: client discards token; prod adds a denylist via jti.
    return {"status": "logged_out"}
