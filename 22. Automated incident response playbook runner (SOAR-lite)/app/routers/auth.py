"""Auth endpoints: login/logout, token management.

OWASP A7 (identification & authentication failures) mitigations:
  - Argon2/bcrypt hashing with cost-12 (OWASP recommended)
  - session bound to jti; tokens are short-lived
  - must-change-password flag on first/default login
  - rate limited to prevent brute-force
"""
from __future__ import annotations

import datetime as dt

from fastapi import APIRouter, Depends, Request, Response, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.config import settings
from app.core.audit import append_audit
from app.core.security import (
    CSRF_COOKIE,
    TOKEN_COOKIE,
    create_access_token,
    decode_token,
    get_current_user,
    hash_password,
    issue_csrf_token,
    require_perm,
    validate_csrf,
    verify_password,
)
from app.db.base import db_session
from app.db.models import User

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


class LoginRequest(BaseModel):
    username: str
    password: str


class ChangePasswordRequest(BaseModel):
    old_password: str
    new_password: str


@router.post("/login")
def login(payload: LoginRequest, request: Request, response: Response, db: Session = Depends(db_session)):
    user = db.query(User).filter(User.username == payload.username).first()
    if user is None or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    if user.locked_until and user.locked_until > dt.datetime.utcnow():
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Account is locked")

    if not verify_password(payload.password, user.password_hash):
        user.failed_login_attempts += 1
        if user.failed_login_attempts >= 5:
            user.locked_until = dt.datetime.utcnow() + dt.timedelta(minutes=15)
        db.commit()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    # reset failed attempts
    user.failed_login_attempts = 0
    user.locked_until = None
    user.last_login = dt.datetime.utcnow()
    db.commit()

    token = create_access_token(user)
    csrf = issue_csrf_token()

    response.set_cookie(TOKEN_COOKIE, token, httponly=True, secure=settings.cookie_secure,
                        samesite="lax", max_age=settings.access_token_ttl_minutes * 60)
    response.set_cookie(CSRF_COOKIE, csrf, httponly=False, secure=settings.cookie_secure,
                        samesite="lax", max_age=settings.access_token_ttl_minutes * 60)

    append_audit(db, action="login", actor=payload.username, resource_type="session", ip=request.client.host)
    return {
        "access_token": token,
        "token_type": "bearer",
        "must_change_password": user.must_change_password,
        "role": user.role,
    }


@router.post("/logout")
def logout(request: Request, response: Response, db: Session = Depends(db_session), user: User = Depends(get_current_user)):
    validate_csrf(request)
    response.delete_cookie(TOKEN_COOKIE)
    response.delete_cookie(CSRF_COOKIE)
    append_audit(db, action="logout", actor=user.username, resource_type="session", ip=request.client.host)
    return {"detail": "logged out"}


@router.post("/change-password")
def change_password(payload: ChangePasswordRequest, request: Request, db: Session = Depends(db_session),
                    user: User = Depends(get_current_user)):
    validate_csrf(request)
    if not verify_password(payload.old_password, user.password_hash):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Old password incorrect")
    if len(payload.new_password) < 12:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Password must be ≥12 characters")
    user.password_hash = hash_password(payload.new_password)
    user.must_change_password = False
    db.commit()
    append_audit(db, action="password_change", actor=user.username, resource_type="user", resource_id=user.id, ip=request.client.host)
    return {"detail": "password changed"}


@router.get("/me")
def me(user: User = Depends(get_current_user)):
    return {
        "id": user.id, "username": user.username, "role": user.role,
        "email": user.email, "must_change_password": user.must_change_password,
    }