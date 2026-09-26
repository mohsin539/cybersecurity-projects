"""Authentication endpoints: login, refresh, logout, change-password.

Password hashing: argon2id. Refresh tokens: httpOnly+Secure cookie, jti
revocable. Failed attempts are audited (AU-2/A.12.4) and rate-limited.
"""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy.orm import Session

from app.api.schemas import ChangePasswordRequest, LoginRequest, UserOut
from app.config import settings
from app.db.models import RefreshToken, User
from app.db.session import get_db
from app.security.audit import audit
from app.security.dependencies import Principal, client_ip, get_current_user
from app.security.passwords import hash_password, verify_password
from app.security.ratelimit import enforce_api_limit
from app.security.tokens import create_access_token, create_refresh_token

router = APIRouter(prefix="/api/auth", tags=["auth"])
REFRESH_COOKIE = "xt_refresh"


@router.post("/login", response_model=dict)
def login(
    body: LoginRequest,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
):
    ip = client_ip(request)
    enforce_api_limit(request, f"login:{body.username}")
    user = db.query(User).filter(User.username == body.username.lower()).first()
    if user is None or not verify_password(body.password, user.password_hash):
        audit.record("auth.login", actor=body.username, outcome="failure",
                     resource="user", ip=ip, details={"reason": "bad credentials"})
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid credentials")
    if not user.enabled:
        audit.record("auth.login", actor=user.username, outcome="failure",
                     resource="user", ip=ip, details={"reason": "disabled account"})
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="account disabled")

    access = create_access_token(user.id, user.username, user.role.value)
    refresh, jti_hash, expires = create_refresh_token(user.id)
    db.add(RefreshToken(user_id=user.id, jti_hash=jti_hash, expires_at=expires,
                        user_agent=(request.headers.get("user-agent") or "")[:255]))
    user.last_login_at = datetime.now(timezone.utc)
    db.add(user)
    db.commit()

    _set_refresh_cookie(response, refresh)
    audit.record("auth.login", actor=user.username, outcome="success", resource="user", ip=ip)
    return {"access_token": access, "token_type": "bearer", "expires_in": 900, "user": UserOut.model_validate(user)}


@router.post("/refresh", response_model=dict)
def refresh(request: Request, response: Response, db: Session = Depends(get_db)):
    from app.security.dependencies import refresh_principal_for_rotation

    user, _old = refresh_principal_for_rotation(request, db)
    access = create_access_token(user.id, user.username, user.role.value)
    refresh, jti_hash, expires = create_refresh_token(user.id)
    db.add(RefreshToken(user_id=user.id, jti_hash=jti_hash, expires_at=expires,
                        user_agent=(request.headers.get("user-agent") or "")[:255]))
    db.commit()
    _set_refresh_cookie(response, refresh)
    return {"access_token": access, "token_type": "bearer", "expires_in": 900}


@router.post("/logout")
def logout(request: Request, response: Response, db: Session = Depends(get_db),
           principal: Principal = Depends(get_current_user)):
    cookie = request.cookies.get(REFRESH_COOKIE)
    if cookie:
        from app.security.tokens import hash_refresh_jti, decode_token

        try:
            payload = decode_token(cookie, "refresh")
            stored = db.query(RefreshToken).filter(
                RefreshToken.jti_hash == hash_refresh_jti(payload["jti"])
            ).first()
            if stored:
                stored.revoked = True
                db.add(stored)
                db.commit()
        except Exception:  # noqa: BLE001
            pass
    response.delete_cookie(REFRESH_COOKIE, httponly=True, secure=True)
    audit.record("auth.logout", actor=principal.username, resource="session",
                 ip=client_ip(request))
    return {"ok": True}


@router.get("/me")
def me(principal: Principal = Depends(get_current_user)):
    return {"user": UserOut.model_validate(principal.user)}


@router.post("/change-password")
def change_password(
    body: ChangePasswordRequest,
    request: Request,
    db: Session = Depends(get_db),
    principal: Principal = Depends(get_current_user),
):
    user = db.get(User, principal.user.id)
    if not verify_password(body.old_password, user.password_hash):
        audit.record("auth.change_password", actor=user.username, outcome="failure",
                     ip=client_ip(request))
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="old password incorrect")
    user.password_hash = hash_password(body.new_password)
    user.must_change_password = False
    db.add(user)
    db.commit()
    audit.record("auth.change_password", actor=user.username, outcome="success", ip=client_ip(request))
    return {"ok": True}


def _set_refresh_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        key=REFRESH_COOKIE,
        value=token,
        httponly=True,
        samesite="strict",
        secure=settings.app_env == "production",
        path="/api/auth",
        max_age=7 * 24 * 3600,
    )