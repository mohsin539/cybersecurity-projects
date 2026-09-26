import time
from collections import defaultdict

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import models, schemas
from ..db import get_db
from ..deps import client_ip, get_current_user
from ..security import create_access_token, verify_password
from ..services.audit import AuditService

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])

LOGIN_WINDOW_SECONDS = 60
LOGIN_MAX_ATTEMPTS = 8
_login_attempts: dict[str, list[float]] = defaultdict(list)


def _rate_limit(ip: str) -> None:
    now = time.monotonic()
    kept = [ts for ts in _login_attempts[ip] if now - ts < LOGIN_WINDOW_SECONDS]
    _login_attempts[ip] = kept
    if len(kept) >= LOGIN_MAX_ATTEMPTS:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many login attempts. Try again later.",
        )
    _login_attempts[ip].append(now)


@router.post("/token", response_model=schemas.TokenOut)
def login(
    body: schemas.LoginIn,
    request: Request,
    db: Session = Depends(get_db),
) -> schemas.TokenOut:
    ip = client_ip(request)
    _rate_limit(ip)

    user = db.scalar(
        select(models.User).where(models.User.username == body.username.lower())
    )
    if user is None or not user.is_active or not verify_password(body.password, user.hashed_password):
        AuditService(db, body.username, ip).log("login.failed", "user")
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )

    token = create_access_token(user.id, user.role, user.username)
    AuditService(db, user.username, ip).log("login.success", "user", user.id)
    db.commit()
    return schemas.TokenOut(
        access_token=token,
        user=schemas.UserOut.model_validate(user),
    )


@router.get("/me", response_model=schemas.UserOut)
def me(user: models.User = Depends(get_current_user)) -> models.User:
    return user