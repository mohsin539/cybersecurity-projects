"""Auth: login, profile, user management (RBAC)."""
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from ..database import naive_utcnow

from ..database import get_db
from ..models import User
from ..security import (
    audit, client_ip, create_token, get_current_user, hash_password, require,
    verify_password,
)

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/login")
def login(payload: dict, request: Request, db: Session = Depends(get_db)):
    username = payload.get("username", "").strip()
    password = payload.get("password", "")
    user = db.query(User).filter(User.username == username).first()
    if not user or not user.is_active or not verify_password(password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials or inactive user")
    user.last_login = naive_utcnow()
    db.commit()
    audit(db, user.username, user.role, "LOGIN_SUCCESS", "USER", user.id,
          {"mfa_enabled": user.mfa_enabled}, client_ip(request))
    tokens = create_token(user)
    return {"token": tokens["access_token"], "token_type": "bearer",
            "expires_in": tokens["expires_in"],
            "user": {"id": user.id, "username": user.username,
                     "display_name": user.display_name, "role": user.role}}


@router.get("/me")
def me(user: User = Depends(get_current_user)):
    return {"id": user.id, "username": user.username, "display_name": user.display_name,
            "role": user.role, "mfa_enabled": user.mfa_enabled}


@router.get("/users")
def list_users(db: Session = Depends(get_db), user: User = Depends(require("user:read"))):
    users = db.query(User).all()
    return [{"id": u.id, "username": u.username, "email": u.email,
             "display_name": u.display_name, "role": u.role,
             "mfa_enabled": u.mfa_enabled, "is_active": u.is_active,
             "last_login": u.last_login.isoformat() if u.last_login else None} for u in users]


@router.post("/users")
def create_user(payload: dict, request: Request, db: Session = Depends(get_db),
                user: User = Depends(require("user:read"))):
    if user.role != "SUPER_ADMIN":
        raise HTTPException(status_code=403, detail="Only SUPER_ADMIN can create users")
    if db.query(User).filter(
        (User.username == payload["username"]) | (User.email == payload["email"])
    ).first():
        raise HTTPException(status_code=409, detail="Username/email exists")
    nu = User(
        username=payload["username"], email=payload["email"],
        display_name=payload.get("display_name", payload["username"]),
        password_hash=hash_password(payload["password"]),
        role=payload.get("role", "VIEWER"),
        mfa_enabled=payload.get("mfa_enabled", True),
    )
    db.add(nu)
    db.commit()
    db.refresh(nu)
    audit(db, user.username, user.role, "USER_CREATE", "USER", nu.id,
          {"target": nu.username, "role": nu.role}, client_ip(request))
    return {"id": nu.id, "username": nu.username, "role": nu.role}