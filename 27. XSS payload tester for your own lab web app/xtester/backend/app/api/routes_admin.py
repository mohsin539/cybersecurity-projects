"""Administrator endpoints: users, API keys, scan targets, audit log.

All mutations are audited and require the `admin` role (ISO 27001 A.9.2,
NIST AC-2; least privilege).
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.api.schemas import CreateApiKeyRequest, CreateUserRequest, TargetCreate, UserOut
from app.config import settings
from app.db.models import ApiKey, AuditLog, Role, Target, User
from app.db.session import get_db
from app.security.audit import audit
from app.security.dependencies import Principal, client_ip, get_current_user
from app.security.passwords import generate_api_key, hash_key, hash_password

router = APIRouter(prefix="/api/admin", tags=["admin"])


def _admin(principal: Principal) -> Principal:
    principal.require(Role.admin)
    return principal


@router.get("/users", response_model=list[UserOut])
def list_users(
    principal: Principal = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    _admin(principal)
    return db.query(User).order_by(User.id).all()


@router.post("/users", status_code=status.HTTP_201_CREATED, response_model=UserOut)
def create_user(
    body: CreateUserRequest,
    request: Request,
    principal: Principal = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    _admin(principal)
    exists = db.query(User).filter(User.username == body.username.lower()).first()
    if exists:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="username taken")
    user = User(
        username=body.username.lower(),
        password_hash=hash_password(body.password),
        role=Role(body.role),
        enabled=body.enabled,
        must_change_password=True,
    )
    db.add(user)
    db.commit()
    audit.record("admin.user.create", actor=principal.username, outcome="success",
                 resource=user.username, ip=client_ip(request),
                 details={"role": user.role.value})
    return UserOut.model_validate(user)


@router.patch("/users/{user_id}/role")
def set_role(
    user_id: int,
    role: str,
    request: Request,
    principal: Principal = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    _admin(principal)
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="user not found")
    if user.id == principal.user.id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="cannot change own role")
    user.role = Role(role)
    db.add(user)
    db.commit()
    audit.record("admin.user.role", actor=principal.username, resource=user.username,
                 ip=client_ip(request), details={"role": role})
    return {"ok": True}


@router.delete("/users/{user_id}")
def disable_user(
    user_id: int,
    request: Request,
    principal: Principal = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    _admin(principal)
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="user not found")
    if user.id == principal.user.id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="cannot disable self")
    user.enabled = False
    db.add(user)
    db.commit()
    audit.record("admin.user.disable", actor=principal.username, resource=user.username,
                 outcome="success", ip=client_ip(request))
    return {"ok": True}


@router.get("/api-keys")
def list_api_keys(
    principal: Principal = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    _admin(principal)
    rows = db.query(ApiKey).order_by(ApiKey.created_at.desc()).all()
    return [
        {
            "id": k.id,
            "username": k.user.username if k.user else None,
            "prefix": k.prefix,
            "role_binding": k.role_binding.value,
            "enabled": k.enabled,
            "created_at": k.created_at,
            "expires_at": k.expires_at,
            "last_used_at": k.last_used_at,
        }
        for k in rows
    ]


@router.post("/api-keys", status_code=status.HTTP_201_CREATED)
def create_api_key(
    body: CreateApiKeyRequest,
    request: Request,
    principal: Principal = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    _admin(principal)
    raw = generate_api_key()
    key = ApiKey(
        user_id=principal.user.id,
        key_hash=hash_key(raw),
        prefix=raw[:9] + "...",
        role_binding=Role(body.role_binding),
        expires_at=datetime.now(timezone.utc) + timedelta(days=body.expires_days),
    )
    db.add(key)
    db.commit()
    audit.record("admin.apikey.create", actor=principal.username, resource=str(key.id),
                 outcome="success", ip=client_ip(request),
                 details={"expires_days": body.expires_days})
    return {"api_key": raw}  # shown once only


@router.delete("/api-keys/{key_id}")
def revoke_api_key(
    key_id: int,
    request: Request,
    principal: Principal = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    _admin(principal)
    key = db.get(ApiKey, key_id)
    if key is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="key not found")
    key.enabled = False
    db.add(key)
    db.commit()
    audit.record("admin.apikey.revoke", actor=principal.username, resource=str(key.id),
                 ip=client_ip(request))
    return {"ok": True}


@router.get("/targets")
def list_targets(
    principal: Principal = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    return db.query(Target).order_by(Target.created_at.desc()).all()


@router.post("/targets", status_code=status.HTTP_201_CREATED)
def create_target(
    body: TargetCreate,
    request: Request,
    principal: Principal = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    _admin(principal)
    exists = db.query(Target).filter(Target.base_url == body.base_url).first()
    if exists:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="target already tracked")
    from urllib.parse import urlparse

    host = urlparse(body.base_url).hostname or ""
    if host and not settings.host_allowed(host):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"host '{host}' is outside ALLOWED_TARGET_HOSTS",
        )
    target = Target(
        label=body.label,
        base_url=body.base_url,
        host=host,
        notes=body.notes,
        approved_by=principal.username,
    )
    db.add(target)
    db.commit()
    audit.record("admin.target.create", actor=principal.username, resource=body.base_url,
                 outcome="success", ip=client_ip(request))
    return {"id": target.id, "label": target.label, "base_url": target.base_url, "host": target.host}


@router.delete("/targets/{target_id}")
def delete_target(
    target_id: int,
    request: Request,
    principal: Principal = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    _admin(principal)
    target = db.get(Target, target_id)
    if target is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="target not found")
    db.delete(target)
    db.commit()
    audit.record("admin.target.delete", actor=principal.username, resource=target.base_url,
                 outcome="success", ip=client_ip(request))
    return {"ok": True}


@router.get("/audit")
def list_audit(
    limit: int = 200,
    action: str | None = None,
    principal: Principal = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    _admin(principal)
    q = db.query(AuditLog).order_by(AuditLog.id.desc())
    if action:
        q = q.filter(AuditLog.action == action)
    return q.limit(min(limit, 1000)).all()


@router.get("/audit/verify")
def verify_audit_chain():
    from app.security.audit import audit as audit_logger

    ok, detail = audit_logger.verify_chain()
    return {"ok": ok, "detail": detail}