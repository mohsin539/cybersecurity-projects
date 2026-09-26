"""Security core — JWT auth, PBKDF2 hashing, RBAC, audit chain (security.md)."""
import base64
import hashlib
import hmac
import os
import secrets
from datetime import datetime, timedelta, timezone

import jwt
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from .database import SessionLocal, naive_utcnow
from .models import AuditLog, User

SECRET_KEY = os.environ.get(
    "CAS_SECRET_KEY",
    "dev-only-change-me-f8e7d6c5b4a39281706f5e4d3c2b1a09-8f76a4c9e2d1b7",
)
ALGORITHM = "HS256"
ACCESS_TOKEN_MINUTES = 30
REFRESH_MINUTES = 60 * 12

# RBAC role matrix (architecture.md §12)
ROLE_PERMISSIONS = {
    "SUPER_ADMIN": {"*"},
    "CISO": {
        "map:write", "assess:write", "risk:write", "evidence:write",
        "remediation:write", "report:write", "report:read", "dashboard:read",
        "audit:read", "asset:write", "user:read",
    },
    "CONTROL_OWNER": {"evidence:write", "assess:read", "report:read", "dashboard:read", "remediation:write"},
    "ASSESSOR": {"assess:write", "evidence:read", "report:read", "dashboard:read", "audit:read"},
    "REGULATOR": {"dashboard:read", "report:read", "evidence:read"},
    "VIEWER": {"dashboard:read", "report:read"},
    "INACTIVE": set(),
}


def hash_password(password: str) -> str:
    """PBKDF2-HMAC-SHA256 with per-user salt & 210k iterations."""
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 210_000)
    return f"pbkdf2${base64.b64encode(salt).decode()}${base64.b64encode(digest).decode()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, salt_b64, digest_b64 = stored.split("$")
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(digest_b64)
        digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 210_000)
        return hmac.compare_digest(digest, expected)
    except Exception:
        return False


def create_token(user: User) -> dict:
    now = naive_utcnow()
    payload = {
        "sub": str(user.id),
        "username": user.username,
        "role": user.role,
        "iat": now,
        "exp": now + timedelta(minutes=ACCESS_TOKEN_MINUTES),
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    return {"access_token": token, "token_type": "bearer", "expires_in": ACCESS_TOKEN_MINUTES * 60}


def decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")


bearer = HTTPBearer(auto_error=False)


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer),
) -> User:
    if credentials is None:
        raise HTTPException(status_code=401, detail="Not authenticated")
    payload = decode_token(credentials.credentials)
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.id == int(payload["sub"])).first()
        if not user or not user.is_active:
            raise HTTPException(status_code=403, detail="User disabled")
        return user
    finally:
        db.close()


def require(permission: str):
    def dependency(user: User = Depends(get_current_user)) -> User:
        perms = ROLE_PERMISSIONS.get(user.role, set())
        if "*" not in perms and permission not in perms:
            raise HTTPException(status_code=403, detail=f"Role '{user.role}' lacks permission '{permission}'")
        return user

    return dependency


def audit(db, actor: str, role: str, action: str, entity_type: str = None,
          entity_id: int = None, detail: dict = None, ip_address: str = None) -> None:
    """Append-only, hash-chained audit write. Each row links to the previous row's hash."""
    prev = db.query(AuditLog).order_by(AuditLog.id.desc()).first()
    prev_hash = prev.row_hash if prev else hashlib.sha256(b"GENESIS").hexdigest()
    ts = naive_utcnow()
    chain_payload = (
        f"{actor}|{role}|{action}|{entity_type}|{entity_id}|"
        f"{json_dump(detail)}|{ip_address}|{prev_hash}|{ts.isoformat()}"
    )
    row_hash = hashlib.sha256(chain_payload.encode()).hexdigest()
    entry = AuditLog(
        actor=actor, actor_role=role, action=action, entity_type=entity_type,
        entity_id=entity_id, detail=detail or {}, ip_address=ip_address,
        prev_hash=prev_hash, row_hash=row_hash, created_at=ts,
    )
    db.add(entry)
    db.commit()


def json_dump(value) -> str:
    import json
    return json.dumps(value, default=str, sort_keys=True)


def client_ip(request: Request) -> str:
    return request.headers.get("x-forwarded-for", request.client.host if request.client else "unknown")


def verify_evidence_chain(rows) -> bool:
    """Re-verifies the hash chain integrity of audit rows back to genesis."""
    prev = hashlib.sha256(b"GENESIS").hexdigest()
    for row in rows:
        payload = (
            f"{row.actor}|{row.actor_role}|{row.action}|{row.entity_type}|{row.entity_id}|"
            f"{json_dump(row.detail)}|{row.ip_address}|{row.prev_hash}|{row.created_at.isoformat()}"
        )
        if hashlib.sha256(payload.encode()).hexdigest() != row.row_hash:
            return False
        if row.prev_hash != prev:
            return False
        prev = row.row_hash
    return True


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()