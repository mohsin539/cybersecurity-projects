from datetime import datetime, timezone

import jwt
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from . import models
from .db import get_db
from .security import decode_token

bearer_scheme = HTTPBearer(auto_error=False)

TRUST_PROXIES = False
ALLOWED_CIDRS = ["127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]


def client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded and TRUST_PROXIES:
        return forwarded.split(",")[0].strip()
    if request.client:
        return request.client.host
    return "unknown"


def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    db: Session = Depends(get_db),
) -> models.User:
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated"
        )
    try:
        payload = decode_token(credentials.credentials)
        user_id = int(payload["sub"])
    except (jwt.PyJWTError, KeyError, ValueError):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token"
        )
    user = db.get(models.User, user_id)
    if user is None or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="User inactive or missing"
        )
    return user


def require_roles(*roles: str):
    def checker(user: models.User = Depends(get_current_user)) -> models.User:
        if user.role not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions"
            )
        return user

    return checker


def parse_target_ip(request: Request):
    ip = client_ip(request)
    from ipaddress import ip_address

    try:
        return ip_address(ip)
    except ValueError:
        return None


def is_internal(ip) -> bool:
    from ipaddress import ip_network

    return any(ip in ip_network(net) for net in ALLOWED_CIDRS)


def within_window(
    last_seen: datetime | None, window_minutes: int = 10
) -> bool:
    if last_seen is None:
        return False
    age = (datetime.now(timezone.utc) - last_seen).total_seconds()
    return age <= window_minutes * 60