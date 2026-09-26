"""Shared API dependencies (rate limiting per client)."""
from __future__ import annotations

from fastapi import Request

from app.core import audit
from app.core.errors import ApiError
from app.core.rate_limit import allow


def client_key(request: Request) -> str:
    # Behind a trusted proxy in production; direct IP in lab.
    return request.client.host if request.client else "unknown"


def rate_limit_api(request: Request) -> None:
    from app.core.config import settings
    if not settings.rate_limit_enabled:
        return
    limit, window = 120, 60
    raw = settings.rate_limit_api
    if "/" in raw:
        n, per = raw.split("/")
        limit = int(n)
        window = {"second": 1, "minute": 60, "hour": 3600}.get(
            per.strip(), 60)
    if not allow(f"api:{client_key(request)}", limit, window):
        audit.record("ratelimit.block", severity="warn",
                     path=request.url.path)
        raise ApiError(429, "RATE_LIMITED", "Too many requests")


def rate_limit_login(request: Request) -> None:
    from app.core.config import settings
    if not settings.rate_limit_enabled:
        return
    limit, window = 5, 60
    raw = settings.rate_limit_login
    if "/" in raw:
        n, per = raw.split("/")
        limit = int(n)
        window = {"second": 1, "minute": 60, "hour": 3600}.get(
            per.strip(), 60)
    if not allow(f"login:{client_key(request)}", limit, window):
        audit.record("auth.bruteforce_block", severity="alert")
        raise ApiError(429, "RATE_LIMITED",
                       "Too many login attempts; try again later")
