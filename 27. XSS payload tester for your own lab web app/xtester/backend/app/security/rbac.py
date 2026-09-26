"""Role-based access control helpers (ISO 27001 A.9.1/A.9.2, NIST AC-2)."""

from __future__ import annotations

from functools import wraps
from typing import Callable

from app.security.dependencies import Principal


def require_roles(*roles):
    """Decorator factory enforcing that the principal holds one of `roles`.

    Usage: `@router.get(...); @require_roles(Role.admin); def f(principal=Depends(get_current_user))`.
    """

    def decorator(func: Callable):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            principal = kwargs.get("principal")
            if not isinstance(principal, Principal):
                raise TypeError("require_roles needs a 'principal' dependency argument")
            principal.require(*roles)
            return await func(*args, **kwargs)

        return wrapper

    return decorator


def can_view(principal: Principal) -> bool:
    return principal.role in ("viewer", "engineer", "admin")


def can_scan(principal: Principal) -> bool:
    return principal.role in ("engineer", "admin")


def can_admin(principal: Principal) -> bool:
    return principal.role == "admin"