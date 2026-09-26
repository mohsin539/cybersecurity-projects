"""Password and secret hashing.

Passwords: argon2id (OWASP Password Storage Cheat Sheet, NIST SP 800-63B).
API keys / refresh-token jti: SHA-256 of the random secret (only the hash
is stored; the raw key is shown to the owner exactly once).
"""

from __future__ import annotations

import hashlib
import secrets

from argon2 import PasswordHasher

_hasher = PasswordHasher(
    time_cost=3,           # OWASP recommendation: Argon2id with min 19 MiB, t=2, p=1
    memory_cost=19_456,    # ~19 MiB
    parallelism=1,
    hash_len=32,
)


def hash_password(password: str) -> str:
    if len(password) < 12:
        raise ValueError("password must be at least 12 characters")
    return _hasher.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return _hasher.verify(password_hash, password)
    except Exception:  # noqa: BLE001 - argon2 raises several typed exceptions
        return False


def generate_api_key() -> str:
    return "xt_" + secrets.token_urlsafe(32)


def key_prefix(api_key: str) -> str:
    return api_key[:9] + "..."

def hash_key(api_key: str) -> str:
    return hashlib.sha256(api_key.encode()).hexdigest()