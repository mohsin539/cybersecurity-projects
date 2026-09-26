from __future__ import annotations

import base64
import hashlib
import os
from pathlib import Path

PBKDF2_ITERATIONS = 600_000
SALT_BYTES = 16
MAGIC = b"TBE1"


def is_encryption_available() -> bool:
    try:
        import cryptography  # noqa: F401
    except Exception:
        return False
    return True


def _fernet():
    from cryptography.fernet import Fernet

    return Fernet


def derive_key(password: str, salt: bytes, iterations: int = PBKDF2_ITERATIONS) -> bytes:
    raw = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations, dklen=32)
    return base64.urlsafe_b64encode(raw)


def seal_bytes(data: bytes, password: str) -> bytes:
    fernet = _fernet()
    salt = os.urandom(SALT_BYTES)
    key = derive_key(password, salt)
    token = fernet(key).encrypt(data)
    return MAGIC + salt + token


def unseal_bytes(blob: bytes, password: str) -> bytes:
    fernet = _fernet()
    if not blob.startswith(MAGIC):
        raise ValueError("unsupported container format")
    salt = blob[len(MAGIC) : len(MAGIC) + SALT_BYTES]
    token = blob[len(MAGIC) + SALT_BYTES :]
    key = derive_key(password, salt)
    return fernet(key).decrypt(token)


def seal_file(source: str | Path, destination: str | Path, password: str) -> Path:
    payload = Path(source).read_bytes()
    dest = Path(destination)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(seal_bytes(payload, password))
    return dest


def unseal_file(source: str | Path, destination: str | Path, password: str) -> Path:
    blob = Path(source).read_bytes()
    dest = Path(destination)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(unseal_bytes(blob, password))
    return dest
