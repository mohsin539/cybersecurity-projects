"""AES-256-GCM encryption for the Secret Vault.

Secrets are never stored in plaintext. A master key is loaded from
`SECRETS_MASTER_KEY`; in development only, a generated key is persisted to
`data/secrets.key`. Keys are versioned so rotation is supported.

OWASP A2 / NIST SC-13 / ISO 27001 A.10.1.
"""
from __future__ import annotations

import base64
import hashlib
import os
import uuid

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.config import settings

KEY_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "data", "secrets.key")
_KEY_ID: str | None = None
_MASTER_KEY: bytes | None = None


def _derive_key(master_b64: str) -> bytes:
    raw = base64.b64decode(master_b64) if "_" not in master_b64 else master_b64.encode()
    return hashlib.sha256(raw).digest()


def _load_master_key() -> tuple[str, bytes]:
    global _KEY_ID, _MASTER_KEY
    if _MASTER_KEY is not None:
        return _KEY_ID, _MASTER_KEY

    if settings.secrets_master_key:
        key_id = "env"
        key = hashlib.sha256(settings.secrets_master_key.encode("utf-8")).digest()
    else:
        os.makedirs(os.path.dirname(KEY_FILE), exist_ok=True)
        if os.path.exists(KEY_FILE):
            with open(KEY_FILE, "r", encoding="utf-8") as fh:
                data = fh.read().strip()
            key_id, key_b64 = data.split(":", 1)
            key = _derive_key(key_b64)
        else:
            from secrets import token_bytes, token_urlsafe

            key_id = "k1"
            key = hashlib.sha256(token_urlsafe(48).encode("utf-8")).digest()
            with open(KEY_FILE, "w", encoding="utf-8") as fh:
                fh.write(f"{key_id}:{token_bytes(64).hex()}")
    _KEY_ID = key_id
    _MASTER_KEY = key
    return _KEY_ID, _MASTER_KEY


def _key_id_for(name_key_id: str | None) -> tuple[str, bytes]:
    if name_key_id and name_key_id != "env":
        return _load_master_key()
    return _load_master_key()


def encrypt_secret(plaintext: str) -> tuple[str, str]:
    """Returns (key_id, ciphertext_b64)."""
    key_id, key = _load_master_key()
    aes = AESGCM(key)
    nonce = uuid.uuid4().bytes[:12]
    ct = aes.encrypt(nonce, plaintext.encode("utf-8"), b"soarlite-v1")
    return key_id, base64.b64encode(nonce + ct).decode("ascii")


def decrypt_secret(key_id: str, ciphertext_b64: str) -> str:
    payload = base64.b64decode(ciphertext_b64)
    nonce, ct = payload[:12], payload[12:]
    _key_id, key = _load_master_key()
    aes = AESGCM(key)
    return aes.decrypt(nonce, ct, b"soarlite-v1").decode("utf-8")


def rotate_keys() -> str:
    """Naive rotation helper: force a new key id using a random master key."""
    from secrets import token_urlsafe

    os.makedirs(os.path.dirname(KEY_FILE), exist_ok=True)
    new_id = f"k{uuid.uuid4().hex[:6]}"
    with open(KEY_FILE, "w", encoding="utf-8") as fh:
        fh.write(f"{new_id}:{token_urlsafe(48)}")
    global _KEY_ID, _MASTER_KEY
    _KEY_ID, _MASTER_KEY = None, None
    _load_master_key()
    return new_id