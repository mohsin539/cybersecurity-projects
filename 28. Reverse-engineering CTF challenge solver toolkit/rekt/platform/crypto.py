"""AES-256-GCM helpers for project-file encryption (OWASP A02, ISO A.8.24).

Algorithm allow-list: AES-256-GCM + scrypt KDF only. No custom crypto, no ECB,
no unauthenticated modes. Nonce: 12 random bytes per message (GCM requirement).
"""
from __future__ import annotations

import hashlib
import os

MAGIC = b"RKENCK1\x00"
_SCRYPT_N, _SCRYPT_R, _SCRYPT_P = 2**14, 8, 1


def new_salt() -> bytes:
    return os.urandom(16)


def derive_key(passphrase: str, salt: bytes) -> bytes:
    """scrypt (memory-hard, NIST SP 800-132 style parameters)."""
    if not passphrase:
        raise ValueError("empty passphrase")
    return hashlib.scrypt(
        passphrase.encode("utf-8"), salt=salt,
        n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P, dklen=32,
        maxmem=64 * 1024 * 1024,
    )


def encrypt(key: bytes, plaintext: bytes) -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, plaintext, None)
    return MAGIC + nonce + ct


def decrypt(key: bytes, blob: bytes) -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    if not blob.startswith(MAGIC):
        raise ValueError("not an encrypted REkt blob")
    nonce, ct = blob[len(MAGIC):len(MAGIC) + 12], blob[len(MAGIC) + 12:]
    return AESGCM(key).decrypt(nonce, ct, None)  # raises on tamper (integrity, A08)
