"""Optional report vault: AES-256-GCM encryption of exported artifacts
(ISO 27001 A.8.24 cryptography / OWASP A02).

Key derivation uses scrypt(N=2**15, r=8, p=1) with a random salt. If the
``cryptography`` package is unavailable the vault degrades to no-ops and the
GUI disables the passphrase option.
"""
from __future__ import annotations

import hashlib
import json
import os

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

    _CRYPTO_AVAILABLE = True
except Exception:  # pragma: no cover - import-time fallback
    _CRYPTO_AVAILABLE = False

_SALT_LEN = 16
_NONCE_LEN = 12
_KDF_N = 2**15


def crypto_available() -> bool:
    return _CRYPTO_AVAILABLE


def _derive_key(passphrase: str, salt: bytes) -> bytes:
    if not _CRYPTO_AVAILABLE:
        raise RuntimeError("cryptography not available")
    kdf = Scrypt(salt=salt, length=32, n=_KDF_N, r=8, p=1)
    return kdf.derive(passphrase.encode("utf-8"))


def encrypt_bytes(passphrase: str, data: bytes) -> bytes:
    """Return salt || nonce || ciphertext (GCM-encrypted, authenticated)."""
    if not _CRYPTO_AVAILABLE:
        raise RuntimeError("cryptography not available; cannot encrypt")
    salt = os.urandom(_SALT_LEN)
    key = _derive_key(passphrase, salt)
    nonce = os.urandom(_NONCE_LEN)
    ct = AESGCM(key).encrypt(nonce, data, None)
    return salt + nonce + ct


def decrypt_bytes(passphrase: str, blob: bytes) -> bytes:
    if not _CRYPTO_AVAILABLE:
        raise RuntimeError("cryptography not available; cannot decrypt")
    salt, nonce, ct = blob[:_SALT_LEN], blob[_SALT_LEN : _SALT_LEN + _NONCE_LEN], blob[_SALT_LEN + _NONCE_LEN :]
    key = _derive_key(passphrase, salt)
    return AESGCM(key).decrypt(nonce, ct, None)


def hash_artifact(path: str) -> str:
    """sha256 of a file - used for the manifest + vault header."""
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def manifest_json(entries: dict[str, str]) -> str:
    return json.dumps(entries, indent=2, sort_keys=True)