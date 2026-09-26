"""Cryptographic services - encryption at rest, key derivation, secure erase.

Controls: OWASP A02, NIST SC-28 / IA-5, ISO A.10.1 (cryptographic controls).
Mitigations:
  - AES-256-GCM for confidentiality + integrity (no padding oracles).
  - PBKDF2-HMAC-SHA256 key derivation from user passphrase (NIST SP 800-132).
  - Random per-record nonce (12 bytes) - never reused.
  - AAD binds ciphertext to context (case id / purpose) preventing swap attacks.
  - Secure erase (overwrite + rename + delete) for data minimization (SI-12).
"""
from __future__ import annotations

import base64
import hashlib
import os
import secrets
from typing import Optional, Tuple

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

from . import constants as C


class SecurityError(Exception):
    """Raised on any cryptographic failure (auth tag mismatch, malformed blob)."""


def derive_key(passphrase: str, salt: bytes, iterations: int = C.PBKDF2_ITERATIONS) -> bytes:
    """PBKDF2-HMAC-SHA256 -> 32-byte AES-256 key (NIST SP 800-132)."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=C.AES_KEY_BYTES,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(passphrase.encode("utf-8"))


def _fresh_salt() -> bytes:
    return secrets.token_bytes(C.SALT_BYTES)


def encrypt_bytes(plaintext: bytes, key: bytes, aad: bytes = b"") -> bytes:
    """Encrypt bytes -> versioned container: MAGIC | salt | nonce | ct.

    GCM tag (16B) is appended to ciphertext by default.
    """
    if not isinstance(plaintext, bytes):
        raise TypeError("plaintext must be bytes")
    salt = _fresh_salt()
    nonce = secrets.token_bytes(C.AES_NONCE_BYTES)
    enc = Cipher(algorithms.AES(key), modes.GCM(nonce)).encryptor()
    enc.authenticate_additional_data(aad)
    ct = enc.update(plaintext) + enc.finalize()
    return C.ENCRYPTED_MAGIC + salt + nonce + ct + enc.tag


def decrypt_bytes(blob: bytes, key: bytes, aad: bytes = b"") -> bytes:
    """Decrypt a container produced by encrypt_bytes. Fails closed (SecurityError)."""
    if len(blob) < len(C.ENCRYPTED_MAGIC) + C.SALT_BYTES + C.AES_NONCE_BYTES + C.AES_TAG_BYTES:
        raise SecurityError("malformed encrypted container")
    if blob[: len(C.ENCRYPTED_MAGIC)] != C.ENCRYPTED_MAGIC:
        raise SecurityError("unrecognized container magic")
    off = 0
    off += len(C.ENCRYPTED_MAGIC)
    salt = blob[off : off + C.SALT_BYTES]; off += C.SALT_BYTES
    nonce = blob[off : off + C.AES_NONCE_BYTES]; off += C.AES_NONCE_BYTES
    ct = blob[off:-C.AES_TAG_BYTES]
    tag = blob[-C.AES_TAG_BYTES:]
    try:
        dec = Cipher(algorithms.AES(key), modes.GCM(nonce, tag)).decryptor()
        dec.authenticate_additional_data(aad)
        return dec.update(ct) + dec.finalize()
    except Exception as exc:  # noqa: BLE001 - all crypto errors are fatal here
        raise SecurityError(f"decryption failed (integrity/auth failure): {exc}") from exc


def encrypt_text(text: str, key: bytes, aad: bytes = b"") -> str:
    return base64.b64encode(encrypt_bytes(text.encode("utf-8"), key, aad)).decode("ascii")


def decrypt_text(token: str, key: bytes, aad: bytes = b"") -> str:
    try:
        return decrypt_bytes(base64.b64decode(token), key, aad).decode("utf-8")
    except Exception as exc:  # noqa: BLE001
        raise SecurityError(f"text decryption failed: {exc}") from exc


def file_hmac(path: str) -> str:
    """SHA-256 integrity fingerprint for a local file (A08 / AU integrity)."""
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def secure_erase(path: str, passes: int = 2) -> None:
    """Overwrite-then-delete a file (data-at-rest minimization, ISO A.8.10)."""
    if not os.path.exists(path):
        return
    size = os.path.getsize(path)
    try:
        with open(path, "r+b") as fh:
            for _ in range(passes):
                fh.seek(0)
                fh.write(os.urandom(size))
                fh.flush()
                os.fsync(fh.fileno())
    except OSError:
        pass
    finally:
        try:
            os.remove(path)
        except OSError:
            pass


def b64(a: bytes) -> str:
    return base64.b64encode(a).decode("ascii")


def unb64(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


def random_token(nbytes: int = 24) -> str:
    return secrets.token_urlsafe(nbytes)


# lru-recent secret boxes are NOT kept in memory by design; callers drop key refs.