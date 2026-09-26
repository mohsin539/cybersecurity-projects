"""Crypto service — Ed25519 signing + AES-256-GCM package sealing.

Backends (architecture.md §10.5):
- `cryptography` (Rust) preferred; Ed25519 (RFC 8032), AES-256-GCM.
- FIPS-conscious deployments: OS CNG/TPM key storage, RSA-3072/PSS fallback.

When `cryptography` is absent the service degrades gracefully: signatures are
hash-chain heads only, clearly flagged `algorithm=sha256-unsigned`. The rest of
the pipeline still runs; seals are marked unsigned (security.md Residual Risks).
"""
from __future__ import annotations

import base64
import os
import time
from pathlib import Path

from .integrity import canonical_json, sha256_text

try:  # optional dependency (pyproject extra `crypto`)
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    _HAVE_CRYPTO = True
except Exception:  # pragma: no cover - environment without cryptography
    Ed25519PrivateKey = None  # type: ignore
    Ed25519PublicKey = None  # type: ignore
    InvalidSignature = Exception  # type: ignore
    serialization = None  # type: ignore
    hashes = None  # type: ignore
    AESGCM = None  # type: ignore
    _HAVE_CRYPTO = False


def have_crypto() -> bool:
    return _HAVE_CRYPTO


class Signer:
    """Signs ledger heads and report manifests."""

    def __init__(self, private_key_obj=None, label: str = "default"):
        self._have = _HAVE_CRYPTO
        if self._have:
            key = private_key_obj or Ed25519PrivateKey.generate()
            self._key = key
            self._public = key.public_key()
        self.label = label

    # -- serialization -----------------------------------------------------
    @classmethod
    def generate_and_save(cls, key_dir: str | Path) -> "Signer":
        key_dir = Path(key_dir)
        key_dir.mkdir(parents=True, exist_ok=True)
        priv_path = key_dir / "signing_key.pem"
        pub_path = key_dir / "signing_key.pub"
        if priv_path.exists():
            raise FileExistsError(
                f"signing key already exists: {priv_path} (create-once, state.md)")
        if not _HAVE_CRYPTO:
            raise RuntimeError("cryptography not installed; cannot persist a key")
        key = Ed25519PrivateKey.generate()
        priv_bytes = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        pub_bytes = key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        priv_path.write_bytes(priv_bytes)
        pub_path.write_bytes(pub_bytes)
        return cls(key)

    @classmethod
    def load(cls, key_dir: str | Path) -> "Signer":
        priv_path = Path(key_dir) / "signing_key.pem"
        if not _HAVE_CRYPTO or not priv_path.exists():
            return cls(label="unsigned")
        from cryptography.hazmat.primitives import serialization as _ser
        key = _ser.load_pem_private_key(priv_path.read_bytes(), password=None)
        return cls(key)

    # -- primitives ----------------------------------------------------------
    def sign_text(self, text: str) -> str:
        if not self._have:
            return f"sha256-unsigned:{sha256_text(text)}"
        sig = self._key.sign(text.encode("utf-8"))
        return base64.b64encode(sig).decode("ascii")

    def signature_bytes(self, data: bytes) -> bytes:
        if not self._have:
            return b""
        return self._key.sign(data)

    @property
    def public_hex(self) -> str:
        if not self._have:
            return "unsigned"
        return base64.b64encode(
            self._public.public_bytes(
                serialization.Encoding.Raw,
                serialization.PublicFormat.Raw,
            )
        ).decode("ascii")

    @property
    def algorithm(self) -> str:
        return "Ed25519" if self._have else "sha256-unsigned"


def verify_signature(public_pem_or_raw: bytes, data: bytes, signature: bytes,
                     signed_payload_preimage: bytes | None = None) -> bool:
    """Verify an Ed25519 signature. Returns False on any failure."""
    if not _HAVE_CRYPTO:
        return False
    try:
        pub = Ed25519PublicKey.from_public_bytes(public_pem_or_raw)
        pub.verify(signature, data)
        return True
    except Exception:
        return False


def seal_bytes(data: bytes, password: str) -> dict:
    """AES-256-GCM wrap of data using a PBKDF2-derived key (memory-safe caller)."""
    if not _HAVE_CRYPTO:
        raise RuntimeError("cryptography not installed (required for package sealing)")
    import hashlib
    salt = os.urandom(16)
    key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 600_000)
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, data, b"SAP.1")
    return {"nonce_b64": base64.b64encode(nonce).decode(), "salt_b64": base64.b64encode(salt).decode()}


def unseal_bytes(ct: bytes, password: str, nonce_b64: str, salt_b64: str) -> bytes:
    if not _HAVE_CRYPTO:
        raise RuntimeError("cryptography not installed")
    import hashlib
    salt = base64.b64decode(salt_b64)
    nonce = base64.b64decode(nonce_b64)
    key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 600_000)
    return AESGCM(key).decrypt(nonce, ct, b"SAP.1")