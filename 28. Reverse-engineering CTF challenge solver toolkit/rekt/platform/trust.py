"""Trust store: Ed25519 verification for plugins (OWASP A08, NIST CM-5).

The release public key is pinned via the REKT_TRUST_ED25519 env var (base64
32-byte raw key) or a trust.pub file next to the app. Plugins signed by a
trusted key load without prompts; anything else requires Developer Mode +
per-session consent (policy.py::check_consent / plugins.py).
"""
from __future__ import annotations

import base64
import os
from pathlib import Path


def trusted_public_key() -> bytes | None:
    """Return the pinned Ed25519 public key, or None (unsigned-only mode)."""
    raw = os.environ.get("REKT_TRUST_ED25519", "")
    if raw:
        try:
            key = base64.b64decode(raw, validate=True)
            if len(key) == 32:
                return key
        except (ValueError, TypeError):
            pass
    p = Path(__file__).resolve().parents[2] / "trust.pub"
    if p.exists():
        try:
            key = base64.b64decode(p.read_text(encoding="ascii").strip(), validate=True)
            if len(key) == 32:
                return key
        except (ValueError, TypeError, OSError):
            return None
    return None


def verify_signature(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Constant-time-ish Ed25519 verify. Returns False on any failure."""
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
            Ed25519PublicKey,
        )
        from cryptography.exceptions import InvalidSignature

        pub = Ed25519PublicKey.from_public_bytes(public_key)
        pub.verify(signature, message)
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def generate_keypair() -> tuple[bytes, bytes]:
    """Dev tooling: returns (public_raw, private_raw) for sign_plugin.py."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization

    priv = Ed25519PrivateKey.generate()
    pub_raw = priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    priv_raw = priv.private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
        serialization.NoEncryption())
    return pub_raw, priv_raw
