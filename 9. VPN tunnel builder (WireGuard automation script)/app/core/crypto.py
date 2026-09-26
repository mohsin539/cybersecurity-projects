"""Crypto operations (NIST SC-13, ISO 27001 A.5.24, A.8.9).

WireGuard keys ARE Curve25519 (X25519) keys serialized as raw 32 bytes,
base64-encoded. Public key = X25519(private) scalar multiplication with the
standard base point. We use the audited `cryptography` library for scalarmult;
wireguard private keys are simply CSPRNG output.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import secrets
from datetime import datetime, timezone

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

from .validate import is_wg_key

_PUBLIC_SALT = b"vpn-tunnel-builder:v1"  # domain separation, not secret


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def generate_private_key() -> str:
    """32 CSPRNG bytes -> base64 (WireGuard private key)."""
    return _b64(secrets.token_bytes(32))


def public_from_private(private_b64: str) -> str:
    """Derive the base64 public key from a WireGuard private key."""
    if not is_wg_key(private_b64):
        raise ValueError("invalid private key")
    raw = base64.b64decode(private_b64, validate=True)
    priv = x25519.X25519PrivateKey.from_private_bytes(raw)
    pub = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return _b64(pub)


def generate_preshared_key() -> str:
    """WireGuard PSK: 32 CSPRNG bytes, base64."""
    return _b64(secrets.token_bytes(32))


def generate_keypair(kind: str = "tunnel", note: str = "") -> dict:
    """Create a {id, private, public, kind, created_at, note} record."""
    priv = generate_private_key()
    pub = public_from_private(priv)
    return {
        "id": secrets.token_hex(8),
        "kind": kind,
        "note": note or "",
        "private_key": priv,
        "public_key": pub,
        "created_at": utc_now_iso(),
    }


def parse_wg_key_in_hex(key_b64: str) -> str:
    """Debug helper: hex of the raw key bytes (no security impact)."""
    return hashlib.sha256(base64.b64decode(key_b64, validate=True)).hexdigest()


def fingerprint(public_key_b64: str) -> str:
    """Short, loggable peer id — never reveals the key material."""
    raw = base64.b64decode(public_key_b64, validate=True)
    return hashlib.sha256(_PUBLIC_SALT + raw).hexdigest()[:12]


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def trusted_base64_decode(value: str) -> bytes:
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("invalid base64 payload") from exc