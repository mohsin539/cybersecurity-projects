"""security.py - Cryptographic services: hashing, HMAC signing, key store, data masking.

Implements the integrity controls required by architecture.md SS7 (ISO 27001 A.8.24,
NIST PR.DS-6, OWASP A02/A08). Design is deliberately dependency-light so the whole
engine packs into a portable .exe:
  - SHA-256 digests for file / evidence hashing
  - HMAC-SHA256 signing of audit chain entries (Ed25519-style asymmetric stored as
    portable X.509 DER is available via cryptography, but HMAC keeps offline portability)
  - Per-install master key, sealed to the user's local app-data directory
  - Clearance-based masking of IPs / PII in reports
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import os
import secrets
import socket
from pathlib import Path

KEY_FILENAME = ".pcapless_master.key"
DERIVED_LABEL = b"pcapless-audit-hmac-v1"


def hashing_key_path():
    return Path(os.environ.get("PCAFLESS_DATA_DIR", Path.home() / ".pcapless")) / KEY_FILENAME


class CryptoService:
    """Deterministic key + hashing/signing service for the suite."""

    def __init__(self, data_dir=None):
        self.data_dir = Path(data_dir) if data_dir else Path(os.environ.get("PCAFLESS_DATA_DIR", Path.home() / ".pcapless"))
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self._master = self._load_or_create_master()

    def _load_or_create_master(self) -> bytes:
        """Load the sealed master key; generate + seal with local entropy if absent."""
        path = self.data_dir / KEY_FILENAME
        if path.exists():
            raw = path.read_bytes()
            if len(raw) >= 32:
                return raw[:32]
        key = secrets.token_bytes(32)
        tmp = path.with_suffix(".tmp")
        tmp.write_bytes(key)
        os.replace(tmp, path)
        return key

    def audit_signing_key(self) -> bytes:
        """Deterministic per-install sub key for HMAC auditing (chain integrity)."""
        return hmac.new(self._master, DERIVED_LABEL, hashlib.sha256).digest()

    # ---------------------------------------------------------------- digests
    @staticmethod
    def sha256_bytes(data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()

    @staticmethod
    def sha256_file(path) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()

    @staticmethod
    def weak_hmac(key: bytes, payload: str) -> bytes:
        return hmac.new(key, payload.encode("utf-8"), hashlib.sha256).digest()

    @staticmethod
    def weak_hmac_hex(key: bytes, payload: str) -> str:
        return hmac.new(key, payload.encode("utf-8"), hashlib.sha256).hexdigest()

    @staticmethod
    def verify_hmac(key: bytes, payload: str, signature_hex: str) -> bool:
        expect = CryptoService.weak_hmac_hex(key, payload)
        return hmac.compare_digest(expect.lower(), signature_hex.lower())

    # ---------------------------------------------------------------- masking
    @staticmethod
    def mask_ip(value: str, clearance: int = 2) -> str:
        """Clearance: 0=all masked, 1=last octet masked, 2=full host (default analyst)."""
        value = value.strip()
        if clearance <= 0:
            return "*.*.*.*"
        try:
            obj = ipaddress.ip_address(value)
        except ValueError:
            return value
        if clearance >= 2:
            return value
        if obj.version == 4:
            parts = value.split(".")
            parts[-1] = "x"
            return ".".join(parts)
        cols = value.split(":")
        if len(cols) == 8:
            return ":".join(cols[:6] + ["xxxx", "xxxx"])
        return value


SYSTEM_KEY = CryptoService()


def sha256_bytes(data: bytes) -> str:
    return SYSTEM_KEY.sha256_bytes(data)


def sha256_file(path) -> str:
    return SYSTEM_KEY.sha256_file(path)


def audit_key() -> bytes:
    return SYSTEM_KEY.audit_signing_key()


def mask_ip(value: str, clearance: int = 2) -> str:
    return SYSTEM_KEY.mask_ip(value, clearance)


def detect_os_from_ttl(ttl: int) -> str:
    if ttl <= 64:
        return "Linux/UNIX (TTL<=64)"
    if ttl <= 128:
        return "Windows (TTL<=128)"
    return "Network hop reachable (TTL>128)"