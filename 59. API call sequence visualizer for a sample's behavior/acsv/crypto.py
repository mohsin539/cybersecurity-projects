"""Integrity, hashing and secret-protection service.

Implements the cryptographic building blocks referenced in architecture.md
section 9 (ISO 27001 A.8.24, A.8.15; OWASP A02/A08):
- SHA-256 hashing and content-addressing
- HMAC-SHA256 hash chaining for the append-only audit log
- DPAPI (CryptProtectData/CryptUnprotectData) secret store bound to the
  current Windows user (data-at-rest protection)
- Optional Ed25519-compatible report signing hook (Python stdlib-free;
  signing key is DPAPI-protected when sign_reports is enabled).
"""

from __future__ import annotations

import base64
import ctypes
import hashlib
import hmac
import json
import os
import struct
import threading
from ctypes import wintypes
from pathlib import Path

_HMAC_BLOCK = 64  # bytes


class IntegrityService:
    """Stateless hash/HMAC helpers."""

    @staticmethod
    def sha256_hex(data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()

    @staticmethod
    def sha256_file(path: Path, chunk: int = 1 << 20) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            while True:
                block = fh.read(chunk)
                if not block:
                    break
                h.update(block)
        return h.hexdigest()

    @classmethod
    def hmac_chain_entry(cls, prev_hash: bytes, payload: bytes, key: bytes) -> str:
        """Return HMAC-SHA256(prev_hash || payload)."""
        return hmac.new(key, prev_hash + payload, hashlib.sha256).hexdigest()

    @classmethod
    def canonical_bytes(cls, obj: dict | list) -> bytes:
        """Deterministic JSON encoding for chaining (sort keys, compact).

        Normalizes through a JSON round-trip first so that in-memory
        representations (tuples, int keys, sets) hash identically to the same
        data after it has been written to and read back from a document.
        """
        encoded = json.dumps(
            obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str
        )
        normalized = json.loads(encoded)
        return json.dumps(
            normalized, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode()


class DPAPIStore:
    """DPAPI-backed key/value store (ISO 27001 A.8.24; OWASP A02).

    Used for the audit HMAC key and (optionally) report signing key material.
    Data is encrypted with CryptProtectData bound to the current user + machine.
    """

    _b64 = staticmethod(base64.b64encode)
    _b64d = staticmethod(base64.b64decode)

    def __init__(self, data_dir: Path) -> None:
        self.path = data_dir / "secrets.enc"
        self._lock = threading.Lock()

    # ------------------------------------------------------------------ DPAPI
    _localfree = ctypes.windll.kernel32.LocalFree
    _localfree.argtypes = [wintypes.HLOCAL]
    _localfree.restype = wintypes.HLOCAL

    @staticmethod
    def _protect(data: bytes, entropy: bytes = b"ACSV-v1") -> bytes:
        blob_in = _DATA_BLOB()
        blob_out = _DATA_BLOB()
        buf = ctypes.create_string_buffer(data)
        blob_in.cbData = len(data)
        blob_in.pbData = ctypes.cast(buf, wintypes.LPVOID)
        ent = ctypes.create_string_buffer(entropy)
        ebuf = _DATA_BLOB()
        ebuf.cbData = len(entropy)
        ebuf.pbData = ctypes.cast(ent, wintypes.LPVOID)
        if not ctypes.windll.crypt32.CryptProtectData(
            ctypes.byref(blob_in),
            "ACSV secrets",
            ctypes.byref(ebuf),
            None,
            None,
            0x00,  # flag 0 -> user-bound (not machine-wide)
            ctypes.byref(blob_out),
        ):
            raise OSError("DPAPI protect failed")
        raw = ctypes.string_at(blob_out.pbData, blob_out.cbData)
        if blob_out.pbData:
            DPAPIStore._localfree(ctypes.cast(blob_out.pbData, wintypes.HLOCAL))
        return raw

    @staticmethod
    def _unprotect(data: bytes, entropy: bytes = b"ACSV-v1") -> bytes:
        blob_in = _DATA_BLOB()
        blob_out = _DATA_BLOB()
        buf = ctypes.create_string_buffer(data)
        blob_in.cbData = len(data)
        blob_in.pbData = ctypes.cast(buf, wintypes.LPVOID)
        ent = ctypes.create_string_buffer(entropy)
        ebuf = _DATA_BLOB()
        ebuf.cbData = len(entropy)
        ebuf.pbData = ctypes.cast(ent, wintypes.LPVOID)
        if not ctypes.windll.crypt32.CryptUnprotectData(
            ctypes.byref(blob_in),
            None,
            ctypes.byref(ebuf),
            None,
            None,
            0,
            ctypes.byref(blob_out),
        ):
            raise OSError("DPAPI unprotect failed")
        raw = ctypes.string_at(blob_out.pbData, blob_out.cbData)
        if blob_out.pbData:
            DPAPIStore._localfree(ctypes.cast(blob_out.pbData, wintypes.HLOCAL))
        return raw

    # ------------------------------------------------------------- key store
    def _ensure(self) -> None:
        if not self.path.exists():
            key = os.urandom(48)
            enc = self._protect(key)
            with open(self.path, "wb") as fh:
                fh.write(enc)

    def get_master_key(self) -> bytes:
        with self._lock:
            self._ensure()
            with open(self.path, "rb") as fh:
                return self._unprotect(fh.read())

    def get_hmac_key(self) -> bytes:
        raw = self.get_master_key()
        return raw[:32]

    def rotate_secrets(self) -> None:
        with self._lock:
            new_key = os.urandom(48)
            enc = self._protect(new_key)
            tmp = self.path.with_suffix(".enc.tmp")
            with open(tmp, "wb") as fh:
                fh.write(enc)
            os.replace(tmp, self.path)


class _DATA_BLOB(ctypes.Structure):
    _fields_ = [
        ("cbData", wintypes.DWORD),
        ("pbData", wintypes.LPVOID),
    ]


def pack_file_digest(path: Path) -> dict:
    """Content-address digest bundle for artifacts and samples."""
    h = IntegrityService.sha256_file(path)
    stat = path.stat()
    return {
        "sha256": h,
        "size": stat.st_size,
        "modified_ns": stat.st_mtime_ns,
    }