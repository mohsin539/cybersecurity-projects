"""Decryption helpers for Chromium secrets on Windows.

Chromium stores cookie and login values using a layered scheme:

* ``v10`` / ``v11``  -> AES-256-GCM with a key wrapped by Windows DPAPI
  (stored base64 in ``Local State`` under ``os_crypt.encrypted_key``).
* ``v20``  -> App-Bound Encryption (Chrome 127+). The key is protected by a
  privileged COM service; extraction requires elevation and is reported as
  *unsupported* rather than silently failing.
* Legacy values -> raw DPAPI blob with no version prefix.

All key material stays in memory for the duration of a scan and is never
written to disk (ISO 27001 A.8.24, NIST SP 800-57).
"""
from __future__ import annotations

import base64
import ctypes
import json
import sys
from ctypes import wintypes
from typing import Optional, Tuple

IS_WINDOWS = sys.platform.startswith("win")

# ---------------------------------------------------------------------------
# Windows DPAPI (Crypt32.dll) via ctypes - no third-party dependency required.
# ---------------------------------------------------------------------------
if IS_WINDOWS:
    class _DataBlob(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD),
                    ("pbData", ctypes.POINTER(ctypes.c_char))]

    _crypt32 = ctypes.windll.crypt32
    _kernel32 = ctypes.windll.kernel32

    _crypt32.CryptUnprotectData.argtypes = [
        ctypes.POINTER(_DataBlob), ctypes.POINTER(wintypes.LPWSTR),
        ctypes.POINTER(_DataBlob), ctypes.c_void_p, ctypes.c_void_p,
        wintypes.DWORD, ctypes.POINTER(_DataBlob),
    ]
    _crypt32.CryptUnprotectData.restype = wintypes.BOOL
    _kernel32.LocalFree.argtypes = [wintypes.HLOCAL]
    _kernel32.LocalFree.restype = wintypes.HLOCAL


def dpapi_decrypt(blob: bytes) -> bytes:
    """Decrypt a DPAPI-protected blob for the current user."""
    if not IS_WINDOWS:
        raise OSError("DPAPI is only available on Windows")
    if not blob:
        return b""

    buffer_in = ctypes.create_string_buffer(blob, len(blob))
    blob_in = _DataBlob(len(blob), ctypes.cast(buffer_in, ctypes.POINTER(ctypes.c_char)))
    blob_out = _DataBlob()

    ok = _crypt32.CryptUnprotectData(
        ctypes.byref(blob_in), None, None, None, None, 0, ctypes.byref(blob_out)
    )
    if not ok:
        raise OSError(f"CryptUnprotectData failed (error {ctypes.GetLastError()})")
    try:
        return ctypes.string_at(blob_out.pbData, blob_out.cbData)
    finally:
        _kernel32.LocalFree(blob_out.pbData)


# ---------------------------------------------------------------------------
# Chromium master key handling
# ---------------------------------------------------------------------------
def load_master_key(local_state_path: str) -> Tuple[Optional[bytes], str]:
    """Return (aes_key, status) from a Chromium ``Local State`` file."""
    try:
        with open(local_state_path, "r", encoding="utf-8", errors="ignore") as fh:
            state = json.load(fh)
    except Exception as exc:  # noqa: BLE001
        return None, f"could not read Local State: {exc}"

    enc = state.get("os_crypt", {}).get("encrypted_key")
    if not enc:
        return None, "Local State has no os_crypt.encrypted_key"
    try:
        raw = base64.b64decode(enc)
    except Exception as exc:  # noqa: BLE001
        return None, f"invalid base64 key: {exc}"
    if raw[:5] == b"DPAPI":
        raw = raw[5:]
    try:
        key = dpapi_decrypt(raw)
    except OSError as exc:
        return None, f"DPAPI unwrap failed: {exc}"
    if len(key) not in (16, 24, 32):
        return None, f"unexpected key length {len(key)}"
    return key, "ok"


# ---------------------------------------------------------------------------
# AES-256-GCM (v10 / v11 / v20)
# ---------------------------------------------------------------------------
def _aes_gcm_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes) -> bytes:
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError("'cryptography' package required for AES-GCM decryption") from exc
    return AESGCM(key).decrypt(nonce, ciphertext + tag, None)


def decrypt_value(encrypted: bytes, key: Optional[bytes]) -> Tuple[str, str]:
    """Decrypt a single Chromium encrypted value.

    Returns ``(plaintext, status)`` where ``status`` is one of
    ``ok`` / ``empty`` / ``no_key`` / ``v20_appbound`` / ``dpapi`` / ``error``.
    """
    if not encrypted:
        return "", "empty"
    prefix = encrypted[:3]

    if prefix in (b"v10", b"v11"):
        if not key:
            return "", "no_key"
        nonce = encrypted[3:15]
        ciphertext = encrypted[15:-16]
        tag = encrypted[-16:]
        try:
            return _aes_gcm_decrypt(key, nonce, ciphertext, tag).decode("utf-8", "replace"), "ok"
        except Exception as exc:  # noqa: BLE001
            return f"<decryption failed: {exc}>", "error"

    if prefix == b"v20":
        return "", "v20_appbound"

    # Legacy: raw DPAPI blob.
    try:
        return dpapi_decrypt(encrypted).decode("utf-8", "replace"), "dpapi"
    except Exception as exc:  # noqa: BLE001
        return f"<dpapi failed: {exc}>", "error"


def chrome_time(value: Optional[int]) -> Optional[str]:
    """Convert a Chromium timestamp (microseconds since 1601) to ISO-8601 UTC."""
    if not value:
        return None
    try:
        from datetime import datetime, timedelta, timezone
        epoch = datetime(1601, 1, 1, tzinfo=timezone.utc)
        return (epoch + timedelta(microseconds=int(value))).isoformat(timespec="seconds")
    except Exception:  # noqa: BLE001
        return None


def firefox_time(value: Optional[int]) -> Optional[str]:
    """Convert a Firefox PRTime timestamp (microseconds since 1970) to ISO-8601."""
    if not value:
        return None
    try:
        from datetime import datetime, timezone
        return datetime.fromtimestamp(int(value) / 1_000_000, tz=timezone.utc).isoformat(timespec="seconds")
    except Exception:  # noqa: BLE001
        return None
