"""Device/user binding via Windows DPAPI (CryptProtectData).

Serves as the portable, hardware-backed "Secure Enclave-lite" root of trust.
DPAPI encrypts blobs with the current Windows user's master key (optionally
TPM-protected), binding key material to this machine + this user.

In a hardened build this role is played by the Secure Enclave / TPM 2.0
(see architecture.md section 5.2 & 12).
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wt


class DATA_BLOB(ctypes.Structure):
    _fields_ = [("cbData", wt.DWORD), ("pbData", ctypes.POINTER(ctypes.c_ubyte))]


def _blob(data: bytes) -> DATA_BLOB:
    buf = (ctypes.c_ubyte * max(1, len(data))).from_buffer_copy(data)
    return DATA_BLOB(len(data), buf)


def _to_bytes(blob: DATA_BLOB) -> bytes:
    if not blob.cbData:
        return b""
    return ctypes.string_at(blob.pbData, blob.cbData)


def _free_allocated(blob: DATA_BLOB) -> None:
    """Free a buffer allocated by CryptProtectData (LocalAlloc from crypt32)."""
    if blob.pbData:
        ctypes.windll.kernel32.LocalFree(blob.pbData)


_CRYPT32 = ctypes.windll.crypt32
_CRYPT32.CryptProtectData.argtypes = [
    ctypes.POINTER(DATA_BLOB), ctypes.c_wchar_p, ctypes.POINTER(DATA_BLOB),
    ctypes.c_void_p, ctypes.c_void_p, wt.DWORD, ctypes.POINTER(DATA_BLOB),
]
_CRYPT32.CryptProtectData.restype = ctypes.c_bool
_CRYPT32.CryptUnprotectData.argtypes = [
    ctypes.POINTER(DATA_BLOB), ctypes.c_void_p, ctypes.POINTER(DATA_BLOB),
    ctypes.c_void_p, ctypes.c_void_p, wt.DWORD, ctypes.POINTER(DATA_BLOB),
]
_CRYPT32.CryptUnprotectData.restype = ctypes.c_bool


def dpapi_protect(data: bytes) -> bytes:
    """Encrypt data under current-user DPAPI scope (machine+user bound)."""
    if not data:
        return b""
    in_blob = _blob(data)
    out_blob = DATA_BLOB()
    try:
        ok = _CRYPT32.CryptProtectData(
            ctypes.byref(in_blob), "SecureNotePro", None, None, None, 0,
            ctypes.byref(out_blob),
        )
        if not ok:
            raise OSError("CryptProtectData failed")
        return _to_bytes(out_blob)
    finally:
        _free_allocated(out_blob)


def dpapi_unprotect(blob_bytes: bytes) -> bytes:
    in_blob = _blob(blob_bytes)
    out_blob = DATA_BLOB()
    try:
        ok = _CRYPT32.CryptUnprotectData(
            ctypes.byref(in_blob), None, None, None, None, 0,
            ctypes.byref(out_blob),
        )
        if not ok:
            raise OSError("CryptUnprotectData failed (not bound to this device/user)")
        return _to_bytes(out_blob)
    finally:
        _free_allocated(out_blob)


def is_available() -> bool:
    try:
        return dpapi_unprotect(dpapi_protect(b"probe")) == b"probe"
    except OSError:
        return False