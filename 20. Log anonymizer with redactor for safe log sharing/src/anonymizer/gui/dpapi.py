"""Windows DPAPI wrapper (zero-dependency, OS-backed encryption).

Uses CryptProtectData/CryptUnprotectData (crypt32.dll) with the
CRYPTPROTECT_UI_FORBIDDEN flag, which binds the ciphertext to the
current Windows user profile (DPAPI - AES-256 keyed by the user's
logon credentials). No key material is stored by the application,
satisfying ISO 27001 A.8.24 (use of cryptography) without managing keys.

Fallback policy: on non-Windows platforms protection is NOT emulated
with client-side obfuscation - the caller is told DPAPI is unavailable
and must decide explicitly how to store the data (never fake security).
"""

import base64
import ctypes
import ctypes.util
import ctypes.wintypes as win
import sys

__all__ = ["DpapiError", "dpapi_available", "protect", "unprotect"]


class DpapiError(RuntimeError):
    """Raised when DPAPI protection/unprotection fails."""


class _DataBlob(ctypes.Structure):
    _fields_ = [("cbData", win.DWORD), ("pbData", ctypes.POINTER(ctypes.c_ubyte))]


def _available() -> bool:
    if sys.platform != "win32" or ctypes.util.find_library("crypt32") is None:
        return False
    try:
        ctypes.windll.LoadLibrary("crypt32")
        ctypes.windll.LoadLibrary("kernel32")
        return True
    except (AttributeError, OSError):
        return False


dpapi_available = _available()


def _to_blob(data: bytes) -> _DataBlob:
    raw = data or b""
    buffer = ctypes.create_string_buffer(raw, len(raw) or 1)
    return _DataBlob(len(raw), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte)))


def _from_blob(blob: _DataBlob) -> bytes:
    if not blob.cbData or not blob.pbData:
        return b""
    return bytes(ctypes.string_at(blob.pbData, blob.cbData))


def _free(ptr) -> None:
    if ptr:
        ctypes.windll.kernel32.LocalFree(ptr)


def _crypt(data_in: _DataBlob, entropy: _DataBlob, decrypt: bool) -> bytes:
    if not dpapi_available:
        raise DpapiError("DPAPI is unavailable on this platform")
    fn = (
        ctypes.windll.crypt32.CryptUnprotectData
        if decrypt
        else ctypes.windll.crypt32.CryptProtectData
    )
    out = _DataBlob(0, None)
    data_in_entropy = ctypes.byref(entropy) if entropy.cbData else None
    ok = fn(
        ctypes.byref(data_in),
        None,  # description (out)
        data_in_entropy,
        None,  # reserved
        None,  # prompt struct
        0x01,  # CRYPTPROTECT_UI_FORBIDDEN
        ctypes.byref(out),
    )
    try:
        if not ok:
            raise DpapiError(f"DPAPI call failed with Win32 error {ctypes.get_last_error()}")
        return _from_blob(out)
    finally:
        _free(out.pbData)


def protect(data: bytes, entropy: bytes = b"") -> bytes:
    """Encrypt bytes bound to the current Windows user (base64 output)."""
    result = _crypt(_to_blob(data), _to_blob(entropy), decrypt=False)
    return base64.b64encode(result)


def unprotect(token_b64: bytes, entropy: bytes = b"") -> bytes:
    """Decrypt a value previously protected with :func:`protect`."""
    raw = base64.b64decode(token_b64)
    return _crypt(_to_blob(raw), _to_blob(entropy), decrypt=True)
