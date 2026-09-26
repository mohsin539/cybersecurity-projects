import ctypes
import ctypes.wintypes as wt
import os

_DPAPI_UI_FORBIDDEN = 0x01
_CRYPTPROTECT_LOCAL_MACHINE = 0x04
_IS_WINDOWS = os.name == "nt"


class _DATA_BLOB(ctypes.Structure):
    _fields_ = [("cbData", wt.DWORD), ("pbData", ctypes.POINTER(wt.BYTE))]


def _make_blob(data):
    size = len(data)
    buf = (wt.BYTE * size)()
    ctypes.memmove(buf, bytes(data), size)
    return _DATA_BLOB(size, buf)


def _blob_bytes(blob):
    n = blob.cbData
    if not n:
        return b""
    return ctypes.string_at(blob.pbData, n)


def dpapi_capable():
    return _IS_WINDOWS


def dpapi_protect(data, local_machine=False):
    if not _IS_WINDOWS:
        raise OSError("DPAPI is only available on Windows")
    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32
    inblob = _make_blob(data)
    out = _DATA_BLOB()
    flags = _DPAPI_UI_FORBIDDEN | (_CRYPTPROTECT_LOCAL_MACHINE if local_machine else 0)
    ok = crypt32.CryptProtectData(
        ctypes.byref(inblob), None, None, None, None, flags, ctypes.byref(out)
    )
    if not ok:
        raise OSError("CryptProtectData failed", ctypes.get_last_error())
    try:
        return _blob_bytes(out)
    finally:
        kernel32.LocalFree(out.pbData)


def dpapi_unprotect(data):
    if not _IS_WINDOWS:
        raise OSError("DPAPI is only available on Windows")
    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32
    inblob = _make_blob(data)
    out = _DATA_BLOB()
    ok = crypt32.CryptUnprotectData(
        ctypes.byref(inblob), None, None, None, None, _DPAPI_UI_FORBIDDEN, ctypes.byref(out)
    )
    if not ok:
        raise OSError("CryptUnprotectData failed", ctypes.get_last_error())
    try:
        return _blob_bytes(out)
    finally:
        kernel32.LocalFree(out.pbData)


def bcrypt_md4(data):
    if not _IS_WINDOWS:
        raise OSError("BCrypt is only available on Windows")
    bcrypt = ctypes.windll.bcrypt
    handle = ctypes.c_void_p()
    bcrypt.BCryptOpenAlgorithmProvider.argtypes = [
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.c_wchar_p,
        ctypes.c_wchar_p,
        wt.DWORD,
    ]
    status = bcrypt.BCryptOpenAlgorithmProvider(ctypes.byref(handle), "MD4", None, 0)
    if status != 0:
        raise OSError("BCryptOpenAlgorithmProvider failed", status)
    try:
        out = (ctypes.c_ubyte * 16)()
        bcrypt.BCryptHash.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            wt.ULONG,
            ctypes.c_char_p,
            wt.ULONG,
            ctypes.POINTER(ctypes.c_ubyte),
            wt.ULONG,
        ]
        status = bcrypt.BCryptHash(handle, None, 0, bytes(data), len(data), out, 16)
        if status != 0:
            raise OSError("BCryptHash failed", status)
        return bytes(out)
    finally:
        bcrypt.BCryptCloseAlgorithmProvider(handle, 0)