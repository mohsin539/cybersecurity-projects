"""Application configuration + machine-scoped secret vault (DPAPI on Windows).

* Public settings (providers enabled, defaults) live plaintext in config.json.
* API keys are stored DPAPI-encrypted (Windows CryptProtectData) in secrets.bin.
This satisfies the architecture.md requirement: no secrets in plaintext, least privilege.
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import json
import os
import sys
from pathlib import Path
from typing import Any, Optional

APP_DIR_NAME = "StaticLab"


def app_data_dir() -> Path:
    base = os.environ.get("APPDATA") or os.path.expanduser("~")
    d = Path(base) / APP_DIR_NAME
    d.mkdir(parents=True, exist_ok=True)
    return d


# ---------------------------------------------------------------------------
# DPAPI helpers (Windows)
# ---------------------------------------------------------------------------

_CRYPTPROTECT_UI_FORBIDDEN = 0x1
_CRYPTPROTECT_LOCAL_MACHINE = 0x4


class _DATA_BLOB(ctypes.Structure):
    _fields_ = [("cbData", wt.DWORD), ("pbData", ctypes.POINTER(ctypes.c_byte))]


def _dll(name: str):
    try:
        return ctypes.windll.LoadLibrary(name)
    except (AttributeError, Exception):  # noqa: BLE001
        return None


def _dpapi_blob(data: bytes) -> _DATA_BLOB:
    buf = ctypes.create_string_buffer(data)
    blob = _DATA_BLOB(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_byte)))
    return blob


def _dpapi_unblob(blob: _DATA_BLOB) -> bytes:
    n = blob.cbData
    arr = (ctypes.c_ubyte * n).from_address(ctypes.addressof(blob.pbData.contents))
    return bytes(arr)


def dpapi_protect(data: bytes) -> Optional[bytes]:
    """Encrypt with current-user DPAPI. Returns None if unavailable (non-Windows)."""
    crypt = _dll("Crypt32.dll")
    if not crypt:
        return None
    in_blob = _dpapi_blob(data)
    out_blob = _DATA_BLOB()
    ok = crypt.CryptProtectData(
        ctypes.byref(in_blob), "StaticLab secrets", None, None, None, _CRYPTPROTECT_UI_FORBIDDEN, ctypes.byref(out_blob)
    )
    if not ok:
        return None
    return _dpapi_unblob(out_blob)


def dpapi_unprotect(blob: bytes) -> Optional[bytes]:
    crypt = _dll("Crypt32.dll")
    if not crypt:
        return None
    in_blob = _dpapi_blob(blob)
    out_blob = _DATA_BLOB()
    ok = crypt.CryptUnprotectData(
        ctypes.byref(in_blob), None, None, None, None, _CRYPTPROTECT_UI_FORBIDDEN, ctypes.byref(out_blob)
    )
    if not ok:
        return None
    return _dpapi_unblob(out_blob)


# ---------------------------------------------------------------------------
# SecretVault
# ---------------------------------------------------------------------------


class SecretVault:
    """Store API keys encrypted at rest, decrypt on demand, forget in memory."""

    _MAGIC = b"STL-VAULT-1"

    def __init__(self, path: Path | str):
        self.path = Path(path)
        self._cache: dict[str, str] = {}
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            return
        raw = self.path.read_bytes()
        if not raw.startswith(self._MAGIC):
            return
        blob = raw[len(self._MAGIC):]
        try:
            clear = dpapi_unprotect(blob)
            if clear:
                self._cache = json.loads(clear.decode("utf-8"))
        except Exception:  # noqa: BLE001
            self._cache = {}

    def save(self, secrets: dict[str, str]) -> None:
        self._cache = {k: v for k, v in secrets.items() if v}
        clear = json.dumps(self._cache).encode("utf-8")
        protected = dpapi_protect(clear)
        if protected is None:
            raise RuntimeError("DPAPI unavailable; refusing to persist secrets in plaintext")
        self.path.write_bytes(self._MAGIC + protected)

    def get(self, key: str) -> Optional[str]:
        return self._cache.get(key)

    def set(self, key: str, value: str) -> None:
        self._cache[key] = value
        self.save(self._cache)


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------


DEFAULTS: dict[str, Any] = {
    "providers": ["virustotal", "malwarebazaar", "otx", "hybridanalysis"],
    "min_string_len": 4,
    "lookup_timeout_sec": 10,
    "max_strings_report": 3000,
    "auto_recency": True,
    "proxy": "",
}


class Config:
    def __init__(self, base: Path) -> None:
        self.base = base
        self.file = base / "config.json"
        self.vault = SecretVault(base / "secrets.bin")
        self._cfg = {**DEFAULTS}
        self.load()

    def load(self) -> None:
        if self.file.exists():
            try:
                self._cfg.update(json.loads(self.file.read_text("utf-8")))
            except Exception:  # noqa: BLE001
                pass
        for k, v in DEFAULTS.items():
            self._cfg.setdefault(k, v)

    def save(self) -> None:
        self.file.write_text(json.dumps(self._cfg, indent=2), "utf-8")

    def get(self, key: str, default=None) -> Any:
        return self._cfg.get(key, default)

    def set(self, key: str, value: Any) -> None:
        self._cfg[key] = value
        self.save()

    # -- secrets convenience --------------------------------------------------
    def api_key(self, provider: str) -> Optional[str]:
        return self.vault.get(provider)

    def secrets_payload(self) -> dict[str, str]:
        return {
            p: (self.vault.get(p) or "")
            for p in ("virustotal", "malwarebazaar", "otx", "hybridanalysis", "hybridanalysis_secret")
        }

    def save_secrets(self, payload: dict[str, str]) -> None:
        keys = tuple(
            p
            for p in ("virustotal", "malwarebazaar", "otx", "hybridanalysis", "hybridanalysis_secret")
            if payload.get(p)
        )
        secrets = {k: payload[k].strip() for k in keys}
        self.vault.save(secrets)


def default_config() -> Config:
    return Config(app_data_dir())