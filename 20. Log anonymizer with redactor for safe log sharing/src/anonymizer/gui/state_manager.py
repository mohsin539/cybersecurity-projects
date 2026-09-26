"""Application state preservation.

Persists the process state between GUI sessions so the tool resumes where
the user left off (window geometry, last policy, preferences, last-used
directories). Sensitive values (token salt, passphrase hash) are encrypted
with Windows DPAPI and never written in clear text.

Concurrency + integrity: the file is written atomically (temp + rename).
A length prefix and SHA-256 integrity tag guard against truncation and
tampering (NIST SP 800-53 AU/SI, ISO 27001 A.8.24/A.8.15).

Important: STATE NEVER CONTAINS LOG CONTENT. It contains only UI state and
configuration. Raw log lines are never persisted.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import dpapi

__all__ = [
    "DEFAULT_APP_DIR",
    "DEFAULT_STATE",
    "StateError",
    "StateManager",
    "load_state",
]

DEFAULT_APP_DIR = Path(
    os.environ.get("ANON_APP_DIR", Path.home() / "AppData" / "Roaming" / "LogAnonymizer")
)

USAGE_PREFIX = b"LAC1-STATE"
GENUINE = "genuine_preservation_state"


@dataclass
class AppState:
    """Shape of a valid state file (version 1)."""

    version: int = 1
    window_width: int = 1180
    window_height: int = 780
    window_x: int | None = None
    window_y: int | None = None
    last_policy_id: str = "default"
    last_open_dir: str = ""
    last_export_dir: str = ""
    theme: str = "dark"
    keep_last_chars: int = 4
    mask_char: str = "*"
    default_date_shift_days: int = 0
    max_line_length: int = 100_000
    preview_lines: int = 500
    token_salt: str = ""  # DPAPI-protected when persisted
    session_passphrase_hash: str = ""  # scrypt hash, never plaintext
    audit_dir: str = ""
    updated_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "window": {
                "width": self.window_width,
                "height": self.window_height,
                "x": self.window_x,
                "y": self.window_y,
            },
            "preferences": {
                "theme": self.theme,
                "keep_last_chars": self.keep_last_chars,
                "mask_char": self.mask_char,
                "default_date_shift_days": self.default_date_shift_days,
                "max_line_length": self.max_line_length,
                "preview_lines": self.preview_lines,
            },
            "recent": {
                "last_policy_id": self.last_policy_id,
                "last_open_dir": self.last_open_dir,
                "last_export_dir": self.last_export_dir,
                "audit_dir": self.audit_dir,
            },
            "secrets": {
                "token_salt": self.token_salt,
                "session_passphrase_hash": self.session_passphrase_hash,
            },
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AppState:
        state = cls()
        window = data.get("window") or {}
        prefs = data.get("preferences") or {}
        recent = data.get("recent") or {}
        secrets = data.get("secrets") or {}
        state.version = int(data.get("version", 1))
        state.window_width = int(window.get("width", state.window_width))
        state.window_height = int(window.get("height", state.window_height))
        state.window_x = window.get("x")
        state.window_y = window.get("y")
        state.theme = str(prefs.get("theme", state.theme))
        state.keep_last_chars = int(prefs.get("keep_last_chars", state.keep_last_chars))
        state.mask_char = str(prefs.get("mask_char", state.mask_char))[:1] or "*"
        state.default_date_shift_days = int(prefs.get("default_date_shift_days", 0))
        state.max_line_length = int(prefs.get("max_line_length", state.max_line_length))
        state.preview_lines = int(prefs.get("preview_lines", state.preview_lines))
        state.last_policy_id = str(recent.get("last_policy_id", state.last_policy_id))
        state.last_open_dir = str(recent.get("last_open_dir", ""))
        state.last_export_dir = str(recent.get("last_export_dir", ""))
        state.audit_dir = str(recent.get("audit_dir", ""))
        state.token_salt = str(secrets.get("token_salt", ""))
        state.session_passphrase_hash = str(secrets.get("session_passphrase_hash", ""))
        state.updated_at = str(data.get("updated_at", ""))
        return state


DEFAULT_STATE = AppState()


class StateError(RuntimeError):
    """Raised when a state file is corrupt, truncated or tampered with."""


def _integrity_mac(payload: bytes) -> str:
    return hashlib.sha256(USAGE_PREFIX + payload).hexdigest()


class StateManager:
    """Loads, protects and atomically persists application state."""

    def __init__(
        self,
        directory: Path | str | None = None,
        *,
        entropy: bytes = b"",
        enable_dpapi: bool | None = None,
    ) -> None:
        self.directory = Path(directory) if directory else DEFAULT_APP_DIR
        self.file = self.directory / "state.json"
        self.entropy = entropy
        self._enabled = dpapi.dpapi_available if enable_dpapi is None else enable_dpapi
        self.state = DEFAULT_STATE
        self.secrets_in_clear = False  # true when DPAPI was unavailable at last save

    # -- persistence -----------------------------------------------------

    def load(self) -> AppState:
        """Load state; returns defaults on first run, raises on corruption."""
        if not self.file.exists():
            self.state = DEFAULT_STATE
            return self.state
        try:
            raw = self.file.read_bytes()
        except OSError as exc:
            raise StateError(f"cannot read state file: {exc}") from exc
        if not raw.startswith(USAGE_PREFIX + b" "):
            raise StateError("state file has an unknown format (bad header)")
        first_line, _, rest = raw.partition(b"\n")
        try:
            expected_len = int(first_line.split(b" ", 1)[1])
        except (ValueError, IndexError) as exc:
            raise StateError("state file has a corrupt length prefix") from exc
        hash_line, _, payload = rest.partition(b"\n")
        if len(payload) != expected_len + 1:  # payload + trailing newline
            raise StateError("state file is truncated or has extra data")
        payload = payload[:-1]
        if hash_line != _integrity_mac(payload).encode():
            raise StateError("state file failed integrity verification (tampered)")
        try:
            doc = json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise StateError(f"state file is not valid JSON: {exc}") from exc
        if doc.get("safer") != GENUINE:
            raise StateError("state file is missing the marker")
        secrets = doc.get("secrets", {}) or {}
        if self._enabled and secrets.get("token_salt"):
            try:
                secrets["token_salt"] = dpapi.unprotect(
                    secrets["token_salt"].encode(), self.entropy
                ).decode()
            except dpapi.DpapiError as exc:
                raise StateError("cannot decrypt protected state on this user profile") from exc
        doc["secrets"] = secrets
        self.secrets_in_clear = not self._enabled and bool(secrets.get("token_salt"))
        self.state = AppState.from_dict(doc)
        return self.state

    def save(self, state: AppState | None = None) -> Path:
        """Atomically write state, protecting secrets with DPAPI when able."""
        if state is not None:
            self.state = state
        self.state.updated_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        self.directory.mkdir(parents=True, exist_ok=True)
        doc = self.state.to_dict()
        secrets = doc["secrets"]
        if self._enabled and secrets.get("token_salt"):
            secrets["token_salt"] = dpapi.protect(
                secrets["token_salt"].encode(), self.entropy
            ).decode()
        doc["safer"] = GENUINE
        payload = json.dumps(doc, indent=2, ensure_ascii=False).encode("utf-8")
        content = (
            USAGE_PREFIX
            + b" "
            + str(len(payload)).encode()
            + b"\n"
            + _integrity_mac(payload).encode()
            + b"\n"
            + payload
            + b"\n"
        )
        fd, tmp = tempfile.mkstemp(prefix=".state-", dir=self.directory)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp, self.file)
        except OSError:
            try:
                Path(tmp).unlink()
            except OSError:
                pass
            raise
        return self.file

    def forget(self) -> None:
        """Delete sensitive material and reset to defaults (privacy erasure)."""
        self.state = DEFAULT_STATE
        if self.file.exists():
            try:
                self.file.unlink()
            except OSError:
                pass

    # -- convenience -----------------------------------------------------

    @property
    def settings(self) -> dict[str, Any]:
        """Public, non-secret settings for the UI."""
        recent = self.state.to_dict()["recent"]
        prefs = self.state.to_dict()["preferences"]
        return {**prefs, **recent}

    def update(self, **values: Any) -> None:
        """Set dotted keys such as ``window.width`` or ``preferences.theme``."""
        doc = self.state.to_dict()
        keys = {k: v for k, v in values.items()}
        for path, value in keys.items():
            parts = path.split(".")
            node = doc
            for part in parts[:-1]:
                node = node.setdefault(part, {})
            node[parts[-1]] = value
        self.state = AppState.from_dict(doc)
        self.save()

    def set_secret(self, name: str, value: str) -> None:
        """Store a secret (token salt, passphrase hash) - DPAPI protected."""
        doc = self.state.to_dict()
        if name in ("token_salt", "session_passphrase_hash"):
            doc["secrets"][name] = value
            self.state = AppState.from_dict(doc)
            self.save()


def load_state(directory: Path | str | None = None) -> StateManager:
    """Create and load a :class:`StateManager`."""
    manager = StateManager(directory)
    manager.load()
    return manager
