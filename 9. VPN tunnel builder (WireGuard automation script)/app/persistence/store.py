"""State persistence (NIST SI-7, AU-9; ISO 27001 A.8.9, A.8.28).

Rules enforced here:
  * Every write is atomic: temp file + fsync + rename + fsync dir
    (no torn/partial state files).
  * A cross-platform file lock serializes writers (flock / msvcrt).
  * Private key material lives in a SEPARATE file (`secrets.json`), never in
    `state.json` which may be exported/mirrored (ISO A.8.12 data leakage).
  * Best-effort POSIX permissions 0600/0700 on the store dirs and files.
"""

from __future__ import annotations

import json
import os
import tempfile
import time
from pathlib import Path

try:
    import fcntl  # type: ignore
    _HAS_FCNTL = True
except ImportError:  # pragma: no cover - Windows
    _HAS_FCNTL = False

try:
    import msvcrt  # type: ignore
    _HAS_MSVCRT = True
except ImportError:  # pragma: no cover - POSIX
    _HAS_MSVCRT = False


class StoreError(Exception):
    pass


class FileLock:
    """Advisory cross-platform lock serializing writers to the store."""

    def __init__(self, path: Path):
        self.path = path
        self._fh = None

    def __enter__(self):
        self._fh = open(self.path, "a+", encoding="utf-8")
        try:
            if _HAS_FCNTL:
                fcntl.flock(self._fh.fileno(), fcntl.LOCK_EX)
            elif _HAS_MSVCRT:
                self._fh.seek(0)
                msvcrt.locking(self._fh.fileno(), msvcrt.LK_LOCK, 1)
        except (OSError, ValueError):
            pass  # lock best-effort only
        return self

    def __exit__(self, *exc):
        try:
            if _HAS_FCNTL:
                fcntl.flock(self._fh.fileno(), fcntl.LOCK_UN)
            elif _HAS_MSVCRT:
                self._fh.seek(0)
                msvcrt.locking(self._fh.fileno(), msvcrt.LK_UNLCK, 1)
        except (OSError, ValueError):
            pass
        self._fh.close()
        self._fh = None


def _atomic_write(path: Path, data: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
        try:
            dir_fd = os.open(str(path.parent), os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        except OSError:
            pass
        _chmod_private(path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _chmod_private(path: Path) -> None:
    if os.name != "posix":
        return
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def _chmod_dir(path: Path) -> None:
    if os.name != "posix":
        return
    try:
        os.chmod(path, 0o700)
    except OSError:
        pass


def _read_json(path: Path, fallback):
    if not path.exists():
        return fallback
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (ValueError, OSError):
        raise StoreError(f"corrupt store file: {path}")


def _empty_state() -> dict:
    return {
        "schema": 1,
        "tunnels": [],
        "peers": [],
        "keypairs": [],
        "updated_at": "",
    }


class StateStore:
    """JSON document store with atomic writes and secret separation."""

    def __init__(self, data_dir: str | Path):
        self.root = Path(data_dir)
        self.conf_dir = self.root / "confs"
        self.lock_path = self.root / ".lock"
        for d in (self.root, self.conf_dir):
            d.mkdir(parents=True, exist_ok=True)
            _chmod_dir(d)
        self.state_path = self.root / "state.json"
        self.secrets_path = self.root / "secrets.json"
        self.settings_path = self.root / "settings.json"
        self.audit_path = self.root / "audit.log"
        self.snapshot_dir = self.root / "snapshots"
        self.snapshot_dir.mkdir(parents=True, exist_ok=True)
        _chmod_dir(self.snapshot_dir)

    # -- state (public, no secrets) -------------------------------------
    def load_state(self) -> dict:
        state = _read_json(self.state_path, _empty_state())
        if not isinstance(state, dict):
            raise StoreError("state.json must be an object")
        state.setdefault("schema", 1)
        state.setdefault("tunnels", [])
        state.setdefault("peers", [])
        state.setdefault("keypairs", [])
        return state

    def save_state(self, state: dict) -> dict:
        state = dict(state)
        state["updated_at"] = time.time()
        with FileLock(self.lock_path):
            _atomic_write(self.state_path, json.dumps(state, indent=2, sort_keys=True))
        return state

    # -- secrets (private material, separate file) -----------------------
    def load_secrets(self) -> dict:
        secrets = _read_json(self.secrets_path, {"private_keys": {}, "psks": {}})
        secrets.setdefault("private_keys", {})
        secrets.setdefault("psks", {})
        return secrets

    def save_secrets(self, secrets: dict) -> None:
        secrets = dict(secrets)
        with FileLock(self.lock_path):
            _atomic_write(
                self.secrets_path,
                json.dumps(secrets, indent=2, sort_keys=True),
            )

    # -- settings --------------------------------------------------------
    def load_settings(self, default_settings: dict) -> dict:
        found = _read_json(self.settings_path, {})
        merged = dict(default_settings)
        merged.update({k: v for k, v in found.items() if k in default_settings})
        return merged

    def save_settings(self, settings: dict) -> None:
        with FileLock(self.lock_path):
            _atomic_write(self.settings_path, json.dumps(settings, indent=2, sort_keys=True))

    # -- convenience -----------------------------------------------------
    def config_file(self, interface: str) -> Path:
        return self.conf_dir / f"{interface}.conf"

    def backend_status_file(self) -> Path:
        return self.root / "status.json"