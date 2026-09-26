"""App state + persistence (architecture.md section 7.3, AppContext/localStorage).

Saves the last inputs so the next launch restores the session. Tries a
`state.json` next to the executable/script first (true portability), then falls
back to %APPDATA% for installed scenarios; silently no-ops when neither works
(private mode), matching architecture.md section 9.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

APP_NAME = "SubnetVLSMPlanner"
STATE_FILENAME = "state.json"

_DEFAULTS: dict[str, object] = {
    "calc_ip": "192.168.10.77",
    "calc_prefix": "26",
    "vlsm_base_ip": "192.168.1.0",
    "vlsm_base_prefix": "24",
    "vlsm_requirements": [
        {"name": "Sales", "hosts": 50},
        {"name": "Engineering", "hosts": 25},
        {"name": "Guest WiFi", "hosts": 10},
    ],
}


def _portable_dir() -> Path | None:
    """Folder next to the script / frozen exe, if it is writable."""
    if getattr(sys, "frozen", False):
        base = Path(sys.executable).resolve().parent
    else:
        base = Path(__file__).resolve().parent.parent
    try:
        probe = base / ".write_test"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink(missing_ok=True)
        return base
    except OSError:
        return None


def _appdata_dir() -> Path | None:
    """%APPDATA%/SubnetVLSMPlanner fallback."""
    base = os.environ.get("APPDATA")
    if not base:
        return None
    path = Path(base) / APP_NAME
    try:
        path.mkdir(parents=True, exist_ok=True)
        return path
    except OSError:
        return None


def state_file_path() -> Path | None:
    """Where state.json would live (portable location preferred)."""
    return _portable_dir() or _appdata_dir()


def load_state() -> dict[str, object]:
    """Load saved state, merging over defaults; never raises."""
    state = dict(_DEFAULTS)
    directory = state_file_path()
    if directory is None:
        return state
    path = directory / STATE_FILENAME
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            state.update(data)
    except (OSError, ValueError):
        pass
    return state


def save_state(state: dict[str, object]) -> bool:
    """Persist state atomically; returns True on success, never raises."""
    directory = state_file_path()
    if directory is None:
        return False
    path = directory / STATE_FILENAME
    try:
        fd, tmp_name = tempfile.mkstemp(dir=str(directory), suffix=".tmp")
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(state, handle, indent=2)
        os.replace(tmp_name, path)
        return True
    except OSError:
        return False
