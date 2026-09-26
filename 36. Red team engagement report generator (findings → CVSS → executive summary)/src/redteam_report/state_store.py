"""Lightweight local UI state persistence for the desktop GUI.

Recalls the last-used input file and output directory between sessions so
analysts resume work without re-selecting paths. State lives in the per-user
app-data directory (``%LOCALAPPDATA%\\redteam_report`` on Windows) rather than
next to the bundle, which keeps the portable .exe write-location agnostic.

This module intentionally performs no cryptographic or network operations; it
only round-trips plain JSON. See ``state.md`` for the data contract and
``security.md`` for the protections applied around stored paths.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

STATE_FILE = "state.json"
DEFAULT_KEYS = ("input_file", "output_dir")


def state_path(base: Path) -> Path:
    """Return the state file path under a base (per-user) directory."""
    return Path(base) / STATE_FILE


def load_state(base: Path, keys: tuple = DEFAULT_KEYS) -> dict:
    """Load persisted UI state as a plain dict (empty dict if absent)."""
    path = state_path(base)
    try:
        with path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        return {}
    if isinstance(data, dict):
        return {k: data[k] for k in keys if k in data}
    return {}


def save_state(base: Path, state: dict, keys: tuple = DEFAULT_KEYS) -> Optional[Path]:
    """Persist UI state as JSON; returns the written path (or None on error).

    Only values present in ``keys`` are written, so unexpected caller keys are
    never serialized. Invalid path values are dropped to keep state clean.
    """
    base = Path(base)
    base.mkdir(parents=True, exist_ok=True)
    payload: dict = {}
    for key in keys:
        value = state.get(key)
        if value and str(value).strip():
            payload[key] = str(value).strip()
    if not payload:
        return None
    path = state_path(base)
    try:
        with path.open("w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2)
    except OSError:  # pragma: no cover - e.g. read-only AppData
        return None
    return path


def clear_state(base: Path) -> bool:
    """Remove persisted UI state (used by tests and the Help -> reset action)."""
    path = state_path(base)
    try:
        path.unlink(missing_ok=True)
    except OSError:  # pragma: no cover - permission errors etc.
        return False
    return True