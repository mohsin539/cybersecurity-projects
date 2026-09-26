from __future__ import annotations

import os
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any

APP_DIRNAME = "TimelineBuilder"

DEFAULT_MAX_FILE_BYTES = 64 * 1024 * 1024
DEFAULT_HASH_MAX_BYTES = 128 * 1024 * 1024
DEFAULT_CHUNK_BYTES = 1024 * 1024
DEFAULT_MAX_DEPTH = 32
DEFAULT_MAX_EVENTS = 2_000_000


def user_data_dir() -> Path:
    base = os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA")
    if not base:
        base = str(Path.home() / ".local" / "share")
    return Path(base) / APP_DIRNAME


@dataclass
class ScanOptions:
    compute_hashes: bool = False
    hash_max_bytes: int = DEFAULT_HASH_MAX_BYTES
    collect_created: bool = True
    collect_accessed: bool = True
    collect_changed: bool = True
    collect_modified: bool = True
    follow_symlinks: bool = False
    max_depth: int = DEFAULT_MAX_DEPTH
    max_events: int = DEFAULT_MAX_EVENTS
    include_hidden: bool = True
    log_max_file_bytes: int = DEFAULT_MAX_FILE_BYTES
    infer_severity: bool = True

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class AppSettings:
    theme: str = "dark"
    timezone: str = "UTC"
    case_dir: str = field(default_factory=lambda: str(user_data_dir() / "cases"))
    audit_dir: str = field(default_factory=lambda: str(user_data_dir() / "audit"))
    scan: ScanOptions = field(default_factory=ScanOptions)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        return data
