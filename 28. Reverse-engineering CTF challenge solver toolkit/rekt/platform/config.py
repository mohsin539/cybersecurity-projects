"""Application configuration — validated, secure-by-default (OWASP A05).

Portable mode: set REKT_PORTABLE=<dir> to keep all data on the USB stick
(NFR-1: no registry writes, no admin rights).
"""
from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, fields
from pathlib import Path

from rekt import APP_NAME, __version__

CONFIG_VERSION = 1


def app_data_dir() -> Path:
    """Writable data directory. Honors portable mode; never touches the registry."""
    portable = os.environ.get("REKT_PORTABLE")
    if portable:
        base = Path(portable)
    else:
        base = Path(os.environ.get("LOCALAPPDATA", str(Path.home() / ".rekt")))
    d = base / "rekt-data"
    d.mkdir(parents=True, exist_ok=True)
    return d


@dataclass
class Config:
    """All defaults are the strictest safe profile (ARCHITECTURE.md §11.3)."""

    config_version: int = CONFIG_VERSION
    app_version: str = __version__

    # --- sandbox / execution (deny-by-default) ---
    dynamic_execution_enabled: bool = False   # user must opt in per session
    default_timeout_s: int = 120              # hard cap for jobs
    max_cpu_seconds: int = 60
    max_memory_mb: int = 1024
    allow_network_in_sandbox: bool = False    # A01: deny-by-default

    # --- limits (DoS/bomb guards, A04) ---
    max_file_mb: int = 64
    max_recipe_steps: int = 100
    max_extract_depth: int = 8

    # --- plugins (A08: signed allow-list) ---
    unsigned_plugins_allowed: bool = False    # requires per-session Developer Mode

    # --- privacy (A09: no PII/content in logs) ---
    telemetry_enabled: bool = False           # hard-off; there is no collector anyway
    update_check_url: str = ""                # empty = offline; pin+allow-list (A10)

    # --- UI ---
    theme: str = "dark"

    def validate(self) -> None:
        if self.default_timeout_s < 5 or self.default_timeout_s > 3600:
            raise ValueError("default_timeout_s out of range [5, 3600]")
        if self.max_file_mb < 1 or self.max_file_mb > 4096:
            raise ValueError("max_file_mb out of range [1, 4096]")
        if self.theme not in {"dark", "light"}:
            raise ValueError("unknown theme")
        if self.telemetry_enabled:
            raise ValueError("telemetry is not supported in this build")  # A09 invariant


def config_path() -> Path:
    return app_data_dir() / "config.json"


def load_config() -> Config:
    """Load config, falling back to defaults on any error (never fail-open to insecure)."""
    p = config_path()
    if not p.exists():
        return Config()
    try:
        raw = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return Config()
    known = {f.name for f in fields(Config)}
    filtered = {k: v for k, v in raw.items() if k in known}  # reject unknown keys (A05)
    cfg = Config(**filtered)
    try:
        cfg.validate()
    except ValueError:
        return Config()  # tampered/invalid config -> defaults, do not persist
    return cfg


def save_config(cfg: Config) -> None:
    cfg.validate()
    config_path().write_text(
        json.dumps(asdict(cfg), indent=2), encoding="utf-8"
    )
