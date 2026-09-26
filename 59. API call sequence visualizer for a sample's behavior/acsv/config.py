"""Config & Policy service.

Loads the hardened default policy, validates it against the embedded schema
(fail-closed if invalid), and resolves the writable data directory depending
on portable vs. managed mode.

Security mapping:
- ISO 27001 A.5.1  (policies for information security)
- ISO 27001 A.5.36 (compliance with policies)
- OWASP A05       (security misconfiguration -> fail-closed, validated config)
"""

from __future__ import annotations

import json
import os
import sys
import threading
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from .crypto import IntegrityService


class ConfigError(RuntimeError):
    """Raised when policy/config fails validation (fail-closed)."""


@dataclass
class Policy:
    """Validated runtime policy snapshot."""

    config_version: str
    max_events_per_session: int
    capture_timeout_seconds: int
    retention_days: int
    redact_pii: bool
    redact_patterns: list[str]
    sign_reports: bool
    audit_enabled: bool
    audit_tail_storage_mb: int
    allowed_export_formats: list[str]
    raw: dict = field(default_factory=dict)
    snapshot_hash: str = ""


_DEFAULT_POLICY = {
    "config_version": "1.0",
    "capture": {
        "max_events_per_session": 5000000,
        "timeout_seconds": 300,
        "default_sandbox": "windows_sandbox",
    },
    "security": {
        "redact_pii": True,
        "redact_patterns": [
            r"(?i)(?P<key>(authorization|password|passwd|pwd|secret|token|bearer|api[_-]?key))[\"']?\s*[:=]\s*(?P<val>(?:\"[^\"]*\")|(?:'[^']*')|\S+)",
            r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b",
            r"\b\d{3}[- ]?\d{2}[- ]?\d{4}\b",
        ],
        "sign_reports": False,
        "audit_enabled": True,
        "audit_tail_storage_mb": 64,
    },
    "compliance": {
        "frameworks": ["ISO27001", "NIST", "OWASP"],
    },
    "reporting": {
        "allowed_export_formats": ["json", "csv", "html", "pdf", "stix"],
        "max_download_bytes": 1073741824,
    },
    "retention_days": 90,
}

_TOPKEYS_STR = {"config_version"}
_TOPKEYS_INT = {"max_events_per_session", "capture_timeout_seconds", "retention_days"}


def _validate(policy_raw: dict) -> None:
    if not isinstance(policy_raw, dict):
        raise ConfigError("policy must be a TOML/JSON object")
    if "config_version" not in policy_raw:
        raise ConfigError("missing required key: config_version")
    if "capture" not in policy_raw:
        raise ConfigError("missing required section: capture")
    if "security" not in policy_raw:
        raise ConfigError("missing required section: security")
    if "reporting" not in policy_raw:
        raise ConfigError("missing required section: reporting")
    c = policy_raw["capture"]
    if not isinstance(c.get("max_events_per_session"), int) or c["max_events_per_session"] <= 0:
        raise ConfigError("capture.max_events_per_session must be a positive integer")
    if not isinstance(c.get("timeout_seconds"), int) or c["timeout_seconds"] <= 0:
        raise ConfigError("capture.timeout_seconds must be a positive integer")
    r = policy_raw["reporting"]
    if "allowed_export_formats" not in r:
        raise ConfigError("missing reporting.allowed_export_formats")


class ConfigService:
    """Loads policy, resolves data dirs, exposes the data integrity handle."""

    def __init__(self, base_dir: Path | None = None) -> None:
        self._base_dir = Path(base_dir) if base_dir else Path(__file__).resolve().parent.parent
        self._lock = threading.RLock()
        self.policy: Policy | None = None
        self.data_dir: Path | None = None
        self.integrity = IntegrityService()
        self._load_policy()
        self._resolve_data_dir()

    # ------------------------------------------------------------------ policy
    def _load_policy(self) -> None:
        env_policy = os.environ.get("ACSV_POLICY", "")
        candidates = [
            self._base_dir / "policies" / "default.toml",
            Path(env_policy) if env_policy else None,
        ]
        raw = None
        loaded_from = None
        for f in candidates:
            if f and f.exists():
                try:
                    with open(f, "rb") as fh:
                        raw = tomllib.load(fh)
                    loaded_from = f
                    break
                except tomlib.TOMLDecodeError as exc:
                    raise ConfigError(f"invalid policy file {f}: {exc}") from exc
        if raw is None:
            raw = dict(_DEFAULT_POLICY)
            loaded_from = Path("<embedded-default>")

        # deep-merge with defaults so a partial policy never drops a control.
        merged = _deep_merge(dict(_DEFAULT_POLICY), raw)
        _validate(merged)

        caps = merged["capture"]
        sec = merged["security"]
        rep = merged["reporting"]
        snap = json.dumps(merged, sort_keys=True, separators=(",", ":"))
        self.policy = Policy(
            config_version=str(merged["config_version"]),
            max_events_per_session=int(caps["max_events_per_session"]),
            capture_timeout_seconds=int(caps["timeout_seconds"]),
            retention_days=int(merged.get("retention_days", 90)),
            redact_pii=bool(sec.get("redact_pii", True)),
            redact_patterns=[str(p) for p in sec.get("redact_patterns", [])],
            sign_reports=bool(sec.get("sign_reports", False)),
            audit_enabled=bool(sec.get("audit_enabled", True)),
            audit_tail_storage_mb=int(sec.get("audit_tail_storage_mb", 64)),
            allowed_export_formats=[str(f) for f in rep.get("allowed_export_formats", [])],
            raw=merged,
            snapshot_hash=self.integrity.sha256_hex(snap.encode()),
        )
        self.policy_source = str(loaded_from)  # noqa

    def policy_snapshot_hash(self) -> str:
        self.integrity  # ensure initialized
        return self.policy.snapshot_hash if self.policy else ""

    # --------------------------------------------------------------- data dir
    def _resolve_data_dir(self) -> None:
        override = os.environ.get("ACSV_DATA")
        if override:
            data_dir = self._safe_data_dir(Path(override))
        else:
            portable = self._base_dir / "data"
            if portable.exists():
                data_dir = self._safe_data_dir(portable)
            else:
                local = Path(os.environ.get("LOCALAPPDATA", Path.home())) / "ACSV"
                data_dir = self._safe_data_dir(local)
        for sub in ("store", "artifacts", "reports", "audit"):
            (data_dir / sub).mkdir(parents=True, exist_ok=True)
        self.data_dir = data_dir

    @staticmethod
    def _safe_data_dir(p: Path) -> Path:
        return p.expanduser().resolve()


def _deep_merge(base: dict, override: dict) -> dict:
    out = dict(base)
    for k, v in override.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out