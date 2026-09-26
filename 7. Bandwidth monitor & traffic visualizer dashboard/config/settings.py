"""Runtime configuration for the Bandwidth Monitor Dashboard.

Values are read from environment variables so the application is portable
across Windows / Linux / macOS and containerised deployment without code
changes.  Every field has a production-safe default.

A ``.env`` file at the project root is supported for local overrides: it is
loaded into ``os.environ`` (without clobbering variables that are already
set) right before the ``Settings`` dataclass reads the environment, so
precedence is always:  real env var  >  .env file  >  built-in default.

Every ``BWMON_*`` variable is described in :data:`ENV_SCHEMA` — the single
source of truth used by ``Settings.from_env``, the ``.env`` validator, the
warning helper and the test-suite drift guards.  When a new setting is
added, add one ``EnvSpec`` row and wire the field's ``default_factory``
through :func:`_get` (or read it in ``from_env``); tests then verify the
schema and the dataclass stay in sync.
"""
from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, List, Literal, Optional

logger = logging.getLogger("bwmon.settings")

_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

EnvKind = Literal["string", "int", "float", "bool", "enum"]

_BOOL_TRUE = {"1", "true", "yes", "on"}
_BOOL_FALSE = {"0", "false", "no", "off"}
_BOOL_VALUES = _BOOL_TRUE | _BOOL_FALSE
_LOG_LEVELS = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
_STORE_BACKENDS = {"sqlite", "memory"}


# ------------------------------------------------------------------ schema
@dataclass(frozen=True)
class EnvSpec:
    """One row of the environment schema: key, kind, default, target field."""

    key: str
    kind: EnvKind
    default: str | float | int | None
    attr: str  # Settings field this variable feeds ("" if consumed elsewhere)
    choices: frozenset[str] | None = None  # only for kind == "enum"
    description: str = ""

    def parse(self, raw: str) -> str | int | float | bool:
        """Parse ``raw`` exactly the way ``Settings`` would consume it.

        Returns the parsed value; raises ``ValueError`` when the value does
        not match the declared kind. Enum lookup is case-insensitive, bools
        accept 1/0, true/false, yes/no, on/off.
        """
        text = raw.strip()
        if self.kind == "int":
            return int(text)
        if self.kind == "float":
            return float(text)
        if self.kind == "bool":
            lowered = text.lower()
            if lowered in _BOOL_TRUE:
                return True
            if lowered in _BOOL_FALSE:
                return False
            raise ValueError(
                f"expected bool ({'|'.join(sorted(_BOOL_VALUES))}), got {raw!r}"
            )
        if self.kind == "enum":
            # Case-insensitive lookup; returns the canonical-cased choice.
            lowered = text.lower()
            for choice in self.choices or set():
                if choice.lower() == lowered:
                    return choice
            raise ValueError(
                f"expected one of {sorted(self.choices or set())}, got {raw!r}"
            )
        return text  # string


ENV_SCHEMA: dict[str, EnvSpec] = {
    s.key: s
    for s in (
        EnvSpec("BWMON_HOST", "string", "127.0.0.1", "host",
                description="Bind address."),
        EnvSpec("BWMON_PORT", "int", 8000, "port",
                description="Bind port."),
        EnvSpec("BWMON_REFRESH_INTERVAL", "float", 1.0, "refresh_interval",
                description="Sampling cadence in seconds."),
        EnvSpec("BWMON_HISTORY_CAPACITY", "int", 3600, "history_capacity",
                description="Retained snapshots."),
        EnvSpec("BWMON_STORE_BACKEND", "enum", "sqlite", "store_backend",
                choices=frozenset(_STORE_BACKENDS),
                description="Snapshot persistence backend."),
        EnvSpec("BWMON_STORE_PATH", "string", "bwmon_history.db", "store_path",
                description="SQLite database file location."),
        EnvSpec("BWMON_PROCESSES_ENABLED", "bool", True, "processes_enabled",
                description="Per-process bandwidth attribution."),
        EnvSpec("BWMON_PROCESS_SCAN_SPACING", "float", 3.0, "process_scan_spacing",
                description="Seconds between process scans (CPU bound)."),
        EnvSpec("BWMON_CONNECTIONS_ENABLED", "bool", True, "connections_enabled",
                description="Enrich dashboard with connection data."),
        EnvSpec("BWMON_CONNECTIONS_LIMIT", "int", 200, "connections_limit",
                description="Max top-processes returned."),
        # include/exclude are consumed in Settings.from_env (attr="").
        EnvSpec("BWMON_INCLUDE", "string", "", "",
                description="Comma-separated interface allowlist."),
        EnvSpec("BWMON_EXCLUDE", "string", "lo", "",
                description="Comma-separated interface denylist."),
        EnvSpec("BWMON_LOG_LEVEL", "enum", "INFO", "log_level",
                choices=frozenset(_LOG_LEVELS),
                description="Logging verbosity."),
        EnvSpec("BWMON_STRICT_PORT", "bool", False, "strict_port",
                description="True: fail on busy port instead of fallback."),
        EnvSpec("BWMON_OPEN_BROWSER", "bool", False, "open_browser",
                description="Open the dashboard URL at startup."),
        EnvSpec("BWMON_ALERT_UPLOAD_BPS", "float", 100 * 1024 * 1024,
                "alert_upload_bps", description="Upload alert threshold (bit/s)."),
        EnvSpec("BWMON_ALERT_DOWNLOAD_BPS", "float", 100 * 1024 * 1024,
                "alert_download_bps", description="Download alert threshold (bit/s)."),
        EnvSpec("BWMON_ALERT_COOLDOWN_SECONDS", "float", 60.0,
                "alert_cooldown_seconds",
                description="Seconds between re-alerts for same event."),
    )
}


def _get(key: str):
    """Read ``key`` from the environment, parsed per its EnvSpec kind.

    Falls back to the declared default (with a warning log) when the raw
    value is missing or malformed, so a bad value can never crash startup.
    """
    spec = ENV_SCHEMA[key]
    raw = os.environ.get(key)
    if raw is None or raw.strip() == "":
        return _default_value(key, spec)
    try:
        return spec.parse(raw)
    except ValueError as exc:
        logger.warning("Ignoring malformed %s (%s); using default %r.", key, exc, spec.default)
        return _default_value(key, spec)


def _default_value(key: str, spec: EnvSpec):
    """Parse an EnvSpec default; a schema bug must not crash startup."""
    try:
        return spec.parse(str(spec.default))
    except ValueError:  # pragma: no cover - schema drift is caught by tests
        logger.error("ENV_SCHEMA default for %s is invalid: %r", key, spec.default)
        return spec.default


def _load_dotenv(path: Optional[Path] = None) -> Optional[Path]:
    """Load KEY=VALUE pairs from a ``.env`` file into ``os.environ``.

    - Variables already present in the real environment are never touched,
      so shell/exported configuration keeps precedence over the file.
    - Blank lines and ``#`` comments are ignored; ``export KEY=VALUE`` and
      single/double-quoted values are accepted; malformed lines are skipped.
    - Returns the path when a file was read, ``None`` otherwise.
    """
    env_path = path if path is not None else Path(__file__).resolve().parent.parent / ".env"
    if not env_path.is_file():
        return None
    try:
        text = env_path.read_text(encoding="utf-8")
    except OSError:
        return None

    for raw in text.splitlines():
        key, value = _parse_env_line(raw)
        if key is None:
            continue
        if key in os.environ:  # real environment always wins
            continue
        os.environ[key] = value
    return env_path


def _parse_env_line(raw: str) -> tuple[Optional[str], str]:
    """Parse one .env line → ``(key, value)``.

    Returns ``(None, "")`` for blank lines, comments, and lines the loader
    must skip (missing ``=`` or a key that violates ``_KEY_RE``).
    """
    line = raw.strip()
    if not line or line.startswith("#"):
        return None, ""
    if line.startswith("export "):
        line = line[len("export "):].strip()
    if "=" not in line:
        return None, ""
    key, _, value = line.partition("=")
    key = key.strip()
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        value = value[1:-1]
    if not key or not _KEY_RE.match(key):
        return None, ""
    return key, value


# ------------------------------------------------------------- .env validation
def collect_env_problems(text: str) -> list[str]:
    """Validate a ``.env`` payload; return human-readable problems (empty = OK).

    The loader itself never raises (silent skip / silent default), so this
    is the guardrail: it flags lines the loader would silently drop and
    values that would silently fall back to defaults.
    """
    problems: list[str] = []

    # Layer 1: structural — BWMON-ish lines the loader would silently skip.
    for lineno, raw in enumerate(text.splitlines(), start=1):
        key, _ = _parse_env_line(raw)
        stripped = raw.strip()
        if key is None and stripped and not stripped.startswith("#") and "BWMON" in stripped.split("=")[0]:
            problems.append(
                f"line {lineno}: malformed BWMON_* entry "
                f"(silently skipped by the loader): {stripped!r}"
            )

    # Layer 2: typed — every value parsed the way Settings would consume it.
    loaded: dict[str, str] = {}
    for raw in text.splitlines():
        key, value = _parse_env_line(raw)
        if key is not None and key.startswith("BWMON_"):
            loaded[key] = value
    for key, value in loaded.items():
        spec = ENV_SCHEMA.get(key)
        if spec is None:
            problems.append(f"{key}: unknown BWMON_ setting (typo? register it in config/settings.py ENV_SCHEMA)")
            continue
        try:
            spec.parse(value)
        except ValueError as exc:
            problems.append(f"{key}: {exc} (would silently fall back to the default)")
    return problems


def warn_on_env_problems(path: Optional[Path] = None) -> list[str]:
    """Log a warning for each problem found in the project-root ``.env``.

    Called once at startup (after logging is configured). Never raises.
    """
    env_path = path if path is not None else Path(__file__).resolve().parent.parent / ".env"
    if not env_path.is_file():
        return []
    try:
        text = env_path.read_text(encoding="utf-8")
    except OSError:
        return []
    problems = collect_env_problems(text)
    for problem in problems:
        logger.warning(".env: %s", problem)
    return problems


# ------------------------------------------------------------------ settings
@dataclass(frozen=True)
class AlertPolicy:
    """Threshold based alerting, expressed in bits per second."""

    upload_bps: float
    download_bps: float
    cooldown_seconds: float
    enabled: bool


@dataclass(frozen=True)
class Settings:
    host: str = field(default_factory=lambda: _get("BWMON_HOST"))
    port: int = field(default_factory=lambda: _get("BWMON_PORT"))
    refresh_interval: float = field(default_factory=lambda: _get("BWMON_REFRESH_INTERVAL"))
    history_capacity: int = field(default_factory=lambda: _get("BWMON_HISTORY_CAPACITY"))
    store_backend: str = field(default_factory=lambda: _get("BWMON_STORE_BACKEND"))
    store_path: str = field(default_factory=lambda: _get("BWMON_STORE_PATH"))
    processes_enabled: bool = field(default_factory=lambda: _get("BWMON_PROCESSES_ENABLED"))
    process_scan_spacing: float = field(default_factory=lambda: _get("BWMON_PROCESS_SCAN_SPACING"))
    connections_enabled: bool = field(default_factory=lambda: _get("BWMON_CONNECTIONS_ENABLED"))
    connections_limit: int = field(default_factory=lambda: _get("BWMON_CONNECTIONS_LIMIT"))
    include_interfaces: List[str] = field(default_factory=list)
    exclude_interfaces: List[str] = field(default_factory=lambda: ["lo"])
    log_level: str = field(default_factory=lambda: _get("BWMON_LOG_LEVEL"))
    strict_port: bool = field(default_factory=lambda: _get("BWMON_STRICT_PORT"))
    open_browser: bool = field(default_factory=lambda: _get("BWMON_OPEN_BROWSER"))
    alert_upload_bps: float = field(default_factory=lambda: _get("BWMON_ALERT_UPLOAD_BPS"))
    alert_download_bps: float = field(default_factory=lambda: _get("BWMON_ALERT_DOWNLOAD_BPS"))
    alert_cooldown_seconds: float = field(default_factory=lambda: _get("BWMON_ALERT_COOLDOWN_SECONDS"))

    version: str = "1.0.0"

    @property
    def alert_policy(self) -> AlertPolicy:
        return AlertPolicy(
            upload_bps=self.alert_upload_bps,
            download_bps=self.alert_download_bps,
            cooldown_seconds=self.alert_cooldown_seconds,
            enabled=True,
        )

    def interface_enabled(self, name: str) -> bool:
        if self.include_interfaces and name not in self.include_interfaces:
            return False
        return name not in self.exclude_interfaces

    @staticmethod
    def from_env() -> "Settings":
        # Separation from merge logic keeps the dataclass frozen/simple.
        parts = os.environ.get("BWMON_INCLUDE", "")
        excludes = os.environ.get("BWMON_EXCLUDE", "lo")
        return Settings(
            include_interfaces=[p.strip() for p in parts.split(",") if p.strip()],
            exclude_interfaces=[p.strip() for p in excludes.split(",") if p.strip()],
        )

    def resolve_store(self):
        """Factory for the configured SnapshotStore backend.

        Lives on Settings (rather than main.py) so tests and alternative
        entry points share one canonical wiring path.
        """
        if self.store_backend.strip().lower() == "sqlite":
            from infrastructure.storage.sqlite_store import SqliteSnapshotStore

            return SqliteSnapshotStore(path=self.store_path, capacity=self.history_capacity)
        from infrastructure.storage.ring_buffer import RingBufferSnapshotStore

        return RingBufferSnapshotStore(capacity=self.history_capacity)


def load_settings() -> Settings:
    """Return the effective runtime settings for the process.

    Loads ``.env`` (if present) first so file-based overrides apply exactly
    like environment variables — while real environment variables keep
    precedence over file entries.
    """
    _load_dotenv()
    return Settings.from_env()
