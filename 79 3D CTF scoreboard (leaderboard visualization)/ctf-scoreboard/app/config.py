"""Runtime configuration for the CTF scoreboard service.

Every value can be overridden with an environment variable so the same image can
run as a local demo or as the production topology described in
``architecture.md``. Secrets have no usable default: the service refuses to start
with a development secret outside development mode (SEC-IAM-01 / DL-01).
"""

from __future__ import annotations

import os
import secrets
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
WEB_DIR = BASE_DIR / "web"
DATA_DIR = BASE_DIR / "data"


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    try:
        return int(raw)
    except ValueError:
        return default


@dataclass(frozen=True)
class Settings:
    app_name: str = "3D CTF Scoreboard"
    version: str = "1.0.0"
    environment: str = field(default_factory=lambda: os.getenv("SCOREBOARD_ENV", "development"))

    host: str = field(default_factory=lambda: os.getenv("SCOREBOARD_HOST", "127.0.0.1"))
    port: int = field(default_factory=lambda: _env_int("SCOREBOARD_PORT", 8000))
    # Reload is a development convenience. Production runs a single process per
    # host behind the load balancer described in architecture.md, and reloading
    # there would drop in-flight requests, so it is forced off below.
    reload: bool = field(default_factory=lambda: _env_bool("SCOREBOARD_RELOAD", True))
    log_level: str = field(default_factory=lambda: os.getenv("SCOREBOARD_LOG_LEVEL", "info"))

    database_path: Path = field(
        default_factory=lambda: Path(os.getenv("SCOREBOARD_DB", str(DATA_DIR / "scoreboard.db")))
    )

    # Cookie signing key. A random key is generated per process in development so
    # that sessions never survive a restart; production must supply a real secret.
    secret_key: str = field(default_factory=lambda: os.getenv("SCOREBOARD_SECRET", ""))
    session_ttl_seconds: int = field(default_factory=lambda: _env_int("SCOREBOARD_SESSION_TTL", 8 * 3600))
    cookie_secure: bool = field(default_factory=lambda: _env_bool("SCOREBOARD_COOKIE_SECURE", False))

    # Webhook trust (SEC-EXT-01..03)
    webhook_secret: str = field(default_factory=lambda: os.getenv("SCOREBOARD_WEBHOOK_SECRET", ""))
    webhook_replay_window_seconds: int = field(
        default_factory=lambda: _env_int("SCOREBOARD_WEBHOOK_WINDOW", 300)
    )

    # Scoring model (state.md section 6 - pure function, no clock, no RNG)
    scoring_model_version: str = field(
        default_factory=lambda: os.getenv("SCOREBOARD_SCORING_MODEL", "scoring-v1.2.0")
    )
    score_decay_per_hour: float = field(
        default_factory=lambda: float(os.getenv("SCOREBOARD_DECAY_PER_HOUR", "0.02"))
    )
    decay_floor_ratio: float = field(
        default_factory=lambda: float(os.getenv("SCOREBOARD_DECAY_FLOOR", "0.4"))
    )
    challenge_base_points: int = field(
        default_factory=lambda: _env_int("SCOREBOARD_CHALLENGE_POINTS", 100)
    )
    first_blood_bonus: int = field(default_factory=lambda: _env_int("SCOREBOARD_FIRST_BLOOD", 50))
    top10_bonus: int = field(default_factory=lambda: _env_int("SCOREBOARD_TOP10_BONUS", 25))

    # Purifier window: decay is frozen for this long after the last solve so that
    # a replay of the same event log is guaranteed to be deterministic.
    purifier_window_seconds: int = field(
        default_factory=lambda: _env_int("SCOREBOARD_PURIFIER_WINDOW", 1800)
    )

    # Merkle sealing (SEC-AUD-05): batch size or age, whichever comes first.
    seal_batch_size: int = field(default_factory=lambda: _env_int("SCOREBOARD_SEAL_BATCH", 250))
    seal_interval_seconds: int = field(default_factory=lambda: _env_int("SCOREBOARD_SEAL_INTERVAL", 300))

    # SSE
    sse_heartbeat_seconds: int = field(default_factory=lambda: _env_int("SCOREBOARD_SSE_HEARTBEAT", 15))
    sse_replay_buffer: int = field(default_factory=lambda: _env_int("SCOREBOARD_SSE_REPLAY", 500))

    # Read-your-writes budget for the acting admin (state.md section 11.3)
    rww_tolerance_seconds: int = field(default_factory=lambda: _env_int("SCOREBOARD_RWW_TOLERANCE", 3))

    # Demo seeding
    seed_on_startup: bool = field(default_factory=lambda: _env_bool("SCOREBOARD_SEED", True))
    seed_teams: int = field(default_factory=lambda: _env_int("SCOREBOARD_SEED_TEAMS", 24))
    seed_challenges: int = field(default_factory=lambda: _env_int("SCOREBOARD_SEED_CHALLENGES", 12))
    seed_solve_rate_per_second: float = field(
        default_factory=lambda: float(os.getenv("SCOREBOARD_SEED_RATE", "0.9"))
    )
    simulator_enabled: bool = field(default_factory=lambda: _env_bool("SCOREBOARD_SIMULATE", True))

    def __post_init__(self) -> None:
        # Enforced here rather than in a default factory so it holds however the
        # settings were built, including Settings(environment="production").
        if self.is_production:
            if self.reload:
                object.__setattr__(self, "reload", False)
            object.__setattr__(self, "cookie_secure", True)

    def resolved_secret(self) -> str:
        if self.secret_key:
            return self.secret_key
        if self.is_production:
            raise RuntimeError(
                "SCOREBOARD_SECRET must be set in production; refusing to sign sessions "
                "with an ephemeral development key (SEC-IAM-01)."
            )
        return secrets.token_urlsafe(48)

    def resolved_webhook_secret(self) -> str:
        if self.webhook_secret:
            return self.webhook_secret
        if self.is_production:
            raise RuntimeError("SCOREBOARD_WEBHOOK_SECRET must be set in production (SEC-EXT-01).")
        return "dev-webhook-secret-change-me"

    @property
    def is_production(self) -> bool:
        return self.environment.lower() in {"production", "prod"}

    @property
    def debug(self) -> bool:
        return not self.is_production


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
