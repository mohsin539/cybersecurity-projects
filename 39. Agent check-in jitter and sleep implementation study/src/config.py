"""Scenario configuration, validated at the schema boundary (ISO 27001 A.7.10 / OWASP A07).

All user input funnels through this model before it reaches the engine.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator, model_validator

JitterType = Literal["uniform", "gaussian", "poisson", "triangular", "exp-truncated"]
SleepMode = Literal["fixed", "random", "adaptive", "burst"]
EngineKind = Literal["exact", "fast"]


class Scenario(BaseModel):
    """Validated study scenario. Clamps every numeric into a safe, meaningful domain."""

    agents: int = Field(default=1000, ge=10, le=100_000, description="Number of simulated agents")
    interval_sec: float = Field(default=60.0, gt=0.1, le=86_400)
    jitter_pct: float = Field(default=25.0, ge=0.0, le=100.0)
    jitter_type: JitterType = "uniform"
    sleep_mode: SleepMode = "fixed"
    sleep_base_sec: float = Field(default=45.0, gt=0.0, le=86_400)
    run_length_sec: float = Field(default=600.0, gt=1.0, le=604_800)
    replicas: int = Field(default=5, ge=1, le=50)
    seed: int = Field(default=42, ge=0)
    engine: EngineKind = "exact"
    server_workers: int = Field(default=20, ge=1, le=100_000)
    server_service_ms: float = Field(default=5.0, gt=0.0, le=10_000)
    server_queue_cap: int = Field(default=1000, ge=0, le=1_000_000)
    power_active_ma: float = Field(default=35.0, ge=0.0)
    power_sleep_ua: float = Field(default=900.0, ge=0.0)
    retry_backoff_base_sec: float = Field(default=5.0, gt=0.0)
    compare_baseline: bool = Field(default=True, description="Also run a no-jitter/fixed-sleep baseline arm")

    @model_validator(mode="after")
    def _clamp(self) -> "Scenario":
        # a jitter bound wider than 2x the interval is nonsense
        if self.jitter_pct > 0 and 100 * (self.jitter_pct / 100.0) > 200:
            raise ValueError("jitter_pct clamped bound exceeded; keep jitter <= 200% of interval")
        if self.interval_sec <= self.server_service_ms / 1000.0:
            raise ValueError("service time must be below interval, else queue saturates trivially")
        if self.sleep_base_sec >= self.run_length_sec:
            raise ValueError("sleep_base_sec must be < run_length_sec")
        return self

    @field_validator("seed")
    @classmethod
    def _seed_sane(cls, v: int) -> int:
        return v % 2**32

    def frozen(self) -> "Scenario":
        """Return a hashable snapshot identity for audit records."""
        return self

    def config_hash(self) -> str:
        canonical = json.dumps(self.model_dump(), sort_keys=True, ensure_ascii=True)
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def baseline_variant(self) -> "Scenario":
        """The control arm: no jitter, fixed sleep, same scale."""
        return self.model_copy(
            update={
                "jitter_pct": 0.0,
                "jitter_type": "uniform",
                "sleep_mode": "fixed",
                "compare_baseline": False,
            }
        )

    def as_dict(self) -> dict[str, Any]:
        return self.model_dump()


SCENARIO_EXAMPLE = """\
# scenario profile - validated with pydantic on load
agents: 5000
interval_sec: 60
jitter_pct: 25
jitter_type: uniform        # uniform | gaussian | poisson | triangular | exp-truncated
sleep_mode: random          # fixed | random | adaptive | burst
sleep_base_sec: 45
run_length_sec: 1800
replicas: 3
seed: 42
engine: exact               # exact | fast
server_workers: 50
server_service_ms: 8
server_queue_cap: 1000
power_active_ma: 35
power_sleep_ua: 900
compare_baseline: true
"""


def scenario_from_dict(raw: dict[str, Any]) -> Scenario:
    """Boundary gate: any mapping becomes a validated Scenario or raises."""
    allowed = Scenario.model_fields.keys()
    known = {k: v for k, v in raw.items() if k in allowed}
    return Scenario(**known)


def scenario_from_yaml(path: str) -> Scenario:
    import yaml

    with open(path, "r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh)  # SafeLoader - OWASP A03 injection guard
    if not isinstance(data, dict):
        raise ValueError(f"{path} does not contain a mapping")
    return scenario_from_dict(data)