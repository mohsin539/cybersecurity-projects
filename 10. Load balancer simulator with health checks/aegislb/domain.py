from __future__ import annotations

from enum import Enum
from dataclasses import dataclass, field
from collections import deque
from typing import Optional


class ProbeType(str, Enum):
    TCP_CONNECT = "TCP_CONNECT"
    HTTP_GET = "HTTP_GET"
    HTTPS_GET = "HTTPS_GET"
    GRPC_HEALTH = "GRPC_HEALTH"


class Policy(str, Enum):
    ROUND_ROBIN = "ROUND_ROBIN"
    WEIGHTED_ROUND_ROBIN = "WEIGHTED_ROUND_ROBIN"
    LEAST_CONNECTIONS = "LEAST_CONNECTIONS"
    LEAST_RESPONSE_TIME = "LEAST_RESPONSE_TIME"
    POWER_OF_TWO_CHOICES = "POWER_OF_TWO_CHOICES"
    RANDOM = "RANDOM"
    IP_HASH = "IP_HASH"
    CONSISTENT_HASH = "CONSISTENT_HASH"


class BackendState(str, Enum):
    BOOTING = "BOOTING"
    HEALTHY = "HEALTHY"
    DEGRADED = "DEGRADED"
    DRAINING = "DRAINING"
    UNHEALTHY = "UNHEALTHY"
    QUARANTINED = "QUARANTINED"
    REMOVED = "REMOVED"


class CircuitState(str, Enum):
    CLOSED = "CLOSED"
    OPEN = "OPEN"
    HALF_OPEN = "HALF_OPEN"


class LatencyModel(str, Enum):
    FIXED = "FIXED"
    EXP = "EXP"
    NORMAL = "NORMAL"
    PARETO = "PARETO"


class FailureProfile(str, Enum):
    NONE = "NONE"
    CRASH = "CRASH"
    LAG = "LAG"
    SLOW_CPU = "SLOW_CPU"
    PROBE_NO_TOKEN = "PROBE_NO_TOKEN"
    FLAP = "FLAP"


class ArrivalModel(str, Enum):
    POISSON = "POISSON"
    CONSTANT = "CONSTANT"
    MMPP = "MMPP"


STATE_INDEX = {
    BackendState.BOOTING: 0,
    BackendState.HEALTHY: 1,
    BackendState.DEGRADED: 2,
    BackendState.DRAINING: 3,
    BackendState.UNHEALTHY: 4,
    BackendState.QUARANTINED: 5,
    BackendState.REMOVED: 6,
}


@dataclass
class HealthSpec:
    probe_type: ProbeType = ProbeType.HTTP_GET
    interval_ms: int = 5000
    timeout_ms: int = 2000
    fail_threshold: int = 3
    pass_threshold: int = 2
    grace_degraded_ms: int = 1500
    jitter_pct: int = 10
    backoff_max_ms: int = 60000
    min_state_hold_ms: int = 2000
    circuit_cooldown_s: float = 10.0
    passive_window: int = 50
    min_passive_samples: int = 10
    error_rate_degrade: float = 0.5
    error_rate_escalate: float = 0.9
    quarantine_threshold: int = 3


@dataclass
class Backend:
    id: str
    name: str
    weight: int = 100
    capacity: int = 1000
    latency_base_ms: int = 40
    latency_model: LatencyModel = LatencyModel.EXP
    severity_error_p: float = 0.005

    state: BackendState = BackendState.BOOTING
    last_state_change: float = 0.0
    active_conns: int = 0
    total_sessions: int = 0
    total_errors: int = 0
    consecutive_fail: int = 0
    consecutive_pass: int = 0
    ewma_ms: float = 40.0

    probes_sent: int = 0
    probes_ok: int = 0
    probes_fail: int = 0
    partial_agreements: int = 0
    last_probe_ok: bool = True
    next_probe_at: float = 0.0
    probe_backoff: float = 1.0

    breaker: CircuitState = CircuitState.CLOSED
    breaker_consecutive_errors: int = 0
    breaker_cooldown_until: float = 0.0
    half_open_trial_used: bool = False

    passive_window: deque = field(default_factory=lambda: deque(maxlen=50))

    failure_profile: FailureProfile = FailureProfile.NONE
    failure_set_at: Optional[float] = None
    slow_start_started: Optional[float] = None
    slow_warmup_s: float = 30.0
    drain_until: Optional[float] = None
    quarantine_count: int = 0

    history: deque = field(default_factory=lambda: deque(maxlen=120))

    def effective_capacity(self, now: float) -> float:
        cap = float(self.capacity)
        if self.failure_profile == FailureProfile.SLOW_CPU:
            cap = max(1.0, cap / 3.0)
        if self.slow_start_started is not None:
            progress = min(1.0, max(0.0, (now - self.slow_start_started) / self.slow_warmup_s))
            cap = max(1.0, cap * (0.2 + 0.8 * progress))
        return cap

    def effective_weight(self, now: float) -> int:
        w = float(self.weight)
        if self.state == BackendState.DEGRADED:
            w = w * 0.5
        if self.slow_start_started is not None:
            progress = min(1.0, max(0.0, (now - self.slow_start_started) / self.slow_warmup_s))
            w = w * (0.2 + 0.8 * progress)
        return max(1, int(w))


@dataclass
class PoolConfig:
    name: str = "default"
    policy: Policy = Policy.LEAST_CONNECTIONS
    health_spec: HealthSpec = field(default_factory=HealthSpec)
    health_sources: int = 2
    warmup_s: float = 30.0
    drain_timeout_s: float = 30.0
    sticky: bool = False