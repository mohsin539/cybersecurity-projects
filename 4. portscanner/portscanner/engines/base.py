"""Engine base protocol (architecture.md §4.4)."""
from __future__ import annotations

import time
from typing import Protocol, Type

from ..models import Evidence, PortResult, PortState, ProbeJob


class ScanEngine(Protocol):
    name: str

    def probe(self, job: ProbeJob, timeout_s: float) -> PortResult: ...


ENGINE_REGISTRY: dict[str, Type] = {}


def available_engines() -> list[str]:
    return sorted(ENGINE_REGISTRY)


def get_engine(name: str):
    try:
        return ENGINE_REGISTRY[name]()
    except KeyError:
        raise ValueError(
            f"engine {name!r} not available; installed: {', '.join(available_engines())}"
        ) from None


def make_result(
    job: ProbeJob, engine: str, state: PortState,
    rtt_ms: float = 0.0, evidence: Evidence | None = None,
) -> PortResult:
    return PortResult(
        host=job.target.ip,
        hostname=job.target.hostname,
        port=job.port,
        proto=job.proto,
        state=state,
        engine=engine,
        attempt=job.attempt,
        rtt_ms=rtt_ms,
        evidence=evidence or Evidence(),
        ts=time.time(),
    )
