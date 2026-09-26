"""Discrete-event simulator cores.

Two engines share one result schema:

* ``exact`` - full discrete-event simulation. Every agent runs the
  SLEEP -> WAKE -> CHECK-IN(server queue) -> SLEEP lifecycle with
  completion-feedback (latency delays the next sleep, drops trigger
  exponential backoff + jitter). Deterministic for a given seed.
* ``fast`` - vectorised pre-scheduling + fluid single-class queue model.
  Ignores completion feedback; useful for parameter sweeps.
"""
from __future__ import annotations

import heapq
import time
from dataclasses import dataclass
from typing import Callable

import numpy as np

from src.config import Scenario
from src.engine.jitter import sample_jitter
from src.engine.sleep import next_sleep

Progress = Callable[[float, str], None]
NOOP_PROGRESS: Progress = lambda frac, msg: None  # noqa: E731


@dataclass
class RunOutcome:
    """Immutable-ish result bundle produced by either engine."""

    label: str
    config_hash: str
    buckets: np.ndarray  # arrivals per 1s bucket
    latencies: list[float]
    duty: float  # mean fraction of time agents spend awake/checking-in
    arrivals_total: int
    dropped_total: int
    seed: int
    elapsed_wall: float
    engine: str
    agents: int


# ----------------------------------------------------------------- exact DES

def run_exact(scenario: Scenario, rng: np.random.Generator,
              progress: Progress = NOOP_PROGRESS) -> RunOutcome:
    """Arrival-driven DES with completion feedback.

    The simulation only processes at arrival instants, and idle workers are
    tracked with a min-heap of per-worker next-free times. This is exact for
    the model: nothing else changes between arrival events. Queue-overflow
    drops trigger exponential backoff + fresh jitter.
    """
    run_len = float(scenario.run_length_sec)
    service = float(scenario.server_service_ms) / 1000.0
    j_bound = float(scenario.interval_sec) * scenario.jitter_pct / 100.0
    n = scenario.agents
    n_buckets = max(1, int(np.ceil(run_len)))
    buckets = np.zeros(n_buckets, dtype=np.int64)

    max_cycles = max(1, int(np.ceil(run_len / max(float(scenario.interval_sec), 1e-3))) + 4)

    # Precompute per-agent jitter offsets + initial phase (vectorised, seeded).
    # Phase = pure jitter: with jitter_pct=0 every agent wakes at t=0 -- the
    # synchronized thundering-herd baseline.
    jitters: list[np.ndarray] = [
        sample_jitter(scenario.jitter_type, rng, max_cycles, j_bound) for _ in range(n)
    ]
    phase = np.array([float(j[0]) for j in jitters])

    # (wake_time, agent, cycle) - next wake instants
    wake_heap: list[tuple[float, int, int]] = [(float(phase[i]), i, 1) for i in range(n)]
    heapq.heapify(wake_heap)

    # per-worker next-free time; c workers
    free_pool: list[float] = [0.0] * scenario.server_workers
    heapq.heapify(free_pool)
    # bounded FIFO queue of waiting check-ins: (arrival_time, agent, cycle)
    pending: list[tuple[float, int, int]] = []

    latencies: list[float] = []
    dropped = 0
    attempts = 0
    active_total = 0.0
    events = 0
    last_stamp = -1.0

    def _serve(arr_t: float, agent: int, cycle: int) -> float:
        """Claim next free worker and complete `arr_t`; return done-time."""
        nonlocal active_total
        worker_free = heapq.heappop(free_pool)
        start = max(arr_t, worker_free)
        done = start + service * float(rng.uniform(0.5, 1.5))
        heapq.heappush(free_pool, done)
        latencies.append(done - arr_t)
        active_total += done - arr_t
        _schedule_next(done, agent, cycle)
        return done

    def _schedule_next(done_t: float, agent: int, cycle: int) -> None:
        if done_t >= run_len or cycle >= max_cycles:
            return
        load = min(1.0, attempts / max(1.0, run_len * scenario.server_workers * (1.0 / service)))
        sleep_dur = next_sleep(scenario.sleep_mode, scenario.sleep_base_sec, rng, cycle, load)
        off = float(jitters[agent][min(cycle, max_cycles - 1)])
        nxt = done_t + sleep_dur + float(scenario.interval_sec) + off
        if nxt < run_len:
            heapq.heappush(wake_heap, (nxt, agent, cycle + 1))

    def _pump(now: float) -> None:
        """Serve queued check-ins whose workers are idle at time ``now``."""
        while pending and free_pool[0] <= now:
            a, ag, cy = heapq.heappop(pending)
            _serve(a, ag, cy)

    def _report(t: float) -> None:
        nonlocal last_stamp
        if t - last_stamp >= run_len / 20.0:
            last_stamp = t
            progress(min(1.0, t / run_len), f"exact: t={t:,.0f}s events={events:,}")

    while wake_heap:
        t, agent, cycle = heapq.heappop(wake_heap)
        events += 1
        if t >= run_len:
            continue
        _report(t)
        # overdue arrivals (wake before t=0) are realised at the horizon t=0
        arr_t = max(t, 0.0)
        buckets[max(0, min(int(arr_t), n_buckets - 1))] += 1
        attempts += 1

        if free_pool[0] <= arr_t:
            _serve(arr_t, agent, cycle)
        elif len(pending) >= scenario.server_queue_cap:
            dropped += 1
            backoff = scenario.retry_backoff_base_sec * (2 ** min(cycle, 5))
            off = float(jitters[agent][min(cycle, max_cycles - 1)])
            nxt = arr_t + backoff + float(scenario.interval_sec) + off
            if nxt < run_len:
                heapq.heappush(wake_heap, (nxt, agent, cycle + 1))
        else:
            heapq.heappush(pending, (arr_t, agent, cycle))
        _pump(arr_t)

    # fair tail: drain queued arrivals against remaining worker capacity
    while pending:
        a, ag, cy = heapq.heappop(pending)
        done = max(a, free_pool[0]) + service
        heapq.heappop(free_pool)
        heapq.heappush(free_pool, done)
        latencies.append(done - a)
        active_total += done - a
        _schedule_next(done, ag, cy)
    progress(1.0, f"exact: {attempts:,} attempts, {dropped:,} dropped")
    return RunOutcome(
        label="exact",
        config_hash=scenario.config_hash(),
        buckets=buckets,
        latencies=latencies,
        duty=max(0.0, min(1.0, active_total / max(run_len, 1e-9))),
        arrivals_total=attempts,
        dropped_total=dropped,
        seed=scenario.seed,
        elapsed_wall=0.0,
        engine="exact",
        agents=n,
    )


# ----------------------------------------------------------------- fast engine

def run_fast(scenario: Scenario, rng: np.random.Generator,
             progress: Progress = NOOP_PROGRESS) -> RunOutcome:
    """Vectorised pre-scheduled check-ins + fluid M/D/c queue approximation."""
    run_len = float(scenario.run_length_sec)
    inter = max(float(scenario.interval_sec), 1e-3)
    j_bound = inter * scenario.jitter_pct / 100.0
    n = scenario.agents
    n_buckets = max(1, int(np.ceil(run_len)))
    n_cycles = max(1, int(np.ceil(run_len / inter)) + 2)

    phase = sample_jitter(scenario.jitter_type, rng, n, j_bound).reshape(n, 1)
    offs = sample_jitter(scenario.jitter_type, rng, n * n_cycles, j_bound).reshape(n, n_cycles)
    full = np.hstack([phase, offs])
    base = (inter * np.arange(n_cycles + 1, dtype=np.float64))[None, :]
    times = base + np.cumsum(full, axis=1)
    flat = times.flatten()
    flat = flat[(flat >= 0.0) & (flat <= run_len)]
    flat.sort()

    if flat.size:
        idx = np.minimum(flat.astype(np.int64), n_buckets - 1)
        buckets = np.bincount(idx, minlength=n_buckets).astype(np.int64)

        service = float(scenario.server_service_ms) / 1000.0
        c = max(scenario.server_workers, 1)
        svc_eff = service / c
        done = np.empty_like(flat)
        busy = 0.0
        for i, t in enumerate(flat):
            busy = max(t, busy) + svc_eff
            done[i] = busy
        lat = (done - flat).tolist()
        duty = max(0.0, min(1.0, float(np.sum(done - flat)) / max(run_len, 1e-9)))
    else:
        buckets = np.zeros(n_buckets, dtype=np.int64)
        lat = []
        duty = 0.0

    progress(1.0, f"fast: {flat.size:,} check-ins scheduled")
    return RunOutcome(
        label="fast",
        config_hash=scenario.config_hash(),
        buckets=buckets,
        latencies=lat,
        duty=duty,
        arrivals_total=int(flat.size),
        dropped_total=0,
        seed=scenario.seed,
        elapsed_wall=0.0,
        engine="fast",
        agents=n,
    )


def run_engine(scenario: Scenario, rng: np.random.Generator,
               progress: Progress = NOOP_PROGRESS) -> RunOutcome:
    wall = time.perf_counter()
    if scenario.engine == "exact":
        out = run_exact(scenario, rng, progress)
    else:
        out = run_fast(scenario, rng, progress)
    out.elapsed_wall = time.perf_counter() - wall
    return out