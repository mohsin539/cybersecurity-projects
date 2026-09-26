"""KPI computation from a RunOutcome (single-arm, per-bucket statistics)."""
from __future__ import annotations

import math

import numpy as np

from src.config import Scenario
from src.engine.simulator import RunOutcome


def compute_kpis(outcome: RunOutcome, scenario: Scenario) -> dict[str, float]:
    buckets = np.asarray(outcome.buckets, dtype=np.float64)
    mean = float(buckets.mean()) if buckets.size else 0.0
    std = float(buckets.std()) if buckets.size else 0.0
    peak = float(buckets.max()) if buckets.size else 0.0

    herd = peak / mean if mean > 0 else 0.0
    uniformity = 1.0 - (std / mean) if mean > 0 else 0.0

    lat = np.asarray(outcome.latencies, dtype=np.float64)
    p50 = float(np.percentile(lat, 50)) if lat.size else 0.0
    p99 = float(np.percentile(lat, 99)) if lat.size else 0.0
    p999 = float(np.percentile(lat, 99.9)) if lat.size else 0.0

    run_h = scenario.run_length_sec / 3600.0
    active_h = outcome.duty * run_h
    mAh = active_h * scenario.power_active_ma
    mAh += (run_h - active_h) * (scenario.power_sleep_ua / 1000.0)  # uA -> mA

    attempts = outcome.arrivals_total or 0
    dropped_rate = float(outcome.dropped_total) / attempts if attempts else 0.0

    per_agent_h2 = 3600.0 / max(scenario.interval_sec, 1e-9)
    if scenario.sleep_base_sec > 0 and scenario.sleep_mode != "burst":
        per_agent_h2 = 3600.0 / max(scenario.interval_sec + scenario.sleep_base_sec, 1e-9)
    bytes_day_estimate = attempts * 512.0

    return {
        "peak_bucket": peak,
        "mean_bucket": mean,
        "std_bucket": std,
        "herd_coef": herd,
        "uniformity": uniformity,
        "latency_p50_ms": p50 * 1000.0,
        "latency_p99_ms": p99 * 1000.0,
        "latency_p99ms": p999 * 1000.0,
        "duty_cycle": outcome.duty,
        "power_mah": mAh,
        "dropped_rate": dropped_rate,
        "dropped_total": float(outcome.dropped_total),
        "attempts": float(attempts),
        "checkins_per_agent_h": per_agent_h2,
        "bytes_estimate": bytes_day_estimate,
        "engine_wall_s": outcome.elapsed_wall,
    }


KPI_LABELS: dict[str, str] = {
    "herd_coef": "Herd coefficient (peak/mean)",
    "uniformity": "Uniformity (1 - std/mean)",
    "latency_p50_ms": "Latency p50 (ms)",
    "latency_p99_ms": "Latency p99 (ms)",
    "latency_p99ms": "Latency p99.9 (ms)",
    "duty_cycle": "Duty cycle (awake %)",
    "power_mah": "Power draw (mAh/day-agent)",
    "dropped_rate": "Drop rate (%)",
    "attempts": "Check-in attempts",
    "bytes_estimate": "Net bytes (est.)",
    "engine_wall_s": "Sim wall time (s)",
}


def tentry(v: float, kind: str | None = None) -> str:
    if kind == "pct":
        return f"{v * 100.0:.2f}%"
    if kind == "ratio":
        return f"{v:.4f}"
    if kind == "ms":
        return f"{v:.3f} ms"
    if math.isnan(v):
        return "n/a"
    return f"{v:,.2f}"