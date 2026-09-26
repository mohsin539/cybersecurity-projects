"""Sleep schedulers - decide how long an agent sleeps after a completed check-in.

``load_factor``: normalised server pressure last window (0=idle..1=saturation);
``cycle``: zero-based check-in counter for that agent (used by backoff modes).
"""
from __future__ import annotations

import numpy as np

from src.config import SleepMode

MODES = ("fixed", "random", "adaptive", "burst")


def next_sleep(
    mode: SleepMode,
    base_sec: float,
    rng: np.random.Generator,
    cycle: int,
    load_factor: float = 0.0,
) -> float:
    """Return the sleep duration before the next wake, in seconds."""
    base = max(float(base_sec), 0.0)
    if mode == "fixed":
        return base
    if mode == "random":
        return base * float(rng.uniform(0.5, 1.5))
    if mode == "adaptive":
        # extend sleep under server pressure -> backpressure-friendly
        return base * (1.0 + 0.75 * min(float(load_factor), 1.0))
    if mode == "burst":
        # stepped growth for stress-testing retry behaviour (capped at 8x)
        growth = min(float(cycle), 8.0)
        return base * (1.0 + 0.5 * growth)
    raise ValueError(f"unknown sleep mode {mode!r}")