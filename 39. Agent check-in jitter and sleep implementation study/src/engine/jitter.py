"""Jitter samplers - time randomisation that de-synchronises agent fleets.

All samplers take a numpy Generator (deterministic) and a bound ``J`` in seconds
and return ``size`` offsets around 0.
"""
from __future__ import annotations

import numpy as np

from src.config import JitterType

SAMPLERS = ("uniform", "gaussian", "poisson", "triangular", "exp-truncated")


def sample_jitter(kind: JitterType, rng: np.random.Generator, size: int, bound: float) -> np.ndarray:
    """Return `size` jitter offsets (seconds, mean ~0) within approximately ±bound."""
    if size <= 0:
        return np.zeros(0, dtype=np.float64)
    bound = max(float(bound), 0.0)
    if kind == "uniform":
        return rng.uniform(-bound, bound, size=size)
    if kind == "gaussian":
        # ~99.9% of |N(0,sigma)| mass stays within ±bound when sigma = bound/4
        return rng.normal(0.0, bound / 4.0, size=size)
    if kind == "triangular":
        return rng.triangular(-bound, 0.0, bound, size=size)
    if kind == "poisson":
        # exponential inter-arrival, truncated to 2*bound then re-centred to
        # [-bound, +bound] (slotted-ALOHA style, bounded support)
        raw = rng.exponential(scale=bound, size=size)
        raw = np.minimum(raw, 2.0 * bound)
        return raw - bound
    if kind == "exp-truncated":
        raw = rng.exponential(scale=bound, size=size)
        raw = np.minimum(raw, bound)  # truncated support
        sign = rng.integers(0, 2, size=size).astype(np.float64) * 2.0 - 1.0
        return sign * raw
    raise ValueError(f"unknown jitter type {kind!r}")