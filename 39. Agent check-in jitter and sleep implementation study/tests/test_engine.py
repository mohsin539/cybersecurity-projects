from __future__ import annotations

import numpy as np
import pytest

from src.config import Scenario
from src.engine.jitter import sample_jitter
from src.engine.simulator import run_engine


def test_jitter_deterministic():
    a = sample_jitter("uniform", np.random.default_rng(7), 1000, 10.0)
    b = sample_jitter("uniform", np.random.default_rng(7), 1000, 10.0)
    assert np.array_equal(a, b)


def test_jitter_within_bound():
    for kind in ("uniform", "gaussian", "poisson", "triangular", "exp-truncated"):
        off = sample_jitter(kind, np.random.default_rng(1), 5000, 5.0)
        assert np.isfinite(off).all(), kind
        assert np.percentile(np.abs(off), 99.9) <= 5.0 + 1e-6, kind
        assert np.abs(off).max() <= 4.0 * 5.0, kind


def test_config_rejects_bad_values():
    with pytest.raises(Exception):
        Scenario(agents=5)
    with pytest.raises(Exception):
        Scenario(agents=1000, server_service_ms=120000, interval_sec=60)
    with pytest.raises(Exception):
        Scenario(agents=1000, sleep_base_sec=500000, run_length_sec=60)


def test_config_hash_stable():
    s1 = Scenario(agents=500, seed=1)
    s2 = Scenario(agents=500, seed=1)
    assert s1.config_hash() == s2.config_hash()
    assert s1.baseline_variant().jitter_pct == 0.0


def test_exact_engine_deterministic():
    sc = Scenario(agents=60, interval_sec=10, jitter_pct=40, sleep_mode="random",
                  sleep_base_sec=6, run_length_sec=120, seed=5, replicas=1)
    r1 = run_engine(sc, np.random.default_rng(5))
    r2 = run_engine(sc, np.random.default_rng(5))
    assert np.array_equal(r1.buckets, r2.buckets)
    assert r1.latencies == r2.latencies
    assert r1.arrivals_total == r2.arrivals_total


def test_jitter_lowers_herd():
    base = Scenario(agents=400, interval_sec=10, jitter_pct=0, sleep_mode="fixed",
                    run_length_sec=300, seed=11, engine="fast")
    jit = Scenario(agents=400, interval_sec=10, jitter_pct=60, sleep_mode="fixed",
                   run_length_sec=300, seed=11, engine="fast")
    ob = run_engine(base, np.random.default_rng(11))
    oj = run_engine(jit, np.random.default_rng(11))
    herd_b, herd_j = ob.buckets.max() / ob.buckets.mean(), oj.buckets.max() / oj.buckets.mean()
    assert herd_j < herd_b, (herd_b, herd_j)


def test_fast_engine_schedule():
    sc = Scenario(agents=50, interval_sec=5, jitter_pct=0, run_length_sec=100,
                  seed=1, engine="fast")
    out = run_engine(sc, np.random.default_rng(1))
    expected = (100 // 5 + 1) * 50  # t = 0, 5, ..., 100
    assert out.arrivals_total == expected
    assert out.buckets.sum() == expected