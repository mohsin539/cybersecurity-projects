from __future__ import annotations

import numpy as np

from src.app.stats import hedges_g, mann_whitney_u, welch_t


def test_mann_whitney_p_range():
    a = np.random.default_rng(0).normal(0, 1, 300)
    b = np.random.default_rng(0).normal(0.3, 1, 300)
    r = mann_whitney_u(a, b)
    assert 0.0 <= r["p"] <= 1.0
    swapped = mann_whitney_u(b, a)
    assert abs(r["p"] - swapped["p"]) < 1e-9


def test_mann_whitney_identical_means():
    a = np.random.default_rng(1).normal(5, 1, 200)
    b = np.random.default_rng(2).normal(5, 1, 200)
    assert mann_whitney_u(a, b)["p"] > 0.05


def test_welch_p_range():
    r = welch_t(np.ones(50), np.zeros(50))
    assert r["p"] < 0.05
    assert mann_whitney_u(np.ones(50), np.zeros(50))["p"] < 0.05


def test_hedges_zero_for_identical():
    x = np.arange(10.0)
    assert abs(hedges_g(x, x)["g"]) < 1e-6
    assert hedges_g(x, x)["interpretation"] == "negligible"