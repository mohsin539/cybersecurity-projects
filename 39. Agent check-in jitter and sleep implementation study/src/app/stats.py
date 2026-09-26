"""Statistical tests (scipy-free, numpy-only) for arm-vs-arm comparisons.

Implements the study's inference toolkit:
  * Mann-Whitney U (normal approximation with tie correction)
  * Welch's t-test (Satterthwaite df)
  * Hedges' g bias-corrected effect size
  * bootstrap confidence intervals
Deterministic given the same inputs + seeded bootstrap rng.
"""
from __future__ import annotations

import math

import numpy as np

TWO_SIDED_ALPHA = 0.05


def _normal_cdf(z: float) -> float:
    return 0.5 * (1.0 + math.erf(z / math.sqrt(2.0)))


def mann_whitney_u(a: np.ndarray, b: np.ndarray) -> dict[str, float]:
    """Two-sided Mann-Whitney U with normal approximation (n >= 20 total)."""
    a = np.asarray(a, dtype=np.float64)
    b = np.asarray(b, dtype=np.float64)
    na, nb = a.size, b.size
    if na == 0 or nb == 0:
        return {"u": float("nan"), "p": float("nan"), "z": float("nan")}
    both = np.concatenate([a, b])
    order = both.argsort(kind="mergesort")
    ranks = np.empty_like(both, dtype=np.float64)
    ranks[order] = np.arange(1, both.size + 1, dtype=np.float64)

    # tie correction: average ranks within equal groups
    _, inv, counts = np.unique(both[order], return_inverse=True, return_counts=True)
    sums = np.bincount(inv, weights=ranks).astype(np.float64)
    avg = sums / counts
    ranks = avg[inv]

    ra = ranks[:na].sum()
    u = ra - na * (na + 1) / 2.0
    u = min(u, na * nb - u)  # two-sided statistic
    mu = na * nb / 2.0
    ties = np.sum(counts**3 - counts)
    var = (na * nb / 12.0) * (na + nb + 1 - ties / ((na + nb) * (na + nb - 1)))
    if var <= 0:
        return {"u": float(u), "p": 1.0, "z": 0.0}
    z = (u - mu) / math.sqrt(var) if var else 0.0
    p = min(1.0, 2.0 * (1.0 - _normal_cdf(abs(z))))
    return {"u": float(u), "z": float(z), "p": float(p)}


def welch_t(a: np.ndarray, b: np.ndarray) -> dict[str, float]:
    a = np.asarray(a, dtype=np.float64)
    b = np.asarray(b, dtype=np.float64)
    na, nb = a.size, b.size
    va, vb = float(a.var(ddof=1)), float(b.var(ddof=1))
    ma, mb = float(a.mean()), float(b.mean())
    sva, svb = va / na, vb / nb
    se2 = sva + svb
    if se2 <= 0.0:
        # degenerate: zero within-arm variance (e.g. constant arrays)
        d = 1.0 if ma != mb else 0.0
        return {"t": float("inf") if d else 0.0, "df": float("inf"), "p": 0.0 if d else 1.0}
    t = (ma - mb) / math.sqrt(se2)
    df = se2 * se2 / (sva * sva / (na - 1) + svb * svb / (nb - 1))
    p = 2.0 * (1.0 - _t_cdf_approx(abs(t), df))
    return {"t": float(t), "df": float(df), "p": float(p)}


def _t_cdf_approx(t: float, df: float) -> float:
    """Student-t survival via the normal-pearson approximation; accurate enough."""
    if df > 1e6:
        return _normal_cdf(t)
    x = df / (df + t * t)
    # Abramowitz-Stegun 26.7.3 approx for the t distribution CDF is complex;
    # use the well-known normal approximation with variance correction.
    z = t * (1 - 1.0 / (4.0 * df)) / math.sqrt(1 + t * t / (2.0 * df))
    return _normal_cdf(z)


def hedges_g(a: np.ndarray, b: np.ndarray) -> dict[str, float]:
    a = np.asarray(a, dtype=np.float64)
    b = np.asarray(b, dtype=np.float64)
    na, nb = a.size, b.size
    sp = math.sqrt(((na - 1) * float(a.var(ddof=1)) + (nb - 1) * float(b.var(ddof=1))) / (na + nb - 2))
    if sp <= 0:
        return {"g": 0.0, "interpretation": "negligible"}
    g = (float(a.mean()) - float(b.mean())) / sp
    # bias correction (Hedges)
    df = na + nb - 2
    J = math.exp(
        math.lgamma(df / 2.0) - math.lgamma((df - 1) / 2.0) - 0.5 * math.log(df / 2.0)
    ) * ((df - 1) / 2.0) if df > 1 else 1.0
    g = g * J
    interp = "negligible"
    if abs(g) >= 0.8:
        interp = "large"
    elif abs(g) >= 0.5:
        interp = "medium"
    elif abs(g) >= 0.2:
        interp = "small"
    return {"g": float(g), "interpretation": interp}


def bootstrap_ci(
    values: np.ndarray,
    stat_fn,
    n_boot: int = 2000,
    rng: np.random.Generator | None = None,
) -> tuple[float, float]:
    """Percentile bootstrap 95% CI of `stat_fn` over `values`."""
    rng = rng or np.random.default_rng(0)
    values = np.asarray(values, dtype=np.float64)
    if values.size == 0:
        return (float("nan"), float("nan"))
    idx = rng.integers(0, values.size, size=(n_boot, values.size))
    stats = np.array([stat_fn(v) for v in values[idx]], dtype=np.float64)
    return (float(np.percentile(stats, 2.5)), float(np.percentile(stats, 97.5)))


def bonferroni_correct(p_vals: list[float]) -> list[float]:
    k = max(len(p_vals), 1)
    return [min(1.0, p * k) for p in p_vals]