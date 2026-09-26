"""Study orchestrator: runs scenario arms (candidate +/- baseline), aggregates
KPIs across replicates, and produces a statistical comparison verdict.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

import numpy as np

from src.app.metrics import compute_kpis
from src.app.stats import (
    bonferroni_correct,
    hedges_g,
    mann_whitney_u,
    welch_t,
)
from src.config import Scenario
from src.engine.rng import SeedRegistry
from src.engine.simulator import RunOutcome, run_engine

Progress = Callable[[float, str], None]


class StudyCancelled(Exception):
    """Raised from a progress callback when the user cancels a study run."""

COMPARE_METRICS = [
    "herd_coef",
    "uniformity",
    "latency_p99ms",
    "dropped_rate",
    "duty_cycle",
    "power_mah",
]
LOWER_BETTER = {"herd_coef", "latency_p99ms", "dropped_rate", "duty_cycle", "power_mah"}
PCT_METRICS = {"uniformity", "dropped_rate", "duty_cycle"}


@dataclass
class ArmResult:
    label: str
    scenario: Scenario
    outcomes: list[RunOutcome] = field(default_factory=list)
    kpis: list[dict[str, float]] = field(default_factory=list)

    @property
    def mean_kpis(self) -> dict[str, float]:
        if not self.kpis:
            return {}
        keys = self.kpis[0].keys()
        return {k: float(np.mean([r[k] for r in self.kpis])) for k in keys}

    @property
    def std_kpis(self) -> dict[str, float]:
        if not self.kpis:
            return {}
        keys = self.kpis[0].keys()
        return {k: float(np.std([r[k] for r in self.kpis])) if len(self.kpis) > 1 else 0.0 for k in keys}


@dataclass
class Comparison:
    metric: str
    candidate_vals: list[float]
    baseline_vals: list[float]
    u_stat: float
    u_p: float
    t_stat: float
    t_p: float
    g: float
    effect: str
    direction: str  # "lower_better" | "higher_better"
    verdict: str
    significant: bool
    relative_delta: float = 0.0  # (cand-mean / base-mean), signed toward candidate

    @property
    def label(self) -> str:
        labels = {
            "herd_coef": "Herd coefficient",
            "uniformity": "Uniformity",
            "latency_p99ms": "Latency p99.9 (ms)",
            "dropped_rate": "Drop rate",
            "duty_cycle": "Duty cycle",
            "power_mah": "Power (mAh)",
        }
        return labels.get(self.metric, self.metric)


@dataclass
class StudyResult:
    scenario: Scenario
    candidate: ArmResult
    baseline: ArmResult | None = None
    comparisons: list[Comparison] = field(default_factory=list)
    seed_registry: SeedRegistry | None = None


def run_arm(scenario: Scenario, label: str, reg: SeedRegistry, rngs: list[np.random.Generator],
            progress: Progress) -> ArmResult:
    arm = ArmResult(label=label, scenario=scenario)
    total = len(rngs)
    for i, rng in enumerate(rngs):
        out = run_engine(scenario, rng, progress=lambda f, m: progress((i + f) / total, f"{label}: {m}"))
        arm.outcomes.append(out)
        arm.kpis.append(compute_kpis(out, scenario))
    return arm


def run_study(scenario: Scenario, progress: Progress | None = None) -> StudyResult:
    """Run the whole study: optional baseline arm + candidate arm + compare."""
    progress = progress or (lambda f, m: None)
    reg = SeedRegistry(master_seed=scenario.seed % 2**32)

    arms: list[tuple[str, Scenario, int]] = [("candidate", scenario, scenario.replicas)]
    n_replicas_total = scenario.replicas
    if scenario.compare_baseline:
        arms.append(("baseline", scenario.baseline_variant(), scenario.replicas))
        n_replicas_total *= 2

    done = 0
    candidate: ArmResult | None = None
    baseline: ArmResult | None = None

    for label, sc, count in arms:
        rngs, reg = _spawn(reg, label, count)
        arm = run_arm(sc, label, reg, rngs, lambda f, m: progress((done + f) / n_replicas_total, m))
        done += 1
        if label == "candidate":
            candidate = arm
        else:
            baseline = arm

    assert candidate is not None
    result = StudyResult(
        scenario=scenario,
        candidate=candidate,
        baseline=baseline,
        seed_registry=reg,
    )
    if baseline is not None:
        result.comparisons = compare_arms(candidate, baseline)
    return result


def _spawn(reg: SeedRegistry, cell: str, count: int) -> tuple[list[np.random.Generator], SeedRegistry]:
    rngs = reg.spawn(cell, count)
    return rngs, reg


def compare_arms(cand: ArmResult, base: ArmResult) -> list[Comparison]:
    comps: list[Comparison] = []
    for metric in COMPARE_METRICS:
        direction = "lower_better" if metric in LOWER_BETTER else "higher_better"

        if metric == "latency_p99ms":
            # strong test: pool every per-arrival latency across replicas
            ca = np.concatenate([np.asarray(o.latencies, dtype=np.float64) for o in cand.outcomes] or [np.array([])])
            ba = np.concatenate([np.asarray(o.latencies, dtype=np.float64) for o in base.outcomes] or [np.array([])])
            cv, bv = [float(o) for o in ca.tolist()], [float(o) for o in ba.tolist()]
        else:
            cv = [r.get(metric, 0.0) for r in cand.kpis]
            bv = [r.get(metric, 0.0) for r in base.kpis]
            ca, ba = np.asarray(cv, dtype=np.float64), np.asarray(bv, dtype=np.float64)

        if ca.size == 0 or ba.size == 0:
            continue
        mw = mann_whitney_u(ca, ba)
        wt = welch_t(ca, ba)
        hg = hedges_g(ca, ba)

        booster = (ca.mean() > ba.mean()) if direction == "higher_better" else (ca.mean() < ba.mean())
        practical = 0.0
        if ba.mean() != 0:
            practical = (ca.mean() - ba.mean()) / abs(ba.mean())
        sig = mw["p"] < 0.05 and abs(hg["g"]) >= 0.2
        improved = booster and (sig or abs(practical) >= 0.25)
        regressed = (not booster) and (sig or abs(practical) >= 0.25)

        if improved and booster:
            verdict = "candidate wins"
        elif regressed and not booster:
            verdict = "baseline wins"
        elif abs(hg["g"]) < 0.2 and abs(practical) < 0.25:
            verdict = "no practical difference"
        else:
            verdict = "inconclusive"
        comps.append(Comparison(
            metric=metric,
            candidate_vals=cv,
            baseline_vals=bv,
            u_stat=mw["u"],
            u_p=mw["p"],
            t_stat=wt["t"],
            t_p=wt["p"],
            g=hg["g"],
            effect=hg["interpretation"],
            direction=direction,
            verdict=verdict,
            significant=sig,
            relative_delta=practical,
        ))
    # Bonferroni correction across tests, applied to verdicts' significance
    ps = [c.u_p for c in comps]
    corrected = bonferroni_correct(ps)
    for c, p_adj in zip(comps, corrected):
        c.u_p = p_adj
        c.significant = c.significant and (p_adj < 0.05)
    return comps


def study_verdict(result: StudyResult) -> tuple[str, str]:
    """Return (badge, text) verdict for the whole study."""
    if result.baseline is None:
        return "INFO", "Single-arm study (no baseline comparison configured)."
    wins = [c for c in result.comparisons if c.verdict == "candidate wins"]
    losses = [c for c in result.comparisons if c.verdict == "baseline wins"]
    weak = [c for c in result.comparisons if c.verdict == "no practical difference"]
    if not result.comparisons:
        return "INFO", "No comparable metrics produced."
    if wins and not losses:
        detail = ", ".join(f"{c.metric} ({c.relative_delta:+.0%})" for c in wins[:4])
        return "PASS", f"Candidate improved {len(wins)} metrics vs no-jitter baseline ({detail})."
    if losses and not wins:
        return "FAIL", "Baseline (no jitter) remained better on tested metrics."
    return "CAUTION", (f"{len(wins)} wins, {len(losses)} losses, {len(weak)} ties; "
                       "check effect sizes and scenario pressure.")