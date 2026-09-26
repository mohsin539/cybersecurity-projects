"""Canonical report model: transforms StudyResult into plain rows consumed by
every writer (xlsx / csv / html / json) - single source of truth.
"""
from __future__ import annotations

import time
import uuid

from src.app.metrics import KPI_LABELS, tentry
from src.app.orchestrator import StudyResult, study_verdict
from src.config import Scenario

_METRIC_KIND = {
    "herd_coef": "ratio",
    "uniformity": "pct",
    "latency_p50_ms": "ms",
    "latency_p99_ms": "ms",
    "latency_p99ms": "ms",
    "dropped_rate": "pct",
    "duty_cycle": "pct",
    "power_mah": "ratio",
}


def build_report_model(result: StudyResult) -> dict:
    run_id = uuid.uuid4().hex[:12]
    stamp = time.strftime("%Y-%m-%d %H:%M:%SZ", time.gmtime())
    badge, verdict_text = study_verdict(result)

    scenario = result.scenario.as_dict()
    cand, base = result.candidate, result.baseline

    summary_rows: list[dict[str, str]] = []
    keys = list(KPI_LABELS.keys())
    cand_mean, base_mean = cand.mean_kpis, (base.mean_kpis if base else {})
    cand_std, base_std = cand.std_kpis, (base.std_kpis if base else {})
    for k in keys:
        if k not in cand_mean:
            continue
        kind = _METRIC_KIND.get(k, "ratio")
        row = {
            "metric": KPI_LABELS.get(k, k),
            "metric_key": k,
            "candidate": tentry(cand_mean[k], kind),
            "candidate_raw": round(cand_mean[k], 6),
            "candidate_std": round(cand_std[k], 4),
        }
        if base_mean:
            row["baseline"] = tentry(base_mean[k], kind)
            row["baseline_raw"] = round(base_mean[k], 6)
            row["baseline_std"] = round(base_std[k], 4)
        summary_rows.append(row)

    replica_rows: list[dict[str, object]] = []
    for arm, label in ((cand, "candidate"), (base, "baseline")):
        if arm is None:
            continue
        for idx, k in enumerate(arm.kpis):
            r = {"arm": label, "replica": idx + 1}
            for group in KPI_LABELS:
                if group in k:
                    r[group] = round(k[group], 6)
            replica_rows.append(r)

    comparison_rows: list[dict[str, object]] = []
    for c in result.comparisons:
        comparison_rows.append({
            "metric": c.label,
            "candidate_mean": round(float(sum(c.candidate_vals)) / max(len(c.candidate_vals), 1), 4),
            "baseline_mean": round(float(sum(c.baseline_vals)) / max(len(c.baseline_vals), 1), 4),
            "u_stat": round(c.u_stat, 3),
            "u_p": f"{c.u_p:.4f}",
            "t_stat": round(c.t_stat, 3),
            "t_p": f"{c.t_p:.4f}",
            "hedges_g": round(c.g, 3),
            "effect": c.effect,
            "direction": c.direction,
            "verdict": c.verdict,
            "significant": "yes" if c.significant else "no",
            "relative_delta": f"{c.relative_delta:+.1%}",
        })

    buckets = {
        "candidate": cand.outcomes[0].buckets.tolist() if cand.outcomes else [],
        "baseline": base.outcomes[0].buckets.tolist() if base and base.outcomes else [],
    }

    model = {
        "run_id": run_id,
        "generated_at": stamp,
        "scenario": scenario,
        "scenario_yaml": _scenario_yaml(result.scenario),
        "config_hash": result.scenario.config_hash(),
        "verdict_badge": badge,
        "verdict_text": verdict_text,
        "summary_rows": summary_rows,
        "replica_rows": replica_rows,
        "comparison_rows": comparison_rows,
        "buckets": buckets,
        "engine": result.scenario.engine,
        "seeds_json": result.seed_registry.to_json() if result.seed_registry else "{}",
    }
    return model


def _scenario_yaml(sc: Scenario) -> str:
    from src.config import SCENARIO_EXAMPLE  # fallback formatting
    lines = []
    for k, v in sc.as_dict().items():
        lines.append(f"{k}: {v}")
    return "\n".join(lines) or SCENARIO_EXAMPLE