from __future__ import annotations

import json

import numpy as np

from src.app.orchestrator import run_study, study_verdict
from src.config import Scenario


def test_study_end_to_end(tmp_path):
    sc = Scenario(agents=80, interval_sec=10, jitter_pct=50, sleep_mode="random",
                  sleep_base_sec=5, run_length_sec=200, replicas=2, seed=3,
                  engine="fast", compare_baseline=True)
    result = run_study(sc)
    assert result.baseline is not None
    assert len(result.candidate.outcomes) == 2
    assert len(result.comparisons) >= 3
    assert result.comparisons[0].label
    badge, text = study_verdict(result)
    assert badge in ("PASS", "FAIL", "CAUTION")
    assert text


def test_report_model_json_safe(tmp_path):
    from src.reporting.report_data import build_report_model
    sc = Scenario(agents=40, interval_sec=8, jitter_pct=40, run_length_sec=120,
                  replicas=1, seed=9, engine="fast", compare_baseline=False)
    result = run_study(sc)
    model = build_report_model(result)
    blob = json.dumps(model)  # must not raise (numpy scalars handled)
    assert model["verdict_badge"] == "INFO"
    assert model["buckets"]["candidate"]


def test_exact_and_fast_both_work():
    sc_fast = Scenario(agents=50, interval_sec=10, jitter_pct=40, run_length_sec=120, seed=1, engine="fast")
    sc_exact = sc_fast.model_copy(update={"engine": "exact"})
    out_f = run_study(sc_fast).candidate.mean_kpis
    out_e = run_study(sc_exact).candidate.mean_kpis
    assert out_f["herd_coef"] > 0
    assert out_e["herd_coef"] > 0