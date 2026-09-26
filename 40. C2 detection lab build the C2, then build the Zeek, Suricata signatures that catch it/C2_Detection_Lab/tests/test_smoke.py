"""Smoke tests - quick full-lab checks (pytest)."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.config import LabConfig  # noqa: E402
from core.lab_runner import LabRunner  # noqa: E402
from detectors.suricata import generate_suricata  # noqa: E402
from detectors.zeek import generate_zeek  # noqa: E402


def test_config_validation():
    good = LabConfig(beacon_interval=5.0, jitter_pct=20, run_duration=6)
    assert good.validate() == []

    bad = LabConfig(beacon_interval=9999, jitter_pct=999)
    assert bad.validate()


def test_signature_generation(tmp_path):
    z = generate_zeek(tmp_path / "sig", 5.0)
    s = generate_suricata(tmp_path / "sig")
    assert z.exists() and s.exists()
    assert "content:\"|00 7f|\"" in s.read_text(encoding="utf-8")
    assert "Beaconing::Periodic" in z.read_text(encoding="utf-8")


def test_full_headless_lab(tmp_path):
    cfg = LabConfig(beacon_interval=0.5, jitter_pct=25, agent_count=2,
                    run_duration=5, benign_rate=3.0, outdir=str(tmp_path))
    runner = LabRunner(cfg)
    result = runner.run()
    m = result["metrics"]
    assert m["c2_events"] >= 1
    assert m["alerts"] >= 1
    assert m["precision"] > 0
    assert m["recall"] > 0
    assert result["signatures"]["zeek"]
    assert (tmp_path / "evidence" / "audit.json").exists()