"""Aggregator tests — risk model, intel floor/cap, band mapping, determinism."""
from sap.orchestration.aggregator import (
    band_for,
    build_triage_card,
    controls_for,
    next_actions,
)
from sap.rules.heuristics import Finding


def _f(sev: str, rule: str = "SAP-T") -> Finding:
    return Finding(rule_id=rule, title=f"finding {rule} {sev}",
                   severity=sev, category="code-injection")


def test_band_mapping():
    assert band_for(0) == "benign"
    assert band_for(24) == "benign"
    assert band_for(25) == "low"
    assert band_for(49) == "low"
    assert band_for(50) == "suspicious"
    assert band_for(74) == "suspicious"
    assert band_for(75) == "high"
    assert band_for(100) == "high"
    assert band_for(1000) == "high"
    assert band_for(-5) == "high"  # clamped by caller, safe fallback


def test_score_sums_deltas():
    findings = [_f("high"), _f("medium"), _f("low"), _f("info")]
    assert sum(f.score_delta for f in findings) == 30
    assert controls_for(findings)
    assert all(len(c) for c in controls_for(findings))


def test_malicious_floor():
    findings = [_f("low")]
    score = sum(f.score_delta for f in findings)
    assert max(score, 80) == 80
    card = _card(findings, "malicious")
    assert card["risk"]["score"] >= 80
    assert card["risk"]["band"] == "high"


def test_benign_cap():
    findings = [_f("high")]
    score = sum(f.score_delta for f in findings)
    assert score == 15
    card = _card(findings, "benign")
    assert card["risk"]["score"] == 15
    assert card["risk"]["band"] == "benign"


def test_next_actions_intel_malicious():
    findings = [_f("high", "SAP-I-MAL")]
    actions = next_actions(findings, "malicious")
    assert any("Block the file hash" in a for a in actions)


def test_controls_sorted_and_deduped():
    a = Finding("r1", "x", "high", "packing")
    b = Finding("r2", "y", "low", "code-injection")
    cs = controls_for([a, b, a])
    assert cs == sorted(set(cs), key=lambda c: (c.split()[0], c.split()[1]))
    assert "ISO A.8.12" in cs


def _card(findings, intel_highest="unknown") -> dict:
    return build_triage_card(
        sample={"original_name": "a.exe", "size_bytes": 1024, "mz": True},
        digests={"sha256": "0" * 64, "sha1": "1" * 40, "md5": "2" * 32},
        strings={"status": "ok", "ascii_count": 1, "utf16_count": 0,
                 "high_entropy_count": 0, "artifact_counts": {}, "artifacts": [],
                 "suspicious_apis": []},
        pe={"status": "ok", "format": "PE", "backend": "pefile", "machine": "I386",
            "bitness": "PE32", "entry_point": 0x1000, "image_base": "0x400000",
            "subsystem": 2, "timestamp_utc": None, "checksum_ok": True,
            "overlay_size": 0, "sections": [], "imports": [], "anomalies": [],
            "cross_check": {}, "fingerprint": "a" * 16},
        intel={"hits": [], "highest_verdict": intel_highest, "egress_used": 0,
               "cached": False, "sources_consulted": []},
        findings=findings,
        spec={"spec_id": "spec-1", "version": "1.0.0", "bundle_ref": "bundle-r1"},
        bundle_sha="beef" * 16,
        ledger_head="0123" * 16, ledger_events=5,
        started_utc="2026-01-01T00:00:00Z", finished_utc="2026-01-01T00:00:01Z")


def test_card_is_deterministic():
    finds = [_f("high"), _f("medium")]
    c1 = _card(finds, "unknown")
    c2 = _card(list(reversed(finds)), "unknown")
    assert c1["risk"]["score"] == c2["risk"]["score"]
    assert c1["risk"]["band"] == c2["risk"]["band"]
    assert c1["schema"] == "sap.triage_card.v1"
    assert c1["scan"]["status"] == "complete"
    assert c1["audit"]["sealed"] is False
    assert c1["pe_summary"]["entry_point"] == 0x1000
    assert c1["risk"]["top_signals"]