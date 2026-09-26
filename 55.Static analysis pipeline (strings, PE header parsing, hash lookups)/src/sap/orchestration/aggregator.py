"""Triage aggregator — risk model and card assembly (architecture.md §5.4 S7).

Risk model:
- sum of per-finding score deltas (info 0 / low 5 / medium 10 / high 15)
- intel overrides: known-malicious hash  -> floor(score, 80+)
                   known-benign vendor   -> cap(score, <= 20)
- clamp to 0..100 and map to band: benign | low | suspicious | high

Card assembly is deterministic: same sample + same spec => identical JSON.
"""
from __future__ import annotations

import time
import uuid
from typing import Iterable

from sap.rules.heuristics import Finding, CATEGORY_CONTROLS

BANDS = (
    (0, 24, "benign"),
    (25, 49, "low"),
    (50, 74, "suspicious"),
    (75, 100, "high"),
)


def band_for(score: int) -> str:
    for lo, hi, name in BANDS:
        if lo <= score <= hi:
            return name
    return "high"


def controls_for(findings: Iterable[Finding]) -> list[str]:
    seen: set[str] = set()
    for f in findings:
        for c in f.controls:
            seen.add(c)
    return sorted(seen, key=lambda c: (c.split()[0], c.split()[1]))


def next_actions(findings: list[Finding], intel_highest: str) -> list[str]:
    actions: list[str] = []
    has_high = any(f.severity == "high" for f in findings)
    has_med = any(f.severity == "medium" for f in findings)
    if intel_highest == "malicious":
        actions.append("Block the file hash on EDR / perimeter policy immediately.")
    if has_high:
        actions.append("Escalate to the authorized dynamic-detonation lab (separate gated stage).")
        actions.append("Publish hash + embedded IOCs to the SOC intel pipeline (STIX export).")
    elif has_med:
        actions.append("Request analyst deep-dive; correlate artifacts against SIEM visibility gaps.")
    else:
        actions.append("Low priority — file for retention; no immediate containment required.")
    actions.append("Preserve evidence and card in the case sandbox for audit (chain-of-custody).")
    return actions


def build_triage_card(*, sample: dict, digests: dict,
                      strings: dict, pe: dict, intel: dict,
                      findings: list[Finding],
                      spec: dict, bundle_sha: str,
                      ledger_head: str, ledger_events: int,
                      started_utc: str, finished_utc: str) -> dict:
    """Assemble the full triage card (schema sap.triage_card.v1)."""
    intel_highest = intel.get("highest_verdict", "unknown")

    score = sum(f.score_delta for f in findings)
    if intel_highest == "malicious":
        score = max(score, 80)
    elif intel_highest == "benign":
        score = min(score, 20)
    score = max(0, min(100, score))
    band = band_for(score)

    top_signals = [f.title for f in findings[:5]]

    rule_hits = [f.to_dict() for f in findings]

    card = {
        "schema": "sap.triage_card.v1",
        "card_id": uuid.uuid4().hex,
        "spec_id": spec["spec_id"],
        "spec_version": spec["version"],
        "bundle_ref": spec["bundle_ref"],
        "bundle_sha256": bundle_sha,
        "engine": "sap",
        "sample": sample,
        "digests": digests,
        "scan": {
            "status": "complete",
            "started_utc": started_utc,
            "finished_utc": finished_utc,
            "engines": {
                "strings": strings.get("status", "error"),
                "pe": pe.get("status", "error"),
                "intel": "ok",
            },
        },
        "strings_summary": {
            "status": strings.get("status"),
            "ascii_count": strings.get("ascii_count"),
            "utf16_count": strings.get("utf16_count"),
            "high_entropy_count": strings.get("high_entropy_count"),
            "artifact_counts": strings.get("artifact_counts"),
            "suspicious_apis": strings.get("suspicious_apis"),
            "artifacts": strings.get("artifacts", [])[:20],
        },
        "pe_summary": {
            "status": pe.get("status"),
            "format": pe.get("format"),
            "backend": pe.get("backend"),
            "machine": pe.get("machine"),
            "bitness": pe.get("bitness"),
            "entry_point": pe.get("entry_point"),
            "image_base": pe.get("image_base"),
            "subsystem": pe.get("subsystem"),
            "timestamp_utc": pe.get("timestamp_utc"),
            "checksum_ok": pe.get("checksum_ok"),
            "overlay_size": pe.get("overlay_size"),
            "sections": pe.get("sections", [])[:64],
            "imports": pe.get("imports", [])[:64],
            "anomalies": pe.get("anomalies"),
            "cross_check": pe.get("cross_check"),
            "fingerprint": pe.get("fingerprint"),
        },
        "intel": intel,
        "findings": rule_hits,
        "risk": {
            "score": score,
            "band": band,
            "top_signals": top_signals,
            "next_actions": next_actions(findings, intel_highest),
            "controls": controls_for(findings),
        },
        "audit": {
            "ledger_head": ledger_head,
            "ledger_events": ledger_events,
            "sealed": False,
        },
    }
    return card