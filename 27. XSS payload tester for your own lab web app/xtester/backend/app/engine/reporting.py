"""Report assembly: turns raw probe results into findings + a scan report.

Implements the OWASP ASVS-flavoured evidence model: each finding carries the
exact probe URL (PoC), observed evidence, severity (CVSS v3.1), and inline
remediation. De-dup: one finding per (vector, context) keeping the worst
strategy that succeeded, matching how pentest reports are normally scoped.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from app.engine.cvss import Cvss
from app.engine.detection import ProbeResult
from app.engine.payloads import Candidate
from app.engine.remediation import remediate

VERDICT_ORDER = {"EXECUTED": 4, "LIKELY": 3, "SUSPICIOUS": 2, "CLEAN": 1}


@dataclass
class FindingDraft:
    candidate: Candidate
    probe: ProbeResult
    severity: str
    cvss: float


def assemble_findings(
    candidates: list[Candidate],
    probes: dict[str, ProbeResult],
) -> list[FindingDraft]:
    drafted: list[FindingDraft] = []
    for cand in candidates:
        probe = probes.get(cand.id)
        if not probe or probe.verdict == "CLEAN":
            continue
        cvss = Cvss.for_context(cand.context.kind.value, probe.verdict == "EXECUTED")
        drafted.append(
            FindingDraft(
                candidate=cand,
                probe=probe,
                severity=cvss.severity(),
                cvss=cvss.base_score(),
            )
        )
    return _dedup(drafted)


def _dedup(drafts: list[FindingDraft]) -> list[FindingDraft]:
    """Keep the single strongest candidate per (vector_name, context_spec).
    Order results by severity then confidence."""
    keep: dict[tuple, FindingDraft] = {}
    for d in drafts:
        key = (d.candidate.vector_name, d.candidate.context.name)
        prev = keep.get(key)
        rank = VERDICT_ORDER.get(d.probe.verdict, 0)
        prev_rank = VERDICT_ORDER.get(prev.probe.verdict, 0) if prev else 0
        if prev is None or rank > prev_rank or (rank == prev_rank and d.cvss > prev.cvss):
            keep[key] = d
    ranked = sorted(
        keep.values(),
        key=lambda d: (VERDICT_ORDER.get(d.probe.verdict, 0), d.cvss),
        reverse=True,
    )
    return ranked


def build_summary(
    findings: list[FindingDraft],
    payload_count: int,
    scan_url: str,
    headers: dict[str, str] | None,
) -> dict:
    counts = {"EXECUTED": 0, "LIKELY": 0, "SUSPICIOUS": 0, "CLEAN": 0}
    sev_counts = {"info": 0, "low": 0, "medium": 0, "high": 0, "critical": 0}
    for f in findings:
        counts[f.probe.verdict] = counts.get(f.probe.verdict, 0) + 1
        sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1
    max_sev = max((k for k in sev_counts if sev_counts[k]), default="info", key=lambda s: {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}[s])
    return {
        "scan_url": scan_url,
        "payload_count": payload_count,
        "findings": len(findings),
        "executed": counts["EXECUTED"],
        "likely": counts["LIKELY"],
        "suspicious": counts["SUSPICIOUS"],
        "clean": counts["CLEAN"],
        "severity_counts": sev_counts,
        "max_severity": max_sev,
        "max_cvss": round(max((f.cvss for f in findings), default=0.0), 1),
        "observed_headers": headers or {},
    }


def incidents_to_json(findings: list[FindingDraft]) -> list[dict]:
    out = []
    for f in findings:
        out.append(
            {
                "vector": f.candidate.vector_name,
                "category": f.candidate.category,
                "context": f.candidate.context.name,
                "strategy": f.candidate.strategy,
                "severity": f.severity,
                "cvss_score": f.cvss,
                "cvss_vector": Cvss.for_context(f.candidate.context.kind.value, True).vector,
                "verdict": f.probe.verdict,
                "confidence": f.probe.confidence,
                "repro": f.candidate.proof_url,
                "payload": f.candidate.payload,
                "evidence": _evidence_text(f),
                "remediation": remediate(f.candidate.context),
            }
        )
    return out


def _evidence_text(f: FindingDraft) -> str:
    p = f.probe
    bits = []
    if p.beacon_hit:
        bits.append("beacon fired (script executed)")
    if p.dialogs:
        bits.append("dialog fired with sentinel")
    if p.dom_contains_token:
        bits.append("sentinel present in rendered DOM")
    if p.errors:
        bits.append(f"js errors: {p.errors[:3]}")
    bits.extend(p.observations)
    return "; ".join(bits) if bits else "no direct evidence (hang/error page was scanned)"


def dump_report(findings: list[FindingDraft], summary: dict) -> str:
    return json.dumps(
        {"summary": summary, "findings": incidents_to_json(findings)},
        indent=2,
        ensure_ascii=False,
    )