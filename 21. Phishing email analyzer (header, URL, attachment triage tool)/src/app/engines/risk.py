"""Correlation & decision engine: explainable risk scoring + fail-closed verdict.

Controls: A04 (insecure design -> policy decision matrix, human-readable),
SI-4 / RA-5. Verdict mapping is deterministic and auditable:

  scoring weight by engine: header 0.25, url 0.30, attachment 0.30, content 0.15
  severity -> points: INFO 0, LOW 1, MEDIUM 2, HIGH 3, CRITICAL 4 (capped 100)

Decision matrix (fail-closed: unverifiable high signals never ALLOW):
  - any CRITICAL finding                          -> QUARANTINE
  - >=2 HIGH malicious signals OR any 5+ total    -> QUARANTINE
  - any HIGH malicious or >=3 MEDIUM signal       -> SANDBOX (needs inspection)
  - risk >= 40                                    -> FLAG
  - otherwise                                     -> ALLOW (evidence logged)
"""
from __future__ import annotations

from typing import Dict, List

from .model import AnalysisReport, EngineResult, Finding, Severity

WEIGHTS = {"header": 0.25, "url": 0.30, "attachment": 0.30, "content": 0.15}
SEVERITY_POINTS = {Severity.INFO: 0, Severity.LOW: 1, Severity.MEDIUM: 2,
                   Severity.HIGH: 3, Severity.CRITICAL: 4}
MALICIOUS_CATEGORIES = {"malicious", "auth", "obfuscation", "reputation"}


def score_report(report: AnalysisReport) -> AnalysisReport:
    """Populates risk_score + verdict + verdict_reason. Pure, deterministic."""
    by_engine: Dict[str, int] = {}
    triggers: List[str] = []
    criticals = 0
    for engine, result in report.results.items():
        pts = 0
        for f in result.findings:
            pts += SEVERITY_POINTS.get(f.severity, 0)
            if f.category in MALICIOUS_CATEGORIES and f.severity.rank >= Severity.HIGH.rank:
                triggers.append(f"{engine}.{f.code}")
            if f.severity == Severity.CRITICAL:
                criticals += 1
        by_engine[engine] = pts
    total = 0
    for engine, pts in by_engine.items():
        total += min(pts, 4) / 4.0 * 100 * WEIGHTS.get(engine, 0.0)
    report.risk_score = int(round(min(100, total)))
    report.results_multi = by_engine  # kept for UI

    high_mal = len([t for t in triggers if t.split(".")[0] in WEIGHTS])
    # conservative: any single CRITICAL or 2+ HIGH malicious features
    if criticals > 0 or high_mal >= 2 or (high_mal == 1 and _has_multisignal(report)):
        report.verdict = "QUARANTINE"
        report.verdict_reason = f"{len(triggers)} high-severity malicious signal(s)"
    elif high_mal == 1 or sum(1 for f in _findings(report) if f.severity.rank >= Severity.MEDIUM.rank) >= 3:
        report.verdict = "SANDBOX"
        report.verdict_reason = "single high-risk or 3+ medium signals; manual inspection recommended"
    elif report.risk_score >= 40:
        report.verdict = "FLAG"
        report.verdict_reason = f"risk score {report.risk_score}/100"
    else:
        report.verdict = "ALLOW"
        report.verdict_reason = f"no actionable signals (risk {report.risk_score}/100)"
    report.verdict_triggers = list(dict.fromkeys(triggers))
    return report


def _has_multisignal(report: AnalysisReport) -> bool:
    engines = {f.engine for f in _findings(report)
               if f.severity.rank >= Severity.HIGH.rank}
    return len(engines) >= 2


def _findings(report: AnalysisReport) -> List[Finding]:
    out: List[Finding] = []
    for r in report.results.values():
        out.extend(r.findings)
    return out


def verdict_rank(verdict: str) -> int:
    return {"ALLOW": 0, "FLAG": 1, "SANDBOX": 2, "QUARANTINE": 3, "BLOCK": 4}.get(verdict, 0)