"""Executive summary engine.

Aggregates scored findings into management-ready metrics, a risk posture
index, prioritized remediation items and a human-readable narrative used by
the XLSX, CSV and HTML report formats.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List

from ..frameworks.owasp import OWASP_BY_ID
from ..models.cvss import Severity
from ..models.finding import Finding, SeverityDistribution


@dataclass
class RemediationPriority:
    """A prioritized remediation work-item."""

    rank: int
    finding_id: str
    title: str
    score: float
    severity: Severity
    owasp_id: str
    remediation: str

    @property
    def label(self) -> str:
        return f"{self.finding_id}: {self.title}"


@dataclass
class ExecutiveSummary:
    """All computed management metrics for an engagement."""

    engagement_name: str = ""
    customer: str = ""
    period: str = ""
    scope: str = ""
    distribution: SeverityDistribution = field(default_factory=SeverityDistribution)
    total_findings: int = 0
    avg_cvss: float = 0.0
    max_cvss: float = 0.0
    min_cvss: float = 0.0
    risk_score: float = 0.0
    risk_rating: str = "Low"
    owasp_counts: Dict[str, int] = field(default_factory=dict)
    top_findings: List[Finding] = field(default_factory=list)
    priorities: List[RemediationPriority] = field(default_factory=list)
    narrative: str = ""
    strengths: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)


def _risk_score(dist: SeverityDistribution) -> float:
    """Normalized 0-100 weighted risk posture.

    Weights mirror CVSS severity bands (Critical x10, High x7, Medium x5,
    Low x2), normalized against a hypothetical worst-case engagement where
    every finding is Critical.
    """
    if dist.total == 0:
        return 0.0
    weighted = dist.critical * 10 + dist.high * 7 + dist.medium * 5 + dist.low * 2
    raw = (weighted / (dist.total * 10)) * 100
    return round(raw, 1)


def _risk_rating(score: float) -> str:
    if score >= 75:
        return "Critical"
    if score >= 50:
        return "High"
    if score >= 30:
        return "Elevated"
    if score >= 10:
        return "Moderate"
    return "Low"


def _narrative(summary: ExecutiveSummary) -> str:
    dist = summary.distribution
    lines: List[str] = []

    if dist.total:
        lines.append(
            f"During the assessment period, {summary.total_findings} findings were "
            f"documented across {summary.scope or 'the defined scope'}. Of these, "
            f"{dist.critical} were rated Critical, {dist.high} High, {dist.medium} Medium "
            f"and {dist.low} Low. The average base CVSS v3.1 score was {summary.avg_cvss:.1f}; "
            f"the most severe finding reached {summary.max_cvss:.1f}."
        )
        lines.append(
            f"Taken together, the findings place the organization at a {summary.risk_rating} "
            f"risk posture (index {summary.risk_score:.0f}/100)."
        )
        if dist.critical or dist.high:
            lines.append(
                f"Immediate executive attention is warranted: {dist.critical + dist.high} "
                "findings fall into the Critical or High bands and present realistic paths "
                "to system, data, or business compromise."
            )
        if summary.owasp_counts:
            top_cats = sorted(summary.owasp_counts.items(), key=lambda kv: (-kv[1], kv[0]))[:3]
            names = ", ".join(f"{cid} {OWASP_BY_ID[cid].name}" for cid, _ in top_cats)
            lines.append(
                f"Concentrated weaknesses appear in the OWASP Top 10 categories: {names}."
            )
    else:
        lines.append(
            "No findings were recorded against the defined scope during the assessment "
            "period. Controls exercised during the engagement appeared to hold under the "
            "tested scenarios."
        )

    lines.append(
        "Scores follow CVSS v3.1 base metrics; framework alignment uses OWASP Top 10 "
        "(2021), NIST SP 800-53 Rev.5 and ISO/IEC 27001:2022, so each recommendation "
        "traces to a defensible control."
    )
    return " ".join(lines)


def _recommendations(summary: ExecutiveSummary) -> List[str]:
    recs: List[str] = []
    dist = summary.distribution
    if dist.critical or dist.high:
        recs.append(
            "Remediate Critical/High findings within 14-30 days, prioritizing externally "
            "reachable assets."
        )
    if dist.medium:
        recs.append(
            "Schedule Medium findings into the next 1-2 release cycles with an owner and "
            "due date per work-item."
        )
    if summary.owasp_counts.get("A06"):
        recs.append(
            "Establish a software composition analysis (SCA) program for dependency and "
            "component hygiene."
        )
    if summary.owasp_counts.get("A09"):
        recs.append(
            "Operationalize centralized logging, correlation rules and 24x7 alerting to "
            "close logging and monitoring gaps."
        )
    if summary.owasp_counts.get("A01") or summary.owasp_counts.get("A07"):
        recs.append(
            "Re-verify authorization and authentication flows across all administrative "
            "interfaces and enforce least privilege."
        )
    if summary.owasp_counts.get("A03"):
        recs.append(
            "Adopt parameterized queries, prepared statements and strict output encoding "
            "for all untrusted input."
        )
    if summary.owasp_counts.get("A02"):
        recs.append(
            "Harden cryptographic posture: enforce TLS 1.2+, modern cipher suites and "
            "centralized key management."
        )
    if summary.owasp_counts.get("A10"):
        recs.append(
            "Restrict outbound application traffic, deny access to internal metadata "
            "services and validate destination hosts."
        )
    return recs


def build_executive_summary(
    findings: List[Finding],
    engagement_name: str = "",
    customer: str = "",
    period: str = "",
    scope: str = "",
) -> ExecutiveSummary:
    """Compute the complete executive summary for a set of scored findings."""
    summary = ExecutiveSummary(
        engagement_name=engagement_name or "Red Team Engagement",
        customer=customer,
        period=period,
        scope=scope,
    )
    if not findings:
        summary.narrative = _narrative(summary)
        return summary

    distribution = SeverityDistribution.from_findings(findings)
    summary.distribution = distribution
    summary.total_findings = len(findings)
    summary.avg_cvss = round(sum(f.base_score for f in findings) / len(findings), 1)
    summary.max_cvss = max(f.base_score for f in findings)
    summary.min_cvss = min(f.base_score for f in findings)
    summary.risk_score = _risk_score(distribution)
    summary.risk_rating = _risk_rating(summary.risk_score)

    owasp_counts: Dict[str, int] = {}
    for finding in findings:
        owasp_counts[finding.owasp_id] = owasp_counts.get(finding.owasp_id, 0) + 1
    summary.owasp_counts = dict(sorted(owasp_counts.items()))

    summary.top_findings = sorted(findings, key=lambda f: f.base_score, reverse=True)
    summary.priorities = [
        RemediationPriority(
            rank=rank,
            finding_id=f.id,
            title=f.title,
            score=f.base_score,
            severity=f.severity,
            owasp_id=f.owasp_id,
            remediation=f.remediation,
        )
        for rank, f in enumerate(summary.top_findings, start=1)
    ]

    summary.recommendations = _recommendations(summary)
    summary.narrative = _narrative(summary)
    return summary