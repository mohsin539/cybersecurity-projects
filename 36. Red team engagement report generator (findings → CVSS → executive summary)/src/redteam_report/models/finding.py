"""Finding domain model.

A finding is the atomic unit produced by a red team engagement: a
vulnerability, weakness or control gap observed against an asset. Every
finding carries a CVSS v3.1 vector string which downstream components
translate into a score, a severity band and cross-framework mappings.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional

from .cvss import CVSS3Engine, CVSS3Result, Severity, score_vector


class FindingSource(str, Enum):
    """Where a finding originated during the engagement."""

    NETWORK = "Network"
    WEB_APP = "Web Application"
    API = "API"
    CLOUD = "Cloud"
    MOBILE = "Mobile"
    WIRELESS = "Wireless"
    SOCIAL_ENGINEERING = "Social Engineering"
    PHYSICAL = "Physical"


@dataclass
class Finding:
    """A single red team finding with its CVSS assessment."""

    id: str
    title: str
    description: str
    asset: str
    cvss_vector: str
    owasp_id: str
    source: FindingSource = FindingSource.WEB_APP
    asset_class: str = "Web Application"
    technical_impact: str = ""
    business_impact: str = ""
    remediation: str = ""
    affected_url: str = ""
    discovered_by: str = ""
    discovered_on: str = ""
    status: str = "Open"
    evidence: str = ""
    references: List[str] = field(default_factory=list)
    extra: Dict[str, str] = field(default_factory=dict)

    cvss: CVSS3Result = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self.cvss = score_vector(self.cvss_vector)

    # -- convenience accessors ---------------------------------------------
    @property
    def base_score(self) -> float:
        return self.cvss.base_score

    @property
    def severity(self) -> Severity:
        return self.cvss.severity

    @property
    def valid_cvss(self) -> bool:
        return self.cvss.valid and not self.cvss.validation_errors

    @property
    def cvss_metrics(self) -> Dict[str, str]:
        return self.cvss.metrics

    def framework_row(self) -> Dict[str, str]:
        """Flat dict for CSV / tabular output."""
        return {
            "Finding ID": self.id,
            "Title": self.title,
            "Asset": self.asset,
            "Asset Class": self.asset_class,
            "Source": self.source.value,
            "OWASP Top 10": self.owasp_id,
            "CVSS Vector": self.cvss_vector,
            "CVSS Base Score": f"{self.base_score:.1f}",
            "Severity": self.severity.value,
            "Temporal Score": (
                f"{self.cvss.temporal_score:.1f}" if self.cvss.temporal_score is not None else "n/a"
            ),
            "Environmental Score": (
                f"{self.cvss.environmental_score:.1f}"
                if self.cvss.environmental_score is not None else "n/a"
            ),
            "Affected URL": self.affected_url,
            "Status": self.status,
            "Discovered By": self.discovered_by,
            "Discovered On": self.discovered_on,
            "Technical Impact": self.technical_impact,
            "Business Impact": self.business_impact,
            "Remediation": self.remediation,
            "Evidence": self.evidence,
            "References": "; ".join(self.references),
        }


@dataclass
class SeverityDistribution:
    """Count of findings per severity band."""

    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    none: int = 0

    @classmethod
    def from_findings(cls, findings: List[Finding]) -> "SeverityDistribution":
        dist = cls()
        for finding in findings:
            key = finding.severity.value.lower()
            if getattr(dist, key) is not None and hasattr(dist, key):
                setattr(dist, key, getattr(dist, key) + 1)
        return dist

    @property
    def total(self) -> int:
        return self.critical + self.high + self.medium + self.low + self.none

    @property
    def raised(self) -> int:
        """Findings at Low severity or above."""
        return self.total - self.none