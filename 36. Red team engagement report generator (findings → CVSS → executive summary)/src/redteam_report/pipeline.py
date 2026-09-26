"""End-to-end pipeline: findings -> CVSS -> frameworks -> executive summary -> reports."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

from .analyzers.executive import ExecutiveSummary, build_executive_summary
from .frameworks.catalog import map_finding_owasp
from .models.finding import Finding, FindingSource
from .reporters.base import ReportResult
from .reporters.csv_reporter import CSVReporter
from .reporters.html_reporter import HTMLReporter
from .reporters.xlsx_reporter import XLSXReporter

REPORTERS = {
    "csv": CSVReporter,
    "xlsx": XLSXReporter,
    "html": HTMLReporter,
}


@dataclass
class Engagement:
    """Top-level engagement document."""

    findings: List[Finding]
    name: str = "Red Team Engagement"
    customer: str = ""
    period: str = ""
    scope: str = ""

    def mappings(self) -> list:
        return [map_finding_owasp(f.owasp_id, finding=f) for f in self.findings]

    def executive_summary(self) -> ExecutiveSummary:
        return build_executive_summary(
            self.findings,
            engagement_name=self.name,
            customer=self.customer,
            period=self.period,
            scope=self.scope,
        )


def _parse_source(value: str) -> FindingSource:
    for member in FindingSource:
        if member.value.lower() == str(value).lower():
            return member
    return FindingSource.WEB_APP


def _parse_finding(raw: dict) -> Finding:
    return Finding(
        id=str(raw.get("id", "RT-000")),
        title=str(raw.get("title", "Untitled finding")),
        description=str(raw.get("description", "")),
        asset=str(raw.get("asset", "")),
        asset_class=str(raw.get("asset_class", "Web Application")),
        cvss_vector=str(raw.get("cvss_vector", "")),
        owasp_id=str(raw.get("owasp_id", "A01")).split(":")[0],
        source=_parse_source(raw.get("source", "Web Application")),
        technical_impact=str(raw.get("technical_impact", "")),
        business_impact=str(raw.get("business_impact", "")),
        remediation=str(raw.get("remediation", "")),
        affected_url=str(raw.get("affected_url", "")),
        discovered_by=str(raw.get("discovered_by", "")),
        discovered_on=str(raw.get("discovered_on", "")),
        status=str(raw.get("status", "Open")),
        evidence=str(raw.get("evidence", "")),
        references=[str(r) for r in raw.get("references", [])],
        extra=raw.get("extra", {}),
    )


def load_engagement(path: Path) -> Engagement:
    """Load an engagement document from a JSON file."""
    with Path(path).open("r", encoding="utf-8") as handle:
        doc = json.load(handle)

    engagement = doc.get("engagement", {})
    findings = [_parse_finding(f) for f in doc.get("findings", [])]
    return Engagement(
        findings=findings,
        name=str(engagement.get("name", "Red Team Engagement")),
        customer=str(engagement.get("customer", "")),
        period=str(engagement.get("period", "")),
        scope=str(engagement.get("scope", "")),
    )


def generate(
    engagement: Engagement,
    output_dir: Path,
    formats: Optional[List[str]] = None,
) -> Dict[str, ReportResult]:
    """Run the full pipeline and emit the requested report formats."""
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    formats = formats or list(REPORTERS)
    mappings = engagement.mappings()
    summary = engagement.executive_summary()

    results: Dict[str, ReportResult] = {}
    for fmt in formats:
        fmt = fmt.lower()
        if fmt not in REPORTERS:
            raise ValueError(f"Unsupported report format '{fmt}'. Use one of: {', '.join(REPORTERS)}")
        reporter = REPORTERS[fmt](output_dir)
        results[fmt] = reporter.write(engagement.findings, summary, mappings)
    return results