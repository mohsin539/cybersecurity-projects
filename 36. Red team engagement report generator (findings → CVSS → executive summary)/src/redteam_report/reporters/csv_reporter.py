"""CSV reporter.

Writes a machine-friendly, flat set of CSV files that can be consumed by
Excel, Power BI and downstream automation:

  - findings.csv             full detail of every finding
  - cvss_metrics.csv         CVSS v3.1 metric breakdown per finding
  - framework_coverage.csv   OWASP / NIST / ISO alignment per finding
  - severity_summary.csv     counts per severity band
  - executive_summary.csv    engagement headline metrics
"""

from __future__ import annotations

import csv
from typing import List

from ..analyzers.executive import ExecutiveSummary
from ..models.finding import Finding
from ..models.framework import FrameworkMapping
from .base import BaseReporter, ReportResult

_HEADER = [
    "Finding ID", "Title", "Asset", "Asset Class", "Source",
    "OWASP Top 10", "CVSS Vector", "CVSS Base Score", "Severity",
    "Temporal Score", "Environmental Score", "Affected URL", "Status",
    "Discovered By", "Discovered On", "Technical Impact", "Business Impact",
    "Remediation", "Evidence", "References",
]


class CSVReporter(BaseReporter):
    """Generates the CSV set of reports."""

    def write(
        self,
        findings: List[Finding],
        summary: ExecutiveSummary,
        mappings: List[FrameworkMapping],
    ) -> ReportResult:
        result = ReportResult(format="csv")

        # 1. Findings detail
        findings_path = self._stamp("findings", "csv")
        with findings_path.open("w", newline="", encoding="utf-8-sig") as handle:
            writer = csv.DictWriter(handle, fieldnames=_HEADER, extrasaction="ignore")
            writer.writeheader()
            for finding in findings:
                writer.writerow(finding.framework_row())
        result.add("findings", findings_path)

        # 2. CVSS metric breakdown
        cvss_path = self._stamp("cvss_metrics", "csv")
        metric_keys = ["AV", "AC", "PR", "UI", "S", "C", "I", "A", "E", "RL", "RC"]
        with cvss_path.open("w", newline="", encoding="utf-8-sig") as handle:
            writer = csv.writer(handle)
            writer.writerow(["Finding ID", "CVSS Vector", "Base Score", "Severity", *metric_keys])
            for finding in findings:
                metrics = finding.cvss.metrics
                writer.writerow([
                    finding.id, finding.cvss_vector, f"{finding.base_score:.1f}",
                    finding.severity.value, *[metrics.get(k, "X") for k in metric_keys],
                ])
        result.add("cvss", cvss_path)

        # 3. Framework coverage
        fw_path = self._stamp("framework_coverage", "csv")
        with fw_path.open("w", newline="", encoding="utf-8-sig") as handle:
            writer = csv.DictWriter(
                handle,
                fieldnames=[
                    "Finding ID", "Title", "OWASP Top 10", "OWASP Category",
                    "OWASP Description", "NIST Controls", "ISO 27001 Controls",
                ],
            )
            writer.writeheader()
            for mapping in mappings:
                row = mapping.framework_matrix()
                row["OWASP Description"] = mapping.owasp.description
                writer.writerow(row)
        result.add("framework", fw_path)

        # 4. Severity distribution
        sev_path = self._stamp("severity_summary", "csv")
        with sev_path.open("w", newline="", encoding="utf-8-sig") as handle:
            writer = csv.writer(handle)
            writer.writerow(["Severity", "Count"])
            for label in ["Critical", "High", "Medium", "Low", "None"]:
                writer.writerow([label, getattr(summary.distribution, label.lower())])
            writer.writerow(["Mean CVSS", f"{summary.avg_cvss:.1f}"])
            writer.writerow(["Max CVSS", f"{summary.max_cvss:.1f}"])
            writer.writerow(["Risk Index", f"{summary.risk_score}/100"])
            writer.writerow(["Risk Rating", summary.risk_rating])
        result.add("severity", sev_path)

        # 5. Executive summary
        exec_path = self._stamp("executive_summary", "csv")
        with exec_path.open("w", newline="", encoding="utf-8-sig") as handle:
            writer = csv.writer(handle)
            writer.writerow(["Engagement", summary.engagement_name])
            writer.writerow(["Customer", summary.customer])
            writer.writerow(["Period", summary.period])
            writer.writerow(["Scope", summary.scope])
            writer.writerow(["Total Findings", summary.total_findings])
            writer.writerow(["Average CVSS", f"{summary.avg_cvss:.1f}"])
            writer.writerow(["Maximum CVSS", f"{summary.max_cvss:.1f}"])
            writer.writerow(["Risk Index", f"{summary.risk_score:.0f}/100"])
            writer.writerow(["Risk Rating", summary.risk_rating])
            writer.writerow([])
            writer.writerow(["Recommendations"])
            for rec in summary.recommendations:
                writer.writerow([rec])
            writer.writerow([])
            writer.writerow(["Executive Narrative"])
            writer.writerow([summary.narrative])
        result.add("executive", exec_path)

        return result