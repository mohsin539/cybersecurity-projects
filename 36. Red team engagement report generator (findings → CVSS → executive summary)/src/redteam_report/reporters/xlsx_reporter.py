"""XLSX reporter (openpyxl).

Produces a color-coded, multi-sheet Excel workbook:

  1. Executive Summary      headline figures, narrative, recommendations
  2. Severity Dashboard     distribution + CVSS heat strip
  3. Findings Detail        every finding with severity-colored badges
  4. CVSS Metrics           v3.1 metric decomposition
  5. Framework Coverage     OWASP / NIST / ISO alignment per finding
  6. Prioritized Plan       ranked remediation work-items
"""

from __future__ import annotations

from typing import List

from openpyxl import Workbook
from openpyxl.formatting.rule import ColorScaleRule
from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
from openpyxl.utils import get_column_letter

from ..analyzers.executive import ExecutiveSummary
from ..models.finding import Finding
from ..models.framework import FrameworkMapping
from .base import BaseReporter, ReportResult
from .palette import BRAND_BLUE, BRAND_TEAL, BRAND_INDIGO, BRAND_VIOLET, HEADER_BG, TEXT_DARK

HEADER_FILL = PatternFill("solid", fgColor=HEADER_BG)
HEADER_FONT = Font(name="Calibri", bold=True, color="FFFFFF", size=11)
TITLE_FONT = Font(name="Calibri", bold=True, color="FFFFFF", size=16)
SECTION_FONT = Font(name="Calibri", bold=True, color=BRAND_INDIGO, size=13)
BODY_FONT = Font(name="Calibri", size=11, color=TEXT_DARK)
THIN = Side(style="thin", color="DEE2E6")
BORDER = Border(left=THIN, right=THIN, top=THIN, bottom=THIN)
WRAP = Alignment(wrap_text=True, vertical="top")
CENTER = Alignment(horizontal="center", vertical="center")


def _severity_fill(severity) -> PatternFill:
    return PatternFill("solid", fgColor=severity.hex_color.lstrip("#"))


def _brand_fill(hex_color: str) -> PatternFill:
    return PatternFill("solid", fgColor=hex_color.lstrip("#"))


def _style_header(ws, row: int, headers: List[str], width_map) -> None:
    for col, header in enumerate(headers, start=1):
        cell = ws.cell(row=row, column=col, value=header)
        cell.fill = HEADER_FILL
        cell.font = HEADER_FONT
        cell.alignment = CENTER
        cell.border = BORDER
    for col, width in width_map.items():
        ws.column_dimensions[get_column_letter(col)].width = width
    ws.freeze_panes = ws.cell(row=row + 1, column=1)


def _title_block(ws, title: str, subtitle: str, fill_hex: str = BRAND_INDIGO) -> None:
    ws.merge_cells("A1:H1")
    ws["A1"] = title
    ws["A1"].font = TITLE_FONT
    ws["A1"].fill = _brand_fill(fill_hex)
    ws["A1"].alignment = Alignment(horizontal="left", vertical="center", indent=1)
    ws.row_dimensions[1].height = 30
    ws.merge_cells("A2:H2")
    ws["A2"] = subtitle
    ws["A2"].font = Font(name="Calibri", italic=True, size=10, color=TEXT_DARK)
    ws.row_dimensions[2].height = 18


class XLSXReporter(BaseReporter):
    """Colorful, board-ready Excel workbook builder."""

    def write(
        self,
        findings: List[Finding],
        summary: ExecutiveSummary,
        mappings: List[FrameworkMapping],
    ) -> ReportResult:
        path = self._stamp("red_team_engagement_report", "xlsx")
        wb = Workbook()

        self._executive_sheet(wb, summary)
        self._severity_dashboard(wb, summary)
        self._findings_sheet(wb, findings)
        self._cvss_metrics_sheet(wb, findings)
        self._framework_coverage_sheet(wb, mappings)
        self._remediation_sheet(wb, summary)

        wb.save(path)
        result = ReportResult(format="xlsx")
        result.add("workbook", path)
        return result

    # -- 1. Executive summary ----------------------------------------------
    def _executive_sheet(self, wb, summary: ExecutiveSummary) -> None:
        ws = wb.active
        ws.title = "Executive Summary"
        _title_block(ws, "RED TEAM ENGAGEMENT - EXECUTIVE SUMMARY", summary.engagement_name)

        stats = [
            ("Total Findings", summary.total_findings, BRAND_BLUE),
            ("Critical", summary.distribution.critical, "E03131"),
            ("High", summary.distribution.high, "F76707"),
            ("Medium", summary.distribution.medium, "FAB005"),
            ("Low", summary.distribution.low, "40C057"),
            ("Risk Index", f"{summary.risk_score:.0f}/100", BRAND_VIOLET),
        ]
        for idx, (label, value, color) in enumerate(stats):
            col = idx + 1
            ws.cell(row=4, column=col, value=label).font = Font(bold=True, color=TEXT_DARK, size=10)
            cell = ws.cell(row=5, column=col, value=value)
            cell.fill = _brand_fill(color)
            cell.font = Font(bold=True, color="FFFFFF", size=18)
            cell.alignment = CENTER
            ws.cell(row=5, column=col).border = BORDER
            ws.column_dimensions[get_column_letter(col)].width = 15

        ws.merge_cells("A8:H8")
        ws["A8"] = "EXECUTIVE NARRATIVE"
        ws["A8"].font = SECTION_FONT
        ws.merge_cells("A9:H15")
        ws["A9"] = summary.narrative
        ws["A9"].alignment = WRAP
        ws["A9"].font = BODY_FONT

        ws.merge_cells("A17:H17")
        ws["A17"] = "KEY RECOMMENDATIONS"
        ws["A17"].font = SECTION_FONT
        for i, rec in enumerate(summary.recommendations, start=18):
            ws.merge_cells(f"A{i}:H{i}")
            cell = ws.cell(row=i, column=1, value=f"{i - 17}. {rec}")
            cell.alignment = WRAP
            cell.fill = PatternFill("solid", fgColor="F1F3F5")
            cell.font = BODY_FONT

    # -- 2. Severity dashboard --------------------------------------------
    def _severity_dashboard(self, wb, summary: ExecutiveSummary) -> None:
        ws = wb.create_sheet("Severity Dashboard")
        _title_block(ws, "SEVERITY DASHBOARD", "Findings by CVSS v3.1 severity band", BRAND_TEAL)

        headers = ["Severity", "Count", "Share %", "CVSS Range"]
        width_map = {1: 16, 2: 10, 3: 12, 4: 14}
        _style_header(ws, 4, headers, width_map)

        ranges = {
            "Critical": "9.0 - 10.0",
            "High": "7.0 - 8.9",
            "Medium": "4.0 - 6.9",
            "Low": "0.1 - 3.9",
            "None": "0.0",
        }
        for i, (label, count) in enumerate(zip(
            ["Critical", "High", "Medium", "Low", "None"],
            [summary.distribution.critical, summary.distribution.high,
             summary.distribution.medium, summary.distribution.low,
             summary.distribution.none],
        ), start=5):
            share = (count / summary.total_findings) * 100 if summary.total_findings else 0.0
            from ..models.cvss import Severity

            severity = Severity(label)
            for col, value in [(1, label), (2, count), (3, f"{share:.1f}%"), (4, ranges[label])]:
                cell = ws.cell(row=i, column=col, value=value)
                cell.border = BORDER
                cell.font = BODY_FONT
                if col == 1:
                    cell.fill = _severity_fill(severity)
                    cell.font = Font(bold=True, color="FFFFFF")
                if col == 2:
                    cell.alignment = CENTER

        ws.merge_cells("A12:D12")
        ws["A12"] = "MEAN BASE CVSS"
        ws["A12"].font = SECTION_FONT
        ws.merge_cells("A13:D13")
        ws["A13"] = f"{summary.avg_cvss:.1f}   |   Max {summary.max_cvss:.1f}   |   Min {summary.min_cvss:.1f}"
        ws["A13"].font = Font(bold=True, size=16, color=BRAND_VIOLET)

    # -- 3. Findings detail -------------------------------------------------
    def _findings_sheet(self, wb, findings: List[Finding]) -> None:
        ws = wb.create_sheet("Findings Detail")
        _title_block(ws, "FINDINGS DETAIL", f"{len(findings)} findings across the engagement scope", BRAND_BLUE)

        headers = ["ID", "Title", "Asset", "OWASP", "CVSS Vector", "Score", "Severity", "Status", "Remediation"]
        width_map = {1: 10, 2: 42, 3: 20, 4: 10, 5: 30, 6: 10, 7: 14, 8: 12, 9: 60}
        _style_header(ws, 4, headers, width_map)

        for i, finding in enumerate(findings, start=5):
            ws.cell(row=i, column=1, value=finding.id).font = BODY_FONT
            ws.cell(row=i, column=2, value=finding.title).font = BODY_FONT
            ws.cell(row=i, column=3, value=finding.asset).font = BODY_FONT
            ws.cell(row=i, column=4, value=finding.owasp_id).font = BODY_FONT
            ws.cell(row=i, column=5, value=finding.cvss_vector).font = BODY_FONT
            score_cell = ws.cell(row=i, column=6, value=round(finding.base_score, 1))
            score_cell.number_format = "0.0"
            score_cell.alignment = CENTER
            sev_cell = ws.cell(row=i, column=7, value=finding.severity.value)
            sev_cell.fill = _severity_fill(finding.severity)
            sev_cell.font = Font(bold=True, color="FFFFFF")
            sev_cell.alignment = CENTER
            ws.cell(row=i, column=8, value=finding.status).font = BODY_FONT
            rem_cell = ws.cell(row=i, column=9, value=finding.remediation)
            rem_cell.alignment = WRAP
            rem_cell.font = BODY_FONT
            for col in range(1, 10):
                ws.cell(row=i, column=col).border = BORDER

        last = 4 + len(findings)
        ws.conditional_formatting.add(
            f"F5:F{last}",
            ColorScaleRule(
                start_type="num", start_value=0, start_color="40C057",
                mid_type="num", mid_value=5, mid_color="FAB005",
                end_type="num", end_value=10, end_color="E03131",
            ),
        )
        ws.auto_filter.ref = f"A4:I{last}"

    # -- 4. CVSS metrics ------------------------------------------------------
    def _cvss_metrics_sheet(self, wb, findings: List[Finding]) -> None:
        ws = wb.create_sheet("CVSS Metrics")
        _title_block(ws, "CVSS v3.1 METRIC DECOMPOSITION", "Base + temporal component metrics per finding", BRAND_VIOLET)

        headers = ["ID", "Vector", "Score", "Severity", "AV", "AC", "PR", "UI", "S", "C", "I", "A", "Temporal", "Environmental"]
        width_map = {1: 10, 2: 32, 3: 8, 4: 12, 5: 6, 6: 6, 7: 6, 8: 6, 9: 6, 10: 6, 11: 6, 12: 6, 13: 10, 14: 10}
        _style_header(ws, 4, headers, width_map)

        for i, finding in enumerate(findings, start=5):
            m = finding.cvss.metrics
            values = [
                finding.id, finding.cvss_vector, round(finding.base_score, 1),
                finding.severity.value,
                m.get("AV", "X"), m.get("AC", "X"), m.get("PR", "X"), m.get("UI", "X"),
                m.get("S", "X"), m.get("C", "X"), m.get("I", "X"), m.get("A", "X"),
                f"{finding.cvss.temporal_score:.1f}" if finding.cvss.temporal_score is not None else "n/a",
                f"{finding.cvss.environmental_score:.1f}" if finding.cvss.environmental_score is not None else "n/a",
            ]
            for col, value in enumerate(values, start=1):
                cell = ws.cell(row=i, column=col, value=value)
                cell.border = BORDER
                cell.font = BODY_FONT
                cell.alignment = CENTER if col >= 5 else Alignment(vertical="center")
            sev_cell = ws.cell(row=i, column=4)
            sev_cell.fill = _severity_fill(finding.severity)
            sev_cell.font = Font(bold=True, color="FFFFFF")

    # -- 5. Framework coverage ---------------------------------------------
    def _framework_coverage_sheet(self, wb, mappings: List[FrameworkMapping]) -> None:
        ws = wb.create_sheet("Framework Coverage")
        _title_block(
            ws,
            "FRAMEWORK COVERAGE",
            "OWASP Top 10 (2021) | NIST SP 800-53 Rev.5 | ISO/IEC 27001:2022",
            "0D9488",
        )

        headers = ["ID", "Title", "OWASP", "OWASP Category", "NIST Controls", "ISO 27001 Controls"]
        width_map = {1: 10, 2: 40, 3: 8, 4: 30, 5: 42, 6: 42}
        _style_header(ws, 4, headers, width_map)

        for i, mapping in enumerate(mappings, start=5):
            row = mapping.framework_matrix()
            ws.cell(row=i, column=1, value=row["Finding ID"]).font = BODY_FONT
            ws.cell(row=i, column=2, value=row["Title"]).font = BODY_FONT
            owasp_cell = ws.cell(row=i, column=3, value=row["OWASP Top 10"])
            owasp_cell.fill = PatternFill("solid", fgColor="B02572")
            owasp_cell.font = Font(bold=True, color="FFFFFF")
            owasp_cell.alignment = CENTER
            ws.cell(row=i, column=4, value=row["OWASP Category"]).font = BODY_FONT
            ws.cell(row=i, column=5, value=row["NIST Controls"]).alignment = WRAP
            ws.cell(row=i, column=6, value=row["ISO 27001 Controls"]).alignment = WRAP
            for col in range(1, 7):
                ws.cell(row=i, column=col).border = BORDER
        ws.auto_filter.ref = f"A4:F{4 + len(mappings)}"

    # -- 6. Prioritized remediation plan -----------------------------------
    def _remediation_sheet(self, wb, summary: ExecutiveSummary) -> None:
        ws = wb.create_sheet("Remediation Plan")
        _title_block(ws, "PRIORITIZED REMEDIATION PLAN", "Ranked by CVSS base score (highest first)", "13795B")

        headers = ["Priority", "ID", "Finding", "Score", "Severity", "OWASP", "Recommended Action"]
        width_map = {1: 10, 2: 10, 3: 42, 4: 8, 5: 12, 6: 8, 7: 60}
        _style_header(ws, 4, headers, width_map)

        for i, priority in enumerate(summary.priorities, start=5):
            ws.cell(row=i, column=1, value=priority.rank).alignment = CENTER
            ws.cell(row=i, column=2, value=priority.finding_id).font = BODY_FONT
            ws.cell(row=i, column=3, value=priority.title).font = BODY_FONT
            score_cell = ws.cell(row=i, column=4, value=round(priority.score, 1))
            score_cell.number_format = "0.0"
            score_cell.alignment = CENTER
            sev_cell = ws.cell(row=i, column=5, value=priority.severity.value)
            sev_cell.fill = _severity_fill(priority.severity)
            sev_cell.font = Font(bold=True, color="FFFFFF")
            sev_cell.alignment = CENTER
            ws.cell(row=i, column=6, value=priority.owasp_id).font = BODY_FONT
            ws.cell(row=i, column=7, value=priority.remediation).alignment = WRAP
            for col in range(1, 8):
                ws.cell(row=i, column=col).border = BORDER