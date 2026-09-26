"""HTML dashboard reporter.

Builds a single self-contained, colorful HTML file (no external assets) that
can be emailed, hosted or archived: KPIs, risk posture, severity chart,
executive narrative, findings table and full framework coverage.
"""

from __future__ import annotations

import html
from typing import List

from ..analyzers.executive import ExecutiveSummary
from ..frameworks.catalog import all_owasp_categories
from ..models.finding import Finding
from ..models.framework import FrameworkMapping
from .base import BaseReporter, ReportResult

_CSS = """
:root {
  --bg:#0f172a; --panel:#1e293b; --panel2:#273549; --line:#334155;
  --text:#e2e8f0; --muted:#94a3b8; --brand:#38bdf8;
  --crit:#e03131; --high:#f76707; --med:#f5c400; --low:#40c057; --none:#868e96;
  --owasp:#d63384; --nist:#16a34a; --iso:#2563eb;
}
*{box-sizing:border-box; margin:0; padding:0;}
body{background:radial-gradient(1200px 600px at 80% -10%, #1e3a8a55, transparent), var(--bg);
  color:var(--text); font-family:'Segoe UI', system-ui, sans-serif; line-height:1.5; padding:24px;}
.wrap{max-width:1200px; margin:0 auto;}
header.hero{background:linear-gradient(135deg,#0c4a6e,#1d4ed8 45%,#7c3aed);
  border-radius:18px; padding:28px 32px; margin-bottom:24px; box-shadow:0 10px 30px #0005;}
header.hero h1{font-size:28px; letter-spacing:.5px;}
header.hero p{color:#cfe8ff; margin-top:6px;}
.header-meta{display:flex; gap:18px; flex-wrap:wrap; margin-top:12px; font-size:13px; color:#dbeafe;}
.badge{display:inline-block; padding:3px 10px; border-radius:999px; font-size:12px; font-weight:600;}
.kpis{display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr)); gap:14px; margin-bottom:24px;}
.kpi{background:var(--panel); border:1px solid var(--line); border-radius:14px; padding:18px; text-align:center;}
.kpi .num{font-size:30px; font-weight:800;}
.kpi .lbl{color:var(--muted); font-size:12px; text-transform:uppercase; letter-spacing:1px;}
.kpi.crit .num{color:var(--crit);} .kpi.high .num{color:var(--high);}
.kpi.med .num{color:var(--med);} .kpi.low .num{color:var(--low);} .kpi.risk .num{color:var(--brand);}
.panel{background:var(--panel); border:1px solid var(--line); border-radius:16px; padding:22px; margin-bottom:24px;}
.panel h2{font-size:18px; margin-bottom:14px; border-left:5px solid var(--brand); padding-left:12px;}
.panel h2.owasp{border-color:var(--owasp);} .panel h2.nist{border-color:var(--nist);} .panel h2.iso{border-color:var(--iso);}
.narrative{color:#cbd5e1; font-size:14.5px; white-space:pre-line;}
ol.recs{margin-left:20px; color:#cbd5e1;} ol.recs li{margin-bottom:8px;}
.chart{display:flex; align-items:flex-end; gap:18px; height:180px; padding-top:10px;}
.bar{flex:1; display:flex; flex-direction:column; align-items:center; gap:6px;}
.bar .fill{width:100%; min-height:4px; border-radius:6px 6px 0 0; transition:.3s;}
.bar span{font-size:12px; color:var(--muted);}
.legend{display:flex; gap:18px; margin-top:12px; font-size:13px; flex-wrap:wrap;}
.legend b{width:12px; height:12px; display:inline-block; border-radius:3px; margin-right:5px; vertical-align:-1px;}
table{width:100%; border-collapse:collapse; font-size:13.5px;}
th{background:var(--panel2); color:#fff; text-align:left; padding:10px; font-weight:600; cursor:default;}
td{padding:10px; border-top:1px solid var(--line); vertical-align:top;}
tr:hover td{background:#22304a;}
.chip{display:inline-block; margin:3px 5px 3px 0; padding:3px 9px; border-radius:999px; font-size:12px; font-weight:600;}
.chip.owasp{background:#d6338422; color:#f06595; border:1px solid #d6338455;}
.chip.nist{background:#16a34a22; color:#4ade80; border:1px solid #16a34a55;}
.chip.iso{background:#2563eb22; color:#8ab4ff; border:1px solid #2563eb55;}
footer{color:var(--muted); font-size:12px; text-align:center; padding:18px 0 8px;}
.sev{color:#fff; font-weight:700; padding:3px 10px; border-radius:999px; font-size:12px; white-space:nowrap;}
.small{color:var(--muted); font-size:12px;}
.heat{display:grid; grid-template-columns:repeat(auto-fit,minmax(190px,1fr)); gap:10px;}
.heat .cat{background:var(--panel2); border:1px solid var(--line); border-radius:12px; padding:12px;}
.heat .cat .top{display:flex; justify-content:space-between; align-items:center;}
.heat .cat code{color:var(--owasp); font-weight:700;}
.heat .cat .cnt{font-weight:800; font-size:18px;}
.pagerow{display:flex; align-items:center; gap:8px; margin-top:6px;}
.barline{height:8px; background:#0b1526; border-radius:6px; flex:1; overflow:hidden;}
.barline i{display:block; height:100%; border-radius:6px; background:linear-gradient(90deg,var(--brand),#7c3aed);}
"""


def _sev_class(severity) -> str:
    return severity.value.lower()


def _sev_color(severity) -> str:
    return severity.hex_color


def _chart_height(count: int, total: int) -> int:
    if total == 0:
        return 6
    return max(6, int((count / total) * 160))


class HTMLReporter(BaseReporter):
    """Renders the self-contained HTML dashboard."""

    def write(
        self,
        findings: List[Finding],
        summary: ExecutiveSummary,
        mappings: List[FrameworkMapping],
    ) -> ReportResult:
        body = self._build_body(findings, summary, mappings)
        page = (
            "<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'>"
            "<meta name='viewport' content='width=device-width,initial-scale=1'>"
            "<title>Red Team Engagement Report</title>"
            f"<style>{_CSS}</style></head><body><div class='wrap'>"
            f"{body}<footer>Generated by the Red Team Engagement Report Generator "
            "- findings &rarr; CVSS v3.1 &rarr; OWASP Top 10 / NIST 800-53 / ISO 27001 "
            "&rarr; executive summary. Report formats: .xlsx / .csv / .html.</footer>"
            "</div></body></html>"
        )

        path = self._stamp("red_team_engagement_report", "html")
        path.write_text(page, encoding="utf-8")
        result = ReportResult(format="html")
        result.add("dashboard", path)
        return result

    def _build_body(
        self,
        findings: List[Finding],
        summary: ExecutiveSummary,
        mappings: List[FrameworkMapping],
    ) -> str:
        dist = summary.distribution
        hero_meta = []
        if summary.customer:
            hero_meta.append(f"Customer: <b>{html.escape(summary.customer)}</b>")
        if summary.period:
            hero_meta.append(f"Period: <b>{html.escape(summary.period)}</b>")
        if summary.scope:
            hero_meta.append(f"Scope: <b>{html.escape(summary.scope)}</b>")
        hero_meta.append(f"Risk posture: <b>{summary.risk_rating} ({summary.risk_score:.0f}/100)</b>")

        kpis = "".join([
            self._kpi("Total Findings", summary.total_findings, "risk"),
            self._kpi("Critical", dist.critical, "crit"),
            self._kpi("High", dist.high, "high"),
            self._kpi("Medium", dist.medium, "med"),
            self._kpi("Low", dist.low, "low"),
        ])

        counts = [dist.critical, dist.high, dist.medium, dist.low, dist.none]
        bars = "".join(
            f"<div class='bar'><div class='fill' style='height:{_chart_height(c, summary.total_findings)}px;"
            f"background:{color}'></div><b>{c}</b><span>{label}</span></div>"
            for label, c, color in zip(
                ["Critical", "High", "Medium", "Low", "None"],
                counts,
                ["var(--crit)", "var(--high)", "var(--med)", "var(--low)", "var(--none)"],
            )
        )

        recs = "".join(f"<li>{html.escape(rec)}</li>" for rec in summary.recommendations)

        owasp_heat = self._owasp_heatmap(summary)

        mapping_by_id = {m.finding.id: m for m in mappings}
        findings_rows = "".join(
            self._finding_row(f, mapping_by_id.get(f.id)) for f in findings
        )

        nist_chips, iso_chips = self._framework_chips(mappings)
        plan_rows = "".join(
            "<tr>"
            f"<td>{p.rank}</td>"
            f"<td>{html.escape(p.finding_id)}</td>"
            f"<td>{html.escape(p.title)}</td>"
            f"<td><span class='sev' style='background:{_sev_color(p.severity)}'>{p.severity.value}</span></td>"
            f"<td>{p.score:.1f}</td>"
            f"<td>{html.escape(p.owasp_id)}</td>"
            f"<td>{html.escape(p.remediation)}</td>"
            "</tr>"
            for p in summary.priorities
        )

        return f"""
<header class='hero'>
  <h1>Red Team Engagement Report</h1>
  <p>{html.escape(summary.engagement_name)}</p>
  <div class='header-meta'>{"".join(f"<span>{m}</span>" for m in hero_meta)}</div>
</header>

<div class='kpis'>{kpis}</div>

<div class='panel'>
  <h2>Executive Summary</h2>
  <p class='narrative'>{html.escape(summary.narrative)}</p>
</div>

<div class='panel'>
  <h2>Severity Distribution</h2>
  <div class='chart'>{bars}</div>
  <div class='legend'>
    <span><b style='background:var(--crit)'></b>Critical (9.0-10.0)</span>
    <span><b style='background:var(--high)'></b>High (7.0-8.9)</span>
    <span><b style='background:var(--med)'></b>Medium (4.0-6.9)</span>
    <span><b style='background:var(--low)'></b>Low (0.1-3.9)</span>
    <span><b style='background:var(--none)'></b>None (0.0)</span>
    <span>Mean CVSS <b>{summary.avg_cvss:.1f}</b> &middot; Max <b>{summary.max_cvss:.1f}</b></span>
  </div>
</div>

<div class='panel'>
  <h2>Recommendations</h2>
  <ol class='recs'>{recs if recs else '<li>No remediation items required.</li>'}</ol>
</div>

<div class='panel'>
  <h2 class='owasp'>OWASP Top 10 (2021) Coverage</h2>
  <div class='heat'>{owasp_heat}</div>
</div>

<div class='panel'>
  <h2>Findings Detail</h2>
  <table>
    <tr><th>ID</th><th>Finding</th><th>Asset</th><th>OWASP</th><th>CVSS Vector</th><th>Score</th><th>Severity</th><th>Status</th></tr>
    {findings_rows}
  </table>
</div>

<div class='panel'>
  <h2 class='nist'>NIST SP 800-53 Rev.5 Controls Exercised</h2>
  {nist_chips}
</div>

<div class='panel'>
  <h2 class='iso'>ISO/IEC 27001:2022 Annex A Controls Exercised</h2>
  {iso_chips}
</div>

<div class='panel'>
  <h2 class='nist'>Prioritized Remediation Plan</h2>
  <table>
    <tr><th>#</th><th>ID</th><th>Finding</th><th>Severity</th><th>Score</th><th>OWASP</th><th>Recommended Action</th></tr>
    {plan_rows}
  </table>
</div>
"""

    def _kpi(self, label: str, value, cls: str) -> str:
        return (
            f"<div class='kpi {cls}'><div class='num'>{value}</div>"
            f"<div class='lbl'>{label}</div></div>"
        )

    def _owasp_heatmap(self, summary: ExecutiveSummary) -> str:
        cells = []
        for cat in all_owasp_categories():
            count = summary.owasp_counts.get(cat.code, 0)
            cells.append(f"""
<div class='cat'>
  <div class='top'><code>{cat.code}</code><span class='cnt'>{count}</span></div>
  <div class='small'>{html.escape(cat.name)}</div>
  <div class='pagerow'><div class='barline'><i style='width:{(count / max(summary.total_findings, 1)) * 100:.0f}%'></i></div>
  <span class='small'>{count}</span></div>
</div>""")
        return "".join(cells)

    def _finding_row(self, finding: Finding, mapping) -> str:
        nist = ", ".join(c.code for c in mapping.nist_controls) if mapping else ""
        iso = ", ".join(c.code for c in mapping.iso_controls) if mapping else ""
        return (
            "<tr>"
            f"<td><b>{html.escape(finding.id)}</b></td>"
            f"<td>{html.escape(finding.title)}<div class='small'>{html.escape(finding.description[:160])}</div></td>"
            f"<td>{html.escape(finding.asset)}<div class='small'>{html.escape(finding.source.value)}</div></td>"
            f"<td><span class='chip owasp'>{html.escape(finding.owasp_id)}</span>"
            f"<div class='small'>{nist}</div><div class='small'>{iso}</div></td>"
            f"<td class='small'>{html.escape(finding.cvss_vector)}</td>"
            f"<td><b>{finding.base_score:.1f}</b></td>"
            f"<td><span class='sev' style='background:{_sev_color(finding.severity)}'>"
            f"{finding.severity.value}</span></td>"
            f"<td>{html.escape(finding.status)}</td>"
            "</tr>"
        )

    def _framework_chips(self, mappings: List[FrameworkMapping]) -> tuple:
        nist_codes, iso_codes = [], []
        nist_seen, iso_seen = set(), set()
        for mapping in mappings:
            for control in mapping.nist_controls:
                if control.code not in nist_seen:
                    nist_seen.add(control.code)
                    nist_codes.append(control.code)
            for control in mapping.iso_controls:
                if control.code not in iso_seen:
                    iso_seen.add(control.code)
                    iso_codes.append(control.code)
        chips_nist = "".join(f"<span class='chip nist'>{c}</span>" for c in nist_codes)
        chips_iso = "".join(f"<span class='chip iso'>{c}</span>" for c in iso_codes)
        if chips_nist:
            chips_nist += f"<div class='small'>Tracing {len(nist_codes)} NIST controls referenced by findings.</div>"
        else:
            chips_nist = "<div class='small'>No findings to map.</div>"
        if chips_iso:
            chips_iso += f"<div class='small'>Tracing {len(iso_codes)} ISO 27001 controls referenced by findings.</div>"
        else:
            chips_iso = "<div class='small'>No findings to map.</div>"
        return chips_nist, chips_iso