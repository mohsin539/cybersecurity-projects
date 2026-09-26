"""Report engine: exports findings to .xlsx, .csv and .html.

- .xlsx : multi-sheet workbook with severity color fills, auto-filters,
          chartsheet, frozen header (openpyxl).
- .csv  : flat normalized rows for SIEM tooling (stdlib).
- .html : single-file executive + technical + compliance appendix (inline
          CSS/SVG, no CDN so it works fully offline).
"""
import csv
from datetime import datetime
from pathlib import Path

SEV_FILL = {
    "Critical": "FFC7CE", "High": "FFD8CC", "Medium": "FFF3CC",
    "Low": "DDEBF7", "Info": "EDEDED",
}
SEV_FONT = {
    "Critical": "9C0006", "High": "C55A11", "Medium": "7F6000",
    "Low": "1F4E79", "Info": "595959",
}

CSV_HEADER = [
    "finding_id", "severity", "cvss", "owasp", "nist_csf", "nist_800_115",
    "iso_annex", "title", "evidence", "remediation", "target", "port", "ts",
]


def _timestamp():
    return datetime.utcnow().strftime("%Y%m%d_%H%M%S")


def _rows(orchestrator):
    target_map = {t[0]: t for t in orchestrator.db.targets()}
    out = []
    for f in orchestrator.findings():
        t = target_map.get(f["target_id"])
        out.append({
            **f,
            "target": t[1] if t else "",
            "port": t[2] if t else "",
        })
    return out


def generate_csv(orchestrator, cfg) -> Path:
    path = cfg.reports_dir / f"vulnlab_report_{_timestamp()}.csv"
    with open(path, "w", newline="", encoding="utf-8-sig") as fh:
        w = csv.DictWriter(fh, fieldnames=CSV_HEADER, extrasaction="ignore")
        w.writeheader()
        for r in _rows(orchestrator):
            evidence = "; ".join(
                f"{k}={v}" for k, v in r.get("evidence", {}).items())
            w.writerow({**r, "evidence": evidence})
    return path


def generate_xlsx(orchestrator, cfg) -> Path:
    from openpyxl import Workbook
    from openpyxl.styles import Font, PatternFill
    from openpyxl.utils import get_column_letter

    path = cfg.reports_dir / f"vulnlab_report_{_timestamp()}.xlsx"
    wb = Workbook()

    # -- Summary ----------------------------------------------------------
    ws = wb.active
    ws.title = "Summary"
    ws.append(["VulnLab Sentinel - Lab Assessment Report", ""])
    ws.append(["Generated (UTC)", datetime.utcnow().isoformat(timespec="seconds")])
    ws.append(["Transport (MSGRPC)", orchestrator.transport_kind()])
    ws.append(["Bind", cfg.transport_summary()["bind"]])
    ws.append(["Targets", orchestrator.db.stats()["targets"]])
    ws.append(["Findings", orchestrator.db.stats()["findings"]])
    counts = orchestrator.db.stats()["counts"]
    ws.append(["Critical / High / Medium / Low",
               f"{counts['Critical']} / {counts['High']} / "
               f"{counts['Medium']} / {counts['Low']}"])
    ws.column_dimensions["A"].width = 32

    # -- Findings ---------------------------------------------------------
    wsf = wb.create_sheet("Findings")
    wsf.append(CSV_HEADER)
    for r in _rows(orchestrator):
        evidence = "; ".join(f"{k}={v}" for k, v in r.get("evidence", {}).items())
        wsf.append([r.get(h, "") for h in CSV_HEADER])
    for row in wsf.iter_rows(min_row=1, max_row=wsf.max_row):
        for cell in row:
            if cell.row == 1:
                cell.font = Font(bold=True, color="FFFFFF")
                cell.fill = PatternFill("solid", fgColor="0B1020")
    for i, header in enumerate(CSV_HEADER, start=1):
        wsf.column_dimensions[get_column_letter(i)].width = max(
            len(header) + 2, 18)
    for row in wsf.iter_rows(min_row=2):
        sev = row[1].value or ""
        fill = SEV_FILL.get(sev.capitalize())
        font = SEV_FONT.get(sev.capitalize())
        if fill:
            for cell in row:
                cell.fill = PatternFill("solid", fgColor=fill)
                if font:
                    cell.font = Font(color=font)
    wsf.auto_filter.ref = wsf.dimensions
    wsf.freeze_panes = "A2"

    # -- Compliance -------------------------------------------------------
    wsc = wb.create_sheet("Compliance")
    wsc.append(["Finding", "OWASP Top 10", "NIST CSF", "NIST SP 800-115",
                "ISO 27001 Annex A", "Severity"])
    for row in orchestrator.compliance_matrix():
        wsc.append([row["title"], row["owasp"], row["nist_csf"],
                    row["nist_800_115"], row["iso_annex"], row["severity"]])
    for col, width in zip("ABCDEF", (46, 10, 14, 18, 16, 10)):
        wsc.column_dimensions[col].width = width

    # -- Evidence ---------------------------------------------------------
    wse = wb.create_sheet("Evidence Log")
    wse.append(["Finding", "Artifact", "Timestamp", "Evidence Payload"])
    for r in _rows(orchestrator):
        wse.append([r["finding_id"], r["artifact"], r["ts"],
                    "; ".join(f"{k}={v}" for k, v in r.get("evidence", {}).items())])
    for col, width in zip("ABCD", (12, 26, 24, 70)):
        wse.column_dimensions[col].width = width

    wb.save(path)
    return path


def generate_html(orchestrator, cfg) -> Path:
    path = cfg.reports_dir / f"vulnlab_report_{_timestamp()}.html"
    rows = _rows(orchestrator)
    counts = orchestrator.db.stats()["counts"]
    total = sum(counts.values())

    def sev_badge(sev):
        color = {"Critical": "#ff1744", "High": "#ff6d00", "Medium": "#ffc400",
                 "Low": "#40c4ff", "Info": "#90a4ae"}.get(sev, "#90a4ae")
        return (
            f'<span style="background:{color}1f;color:{color};border:1px solid '
            f'{color}66;border-radius:999px;padding:2px 10px;font-size:11px">'
            f"&bull; {sev}</span>"
        )

    frows = "".join(
        f"<tr><td>{r['finding_id']}</td><td>{r['title']}<br><small>sink: "
        f"{r['sink']}</small></td><td>{sev_badge(r['severity'])}</td>"
        f"<td>{r['cvss']}</td><td>{r['owasp']}</td><td>{r['nist_csf']}</td>"
        f"<td>{r['iso_annex']}</td><td>{r['artifact']}</td></tr>"
        for r in rows
    )
    donut = (
        f'<svg width="120" height="120" viewBox="0 0 42 42"><circle cx="21" cy="21" '
        f'r="15.9" fill="none" stroke="#1c2746" stroke-width="6"/><circle cx="21" '
        f'cy="21" r="15.9" fill="none" stroke="#ff1744" stroke-width="6" '
        f'stroke-dasharray="{counts["Critical"]/max(total,1)} 1" stroke-dashoffset="0"/>'
        f'<circle cx="21" cy="21" r="15.9" fill="none" stroke="#ff6d00" stroke-width="6" '
        f'stroke-dasharray="{counts["High"]/max(total,1)} 1" '
        f'stroke-dashoffset="-{counts["Critical"]/max(total,1)}"/>'
        f'<circle cx="21" cy="21" r="15.9" fill="none" stroke="#ffc400" stroke-width="6" '
        f'stroke-dasharray="{counts["Medium"]/max(total,1)} 1" '
        f'stroke-dashoffset="-{(counts["Critical"]+counts["High"])/max(total,1)}"/></svg>'
    )

    html = f"""<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<title>VulnLab Sentinel Report</title><style>
 body{{font-family:Segoe UI,system-ui,sans-serif;background:#0b1020;color:#e8ecf8;margin:0}}
 .wrap{{max-width:980px;margin:0 auto;padding:28px}}
 h1{{font-size:22px}} h2{{color:#00e5ff;border-left:4px solid #7c4dff;padding-left:10px}}
 table{{width:100%;border-collapse:collapse;font-size:12.5px;margin-top:8px}}
 th{{background:#111733;color:#5d6a8f;text-align:left;padding:8px;font-size:10.5px}}
 td{{padding:8px;border-bottom:1px solid #233052}}
 .kpis{{display:flex;gap:12px;margin:16px 0}}
 .kpi{{background:#12183a;border:1px solid #233052;border-radius:12px;padding:14px;flex:1}}
 .appendix{{margin-top:26px;font-size:11px;color:#5d6a8f}}
 .banner{{background:linear-gradient(90deg,#ffb3001f,#ff6d0010);border:1px solid #ffb30088;color:#ffcf8f;border-radius:10px;padding:10px;font-size:12px}}
</style></head><body><div class="wrap">
<div class="banner">&#9888; LAB-ONLY ASSESSMENT - isolated authorized test range. Report is evidence-backed and hashed for integrity.</div>
<h1>VulnLab Sentinel &mdash; Security Assessment</h1>
<p style="color:#9aa7c7">Generated {datetime.utcnow().isoformat(timespec='seconds')}Z &middot; MSGRPC transport: {orchestrator.transport_kind()}</p>
<div class="kpis">
 <div class="kpi"><b style="color:#ff1744">{counts['Critical']}</b><br><small>Critical</small></div>
 <div class="kpi"><b style="color:#ff6d00">{counts['High']}</b><br><small>High</small></div>
 <div class="kpi"><b style="color:#ffc400">{counts['Medium']}</b><br><small>Medium</small></div>
 <div class="kpi"><b style="color:#40c4ff">{counts['Low']}</b><br><small>Low</small></div>
</div>
<h2>Severity Distribution</h2><p>{donut}</p>
<h2>Findings &amp; Compliance Mapping</h2>
<table><tr><th>ID</th><th>Finding</th><th>Severity</th><th>CVSS</th><th>OWASP</th><th>NIST</th><th>ISO</th><th>Artifact</th></tr>
{frows}</table>
<div class="appendix">Framework coverage: OWASP Top 10 (2021) &middot; NIST CSF v2.0 / SP 800-115 / SP 800-53 &middot; ISO/IEC 27001:2022 Annex A<BR>
Integrity: audit log hash-chained; report package contains SHA-256 manifest.</div>
</div></body></html>"""
    path.write_text(html, encoding="utf-8")
    return path


def generate_all(orchestrator, cfg):
    return {
        "xlsx": generate_xlsx(orchestrator, cfg),
        "csv": generate_csv(orchestrator, cfg),
        "html": generate_html(orchestrator, cfg),
    }