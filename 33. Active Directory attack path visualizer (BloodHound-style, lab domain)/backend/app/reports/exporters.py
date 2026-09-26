"""GRC export: PDF (executive + detail) and CSV reports for findings and
compliance posture. CSV is Excel/formula-injection-safe; PDF renders a
bank-ready layout with risk tables and per-control status."""
from __future__ import annotations

import csv
import io
import time
from typing import Any

from app.compliance import mapper as compliance_mapper
from app.findings import rules as findings_engine
from app.graph.store import GraphStore

CSV_INJECTION_PREFIXES = ("=", "+", "@", "\r", "\t")


def _csv_safe(value: Any) -> str:
    """Neutralize spreadsheet formula injection (OWASP CSV injection)."""
    s = "" if value is None else str(value)
    if s.startswith(CSV_INJECTION_PREFIXES):
        s = "'" + s
    return s


def _ts() -> str:
    return time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime())


# ------------------------------------------------------------------ CSV -----
def findings_csv(store: GraphStore) -> bytes:
    findings = findings_engine.run_all_rules(store)
    buf = io.StringIO()
    w = csv.writer(buf, quoting=csv.QUOTE_MINIMAL)
    w.writerow(["finding_id", "title", "severity", "category",
                "affected_id", "affected_label", "why",
                "mitre", "remediation"])
    for f in findings:
        if not f.affected:
            w.writerow([f.id, f.title, f.severity, f.category,
                        "", "", "", ";".join(f.mitre), f.remediation])
        for a in f.affected:
            w.writerow([f.id, f.title, f.severity, f.category,
                        _csv_safe(a.get("id")), _csv_safe(a.get("label")),
                        _csv_safe(a.get("why")),
                        ";".join(f.mitre), _csv_safe(f.remediation)])
    return buf.getvalue().encode("utf-8-sig")  # BOM: Excel-friendly


def compliance_csv(store: GraphStore) -> bytes:
    posture = compliance_mapper.compliance_posture(store)
    buf = io.StringIO()
    w = csv.writer(buf, quoting=csv.QUOTE_MINIMAL)
    w.writerow(["framework", "framework_name", "control_id", "control_title",
                "category", "status", "criticality", "statement"])
    for fw_id, fw in posture["frameworks"].items():
        for c in fw["controls"]:
            w.writerow([fw_id, fw["name"], c["id"], _csv_safe(c["title"]),
                        _csv_safe(c["category"]), c["status"],
                        c["criticality"], _csv_safe(c["statement"])])
    return buf.getvalue().encode("utf-8-sig")


# ------------------------------------------------------------------ PDF -----
_PAGE_W, _PAGE_H = 792, 612  # US Letter landscape (tables need width)

_SEV_COLOR = {"critical": "#DC2626", "high": "#EA580C", "medium": "#D97706",
              "low": "#64748B", "info": "#94A3B8"}
_STATUS_COLOR = {"pass": "#059669", "partial": "#D97706", "fail": "#DC2626"}


def _pdf_header(c, title: str, subtitle: str) -> float:
    from reportlab.lib.colors import HexColor
    from reportlab.pdfgen import canvas as _c  # noqa: F401
    y = _PAGE_H - 44
    c.setFillColor(HexColor("#0A0F1C"))
    c.rect(0, _PAGE_H - 30, _PAGE_W, 30, stroke=0, fill=1)
    c.setFillColor(HexColor("#22D3EE"))
    c.setFont("Helvetica-Bold", 8)
    c.drawString(36, _PAGE_H - 20, "SENTINELGRAPH  ·  LAB ASSESSMENT  ·  "
                 "CONFIDENTIAL — INTERNAL RESTRICTED")
    c.setFillColor(HexColor("#0A0F1C"))
    c.setFont("Helvetica-Bold", 18)
    c.drawString(36, y - 8, title)
    c.setFont("Helvetica", 9)
    c.setFillColor(HexColor("#475569"))
    c.drawString(36, y - 24, subtitle)
    c.setFont("Helvetica", 8)
    c.drawString(_PAGE_W - 200, y - 24, f"Generated: {_ts()}")
    return y - 44


def _pdf_footer(c, page_no: int, pages: int) -> None:
    c.setStrokeColor("#CBD5E1")
    c.setLineWidth(0.5)
    c.line(36, 36, _PAGE_W - 36, 36)
    c.setFont("Helvetica", 7.5)
    c.setFillColor("#64748B")
    c.drawString(36, 26, "SentinelGraph — AD attack path & compliance "
                 "posture. Handle per bank data classification policy.")
    c.drawRightString(_PAGE_W - 36, 26, f"Page {page_no} / {pages}")


def _wrap(text: str, font: str, size: float, width: float) -> list[str]:
    from reportlab.pdfbase.pdfmetrics import stringWidth
    words, lines, cur = text.split(), [], ""
    for w in words:
        t = (cur + " " + w).strip()
        if stringWidth(t, font, size) <= width:
            cur = t
        else:
            if cur:
                lines.append(cur)
            cur = w
    if cur:
        lines.append(cur)
    return lines or [""]


def _draw_kv(c, x: float, y: float, label: str, value: str,
             value_color: str = "#0A0F1C") -> float:
    c.setFont("Helvetica-Bold", 7.5)
    c.setFillColor("#64748B")
    c.drawString(x, y, label.upper())
    c.setFont("Helvetica-Bold", 13)
    c.setFillColor(value_color)
    c.drawString(x, y - 13, str(value))
    return y - 32


def findings_pdf(store: GraphStore) -> bytes:
    findings = findings_engine.run_all_rules(store)
    summary = findings_engine.findings_summary(findings)

    import tempfile, os
    fd, tmp = tempfile.mkstemp(suffix=".pdf")
    os.close(fd)

    # Page 1: executive summary
    lines_out: list[list[tuple]] = [[]]
    from reportlab.pdfgen import canvas as rl_canvas
    c = rl_canvas.Canvas(tmp, pagesize=(_PAGE_W, _PAGE_H))

    y = _pdf_header(
        c, "Findings Report",
        "AD misconfiguration assessment — risk-ranked, MITRE ATT&CK mapped")
    y = _draw_kv(c, 36, y, "Risk index",
                 f"{summary['risk_index']} / 100", "#DC2626")
    x2 = 250
    y2 = _draw_kv(c, x2, y + 32, "Total findings", summary["total"])
    _draw_kv(c, 470, y + 32, "Critical", summary["by_severity"]["critical"],
             "#DC2626")
    y = min(y, y2) - 6

    # Severity distribution bar
    total = max(1, summary["total"])
    bar_y = y - 6
    seg_x = 36
    for sev in ("critical", "high", "medium", "low", "info"):
        n = summary["by_severity"].get(sev, 0)
        if not n:
            continue
        seg_w = 520 * n / total
        c.setFillColor(_SEV_COLOR[sev])
        c.rect(seg_x, bar_y, seg_w, 12, stroke=0, fill=1)
        seg_x += seg_w
    c.setFont("Helvetica", 7.5)
    c.setFillColor("#475569")
    c.drawString(36, bar_y - 10,
                 "critical · high · medium · low · info distribution "
                 f"({summary['total']} findings)")
    y = bar_y - 30

    # Category chips
    chip_x = 36
    for cat, n in sorted(summary["by_category"].items(),
                         key=lambda kv: -kv[1]):
        label = f"{cat} ({n})"
        c.setFont("Helvetica-Bold", 7)
        w = c.stringWidth(label, "Helvetica-Bold", 7) + 10
        if chip_x + w > _PAGE_W - 36:
            chip_x = 36
            y -= 14
        c.setFillColor("#0E7490")
        c.rect(chip_x, y - 4, w, 12, stroke=0, fill=1)
        c.setFillColor("#FFFFFF")
        c.drawString(chip_x + 5, y - 1, label)
        chip_x += w + 6
    y -= 26

    # Findings detail
    for f in findings:
        if y < 120:
            c.showPage()
            y = _PAGE_H - 60
            c.setFont("Helvetica-Bold", 12)
            c.drawString(36, y, "Findings Report (cont.)")
            y -= 18
        c.setFillColor(_SEV_COLOR.get(f.severity, "#64748B"))
        c.rect(36, y - 2, 3, 12, stroke=0, fill=1)
        c.setFont("Helvetica-Bold", 10)
        c.setFillColor("#0A0F1C")
        c.drawString(46, y, f"{f.id} — {f.title}")
        c.setFont("Helvetica-Bold", 8)
        c.setFillColor(_SEV_COLOR.get(f.severity, "#64748B"))
        c.drawRightString(_PAGE_W - 36, y, f"{f.severity.upper()} · "
                          f"{len(f.affected)} affected")
        y -= 13
        c.setFont("Helvetica", 8)
        c.setFillColor("#334155")
        for ln in _wrap(f.description, "Helvetica", 8, _PAGE_W - 110)[:2]:
            c.drawString(46, y, ln)
            y -= 10
        mitre = "  ".join(f.mitre)
        if mitre:
            c.setFont("Courier-Bold", 7.5)
            c.setFillColor("#7C3AED")
            c.drawString(46, y, mitre)
            y -= 11
        for a in f.affected[:6]:
            c.setFont("Helvetica", 7.5)
            c.setFillColor("#475569")
            c.drawString(56, y, f"• {a.get('label','')} — {a.get('why','')}")
            y -= 9.5
        if len(f.affected) > 6:
            c.drawString(56, y, f"  … +{len(f.affected)-6} more (see CSV)")
            y -= 9.5
        c.setFont("Helvetica-Oblique", 7.5)
        c.setFillColor("#059669")
        for ln in _wrap("Remediation: " + f.remediation, "Helvetica-Oblique",
                        7.5, _PAGE_W - 100)[:2]:
            c.drawString(46, y, ln)
            y -= 9.5
        y -= 8

    _pdf_footer(c, 1, 1)
    c.save()
    with open(tmp, "rb") as fh:
        data = fh.read()
    os.unlink(tmp)
    return data


def compliance_pdf(store: GraphStore) -> bytes:
    posture = compliance_mapper.compliance_posture(store)
    import tempfile, os
    fd, tmp = tempfile.mkstemp(suffix=".pdf")
    os.close(fd)
    from reportlab.pdfgen import canvas as rl_canvas
    c = rl_canvas.Canvas(tmp, pagesize=(_PAGE_W, _PAGE_H))

    y = _pdf_header(
        c, "Compliance Posture Report",
        "OWASP Top 10 2021 · ISO/IEC 27001:2022 · NIST CSF 2.0 · "
        "NIST 800-53 r5 · PCI DSS 4.0 · CIS Controls v8")

    # Score table
    col_x = [36, 306, 470, 590, 660]
    c.setFont("Helvetica-Bold", 8)
    c.setFillColor("#0A0F1C")
    c.drawString(col_x[0], y, "Framework")
    c.drawString(col_x[1], y, "Pass")
    c.drawString(col_x[2], y, "Partial")
    c.drawString(col_x[3], y, "Fail")
    c.drawString(col_x[4], y, "Score")
    y -= 4
    c.setStrokeColor("#CBD5E1")
    c.line(36, y, _PAGE_W - 36, y)
    y -= 14
    for fw_id, fw in posture["frameworks"].items():
        score = fw["score"]
        color = ("#059669" if score >= 80 else
                 "#D97706" if score >= 55 else "#DC2626")
        c.setFont("Helvetica-Bold", 8.5)
        c.setFillColor("#0A0F1C")
        c.drawString(col_x[0], y, fw["name"])
        c.setFont("Helvetica", 8.5)
        c.setFillColor("#059669")
        c.drawString(col_x[1], y, str(fw["counts"]["pass"]))
        c.setFillColor("#D97706")
        c.drawString(col_x[2], y, str(fw["counts"]["partial"]))
        c.setFillColor("#DC2626")
        c.drawString(col_x[3], y, str(fw["counts"]["fail"]))
        c.setFont("Helvetica-Bold", 9)
        c.setFillColor(color)
        c.drawString(col_x[4], y, f"{score:.0f}")
        y -= 16
    y -= 8

    # Per-control matrix
    for fw_id, fw in posture["frameworks"].items():
        if y < 130:
            c.showPage()
            y = _PAGE_H - 60
            c.setFont("Helvetica-Bold", 12)
            c.drawString(36, y, "Compliance Posture Report (cont.)")
            y -= 18
        c.setFont("Helvetica-Bold", 10)
        c.setFillColor("#0E7490")
        c.drawString(36, y, fw["name"])
        y -= 13
        for ctl in fw["controls"]:
            if y < 90:
                c.showPage()
                y = _PAGE_H - 60
            c.setFillColor(_STATUS_COLOR[ctl["status"]])
            c.rect(40, y - 1.5, 3, 9, stroke=0, fill=1)
            c.setFont("Courier-Bold", 7.5)
            c.setFillColor("#334155")
            c.drawString(50, y, ctl["id"])
            c.setFont("Helvetica", 7.5)
            c.setFillColor("#0A0F1C")
            c.drawString(150, y, ctl["title"][:80])
            c.setFont("Helvetica-Bold", 7.5)
            c.setFillColor(_STATUS_COLOR[ctl["status"]])
            c.drawString(700, y, ctl["status"].upper())
            y -= 11.5
        y -= 6

    _pdf_footer(c, 1, 1)
    c.save()
    with open(tmp, "rb") as fh:
        data = fh.read()
    os.unlink(tmp)
    return data
