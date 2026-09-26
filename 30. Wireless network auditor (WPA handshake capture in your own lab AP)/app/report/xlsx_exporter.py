"""Minimal XLSX exporter - produces a valid Office Open XML workbook using
only the standard library (zipfile + XML). No openpyxl required.

Sheets: Dashboard, APs, Clients, Handshakes, Findings, Audit.
"""
import os
import xml.sax.saxutils as sax
import zipfile
from datetime import datetime, timezone

SEV_FILLS = {
    "Critical": "FF3D1513",
    "High": "FF3A2410",
    "Medium": "FF1E2A0B",
    "Low": "FF2C2308",
    "Info": "FF161B22",
}
SEV_FG = {
    "Critical": "FFF85149",
    "High": "FFF0883E",
    "Medium": "FF93D50A",
    "Low": "FFF0B429",
    "Info": "FF8B949E",
}


def _t(v):
    return sax.escape(str(v))


def sheet_xml(title, headers, rows, colors=None, col_widths=None):
    def styles_for(row_i, col_i, val):
        if row_i == 0:
            return 1  # header
        if colors:
            sev = str(val).strip()
            if sev in SEV_FILLS and col_i == 0:
                return 2 + list(SEV_FILLS).index(sev)
        return 0

    parts = [f'<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">']
    if col_widths:
        cols = "".join(f'<col min="{i+1}" max="{i+1}" width="{w}" customWidth="1"/>'
                       for i, w in enumerate(col_widths))
        parts.append(f"<cols>{cols}</cols>")
    parts.append("<sheetData>")
    for ri, row in enumerate([headers] + rows):
        parts.append(f'<row r="{ri+1}">')
        for ci, val in enumerate(row):
            st = styles_for(ri, ci, val)
            cell = f'<c r="{chr(65 + (ci % 26)) + str(ri + 1)}" s="{st}" t="inlineStr"><is><t>{_t(val)}</t></is></c>'
            parts.append(cell)
        parts.append("</row>")
    parts.append("</sheetData></worksheet>")
    return "".join(parts)


def export(data, path: str) -> str:
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")

    kpi = [
        ["Metric", "Value"],
        ["Generated At", now],
        ["Lab APs", data.stats["aps"]],
        ["Clients Seen", data.stats["clients"]],
        ["EAPOL Sessions", data.stats["sessions"]],
        ["Complete 4-Way Handshakes", data.stats["complete"]],
        ["Findings", data.stats["findings"]],
        ["Hash-Chain Length", data.chain.get("length", 0)],
        ["Hash-Chain Head", data.chain.get("head", "")],
    ]
    aps = [[a["ssid"], a["bssid"], a["channel"], a["cipher"], a["first_seen"]] for a in data.aps]
    clients = [[c["mac"], c["bssid"], c["first_seen"]] for c in data.clients]
    sessions = [[s["client"], s["bssid"], str(s["msgs"]), "Yes" if s["complete"] else "No", s["started"], s.get("finished", "")] for s in data.sessions]
    findings = [[f["severity"], f["title"], f["bssid"], f["ssid"], f["detail"], f["ts"]] for f in data.findings]
    audit = [[a["ts"], a["action"], a["detail"]] for a in data.audit]

    sheets = [
        ("Dashboard", ["Metric", "Value"], kpi[1:], None, [18, 90]),
        ("APs", ["SSID", "BSSID", "Channel", "Cipher", "First Seen"], aps, None, [20, 20, 10, 14, 24]),
        ("Clients", ["MAC", "Associated BSSID", "First Seen"], clients, None, [20, 20, 24]),
        ("Handshakes", ["Client", "AP BSSID", "Msgs", "Complete", "Started", "Finished"],
         sessions, None, [20, 20, 8, 10, 24, 24]),
        ("Findings", ["Severity", "Title", "BSSID", "SSID", "Detail", "Time"],
         findings, list(SEV_FILLS), [12, 34, 20, 20, 50, 24]),
        ("Audit", ["Time", "Action", "Detail"], audit, None, [24, 18, 60]),
    ]

    workbook = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
    )
    sheets_xml = "".join(
        f'<sheet name="{_t(name)}" sheetId="{i+1}" r:id="rId{i+1}"/>'
        for i, (name, *_rest) in enumerate(sheets)
    )
    workbook += f"<sheets>{sheets_xml}</sheets></workbook>"

    rels = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        f'<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>'
        f'<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>'
        "</Relationships>"
    )
    workbook_rels = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        f'<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>'
        f'<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet2.xml"/>'
        f'<Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet3.xml"/>'
        f'<Relationship Id="rId4" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet4.xml"/>'
        f'<Relationship Id="rId5" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet5.xml"/>'
        f'<Relationship Id="rId6" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet6.xml"/>'
        f'<Relationship Id="rId7" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>'
        "</Relationships>"
    )

    content_types = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
        '<Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>'
        f'<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
        f'<Override PartName="/xl/worksheets/sheet2.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
        f'<Override PartName="/xl/worksheets/sheet3.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
        f'<Override PartName="/xl/worksheets/sheet4.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
        f'<Override PartName="/xl/worksheets/sheet5.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
        f'<Override PartName="/xl/worksheets/sheet6.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
        f'<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>'
        "</Types>"
    )

    fills = [f'<fill><patternFill patternType="solid"><fgColor rgb="FF{SEV_FILLS[s]}"/><bgColor indexed="64"/></patternFill></fill>'
             for s in SEV_FILLS]
    xfs = ['<xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>',
           '<xf numFmtId="0" fontId="1" fillId="1" borderId="0" xfId="0" applyFont="1" applyFill="1"/>']
    for s in SEV_FILLS:
        xfs.append(f'<xf numFmtId="0" fontId="2" fillId="{2 + list(SEV_FILLS).index(s)}" borderId="0" xfId="0" applyFont="1" applyFill="1"/>')
    styles_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        '<fonts count="3">'
        '<font><sz val="11"/><name val="Segoe UI"/></font>'
        '<font><b/><sz val="11"/><color rgb="FFFFFFFF"/><name val="Segoe UI"/></font>'
        '<font><sz val="11"/><name val="Segoe UI"/></font>'
        "</fonts>"
        '<fills count="' + str(2 + len(SEV_FILLS)) + '">'
        '<fill><patternFill patternType="none"/></fill>'
        '<fill><patternFill patternType="solid"><fgColor rgb="FF30363D"/><bgColor indexed="64"/></patternFill></fill>'
        + "".join(fills) +
        "</fills>"
        '<borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders>'
        '<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>'
        f'<cellXfs count="{len(xfs)}">{"".join(xfs)}</cellXfs>'
        '<cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles>'
        "</styleSheet>"
    )

    core = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" '
        'xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" '
        'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
        f"<dc:title>Wireless Network Auditor Report</dc:title>"
        f"<dc:creator>Lab Security Team</dc:creator>"
        f'<dcterms:created xsi:type="dcterms:W3CDTF">{now}</dcterms:created>'
        "</cp:coreProperties>"
    )

    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", content_types)
        z.writestr("_rels/.rels", rels)
        z.writestr("docProps/core.xml", core)
        z.writestr("xl/workbook.xml", workbook)
        z.writestr("xl/_rels/workbook.xml.rels", workbook_rels)
        z.writestr("xl/styles.xml", styles_xml)
        for i, (name, headers, rows, colors, widths) in enumerate(sheets, 1):
            z.writestr(f"xl/worksheets/sheet{i}.xml", sheet_xml(name, headers, rows, colors, widths))
    return path