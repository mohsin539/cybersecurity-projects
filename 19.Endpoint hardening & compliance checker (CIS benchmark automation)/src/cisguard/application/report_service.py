"""ReportService: HTML / JSON / CSV exports + SQLite scan history.

HTML is self-contained (inline CSS, no external fetches — CSP-friendly,
security.md §3 A05). JSON is machine-readable for SIEM/GPO pipelines.
"""

from __future__ import annotations

import html
import json
import sqlite3
from pathlib import Path

from cisguard.domain.models import ScanRecord, Status

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    started_at TEXT, finished_at TEXT,
    hostname TEXT, os_caption TEXT,
    total INTEGER, passed INTEGER, failed INTEGER, errors INTEGER, not_applicable INTEGER,
    score REAL
);
CREATE TABLE IF NOT EXISTS findings (
    scan_id TEXT REFERENCES scans(id),
    control_id TEXT, status TEXT, observed TEXT, expected TEXT
);
"""


class HistoryStore:
    def __init__(self, path: Path) -> None:
        self._conn = sqlite3.connect(str(path))
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    def save(self, record: ScanRecord) -> None:
        s = record.summary
        self._conn.execute(
            "INSERT OR REPLACE INTO scans VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (s.scan_id, s.started_at.isoformat(), s.finished_at.isoformat(),
             s.hostname, s.os_caption, s.total, s.passed, s.failed, s.errors,
             s.not_applicable, s.score),
        )
        self._conn.executemany(
            "INSERT INTO findings VALUES(?,?,?,?,?)",
            [(s.scan_id, r.control_id, r.status.value, r.observed, r.expected)
             for r in record.results],
        )
        self._conn.commit()

    def list_scans(self) -> list[tuple]:
        return self._conn.execute(
            "SELECT id, started_at, hostname, score, passed, failed, errors FROM scans ORDER BY started_at DESC"
        ).fetchall()

    def close(self) -> None:
        self._conn.close()


class ReportService:
    def export_html(self, record: ScanRecord, out: Path) -> Path:
        s = record.summary
        rows = []
        for r in record.results:
            c = record.controls_by_id[r.control_id]
            color = {"PASS": "#1a7f37", "FAIL": "#c62828", "ERROR": "#9e9e9e", "N/A": "#8d6e63"}[r.status.value]
            rows.append(
                f"<tr><td>{html.escape(c.control_id)}</td>"
                f"<td>{html.escape(c.category.value)}</td>"
                f"<td>{html.escape(c.title)}</td>"
                f"<td>L{c.level} {c.severity.value}</td>"
                f"<td style='color:{color};font-weight:700'>{r.status.value}</td>"
                f"<td><code>{html.escape(r.observed)}</code></td>"
                f"<td><code>{html.escape(r.expected)}</code></td>"
                f"<td class='ev'>{html.escape(r.evidence.source)}</td></tr>"
            )
        doc = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<title>CISGuard Report {html.escape(s.scan_id)}</title>
<style>
body{{font-family:Segoe UI,Arial,sans-serif;margin:24px;color:#1c1c1c}}
h1{{margin-bottom:0}} .sub{{color:#555;margin-bottom:18px}}
.kpis{{display:flex;gap:14px;margin:14px 0 22px}}
.kpi{{border:1px solid #ddd;border-radius:8px;padding:10px 16px;min-width:110px}}
.kpi b{{display:block;font-size:26px}}
table{{border-collapse:collapse;width:100%;font-size:13px}}
th,td{{border:1px solid #ddd;padding:6px 8px;text-align:left;vertical-align:top}}
th{{background:#f5f5f5}} .ev{{color:#555;font-family:Consolas,monospace;font-size:11px}}
</style></head><body>
<h1>CISGuard Compliance Report</h1>
<div class="sub">{html.escape(s.hostname)} — {html.escape(s.os_caption)} — scan {html.escape(s.scan_id)}
@ {html.escape(s.finished_at.isoformat(timespec='seconds'))}</div>
<div class="kpis">
<div class="kpi">Score<b>{s.score}</b></div>
<div class="kpi">Passed<b>{s.passed}</b></div>
<div class="kpi" style="border-color:#c62828">Failed<b>{s.failed}</b></div>
<div class="kpi">Errors<b>{s.errors}</b></div>
<div class="kpi">N/A<b>{s.not_applicable}</b></div>
</div>
<table><thead><tr><th>ID</th><th>Category</th><th>Control</th><th>Level/Severity</th>
<th>Status</th><th>Observed</th><th>Expected</th><th>Evidence source</th></tr></thead>
<tbody>{''.join(rows)}</tbody></table>
<p class="sub">Read-only assessment. Evidence retained verbatim. Remediation guidance is advisory —
apply changes via approved change management.</p>
</body></html>"""
        out = Path(out)
        out.write_text(doc, encoding="utf-8")
        return out

    def export_json(self, record: ScanRecord, out: Path) -> Path:
        payload = {
            "scan": {
                "id": record.summary.scan_id,
                "hostname": record.summary.hostname,
                "os": record.summary.os_caption,
                "started_at": record.summary.started_at.isoformat(),
                "finished_at": record.summary.finished_at.isoformat(),
                "score": record.summary.score,
                "counts": {
                    "total": record.summary.total, "passed": record.summary.passed,
                    "failed": record.summary.failed, "errors": record.summary.errors,
                    "not_applicable": record.summary.not_applicable,
                },
            },
            "results": [
                {
                    "control_id": r.control_id,
                    "title": record.controls_by_id[r.control_id].title,
                    "category": record.controls_by_id[r.control_id].category.value,
                    "level": record.controls_by_id[r.control_id].level,
                    "severity": record.controls_by_id[r.control_id].severity.value,
                    "status": r.status.value,
                    "observed": r.observed,
                    "expected": r.expected,
                    "evidence_source": r.evidence.source,
                    "recommendation": record.controls_by_id[r.control_id].recommendation,
                }
                for r in record.results
            ],
        }
        out = Path(out)
        out.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        return out

    def export_csv(self, record: ScanRecord, out: Path) -> Path:
        import csv

        out = Path(out)
        with out.open("w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(["control_id", "category", "title", "level", "severity",
                        "status", "observed", "expected", "evidence_source", "recommendation"])
            for r in record.results:
                c = record.controls_by_id[r.control_id]
                w.writerow([c.control_id, c.category.value, c.title, c.level, c.severity.value,
                            r.status.value, r.observed, r.expected, r.evidence.source,
                            c.recommendation])
        return out
