"""CSV exporters - one file per report facet, UTF-8 BOM for Excel."""

from __future__ import annotations

import csv
from pathlib import Path
from typing import List

from src.reporting.bundle import ReportBundle


def _write_csv(path: Path, headers: List[str], rows: List[List]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8-sig") as fh:
        w = csv.writer(fh)
        w.writerow(headers)
        w.writerows(rows)


def export_csv(bundle: ReportBundle, out_dir: Path) -> List[Path]:
    written: List[Path] = []

    # 1. flow verdicts
    head = ["record_id", "scenario", "sni", "host_header", "dest_ip",
            "cdn_owner", "score", "label", "findings"]
    rows = [[r["record_id"], r["scenario"], r["sni"], r["host_header"],
             r["dest_ip"], r["cdn_owner"], r["score"], r["label"], r["findings"]]
            for r in bundle.verdict_rows()]
    p = out_dir / "flow_verdicts.csv"
    _write_csv(p, head, rows)
    written.append(p)

    # 2. findings
    head2 = ["record_id", "finding_id", "severity", "check", "title", "description", "evidence", "refs"]
    rows2 = [[f.record_id.split("-")[0], f.finding_id, f.severity.value,
              f.check, f.title, f.description, f.evidence, "|".join(f.refs)]
             for f in bundle.findings]
    p2 = out_dir / "findings.csv"
    _write_csv(p2, head2, rows2)
    written.append(p2)

    # 3. framework mapping
    head3 = ["framework", "ref", "title", "category", "status", "description"]
    rows3 = [[c.framework.value, c.ref, c.title, c.category, c.status, c.description]
             for c in _catalog()]
    p3 = out_dir / "framework_mapping.csv"
    _write_csv(p3, head3, rows3)
    written.append(p3)

    return written


def _catalog():
    from src.frameworks import build_catalog
    return build_catalog()