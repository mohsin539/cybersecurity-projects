"""JSON exporter - machine-readable full bundle."""

from __future__ import annotations

import json
from pathlib import Path

from src.reporting.bundle import ReportBundle


def export_json(bundle: ReportBundle, out_path: Path) -> Path:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "project": bundle.project,
        "version": bundle.version,
        "generated_at": bundle.generated_at,
        "meta": bundle.meta,
        "framework_stats": bundle.framework_stats,
        "flows": bundle.verdict_rows(),
        "findings": bundle.finding_rows(),
        "records": bundle.summary_of_records(),
    }
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)
    return out_path