"""Flatten run results into RFC-4180 .CSV exports (architecture section 6).

Writes alerts.csv, iocs.csv, metrics.csv and compliance.csv - the
machine-readable / SIEM-ready layer of the report set.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path


def _dump(path: Path, header: list[str], rows: list[list]):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8-sig") as fh:
        w = csv.writer(fh)
        w.writerow(header)
        w.writerows(rows)


def write_csv(run_result: dict, out_dir: str | Path) -> list[Path]:
    d = Path(out_dir)
    d.mkdir(parents=True, exist_ok=True)
    metrics = run_result["metrics"]
    alerts = run_result["alerts"]

    written: list[Path] = []

    alerts_path = d / "alerts.csv"
    _dump(alerts_path,
          ["ts_iso", "detector", "rule_id", "score", "severity", "src_ip", "dst_ip",
           "dst_port", "channel", "agent_id", "mitre_technique", "true_positive"],
          [[a["ts_iso"], a["detector"], a["rule_id"], a["score"], a["severity"],
            a["src_ip"], a["dst_ip"], a["dst_port"], a["channel"], a["agent_id"],
            a["mitre_technique"], a["true_positive"]] for a in alerts])
    written.append(alerts_path)

    iocs = []
    for a in alerts:
        for ioc in ("dst_ip", "src_ip"):
            iocs.append(["ipv4", a[ioc], a["detector"], a["ts_iso"], a["mitre_technique"]])
        if a["channel"]:
            iocs.append(["channel", a["channel"], a["detector"], a["ts_iso"], "T1071.001"])
    iocs_path = d / "iocs.csv"
    _dump(iocs_path, ["ioc_type", "ioc_value", "source", "first_seen", "mitre"], iocs)
    written.append(iocs_path)

    metrics_path = d / "metrics.csv"
    _dump(metrics_path, ["kpi", "value"],
          [[k, v] for k, v in metrics.items()])
    written.append(metrics_path)

    compliance_path = d / "compliance.csv"
    from core.compliance import COMPLIANCE_MATRIX
    _dump(compliance_path, ["framework", "control", "topic", "implemented_by", "status"],
          [[c["framework"], c["control"], c["topic"], c["artifact"], c["status"]]
           for c in COMPLIANCE_MATRIX])
    written.append(compliance_path)

    # machine-readable JSONL of the raw event stream (pcap stand-in)
    raw_path = d / "events.jsonl"
    with raw_path.open("w", encoding="utf-8") as fh:
        for ev in run_result.get("events") or []:
            fh.write(json.dumps(ev, ensure_ascii=False) + "\n")
    written.append(raw_path)
    return written