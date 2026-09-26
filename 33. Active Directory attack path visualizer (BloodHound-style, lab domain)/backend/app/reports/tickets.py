"""Per-finding ticket exports for ITSM handoff (Jira / ServiceNow CSV).

One row = one ticket = one finding, with a stable external id (the finding
id) so imports deduplicate on re-export. Content matches what GRC analysts
need to open actionable tickets: what is wrong, where, why, and the fix.
"""
from __future__ import annotations

import csv
import io
from typing import Any

from app.findings import rules as findings_engine
from app.graph.store import GraphStore
from app.reports.exporters import _csv_safe

# Jira priority ladder (default priority scheme)
_JIRA_PRIORITY = {"critical": "Highest", "high": "High", "medium": "Medium",
                  "low": "Low", "info": "Lowest"}
# ServiceNow priority = impact x urgency (standard 1-4 ladder)
_SN_PRIORITY = {"critical": "1 - Critical", "high": "2 - High",
                "medium": "3 - Moderate", "low": "4 - Low",
                "info": "4 - Low"}
_SN_IMPACT = {"critical": "1 - High", "high": "1 - High", "medium": "2 - Medium",
              "low": "3 - Low", "info": "3 - Low"}
_SN_URGENCY = {"critical": "1 - High", "high": "2 - Medium",
               "medium": "2 - Medium", "low": "3 - Low", "info": "3 - Low"}

_JIRA_TYPE = "Task"          # generic; map to "Security" type if configured
_SN_CATEGORY = "Vulnerability"
_SN_CI = "Active Directory"  # configuration item class for the whole domain


def _description(f) -> str:
    lines = [f.description, "", "Affected principals:"]
    for a in f.affected[:10]:
        lines.append(f"  - {a.get('label', '')} ({a.get('id', '')}) — "
                     f"{a.get('why', '')}")
    if len(f.affected) > 10:
        lines.append(f"  … and {len(f.affected) - 10} more (see findings CSV)")
    lines += ["", f"Remediation: {f.remediation}",
              f"MITRE ATT&CK: {', '.join(f.mitre) or 'n/a'}",
              "", "-- SentinelGraph lab assessment (Confidential)"]
    return "\n".join(lines)


def _select(store: GraphStore, finding_ids: list[str] | None,
            sev_min: str | None):
    findings = findings_engine.run_all_rules(store)
    if finding_ids:
        want = set(finding_ids)
        findings = [f for f in findings if f.id in want]
    if sev_min:
        rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        if sev_min in rank:
            findings = [f for f in findings
                        if rank.get(f.severity, 9) <= rank[sev_min]]
    return findings


def tickets_jira_csv(store: GraphStore, finding_ids: list[str] | None = None,
                     sev_min: str | None = None) -> bytes:
    rows = _select(store, finding_ids, sev_min)
    buf = io.StringIO()
    w = csv.writer(buf, quoting=csv.QUOTE_MINIMAL)
    # Headers match Jira's CSV importer defaults; "Summary/Description/Issue
    # Type/Priority/Labels" import cleanly into any Jira project.
    w.writerow(["Summary", "Description", "Issue Type", "Priority",
                "Labels", "External ID"])
    for f in rows:
        summary = _csv_safe(
            f"[{f.severity.upper()}] {f.id} — {f.title} "
            f"({len(f.affected)} affected)")
        labels = " ".join(["sentinelgraph", f.category,
                           *(t.lower().replace('.', '_') for t in f.mitre)])
        w.writerow([summary, _csv_safe(_description(f)), _JIRA_TYPE,
                    _JIRA_PRIORITY.get(f.severity, "Medium"),
                    _csv_safe(labels), f.id])
    return buf.getvalue().encode("utf-8-sig")


def tickets_servicenow_csv(store: GraphStore,
                           finding_ids: list[str] | None = None,
                           sev_min: str | None = None) -> bytes:
    rows = _select(store, finding_ids, sev_min)
    buf = io.StringIO()
    w = csv.writer(buf, quoting=csv.QUOTE_MINIMAL)
    # Headers match ServiceNow's standard import (transform) column labels.
    w.writerow(["Short description", "Description", "Priority", "Impact",
                "Urgency", "Category", "Configuration item",
                "Correlation ID"])
    for f in rows:
        short = _csv_safe(
            f"[{f.severity.upper()}] {f.id} — {f.title} "
            f"({len(f.affected)} affected)")
        w.writerow([short, _csv_safe(_description(f)),
                    _SN_PRIORITY.get(f.severity, "3 - Moderate"),
                    _SN_IMPACT.get(f.severity, "2 - Medium"),
                    _SN_URGENCY.get(f.severity, "2 - Medium"),
                    _SN_CATEGORY, _SN_CI, f.id])
    return buf.getvalue().encode("utf-8-sig")
