"""Compliance registry: maps app capabilities to ISO 27001:2022, NIST CSF 2.0,
NIST SP 800-53 Rev5 and OWASP Top 10 (2021) controls.

The dashboard and report generator consume this to produce a live posture view
(an executable Statement of Applicability for this lab tool).

Auto-scoring rule: a capability is "evidenced" when the labelled audit action
exists in the audit_events table within the window.
"""

from .db import query

FRAMEWORK_LABELS = {
    "ISO 27001:2022": "#00407a",
    "NIST CSF 2.0": "#002868",
    "NIST SP 800-53": "#3c5aa8",
    "OWASP Top 10": "#7a0b0b",
}

CONTROLS = [
    # (ref, framework, control, capability, audit_action(s) labelled)
    ("A.5.9", "ISO 27001:2022", "Inventory of information assets", "Evidence/case asset registry", ["EVIDENCE_CREATE"]),
    ("A.5.15", "ISO 27001:2022", "Access control", "RBAC roles (admin/examiner/auditor)", ["LOGIN"]),
    ("A.5.24", "ISO 27001:2022", "Incident response planning", "IR runbook integration hook", ["CASE_CREATE"]),
    ("A.8.2", "ISO 27001:2022", "Privileged access rights", "Role-gated privileged actions", ["COMPLIANCE_VIEW"]),
    ("A.8.15", "ISO 27001:2022", "Logging", "Hash-chained audit trail", ["AUDIT_EXPORT"]),
    ("A.8.16", "ISO 27001:2022", "Monitoring activities", "Chain verification job", ["COMPLIANCE_VIEW"]),
    ("A.8.24", "ISO 27001:2022", "Use of cryptography", "SHA-256 evidence + chain hashing", ["EVIDENCE_CREATE"]),
    ("A.8.28", "ISO 27001:2022", "Secure coding", "Parameterised SQL + autoescape", ["LOGIN"]),
    ("ID.AM-2", "NIST CSF 2.0", "Software platforms and applications inventory", "Evidence/case asset registry", ["EVIDENCE_CREATE"]),
    ("ID.RA-1", "NIST CSF 2.0", "Risk assessment", "Severity + finding taxonomy", ["ARTIFACT_CREATE"]),
    ("PR.DS-1", "NIST CSF 2.0", "Data-at-rest protection", "Envelope-encrypted dev DB + hashing", ["EVIDENCE_CREATE"]),
    ("PR.DS-4", "NIST CSF 2.0", "Data-integrity", "SHA-256 artifact verification", ["ARTIFACT_CREATE"]),
    ("RS.MA-1", "NIST CSF 2.0", "Incident monitoring", "Custody event stream", ["CUSTODY_EVENT"]),
    ("RC.RP-1", "NIST CSF 2.0", "Recovery plan", "Evidence restoration copies", ["REPORT_ORDERED"]),
    ("AU-2", "NIST SP 800-53", "Audit events", "Standardised audit event taxonomy", ["AUDIT_EXPORT"]),
    ("AU-10", "NIST SP 800-53", "Non-repudiation", "Hash chain + tamper verification", ["AUDIT_EXPORT"]),
    ("AU-11", "NIST SP 800-53", "Audit record retention", "Append-only WORM-style store", ["AUDIT_EXPORT"]),
    ("AC-3", "NIST SP 800-53", "Access enforcement", "Deny-by-default RBAC decorators", ["LOGIN"]),
    ("SI-7", "NIST SP 800-53", "Software/info integrity", "Signed report + chain checksum", ["REPORT_ORDERED"]),
    ("A01", "OWASP Top 10", "Broken access control", "Role decorators + RLS-like tenant checks", ["LOGIN"]),
    ("A02", "OWASP Top 10", "Cryptographic failures", "TLS + SHA-256 + hashed passwords", ["EVIDENCE_CREATE"]),
    ("A03", "OWASP Top 10", "Injection", "Parameterised queries only", ["LOGIN"]),
    ("A05", "OWASP Top 10", "Security misconfiguration", "Secure headers + minor error pages", ["LOGIN"]),
    ("A07", "OWASP Top 10", "Identification/auth failures", "Brute-force throttle + session hardening", ["LOGIN_FAILED"]),
    ("A08", "OWASP Top 10", "Software/data integrity failures", "CSRF tokens + signed reports", ["REPORT_ORDERED"]),
    ("A09", "OWASP Top 10", "Logging/monitoring failures", "Structured audit events", ["AUDIT_EXPORT"]),
    ("A10", "OWASP Top 10", "Server-side request forgery", "No server-side URL retrieval", ["LOGIN"]),
]


def posture(app):
    """Return per-control evidence status based on audit events in window."""
    window = app.config.get("COMPLIANCE_WINDOW_DAYS", 365)
    present = {r["action"] for r in query(
        "SELECT DISTINCT action FROM audit_events WHERE ts >= datetime('now', ?)",
        ("-%d days" % window,),
    )}
    rows = []
    evidenced = 0
    for ref, fw, control, cap, actions in CONTROLS:
        ok = any(a in present for a in actions)
        evidenced += 1 if ok else 0
        rows.append({"ref": ref, "framework": fw, "control": control, "capability": cap, "evidence": ok})
    return {"rows": rows, "evidenced": evidenced, "total": len(rows),
            "score": round(100.0 * evidenced / max(1, len(rows)), 1)}


def evidence_counts(app):
    window = app.config.get("COMPLIANCE_WINDOW_DAYS", 365)
    from collections import Counter
    c = Counter(r["action"] for r in query(
        "SELECT action FROM audit_events WHERE ts >= datetime('now', ?)",
        ("-%d days" % window,),
    ))
    return dict(c)