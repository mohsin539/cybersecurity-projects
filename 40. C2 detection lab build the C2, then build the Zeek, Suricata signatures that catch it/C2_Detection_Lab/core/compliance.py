"""Compliance register - architecture.md section 5 confirmed mappings.

Every lab artifact can be traced to a framework control. The register is
consumed by the reporting module (.XLSX compliance sheet, .CSV compliance file
and the HTML dashboard scorecard).
"""

COMPLIANCE_MATRIX: list[dict] = [
    # ----- ISO/IEC 27001:2022 Annex A -----
    {"framework": "ISO 27001", "control": "A.5.1 / A.5.2", "topic": "Policies + role-based access",
     "artifact": "gui RBAC, startup policy check", "status": "implemented"},
    {"framework": "ISO 27001", "control": "A.5.25", "topic": "Secure development lifecycle",
     "artifact": "SBOM + code-sign manifest (build pipeline)", "status": "implemented"},
    {"framework": "ISO 27001", "control": "A.8.10 / A.8.11", "topic": "Info deletion / review",
     "artifact": "one-command lab teardown + snapshot rollback", "status": "implemented"},
    {"framework": "ISO 27001", "control": "A.8.16 / A.8.17", "topic": "Monitoring + logging",
     "artifact": "pcap + notice.log + eve.json audit trail", "status": "implemented"},
    {"framework": "ISO 27001", "control": "A.8.28", "topic": "Secure coding",
     "artifact": "lint (ruff) + typecheck (mypy) + pytest CI gate", "status": "implemented"},
    {"framework": "ISO 27001", "control": "A.8.29", "topic": "Security testing",
     "artifact": "every lab run is a controlled, evidence-producing test", "status": "implemented"},

    # ----- NIST CSF 2.0 -----
    {"framework": "NIST CSF", "control": "IDENTIFY", "topic": "Asset inventory",
     "artifact": "component manifest written per run", "status": "implemented"},
    {"framework": "NIST CSF", "control": "PROTECT", "topic": "Sandbox isolation",
     "artifact": "localhost-only sockets, host firewall guidance", "status": "implemented"},
    {"framework": "NIST CSF", "control": "DETECT", "topic": "Zeek + Suricata engine",
     "artifact": "beacon.zeek + c2_beacon.rules + live alerts", "status": "implemented"},
    {"framework": "NIST CSF", "control": "RESPOND", "topic": "Alert workflow",
     "artifact": "normalized detections + severity scoring", "status": "implemented"},
    {"framework": "NIST CSF", "control": "RECOVER", "topic": "Snapshot rollback",
     "artifact": "teardown fn + state restore (see state.md)", "status": "implemented"},

    # ----- NIST SP 800-53 -----
    {"framework": "NIST 800-53", "control": "AC-2/AC-3", "topic": "Access control",
     "artifact": "PIN-lock + RBAC on lab console", "status": "implemented"},
    {"framework": "NIST 800-53", "control": "AU-6/AU-12", "topic": "Audit review + logging",
     "artifact": "SHA-256 evidence chain (audit.json)", "status": "implemented"},
    {"framework": "NIST 800-53", "control": "SI-4", "topic": "System monitoring",
     "artifact": "continuous alert collection during run", "status": "implemented"},
]

OWASP_CHECKLIST: list[dict] = [
    {"risk": "A01 Broken Access Control", "check": "PIN-lock + role gates on every destructive action",
     "status": "pass"},
    {"risk": "A02 Cryptographic Failures", "check": "AES-GCM payload, TLS 1.3, keys never hardcoded",
     "status": "pass"},
    {"risk": "A03 Injection", "check": "Rule/pattern input validated (LabConfig.validate)",
     "status": "pass"},
    {"risk": "A05 Security Misconfiguration", "check": "Secure defaults, ephemeral ports, no production exfiltration",
     "status": "pass"},
    {"risk": "A06 Vulnerable Components", "check": "pip-audit + SPDX SBOM enforced in CI",
     "status": "pass"},
    {"risk": "A07 Identification/Auth Failures", "check": "Strong PIN policy + lockout after 5 tries",
     "status": "pass"},
    {"risk": "A09 Logging Failures", "check": "Structured audit log, secrets never logged",
     "status": "pass"},
]