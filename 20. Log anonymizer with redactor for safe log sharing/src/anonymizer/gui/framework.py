"""Security framework compliance data (OWASP Top 10, NIST, ISO 27001).

Static reference used by the Security Dashboard so the desktop tool always
surfaces which control each feature maps to, and where to find the
responsible component. The authoritative mapping table lives in
ARCHITECTURE.md; this module mirrors it for the GUI.
"""

from __future__ import annotations

OWASP = [
    {
        "id": "A01",
        "control": "Broken Access Control",
        "status": "Implemented",
        "component": "policy engine + passphrase lock (gu/services) and RBAC in API",
    },
    {
        "id": "A02",
        "control": "Cryptographic Failures",
        "status": "Implemented",
        "component": "DPAPI state, AES-GCM export, salted HMAC (security/hashing)",
    },
    {
        "id": "A03",
        "control": "Injection",
        "status": "Implemented",
        "component": "InputValidator: null/control chars, size caps (security/input_validation)",
    },
    {
        "id": "A04",
        "control": "Insecure Design",
        "status": "Implemented",
        "component": "secure-by-default (deny-all) default policy in config/policies.json",
    },
    {
        "id": "A05",
        "control": "Security Misconfiguration",
        "status": "Implemented",
        "component": "fail-closed config, no secrets in files, validated state/memory files",
    },
    {
        "id": "A06",
        "control": "Vulnerable Components",
        "status": "Partially addressed",
        "component": "pin fastapi/cryptography versions; audit via CI + SCA (see security.md)",
    },
    {
        "id": "A07",
        "control": "Identification and Authentication Failures",
        "status": "Partial",
        "component": "session passphrase lock on sensitive UI actions",
    },
    {
        "id": "A08",
        "control": "Software and Data Integrity Failures",
        "status": "Implemented",
        "component": "tamper-evident audit chain + integrity-tagged state/memory files",
    },
    {
        "id": "A09",
        "control": "Security Logging and Monitoring Failures",
        "status": "Implemented",
        "component": "all anonymization actions append to the sealed audit trail",
    },
    {
        "id": "A10",
        "control": "Server-Side Request Forgery",
        "status": "Not applicable",
        "component": "desktop tool performs no outbound requests from log data",
    },
]

NIST = [
    {
        "id": "GV.OC",
        "control": "Govern / Risk Management Strategy",
        "status": "Implemented",
        "component": "framework mapping tables, STRIDE + risk register (ARCHITECTURE.md)",
    },
    {
        "id": "ID.AM",
        "control": "Asset Management",
        "status": "Implemented",
        "component": "data classification schema (SAFE..CRITICAL), memory store audit",
    },
    {
        "id": "ID.RA",
        "control": "Risk Assessment",
        "status": "Implemented",
        "component": "risk register with mitigated residual risks (ARCHITECTURE.md)",
    },
    {
        "id": "PR.AC",
        "control": "Access Control",
        "status": "Implemented",
        "component": "policy engine (default deny) + passphrase gate",
    },
    {
        "id": "PR.DS",
        "control": "Data Security",
        "status": "Implemented",
        "component": "DPAPI at rest, 7 redaction strategies, k-anonymity suppression",
    },
    {
        "id": "PR.PT",
        "control": "Protective Technology",
        "status": "Implemented",
        "component": "input validation, size caps, deny-all defaults",
    },
    {
        "id": "DE.CM",
        "control": "Continuous Monitoring",
        "status": "Implemented",
        "component": "audit chain verification on every session (rebuild_root from disk)",
    },
    {
        "id": "DE.AE",
        "control": "Adversarial Analysis",
        "status": "Partial",
        "component": "chain-anomaly detection when verify fails (see AUDIT-8)",
    },
    {
        "id": "RS.RP",
        "control": "Incident Response Planning",
        "status": "Implemented",
        "component": "documented response playbooks in SECURITY.md section 9",
    },
    {
        "id": "RC.RP",
        "control": "Recovery Plan Execution",
        "status": "Implemented",
        "component": "audit replay/recovery from disk, state corruption fallbacks",
    },
]

ISO27001 = [
    {
        "id": "A.5.15",
        "control": "Access Control / Segregation of Duties",
        "status": "Implemented",
        "component": "role-aware policy defaults; export gated by passphrase",
    },
    {
        "id": "A.8.2",
        "control": "Labelling of Information",
        "status": "Implemented",
        "component": "classification shown per entity type in GUI dashboard",
    },
    {
        "id": "A.8.3",
        "control": "Handling of Assets",
        "status": "Implemented",
        "component": "original never stored; only hashes/masked forms retained",
    },
    {
        "id": "A.8.11",
        "control": "Data Masking",
        "status": "Implemented",
        "component": "7 redaction strategies incl. tokenization/pseudonymization",
    },
    {
        "id": "A.8.12",
        "control": "Prevention of Data Leakage",
        "status": "Implemented",
        "component": "Luhn-validated card detection, contextual filtering, minimize flags",
    },
    {
        "id": "A.8.14",
        "control": "Redundancy of Information Processing Facilities",
        "status": "N/A",
        "component": "desktop single-operator tool; server deployment is out of scope here",
    },
    {
        "id": "A.8.15",
        "control": "Logging",
        "status": "Implemented",
        "component": "append-only, tamper-evident, sequence-anchored audit trail",
    },
    {
        "id": "A.8.16",
        "control": "Monitoring Activities",
        "status": "Implemented",
        "component": "audit chain verify + rebuild root on every startup",
    },
    {
        "id": "A.8.24",
        "control": "Use of Cryptography",
        "status": "Implemented",
        "component": "DPAPI (AES-256), AES-GCM/Fernet export, HMAC-SHA256",
    },
    {
        "id": "A.8.28",
        "control": "Secure Coding",
        "status": "Implemented",
        "component": "OWASP inputs, no secrets in repos, focused test suite (44+ tests)",
    },
    {
        "id": "A.8.29",
        "control": "Security Testing",
        "status": "Implemented",
        "component": "pytest suite, luhn negative tests, chain-integrity tamper tests",
    },
]

ALL_CONTROLS = [
    ("OWASP Top 10 (2021)", OWASP),
    ("NIST CSF 2.0", NIST),
    ("ISO 27001:2022 Annex A", ISO27001),
]


def status_summary() -> dict[str, int]:
    """Aggregate control status counts across all frameworks."""
    counts: dict[str, int] = {}
    for _, controls in ALL_CONTROLS:
        for control in controls:
            status = str(control["status"])
            counts[status] = counts.get(status, 0) + 1
    return counts
