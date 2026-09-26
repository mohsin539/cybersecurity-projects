CONTROL_MATRIX = [
    {"id": "C01", "domain": "Access Control", "iso": "A.5.15-A.5.18", "nist": "800-124 Sec 4.3",
     "owasp": "A01", "zone": "All", "note": "RBAC + MFA, least privilege"},
    {"id": "C02", "domain": "Evidence Integrity", "iso": "A.8.12", "nist": "800-101 Sec 6.3",
     "owasp": "-", "zone": "ZONE2", "note": "SHA-256 hashing + WORM vault"},
    {"id": "C03", "domain": "Event Logging", "iso": "A.8.15", "nist": "800-101 Sec 8.3",
     "owasp": "A09", "zone": "ZONE5", "note": "Immutable hash-linked audit journal"},
    {"id": "C04", "domain": "Data Protection", "iso": "A.8.24-A.8.25", "nist": "800-124 Sec 4.4",
     "owasp": "-", "zone": "ZONE1", "note": "AES-256 vault + HSM/TPM keys"},
    {"id": "C05", "domain": "Secure Comms", "iso": "A.8.26", "nist": "800-101 Sec 4.5",
     "owasp": "A02/A08", "zone": "ZONE1", "note": "ADB bound auth, no plaintext"},
    {"id": "C06", "domain": "Vulnerability Mgmt", "iso": "A.8.8-A.8.10", "nist": "800-124 Sec 5",
     "owasp": "A06", "zone": "SW tier", "note": "SBOM + CVE scanning + patch SLA"},
    {"id": "C07", "domain": "Input Validation", "iso": "-", "nist": "-",
     "owasp": "A03", "zone": "ZONE2", "note": "Path/artifact validation before parse"},
    {"id": "C08", "domain": "Secure Config", "iso": "A.8.9", "nist": "800-124 Sec 4.6",
     "owasp": "A05", "zone": "ZONE1", "note": "CIS-hardened host, deny-by-default"},
    {"id": "C09", "domain": "Crypto Strength", "iso": "A.8.24", "nist": "-",
     "owasp": "A02", "zone": "All", "note": "AES-256-GCM default cipher policy"},
    {"id": "C10", "domain": "Supply Chain", "iso": "A.5.19-A.5.22", "nist": "-",
     "owasp": "A06", "zone": "SW tier", "note": "Signed images, tool vetting"},
    {"id": "C11", "domain": "Incident Response", "iso": "A.5.24-A.5.28", "nist": "800-124 Sec 5.3",
     "owasp": "-", "zone": "All", "note": "Breach containment runbook"},
    {"id": "C12", "domain": "Physical Security", "iso": "A.7.1-A.7.14", "nist": "800-101 Sec 4.2",
     "owasp": "-", "zone": "ZONE0", "note": "Access-controlled lab + custody"},
    {"id": "C13", "domain": "Business Continuity", "iso": "A.5.30-A.5.31", "nist": "-",
     "owasp": "-", "zone": "Vault", "note": "Replication + DR drills"},
    {"id": "C14", "domain": "Regulatory Handover", "iso": "A.5.34", "nist": "800-101 Sec 9",
     "owasp": "-", "zone": "ZONE4", "note": "Discovery-ready signed exports"},
]

ZONES = {
    "ZONE0": ("Intake & Registration", "#F57C00"),
    "ZONE1": ("Acquisition (Lab Device)", "#1565C0"),
    "ZONE2": ("Examination & Extraction", "#2E7D32"),
    "ZONE3": ("Analysis & Correlation", "#6A1B9A"),
    "ZONE4": ("Reporting & Disclosure", "#D84315"),
    "ZONE5": ("Audit & Compliance", "#37474F"),
}

OWASP = {
    "A01": "Broken Access Control",
    "A02": "Cryptographic Failures",
    "A03": "Injection",
    "A04": "Insecure Design",
    "A05": "Security Misconfiguration",
    "A06": "Vulnerable and Outdated Components",
    "A07": "Identification and Authentication Failures",
    "A08": "Software and Data Integrity Failures",
    "A09": "Security Logging and Monitoring Failures",
    "A10": "Server-Side Request Forgery",
}

ISO_CLAUSES = [
    ("4", "Context of the organisation"),
    ("5", "Leadership"),
    ("6", "Planning"),
    ("7", "Support"),
    ("8", "Operation"),
    ("9", "Performance evaluation"),
    ("10", "Improvement"),
]


def compliance_scorecard(met_controls: set[str]) -> dict:
    total = len(CONTROL_MATRIX)
    met = sum(1 for c in CONTROL_MATRIX if c["id"] in met_controls)
    return {"total": total, "met": met, "open": total - met, "pct": round(100 * met / total, 1)}