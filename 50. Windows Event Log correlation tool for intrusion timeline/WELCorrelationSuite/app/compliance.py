"""Security-framework compliance mapping engine.

Maps detected activity to:
  * ISO/IEC 27001:2022 Annex A controls (evidence of conformance)
  * NIST Cybersecurity Framework (CSF 2.0) function/category
  * OWASP Top 10 2021 (for this tool's own browser/API surface)

Also exposes the hardening checklist the tool implements so security
reviewers can verify the surface itself is defensible.
"""

ISO_27001_CONTROLS = {
    "5.15": {"name": "Access control", "family": "Organizational controls"},
    "5.24": {"name": "Information security incident management planning and preparation", "family": "Organizational controls"},
    "5.25": {"name": "Assessment and decision on information security events", "family": "Organizational controls"},
    "5.26": {"name": "Response to information security incidents", "family": "Organizational controls"},
    "5.27": {"name": "Learning from information security incidents", "family": "Organizational controls"},
    "5.28": {"name": "Collection of evidence", "family": "Organizational controls"},
    "8.2": {"name": "Access right assignment and management", "family": "People controls"},
    "8.5": {"name": "Authentication information", "family": "People controls"},
    "8.7": {"name": "Protection against malware", "family": "Technological controls"},
    "8.11": {"name": "Data masking", "family": "Technological controls"},
    "8.15": {"name": "Logging", "family": "Technological controls"},
    "8.16": {"name": "Monitoring activities", "family": "Technological controls"},
    "8.20": {"name": "Networks security", "family": "Technological controls"},
    "8.28": {"name": "Secure coding", "family": "Technological controls"},
    "8.34": {"name": "Protection of information systems during audit testing", "family": "Technological controls"},
    "8.24": {"name": "Use of cryptography", "family": "Technological controls"},
}

NIST_CSF = {
    "ID": {"name": "Identify", "categories": {"ID.AM": "Asset Management", "ID.RA": "Risk Assessment"}},
    "PR": {"name": "Protect", "categories": {"PR.AC": "Identity & Access Mgmt", "PR.PT": "Technology Protection", "PR.DS": "Data Security"}},
    "DE": {"name": "Detect", "categories": {"DE.AE": "Anomalies & Events", "DE.CM": "Continuous Monitoring"}},
    "RS": {"name": "Respond", "categories": {"RS.MA": "Mitigation", "RS.CO": "Communications"}},
    "RC": {"name": "Recover", "categories": {"RC.RP": "Recovery Planning"}},
}

OWASP_TOP10_2021 = {
    "A01:2021": "Broken Access Control",
    "A02:2021": "Cryptographic Failures",
    "A03:2021": "Injection",
    "A04:2021": "Insecure Design",
    "A05:2021": "Security Misconfiguration",
    "A06:2021": "Vulnerable and Outdated Components",
    "A07:2021": "Identification and Authentication Failures",
    "A08:2021": "Software and Data Integrity Failures",
    "A09:2021": "Security Logging and Monitoring Failures",
    "A10:2021": "Server-Side Request Forgery",
}


def map_rule_frameworks(rule):
    """Return per-rule framework coverage dictionary for reports/UI."""
    iso = [{"id": c, "name": ISO_27001_CONTROLS.get(c, {}).get("name", c)}
           for c in rule.iso]
    nist = []
    for cat in rule.nist:
        pref, cat_id = cat.split(".", 1)
        info = NIST_CSF.get(pref, {})
        label = info.get("categories", {}).get(cat, cat)
        nist.append({"id": cat, "function": info.get("name", pref), "name": label})
    return {"iso": iso, "nist": nist}


def coverage_matrix(rules):
    """Aggregate control coverage to confirm framework alignment."""
    iso, nist = set(), set()
    for r in rules:
        iso.update(r.iso)
        nist.update(r.nist)
    return {
        "iso_27001": sorted(iso, key=lambda x: x),
        "nist_csf": sorted(nist),
        "iso_27001_total": len(ISO_27001_CONTROLS),
        "nist_csf_total": sum(len(v["categories"]) for v in NIST_CSF.values()),
    }


TOOL_HARDENING = [
    {"measure": "Localhost-only binding (127.0.0.1), random ephemeral port", "framework": ["A05:2021"], "nist": "PR.PT", "iso": "8.20"},
    {"measure": "Single-use session token required on every request", "framework": ["A07:2021", "A01:2021"], "nist": "PR.AC", "iso": "8.2"},
    {"measure": "No SQL / no shell interpolation - parameterized subprocess calls", "framework": ["A03:2021"], "nist": "PR.DS", "iso": "8.28"},
    {"measure": "Contextual output encoding (XSS-safe rendering of untrusted log data)", "framework": ["A03:2021"], "nist": "PR.DS", "iso": "8.28"},
    {"measure": "Security headers: CSP, nosniff, referrer-policy, frame-ancestors none", "framework": ["A05:2021"], "nist": "PR.PT", "iso": "8.28"},
    {"measure": "Strict Content-Type checks and size caps on imports", "framework": ["A03:2021"], "nist": "PR.DS", "iso": "8.28"},
    {"measure": "Path-traversal-safe static file serving (whitelisted mapping)", "framework": ["A05:2021"], "nist": "PR.PT", "iso": "8.28"},
    {"measure": "Automatic idle self-termination and graceful shutdown endpoint", "framework": ["A05:2021"], "nist": "PR.PT", "iso": "8.16"},
    {"measure": "Full action-level audit trail with SHA-256 integrity (A09-friendly)", "framework": ["A09:2021"], "nist": "DE.CM", "iso": "8.15"},
    {"measure": "Tamper-evident reports - embedded SHA-256 of generated artefacts", "framework": ["A08:2021"], "nist": "PR.DS", "iso": "8.24"},
    {"measure": "No inbound network listeners beyond loopback; no arbitrary URLs fetched", "framework": ["A10:2021"], "nist": "PR.PT", "iso": "8.20"},
]

OWASP_STATUS = []
for item in TOOL_HARDENING:
    for item_id in item["framework"]:
        OWASP_STATUS.append({"id": item_id, "name": OWASP_TOP10_2021.get(item_id, item_id), "measure": item["measure"]})


def tool_framework_compliance():
    """Evidence that the tool surface follows the named frameworks."""
    by_id = {}
    for st in OWASP_STATUS:
        by_id.setdefault(st["id"], []).append(st["measure"])
    owasp = [{"id": k, "name": OWASP_TOP10_2021.get(k, ""), "items": v} for k, v in sorted(by_id.items())]
    nist = {}
    iso = set()
    for item in TOOL_HARDENING:
        nist.setdefault(item["nist"], []).append(item["measure"])
        if item["iso"]:
            iso.add(item["iso"])
    return {
        "owasp": owasp,
        "nist": [{"id": k, "name": _nist_label(k), "items": v} for k, v in sorted(nist.items())],
        "iso": sorted(iso),
        "hardening_items": TOOL_HARDENING,
    }


def _nist_label(cat):
    pref, cat_id = cat.split(".", 1) if "." in cat else (cat, cat)
    info = NIST_CSF.get(pref, {})
    return info.get("categories", {}).get(cat, info.get("name", cat))