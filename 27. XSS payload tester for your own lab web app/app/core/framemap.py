"""XSS Payload Tester - category metadata mapped to OWASP Top 10:2025, NIST, ISO 27001:2022."""
from __future__ import annotations

from typing import Dict, List

MODULES: Dict[str, Dict[str, object]] = {
    "basic": {
        "title": "Basic script injection (<script>, <img>, <svg>, <body>)",
        "owasp": "A05 Injection",
        "cwes": ["CWE-79", "CWE-80"],
        "nist": ["SI-10", "SI-15", "CA-8"],
        "iso": ["A.8.29", "A.8.28"],
        "ssdf": ["PW.8.2", "RV.1"],
        "severity": "High",
        "remediation": "Context-aware output encoding for every reflection (OWASP RULE #1).",
    },
    "event_handler": {
        "title": "Event-handler injection (onerror/onload/onfocus/ontoggle/autofocus)",
        "owasp": "A05 Injection",
        "cwes": ["CWE-79", "CWE-80"],
        "nist": ["SI-10", "SI-15", "CA-8"],
        "iso": ["A.8.29", "A.8.28"],
        "ssdf": ["PW.8.2", "RV.1"],
        "severity": "High",
        "remediation": "Never emit unencoded user data into tag attributes; encode quotes/angle brackets.",
    },
    "iframe": {
        "title": "iframe srcdoc / nested document injection",
        "owasp": "A05 Injection",
        "cwes": ["CWE-79", "CWE-80"],
        "nist": ["SI-10", "SI-15", "CA-8"],
        "iso": ["A.8.29", "A.8.28"],
        "ssdf": ["PW.8.2", "RV.1"],
        "severity": "High",
        "remediation": "Sanitize / reject reflected content that permits embedded documents.",
    },
    "scheme": {
        "title": "javascript: scheme injection (href/src/URL params)",
        "owasp": "A05 Injection",
        "cwes": ["CWE-79", "CWE-941"],
        "nist": ["SI-10", "SI-15", "CA-8"],
        "iso": ["A.8.29", "A.8.28"],
        "ssdf": ["PW.8.2", "RV.1"],
        "severity": "High",
        "remediation": "Scheme allowlist (http/https/mailto), never javascript: or data:.",
    },
    "breakout": {
        "title": "Context breakout (attribute / script-string escape)",
        "owasp": "A05 Injection",
        "cwes": ["CWE-79", "CWE-80"],
        "nist": ["SI-10", "SI-15", "CA-8"],
        "iso": ["A.8.29", "A.8.28"],
        "ssdf": ["PW.8.2", "RV.1"],
        "severity": "High",
        "remediation": "Quote and encode attribute values; forbid `</script`; use JSON.stringify in <script>.",
    },
    "dom": {
        "title": "DOM sink injection (innerHTML / document.write / clobbering)",
        "owasp": "A05 Injection",
        "cwes": ["CWE-79", "CWE-696"],
        "nist": ["SI-10", "SI-15", "CA-8"],
        "iso": ["A.8.29", "A.8.28"],
        "ssdf": ["PW.8.2", "RV.1"],
        "severity": "Medium",
        "remediation": "Replace HTML sinks with textContent / safe DOM APIs; allowlist sanitizer at sinks.",
    },
}

SEVERITY_WEIGHT = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}


def module_meta(module: str) -> Dict[str, object]:
    return MODULES.get(module, {})


def list_modules() -> List[str]:
    return list(MODULES.keys())


def owasp_categories() -> List[str]:
    return sorted({str(m["owasp"]) for m in MODULES.values()})