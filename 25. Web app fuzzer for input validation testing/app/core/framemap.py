"""Web App Fuzzer - module metadata mapped to OWASP Top 10:2025, NIST, ISO 27001:2022."""
from __future__ import annotations

from typing import Dict, List

MODULES: Dict[str, Dict[str, object]] = {
    "sqli": {
        "title": "SQL Injection (Error/Boolean/Time-based)",
        "owasp": "A05 Injection",
        "cwes": ["CWE-89", "CWE-20"],
        "nist": ["SI-10", "CA-8"],
        "iso": ["A.8.29", "A.8.28", "A.8.8"],
        "ssdf": ["PW.8.2", "RV.1"],
        "severity": "High",
        "remediation": (
            "Use parameterized queries / prepared statements, ORM parameter binding, "
            "strict input whitelisting and least-privilege DB accounts. "
            "Reference: OWASP SQL Injection Prevention Cheat Sheet."
        ),
    },
    "xss": {
        "title": "Cross-Site Scripting (Reflected)",
        "owasp": "A05 Injection",
        "cwes": ["CWE-79", "CWE-20"],
        "nist": ["SI-10", "CA-8"],
        "iso": ["A.8.29", "A.8.28"],
        "ssdf": ["PW.8.2"],
        "severity": "Medium",
        "remediation": (
            "Context-aware output encoding, per-call sanitisation at sinks, CSP without "
            "unsafe-inline. Reference: OWASP XSS Prevention Cheat Sheet."
        ),
    },
    "ssti": {
        "title": "Server-Side Template Injection",
        "owasp": "A05 Injection",
        "cwes": ["CWE-1336", "CWE-20"],
        "nist": ["SI-10", "CA-8"],
        "iso": ["A.8.29", "A.8.28"],
        "ssdf": ["PW.8.2"],
        "severity": "High",
        "remediation": (
            "Never treat user input as template text; sandboxed template engines; "
            "input validation. Reference: OWASP Server-Side Template Injection."
        ),
    },
    "traversal": {
        "title": "Path Traversal",
        "owasp": "A01 Broken Access Control",
        "cwes": ["CWE-22", "CWE-20"],
        "nist": ["SI-10", "CA-8"],
        "iso": ["A.8.29", "A.8.28"],
        "ssdf": ["PW.8.2"],
        "severity": "High",
        "remediation": (
            "Canonicalise and validate paths, deny by default, use safelists of allowed "
            "filenames. Reference: OWASP Path Traversal Cheat Sheet."
        ),
    },
    "ssrf": {
        "title": "Server-Side Request Forgery (URL parameter)",
        "owasp": "A01 Broken Access Control",
        "cwes": ["CWE-918", "CWE-20"],
        "nist": ["SI-10", "CA-8"],
        "iso": ["A.8.29", "A.8.28"],
        "ssdf": ["PW.8.2"],
        "severity": "High",
        "remediation": (
            "Validate and deny-by-default server-side URL fetching (schemel + host allow-list), "
            "no cloud-metadata reachability. Reference: OWASP SSRF Prevention Cheat Sheet."
        ),
    },
    "cmdi": {
        "title": "OS Command Injection",
        "owasp": "A05 Injection",
        "cwes": ["CWE-78", "CWE-77"],
        "nist": ["SI-10", "CA-8"],
        "iso": ["A.8.29", "A.8.28"],
        "ssdf": ["PW.8.2"],
        "severity": "High",
        "remediation": (
            "Eliminate shell invocation with user data; APIs instead of shells; strict "
            "token validation. Reference: OWASP Command Injection Cheat Sheet."
        ),
    },
    "header": {
        "title": "CRLF / HTTP Header Injection",
        "owasp": "A05 Injection",
        "cwes": ["CWE-113", "CWE-93"],
        "nist": ["SI-10", "CA-8"],
        "iso": ["A.8.29", "A.8.28"],
        "ssdf": ["PW.8.2"],
        "severity": "Medium",
        "remediation": (
            "Reject CR/LF (0x0d, 0x0a) in header values; no raw user data in headers. "
            "Reference: OWASP HTTP Response Splitting."
        ),
    },
    "errors": {
        "title": "Verbose Errors / Stack Trace Disclosure",
        "owasp": "A10 Mishandling of Exceptional Conditions",
        "cwes": ["CWE-209", "CWE-755"],
        "nist": ["SI-10", "CA-8"],
        "iso": ["A.8.29", "A.8.28"],
        "ssdf": ["PW.8.2"],
        "severity": "Medium",
        "remediation": (
            "Return generic error pages; log details server-side only; fail closed. "
            "Reference: OWASP A10:2025 - Mishandling of Exceptional Conditions."
        ),
    },
    "boundary": {
        "title": "Boundary / Type Confusion (Malformed Input)",
        "owasp": "A10 Mishandling of Exceptional Conditions",
        "cwes": ["CWE-755", "CWE-241"],
        "nist": ["SI-10", "CA-8"],
        "iso": ["A.8.29", "A.8.28"],
        "ssdf": ["PW.8.2"],
        "severity": "Medium",
        "remediation": (
            "Strict schema validation, type coercion with error, boundary condition testing. "
            "Reference: OWASP WSTG - Test for Error Handling."
        ),
    },
    "auth": {
        "title": "Authentication / Session Tampering",
        "owasp": "A07 Authentication Failures",
        "cwes": ["CWE-287", "CWE-384"],
        "nist": ["SI-10", "CA-8"],
        "iso": ["A.8.29", "A.8.28"],
        "ssdf": ["PW.8.2"],
        "severity": "High",
        "remediation": (
            "Validate session tokens, secure session attributes, rate-limit auth endpoints. "
            "Reference: OWASP Authentication Cheat Sheet."
        ),
    },
}

SEVERITY_WEIGHT = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}


def module_meta(module: str) -> Dict[str, object]:
    return MODULES.get(module, {})


def list_modules() -> List[str]:
    return list(MODULES.keys())


def owasp_categories() -> List[str]:
    return sorted({str(m["owasp"]) for m in MODULES.values()})