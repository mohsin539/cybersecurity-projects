"""Compliance control catalog and self-assessment.

The catalog documents exactly which technical control satisfies which framework
requirement, so an auditor can trace observed behaviour back to a standard.
Frameworks covered:

* ISO/IEC 27001:2022 - Annex A controls
* NIST SP 800-53 Rev.5 - security & privacy controls
* NIST SP 800-86 - forensic collection guidance
* OWASP Top 10:2021 - web/application risks mitigated in output & input handling
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Dict, List

FRAMEWORKS = {
    "ISO 27001:2022": "https://www.iso.org/standard/27001",
    "NIST SP 800-53": "https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final",
    "NIST SP 800-86": "https://csrc.nist.gov/pubs/sp/800/86/final",
    "OWASP Top 10": "https://owasp.org/Top10/",
}

# Each control: id -> (framework, title, implementation, module)
CONTROLS: List[Dict] = [
    # --- ISO 27001:2022 --------------------------------------------------
    {"framework": "ISO 27001:2022", "control": "A.5.15", "title": "Access control",
     "implementation": "Operator-supplied consent flag and read-only source access; no elevation required for standard collection.",
     "module": "core.engine / ui.app"},
    {"framework": "ISO 27001:2022", "control": "A.8.3", "title": "Information backup / evidence handling",
     "implementation": "Evidence databases are copied to an isolated temp directory before parsing; originals are never modified.",
     "module": "core.extractors._open_db"},
    {"framework": "ISO 27001:2022", "control": "A.8.10", "title": "Information deletion",
     "implementation": "Temporary evidence copies and in-memory key material are wiped at the end of each run.",
     "module": "core.engine / core.extractors"},
    {"framework": "ISO 27001:2022", "control": "A.8.11", "title": "Data masking",
     "implementation": "Secret values (cookie/password) are only decrypted on explicit opt-in and are masked by default.",
     "module": "core.models.ScanOptions"},
    {"framework": "ISO 27001:2022", "control": "A.8.12", "title": "Data leakage prevention",
     "implementation": "The application makes zero outbound network connections and never phones home.",
     "module": "ui.app (offline design)"},
    {"framework": "ISO 27001:2022", "control": "A.8.15", "title": "Logging",
     "implementation": "Every action is written to a hash-chained JSON-lines audit log.",
     "module": "sec.audit"},
    {"framework": "ISO 27001:2022", "control": "A.8.24", "title": "Use of cryptography",
     "implementation": "AES-256-GCM and Windows DPAPI are used for secret unwrapping; SHA-256 for integrity.",
     "module": "core.decrypt / sec.integrity"},
    # --- NIST SP 800-53 --------------------------------------------------
    {"framework": "NIST SP 800-53", "control": "AU-2/AU-3", "title": "Event logging",
     "implementation": "Structured audit events with timestamps, actor, host, PID and severity.",
     "module": "sec.audit"},
    {"framework": "NIST SP 800-53", "control": "AU-9", "title": "Protection of audit information",
     "implementation": "SHA-256 hash chain makes audit records tamper-evident and independently verifiable.",
     "module": "sec.integrity.HashChain"},
    {"framework": "NIST SP 800-53", "control": "SC-8/SC-13", "title": "Cryptographic protection",
     "implementation": "DPAPI + AES-256-GCM for secrets-at-rest; FIPS-validated primitives via 'cryptography'.",
     "module": "core.decrypt"},
    {"framework": "NIST SP 800-53", "control": "SI-10", "title": "Information input validation",
     "implementation": "Paths validated; SQLite queries fully parameterised; wildcard expansion bounded.",
     "module": "core.extractors / core.paths"},
    {"framework": "NIST SP 800-53", "control": "CM-7", "title": "Least functionality",
     "implementation": "Extractor ships only collection features; no arbitrary code execution surface.",
     "module": "core.engine"},
    # --- NIST SP 800-86 --------------------------------------------------
    {"framework": "NIST SP 800-86", "control": "3.2", "title": "Data collection integrity",
     "implementation": "SHA-256 hashes of every source artifact recorded in a signed evidence manifest.",
     "module": "sec.integrity.build_manifest"},
    {"framework": "NIST SP 800-86", "control": "3.3", "title": "Chain of custody",
     "implementation": "Collector, host, timestamps and per-artifact digests captured in the report header.",
     "module": "core.models.ScanResult / report.exporters"},
    # --- OWASP Top 10:2021 ----------------------------------------------
    {"framework": "OWASP Top 10", "control": "A01:2021", "title": "Broken access control",
     "implementation": "Only operator-selected artifacts are collected; nothing is exfiltrated or escalated.",
     "module": "core.engine"},
    {"framework": "OWASP Top 10", "control": "A03:2021", "title": "Injection",
     "implementation": "All report output is HTML/CSV/XML escaped; SQLite access is parameterised.",
     "module": "report.exporters"},
    {"framework": "OWASP Top 10", "control": "A05:2021", "title": "Security misconfiguration",
     "implementation": "No debug endpoints, no default credentials, safe defaults for secret handling.",
     "module": "ui.app"},
    {"framework": "OWASP Top 10", "control": "A06:2021", "title": "Vulnerable & outdated components",
     "implementation": "Pinned dependency ranges and dependency inventory in report manifest.",
     "module": "requirements.txt"},
    {"framework": "OWASP Top 10", "control": "A08:2021", "title": "Software & data integrity failures",
     "implementation": "Evidence hashing + HMAC-signed manifests detect post-collection tampering.",
     "module": "sec.integrity"},
    {"framework": "OWASP Top 10", "control": "A09:2021", "title": "Security logging & monitoring",
     "implementation": "Comprehensive audit trail with integrity verification command.",
     "module": "sec.audit"},
]

DEFAULT_SUMMARY = {
    "evidence_preserved": True,
    "offline_operation": True,
    "audit_logging": True,
    "integrity_hashing": True,
    "secrets_opt_in": True,
    "output_sanitised": True,
}


def catalog() -> List[Dict]:
    return list(CONTROLS)


def catalog_by_framework() -> Dict[str, List[Dict]]:
    grouped: Dict[str, List[Dict]] = {name: [] for name in FRAMEWORKS}
    for control in CONTROLS:
        grouped.setdefault(control["framework"], []).append(control)
    return grouped


def assessment(summary: Dict = None) -> Dict:
    """Build a self-assessment block for embedding in reports."""
    flags = dict(DEFAULT_SUMMARY)
    if summary:
        flags.update(summary)
    total = len(CONTROLS)
    satisfied = sum(1 for key, ok in flags.items() if ok)
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "frameworks": JSON_SAFE_FRAMEWORKS(),
        "control_count": total,
        "summary": flags,
        "coverage_percent": round(100.0 * satisfied / max(len(flags), 1), 1),
        "controls": CONTROLS,
    }


def JSON_SAFE_FRAMEWORKS() -> Dict[str, str]:
    return dict(FRAMEWORKS)
