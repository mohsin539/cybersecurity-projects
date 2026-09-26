"""Cross-framework mapping catalogue.

Each OWASP Top 10 (2021) category is mapped to the NIST SP 800-53 Rev.5
controls and ISO/IEC 27001:2022 Annex A controls that directly govern
detection, prevention and remediation of that weakness class.

The mapping is authoritative for this tool and can be extended by adding
entries to `OWASP_CROSS_MAP`.
"""

from __future__ import annotations

from typing import Dict, List

from ..models.framework import FrameworkControl, FrameworkMapping
from .iso27001 import iso_control
from .nist import nist_control
from .owasp import owasp_control

# OWASP code -> (NIST control ids, ISO 27001 control ids)
OWASP_CROSS_MAP: Dict[str, tuple] = {
    "A01": (
        ("AC-2", "AC-3", "AC-4", "AC-6", "AC-17", "AC-20"),
        ("A.5.15", "A.5.16", "A.5.17", "A.5.18", "A.8.2", "A.8.3"),
    ),
    "A02": (
        ("SC-8", "SC-13", "SC-28", "SC-28(1)", "CM-6"),
        ("A.8.24", "A.8.28", "A.8.10", "A.5.33"),
    ),
    "A03": (
        ("SI-10", "SI-11", "SC-7", "SA-11", "SI-16"),
        ("A.8.26", "A.8.27", "A.8.28", "A.8.29"),
    ),
    "A04": (
        ("PL-8", "RA-3", "SA-10", "SA-11", "CA-7"),
        ("A.8.25", "A.8.26", "A.8.27", "A.8.29"),
    ),
    "A05": (
        ("CM-6", "CM-7", "CM-8", "CM-11", "SC-7", "SI-2"),
        ("A.8.8", "A.8.9", "A.8.19", "A.8.20", "A.8.21", "A.8.22", "A.8.32", "A.8.31"),
    ),
    "A06": (
        ("CM-8", "CM-11", "RA-5", "SI-2", "SI-7", "SI-16", "SA-11", "SR-3", "SR-11"),
        ("A.8.8", "A.8.19", "A.5.37", "A.8.25"),
    ),
    "A07": (
        ("IA-2", "IA-5", "IA-8", "IA-11", "AC-7", "AC-8"),
        ("A.8.5", "A.5.16", "A.5.17", "A.5.18"),
    ),
    "A08": (
        ("SI-7", "SI-10", "SI-16", "SA-10", "SA-11", "SR-11", "SC-23"),
        ("A.8.27", "A.8.28", "A.8.29", "A.8.30", "A.5.33"),
    ),
    "A09": (
        ("AU-3", "AU-6", "AU-9", "AU-12", "AU-16", "SI-4", "SI-11", "CM-7"),
        ("A.8.15", "A.8.16", "A.8.17", "A.6.8", "A.5.24", "A.5.25", "A.5.28"),
    ),
    "A10": (
        ("SC-7", "AC-4", "SI-10", "SC-20", "SC-24"),
        ("A.8.20", "A.8.21", "A.8.22", "A.8.26", "A.8.27", "A.8.28"),
    ),
}


def map_finding_owasp(owasp_id: str, finding=None) -> FrameworkMapping:
    """Build a FrameworkMapping for the OWASP category `owasp_id`."""
    owasp = owasp_control(owasp_id)
    nist_codes, iso_codes = OWASP_CROSS_MAP[owasp.code]
    nist = [nist_control(c) for c in nist_codes]
    iso = [iso_control(c) for c in iso_codes]
    return FrameworkMapping(finding=finding, owasp=owasp, nist_controls=nist, iso_controls=iso)


def all_owasp_categories() -> List[FrameworkControl]:
    from .owasp import OWASP_TOP_10_2021

    return list(OWASP_TOP_10_2021)


def framework_coverage_stats(mappings: List[FrameworkMapping]) -> Dict[str, dict]:
    """Per-framework stats for report dashboards.

    Returns e.g.:
      {"OWASP Top 10 2021": {"covered": ["A03"], "count": 1},
       "NIST SP 800-53 Rev.5": {"covered": ["SI-10", ...], "count": ...},
       "ISO/IEC 27001:2022": {...}}
    """
    stats: Dict[str, dict] = {
        "OWASP Top 10 2021": {"covered": [], "count": 0},
        "NIST SP 800-53 Rev.5": {"covered": [], "count": 0},
        "ISO/IEC 27001:2022": {"covered": [], "count": 0},
    }
    seen = {k: set() for k in stats}
    for mapping in mappings:
        stats["OWASP Top 10 2021"]["covered"].append(mapping.owasp.code)
        stats["OWASP Top 10 2021"]["count"] += 1
        for control in mapping.nist_controls:
            if control.code not in seen["NIST SP 800-53 Rev.5"]:
                seen["NIST SP 800-53 Rev.5"].add(control.code)
                stats["NIST SP 800-53 Rev.5"]["covered"].append(control.code)
                stats["NIST SP 800-53 Rev.5"]["count"] += 1
        for control in mapping.iso_controls:
            if control.code not in seen["ISO/IEC 27001:2022"]:
                seen["ISO/IEC 27001:2022"].add(control.code)
                stats["ISO/IEC 27001:2022"]["covered"].append(control.code)
                stats["ISO/IEC 27001:2022"]["count"] += 1
    return stats