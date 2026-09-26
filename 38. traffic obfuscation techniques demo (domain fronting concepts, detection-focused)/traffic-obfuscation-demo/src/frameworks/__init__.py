"""Compliance framework layer: OWASP Top 10, NIST CSF 2.0, ISO 27001:2022.

Each control/category carries mapping metadata so findings, mitigations and
audit evidence can be cross-referenced programmatically and exported with
the demo reports.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Dict, List


class Framework(str, Enum):
    OWASP = "OWASP Top 10 (2021)"
    NIST = "NIST CSF 2.0"
    ISO = "ISO/IEC 27001:2022"


@dataclass
class Control:
    framework: Framework
    ref: str
    title: str
    category: str
    description: str
    relevant: bool = True
    status: str = "review"  # adopt / review / monitoring

    def to_dict(self) -> dict:
        return asdict(self)


# ---------------------------------------------------------------------------
# OWASP Top 10 (2021) - the controls highlighted by this demo
# ---------------------------------------------------------------------------
OWASP_CATALOG: List[Control] = [
    Control(Framework.OWASP, "A01", "Broken Access Control",
            "Access Control",
            "Hidden origins exposed by fronted channels bypass coarse IP/DNS allow-lists.",
            relevant=True, status="adopt"),
    Control(Framework.OWASP, "A02", "Cryptographic Failures",
            "Cryptography",
            "Weak/legacy cipher advertising inside ClientHello must be recorded.",
            relevant=True, status="adopt"),
    Control(Framework.OWASP, "A03", "Injection",
            "Injection",
            "Host/:authority validation prevents request-route injection.",
            relevant=True, status="adopt"),
    Control(Framework.OWASP, "A04", "Insecure Design",
            "Design",
            "Design must assume attacker controls SNI and Host independently.",
            relevant=True, status="adopt"),
    Control(Framework.OWASP, "A05", "Security Misconfiguration",
            "Configuration",
            "CDN fronting relies on permissive TLS termination configs.",
            relevant=True, status="adopt"),
    Control(Framework.OWASP, "A06", "Vulnerable and Outdated Components",
            "Components",
            "Edge TLS stacks and proxy engines must be patched.",
            relevant=True, status="monitoring"),
    Control(Framework.OWASP, "A07", "Identification and Authentication Failures",
            "Identity",
            "Origin must not rely on SNI as a bearer of identity.",
            relevant=True, status="adopt"),
    Control(Framework.OWASP, "A08", "Software and Data Integrity Failures",
            "Integrity",
            "Trust decisions must validate Host + authority consistently end-to-end.",
            relevant=True, status="adopt"),
    Control(Framework.OWASP, "A09", "Security Logging and Monitoring Failures",
            "Logging & Monitoring",
            "SNI/Host telemetry must feed SIEM pipelines for detection.",
            relevant=True, status="monitoring"),
    Control(Framework.OWASP, "A10", "Server-Side Request Forgery",
            "SSRF",
            "Fronted channels can turn the CDN edge into an SSRF proxy toward origins.",
            relevant=True, status="adopt"),
]

# ---------------------------------------------------------------------------
# NIST CSF 2.0 - six core functions
# ---------------------------------------------------------------------------
NIST_CATALOG: List[Control] = [
    Control(Framework.NIST, "GV", "Govern",
            "Govern",
            "Establish org-wide policy for allowed egress and obfuscation use.",
            relevant=True, status="review"),
    Control(Framework.NIST, "ID", "Identify",
            "Identify",
            "Inventory of origins, CDN edges and expected SNI/Host pairings.",
            relevant=True, status="review"),
    Control(Framework.NIST, "PR", "Protect",
            "Protect",
            "TLS 1.3 policies, pinned certificate discipline, allow-list defaults.",
            relevant=True, status="adopt"),
    Control(Framework.NIST, "DE", "Detect",
            "Detect",
            "Continuous SNI/authority/TTL/JA4 analytics on egress & ingress.",
            relevant=True, status="monitoring"),
    Control(Framework.NIST, "RS", "Respond",
            "Respond",
            "Playbooks to terminate or quarantine fronted channels.",
            relevant=True, status="review"),
    Control(Framework.NIST, "RC", "Recover",
            "Recover",
            "Restore clean routing tables after remediation.",
            relevant=True, status="review"),
]

# ---------------------------------------------------------------------------
# ISO/IEC 27001:2022 - Annex A controls referenced by the demo
# ---------------------------------------------------------------------------
ISO_CATALOG: List[Control] = [
    Control(Framework.ISO, "A.5.2", "Information security roles and responsibilities",
            "A.5 Organisational",
            "Assign ownership for egress and obfuscation-monitoring capability.",
            relevant=True, status="review"),
    Control(Framework.ISO, "A.5.10", "Acceptable use of information and assets",
            "A.5 Organisational",
            "Define acceptable egress domains and prohibit unauthorised fronting.",
            relevant=True, status="review"),
    Control(Framework.ISO, "A.8.9", "Configuration management",
            "A.8 Technological",
            "Version-controlled edge / TLS / proxy configuration baselines.",
            relevant=True, status="adopt"),
    Control(Framework.ISO, "A.8.10", "Information deletion", 
            "A.8 Technological",
            "Ensure telemetry retention satisfies data-handling policy.",
            relevant=False, status="monitoring"),
    Control(Framework.ISO, "A.8.16", "Monitoring activities",
            "A.8 Technological",
            "Active monitoring of networks, systems and applications for misuse.",
            relevant=True, status="monitoring"),
    Control(Framework.ISO, "A.8.20", "Networks security", 
            "A.8 Technological",
            "Segment and filter egress so fronted channels cannot reach origins.",
            relevant=True, status="adopt"),
    Control(Framework.ISO, "A.8.24", "Use of cryptography",
            "A.8 Technological",
            "Cryptographic policy applied consistently to egress TLS.",
            relevant=True, status="adopt"),
    Control(Framework.ISO, "A.8.28", "Secure coding",
            "A.8 Technological",
            "Host/:authority validation in application code; no implicit trust of SNI.",
            relevant=True, status="adopt"),
]


# ---------------------------------------------------------------------------
# Aggregated cross-framework catalog
# ---------------------------------------------------------------------------
def build_catalog() -> List[Control]:
    """Merge all framework catalogs into a single reference list."""
    return OWASP_CATALOG + NIST_CATALOG + ISO_CATALOG


def catalog_index() -> Dict[str, Control]:
    return {c.framework.value + ":" + c.ref: c for c in build_catalog()}


def resolve_refs(refs: List[str]) -> List[Control]:
    index = catalog_index()
    resolved = []
    for ref in refs:
        for framework in Framework:
            key = f"{framework.value}:{ref}"
            if key in index:
                resolved.append(index[key])
    return resolved


def summary_stats() -> Dict[str, Dict[str, int]]:
    out: Dict[str, Dict[str, int]] = {}
    for fw in Framework:
        rows = [c for c in build_catalog() if c.framework == fw]
        out[fw.value] = {
            "total": len(rows),
            "relevant": sum(1 for c in rows if c.relevant),
            "adopt": sum(1 for c in rows if c.status == "adopt"),
            "review": sum(1 for c in rows if c.status == "review"),
            "monitoring": sum(1 for c in rows if c.status == "monitoring"),
        }
    return out