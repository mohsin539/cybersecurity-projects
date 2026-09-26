"""Compliance snapshot module (ARCHITECTURE.md section 9).

Renders control-to-implementation mapping for the four frameworks and exports
a timestamped evidence snapshot for the audit pack.
"""
from __future__ import annotations

import json
import time
from typing import Dict, List

ISO_MAP = [
    ("A.5.9", "Inventory of information", "Asset/Target model + data class inventory"),
    ("A.5.15", "Access control", "RBAC + SSO/MFA + two-person approvals"),
    ("A.5.17", "Authentication information", "No local passwords; Vault-based secrets"),
    ("A.8.10/11", "Info deletion / Data masking", "Retention matrix + PII redaction-at-ingest"),
    ("A.8.16", "Monitoring activities", "Full telemetry + SIEM export"),
    ("A.8.20/22/23", "Network security / segregation", "Dedicated segment, egress allow-list"),
    ("A.8.24", "Use of cryptography", "TLS 1.2+ / AES-256-GCM / KMS rotation"),
    ("A.8.25-28", "Secure dev / secure coding", "SDLC, SAST/SCA, input validation"),
    ("A.8.29", "Security testing", "Detection-layer CI tests + evasion suite"),
    ("A.8.31", "Env separation", "Segregated dev/staging/prod + gated promotion"),
]

NIST_MAP = [
    ("AC-2/3/6/7", "Identity & access", "RBAC, enforce, least-privilege, throttle"),
    ("AU-2/3/6/9/11", "Audit & accountability", "Hash-chained audit, review, retention"),
    ("CA-7 / SI-4", "Continuous monitoring", "SIEM feed, detector telemetry"),
    ("SC-7/8/12/28", "System & comms protection", "Segmentation, TLS, KMS, at-rest crypto"),
    ("SI-3/7/10/11", "System integrity", "Input validation, signed artifacts, error hygiene"),
    ("RA-3/5", "Risk assessment / vuln scanning", "Active scanner + risk scoring"),
    ("IR-4/6", "Incident response", "IR runbooks + tabletop exercises"),
    ("CP-2", "Contingency planning", "Backup/restore tested on schedule"),
]

OWASP_MAP = [
    ("A01", "Broken Access Control", "RBAC, MFA, per-record ACLs on evidence"),
    ("A02", "Cryptographic Failures", "TLS 1.2+, AES-256-GCM, HSM/KMS, crypto-agility"),
    ("A03", "Injection", "CORE: 5-layer detection + vulnerable-param identification"),
    ("A05", "Security Misconfiguration", "CM baselines, IaC, drift detection"),
    ("A06", "Vulnerable & Outdated Components", "SCA, pinning, SBOM"),
    ("A08", "Software & Data Integrity Failures", "Signed artifacts, hash-chained audit"),
    ("A09", "Logging & Monitoring Failures", "Structured logs, SIEM, alerting"),
    ("A10", "SSRF", "Target allow-lists, webhook allow-lists, sandbox egress"),
]

PCI_MAP = [
    ("Req 4", "Encrypt transmissions", "TLS 1.2+ throughout"),
    ("Req 6.5/6.6", "Secure code / web-app attacks", "Detection control qualifies for 6.6"),
    ("Req 10", "Logging", "Tamper-evident audit trail + SIEM"),
    ("Req 11", "Scanning / pen-testing", "Active Scanner results feed ASV/PT scope"),
    ("Req 12", "InfoSec policy", "ISMS alignment per Section 9.1"),
]


def framework_snapshots() -> Dict[str, List[str]]:
    def render(framework: str, rows) -> List[str]:
        out = [f"### {framework}", "| Control | Requirement | Implementation |",
               "|---|---|---|"]
        out += [f"| {c} | {n} | {i} |" for c, n, i in rows]
        return out

    return {
        "ISO/IEC 27001:2022": render("ISO/IEC 27001:2022 (Annex A)", ISO_MAP),
        "NIST SP 800-53 / CSF 2.0": render("NIST SP 800-53 / CSF 2.0", NIST_MAP),
        "OWASP Top 10 (2021)": render("OWASP Top 10 (2021)", OWASP_MAP),
        "PCI DSS 4.0": render("PCI DSS 4.0", PCI_MAP),
    }


def export_snapshot(extra: Dict[str, object] | None = None) -> str:
    doc = [
        "# SQLiDetect Shield - Compliance Snapshot",
        "",
        f"_Generated: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}_",
        "",
        "Source mapping: ARCHITECTURE.md v1.0, Section 9.",
        "",
    ]
    for name, rows in framework_snapshots().items():
        doc += rows
        doc += [""]
    doc.append("## Runtime evidence")
    if extra:
        for k, v in extra.items():
            doc.append(f"- **{k}:** {v}")
    else:
        doc.append("- (attach findings/scanner evidence per audit)")
    return "\n".join(doc)


def export_json(extra: Dict[str, object] | None = None) -> str:
    payload = {
        "tool": "SQLiDetect Shield",
        "version": "1.0.0",
        "generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "frameworks": {
            "iso27001": [{"control": c, "requirement": n, "implementation": i}
                         for c, n, i in ISO_MAP],
            "nist": [{"control": c, "requirement": n, "implementation": i}
                     for c, n, i in NIST_MAP],
            "owasp": [{"control": c, "requirement": n, "implementation": i}
                      for c, n, i in OWASP_MAP],
            "pci": [{"control": c, "requirement": n, "implementation": i}
                    for c, n, i in PCI_MAP],
        },
        "runtime_evidence": extra or {},
    }
    return json.dumps(payload, indent=2)