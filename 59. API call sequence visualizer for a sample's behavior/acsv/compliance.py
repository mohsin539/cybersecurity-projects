"""Compliance mapping service (ISO 27001 A.5.36, A.8.25).

Embeds the control inventory from architecture.md section 9 as machine-readable
data and exposes:
- `coverage_matrix()` -> controls x status for a findings set
- `map_finding()`     -> control IDs linked to a finding/tag
- `controls()`        -> raw control list for the Compliance Console
"""

from __future__ import annotations

ISO_CONTROLS: list[dict] = [
    {"id": "A.5.1", "name": "Policies for information security", "plugin": "policy_snapshot", "domain": "Isolation, policy service"},
    {"id": "A.5.7", "name": "Threat intelligence", "plugin": "stix_export", "domain": "Reporting"},
    {"id": "A.5.9", "name": "Inventory of information and assets", "plugin": "artifact_registry", "domain": "Data layer"},
    {"id": "A.5.10", "name": "Acceptable use of information and assets", "plugin": "no_exec_default", "domain": "Sample intake"},
    {"id": "A.5.11", "name": "Return of assets", "plugin": "secure_wipe", "domain": "Portable mode"},
    {"id": "A.5.12", "name": "Classification of information", "plugin": "report_classification", "domain": "Reporting"},
    {"id": "A.5.13", "name": "Labelling of information", "plugin": "report_classification", "domain": "Reporting"},
    {"id": "A.5.15", "name": "Access control", "plugin": "rbac_scaffold", "domain": "Application"},
    {"id": "A.5.16", "name": "Identity management", "plugin": "rbac_scaffold", "domain": "Application"},
    {"id": "A.5.18", "name": "Access rights", "plugin": "rbac_scaffold", "domain": "Application"},
    {"id": "A.5.20", "name": "Supplier relationships", "plugin": "offline_default", "domain": "Runtime"},
    {"id": "A.5.23", "name": "Cloud services security", "plugin": "offline_default", "domain": "Runtime"},
    {"id": "A.5.24", "name": "Incident management planning", "plugin": "finding_model", "domain": "Analysis"},
    {"id": "A.5.26", "name": "Response to incidents", "plugin": "finding_model", "domain": "Analysis"},
    {"id": "A.5.28", "name": "Collection of evidence", "plugin": "event_store_integrity", "domain": "Data layer"},
    {"id": "A.5.29", "name": "Disruption resilience", "plugin": "portable_exe", "domain": "Packaging"},
    {"id": "A.5.31", "name": "Legal/regulatory compliance", "plugin": "sbom_license", "domain": "Packaging"},
    {"id": "A.5.33", "name": "Protection of records", "plugin": "audit_chain", "domain": "Audit"},
    {"id": "A.5.34", "name": "Privacy and PII protection", "plugin": "redaction", "domain": "Data layer"},
    {"id": "A.5.36", "name": "Compliance with policies", "plugin": "compliance_console", "domain": "Application"},
    {"id": "A.5.37", "name": "Documented operating procedures", "plugin": "handbook", "domain": "Docs"},
    {"id": "A.7.1", "name": "Physical security premises", "plugin": "portable_media_guidance", "domain": "Portable mode"},
    {"id": "A.8.1", "name": "User endpoint devices", "plugin": "portable_exe", "domain": "Packaging"},
    {"id": "A.8.2", "name": "Privileged access rights", "plugin": "jit_admin", "domain": "Runtime"},
    {"id": "A.8.5", "name": "Secure authentication", "plugin": "rbac_scaffold", "domain": "Application"},
    {"id": "A.8.9", "name": "Configuration management", "plugin": "schema_registry", "domain": "Data layer"},
    {"id": "A.8.15", "name": "Logging", "plugin": "audit_chain", "domain": "Audit"},
    {"id": "A.8.16", "name": "Monitoring activities", "plugin": "audit_chain", "domain": "Audit"},
    {"id": "A.8.24", "name": "Use of cryptography", "plugin": "dpapi_signing", "domain": "Crypto"},
    {"id": "A.8.25", "name": "Secure development lifecycle", "plugin": "threat_model", "domain": "SDL"},
    {"id": "A.8.26", "name": "Application security requirements", "plugin": "schema_registry", "domain": "SDL"},
    {"id": "A.8.28", "name": "Secure coding", "plugin": "hardened_stack", "domain": "SDL"},
    {"id": "A.8.31", "name": "Separation of environments", "plugin": "build_profiles", "domain": "SDL"},
    {"id": "A.8.32", "name": "Change management", "plugin": "versioning", "domain": "SDL"},
    {"id": "A.8.33", "name": "Test information", "plugin": "benign_corpus", "domain": "Testing"},
    {"id": "A.8.34", "name": "Protection during audit", "plugin": "audit_readonly", "domain": "Audit"},
    {"id": "A.8.35", "name": "Security audit testing", "plugin": "integrity_check", "domain": "Audit"},
    {"id": "A.8.51", "name": "Secure transfer of information", "plugin": "tls13_future", "domain": "Reporting"},
]

NIST_CONTROLS: list[dict] = [
    {"id": "CSF-GOVERN", "name": "Govern", "plugin": "policy_snapshot", "domain": "Governance"},
    {"id": "CSF-IDENTIFY", "name": "Identify", "plugin": "artifact_registry", "domain": "Inventory"},
    {"id": "CSF-PROTECT", "name": "Protect", "plugin": "isolation_redaction", "domain": "Protection"},
    {"id": "CSF-DETECT", "name": "Detect", "plugin": "analysis_engine", "domain": "Detection"},
    {"id": "CSF-RESPOND", "name": "Respond", "plugin": "finding_model", "domain": "Response"},
    {"id": "CSF-RECOVER", "name": "Recover", "plugin": "portable_exe", "domain": "Recovery"},
    {"id": "SP800-53-AC-2", "name": "Account management", "plugin": "rbac_scaffold", "domain": "Access"},
    {"id": "SP800-53-AC-3", "name": "Access enforcement", "plugin": "rbac_scaffold", "domain": "Access"},
    {"id": "SP800-53-AC-6", "name": "Least privilege", "plugin": "jit_admin", "domain": "Access"},
    {"id": "SP800-53-AU-2", "name": "Audit events", "plugin": "audit_chain", "domain": "Audit"},
    {"id": "SP800-53-AU-3", "name": "Content of audit records", "plugin": "audit_chain", "domain": "Audit"},
    {"id": "SP800-53-AU-9", "name": "Protection of audit info", "plugin": "audit_chain", "domain": "Audit"},
    {"id": "SP800-53-AU-11", "name": "Audit record retention", "plugin": "retention_policy", "domain": "Audit"},
    {"id": "SP800-53-CM-2", "name": "Baseline configuration", "plugin": "schema_registry", "domain": "Config"},
    {"id": "SP800-53-CM-6", "name": "Configuration settings", "plugin": "policy_snapshot", "domain": "Config"},
    {"id": "SP800-53-CP-9", "name": "System backup", "plugin": "portable_data", "domain": "Recovery"},
    {"id": "SP800-53-IA-2", "name": "Identification/auth", "plugin": "rbac_scaffold", "domain": "Access"},
    {"id": "SP800-53-IR-4", "name": "Incident handling", "plugin": "finding_model", "domain": "Response"},
    {"id": "SP800-53-IR-5", "name": "Incident monitoring", "plugin": "finding_model", "domain": "Response"},
    {"id": "SP800-53-RA-5", "name": "Vulnerability scanning", "plugin": "dependency_scan", "domain": "SDL"},
    {"id": "SP800-53-SA-11", "name": "Developer testing/eval", "plugin": "golden_corpus", "domain": "SDL"},
    {"id": "SP800-53-SA-15", "name": "Development process", "plugin": "threat_model", "domain": "SDL"},
    {"id": "SP800-53-SC-28", "name": "Protection at rest", "plugin": "dpapi_signing", "domain": "Crypto"},
    {"id": "SP800-53-SI-4", "name": "System monitoring", "plugin": "audit_chain", "domain": "Audit"},
    {"id": "SP800-53-SR-3", "name": "Supply chain protection", "plugin": "sbom_license", "domain": "SDL"},
    {"id": "SP800-53-SR-4", "name": "Supply chain provenance", "plugin": "sbom_license", "domain": "SDL"},
]

OWASP_CONTROLS: list[dict] = [
    {"id": "OWASP-A01", "name": "Broken Access Control", "plugin": "rbac_scaffold", "domain": "Access"},
    {"id": "OWASP-A02", "name": "Cryptographic Failures", "plugin": "dpapi_signing", "domain": "Crypto"},
    {"id": "OWASP-A03", "name": "Injection", "plugin": "prepared_sql_html_escape", "domain": "Data"},
    {"id": "OWASP-A04", "name": "Insecure Design", "plugin": "sandbox_default", "domain": "Runtime"},
    {"id": "OWASP-A05", "name": "Security Misconfiguration", "plugin": "fail_closed_config", "domain": "Config"},
    {"id": "OWASP-A06", "name": "Vulnerable and Outdated Components", "plugin": "dependency_scan", "domain": "SDL"},
    {"id": "OWASP-A07", "name": "Identification and Authentication Failures", "plugin": "rbac_scaffold", "domain": "Access"},
    {"id": "OWASP-A08", "name": "Software and Data Integrity Failures", "plugin": "audit_chain", "domain": "Audit"},
    {"id": "OWASP-A09", "name": "Security Logging and Monitoring Failures", "plugin": "audit_chain", "domain": "Audit"},
    {"id": "OWASP-A10", "name": "Server-Side Request Forgery", "plugin": "deny_egress", "domain": "Runtime"},
]

FRAMEWORKS = {"ISO27001": ISO_CONTROLS, "NIST": NIST_CONTROLS, "OWASP": OWASP_CONTROLS}

# Findings/tags carry control tags; map each control's likely evidence plugin.
_PLUGIN_MAP = {c["id"]: c["plugin"] for group in FRAMEWORKS.values() for c in group}


class ComplianceService:
    def __init__(self) -> None:
        self._add_meta()

    def _add_meta(self) -> None:
        for grp in FRAMEWORKS.values():
            for c in grp:
                c["compliance_level"] = "present" if c["plugin"] else "absent"
                c["status"] = "implemented" if c["plugin"] else "planned"

    def controls(self, framework: str) -> list[dict]:
        if framework not in FRAMEWORKS:
            raise KeyError(framework)
        return list(FRAMEWORKS[framework])

    def map_finding(self, finding_tags: list[str]) -> list[str]:
        """Map finding tags (e.g. 'OWASP-A05','A.8.24') to control IDs."""
        tags = set(t.upper() for t in (finding_tags or []))
        hits: list[str] = []
        for grp in FRAMEWORKS.values():
            for c in grp:
                if c["id"].upper() in tags:
                    hits.append(c["id"])
        return sorted(hits)

    def coverage_matrix(self, evidence_tags: list[str]) -> dict:
        """Return frameworks with control status given available evidence tags.

        Structure: {"ISO27001": {"rows": [...], "summary": {...}}, ...}
        """
        ev = set(t.upper() for t in evidence_tags or [])
        out: dict[str, dict] = {}
        for fw, controls in FRAMEWORKS.items():
            rows = []
            evidenced = 0
            for c in controls:
                plugin_present = bool(c["plugin"])
                evidenced_flag = c["id"].upper() in ev or c["plugin"].lower() in ev
                status = "evidenced" if evidenced_flag else ("implemented" if plugin_present else "planned")
                if evidenced_flag:
                    evidenced += 1
                rows.append({**c, "status": status})
            out[fw] = {
                "rows": rows,
                "summary": {
                    "total": len(rows),
                    "evidenced": evidenced,
                    "implemented": sum(1 for r in rows if r["status"] in ("implemented", "evidenced")),
                },
            }
        return out

    def coverage_summary(self, evidence_tags: list[str]) -> dict:
        matrix = self.coverage_matrix(evidence_tags)
        total = 0
        evidenced = 0
        implemented = 0
        for v in matrix.values():
            s = v["summary"]
            total += s["total"]
            evidenced += s["evidenced"]
            implemented += s["implemented"]
        return {"total": total, "evidenced": evidenced, "implemented": implemented,
                "coverage_pct": round(implemented / total * 100, 1) if total else 0.0}