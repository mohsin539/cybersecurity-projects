"""Heuristic rules — strings + PE signals -> findings with control mapping.

Every finding carries:
- rule_id (stable), title, severity (info/low/medium/high) = risk delta
- category  -> mapped controls (ISO/NIST/OWASP) via CATEGORY_CONTROLS
- evidence  -> the raw signals that triggered it

architecture.md §5.4 S6 + §10 compliance anchors.
"""
from __future__ import annotations

from dataclasses import dataclass, field

SCORE = {"info": 0, "low": 5, "medium": 10, "high": 15}

CATEGORY_CONTROLS = {
    "packing":          ["ISO A.8.12", "NIST PR.DS-01", "NIST DE.CM-08", "OWASP A08"],
    "code-injection":   ["ISO A.8.12", "NIST DE.CM-08", "NIST SI-3", "OWASP A08"],
    "persistence":      ["ISO A.8.12", "NIST PR.DS-01", "NIST DE.CM-08", "OWASP A09"],
    "network-ioi":      ["ISO A.8.12", "NIST PR.DS-02", "NIST DE.CM-08", "OWASP A05"],
    "evasion":          ["ISO A.8.28", "NIST PR.DS-06", "NIST DE.CM-08", "OWASP A08"],
    "structural":       ["ISO A.8.28", "NIST SI-10", "OWASP A03"],
    "integrity":        ["ISO A.8.12", "NIST PR.DS-06", "OWASP A08"],
    "intel":            ["ISO A.8.12", "NIST DE.CM-04", "NIST RA-3", "OWASP A08"],
}

DEFAULT_CONTROLS = ["ISO A.8.12", "NIST PR.DS-01", "OWASP A08"]


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str
    category: str
    evidence: dict = field(default_factory=dict)

    @property
    def controls(self) -> list[str]:
        return CATEGORY_CONTROLS.get(self.category, DEFAULT_CONTROLS)

    @property
    def score_delta(self) -> int:
        return SCORE[self.severity]

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "category": self.category,
            "controls": self.controls,
            "score_delta": self.score_delta,
            "evidence": self.evidence,
        }


def _lower_api_set(apis: list[str]) -> set[str]:
    return {a.lower() for a in apis}


def evaluate(strings: dict, pe: dict, intel_highest: str = "unknown") -> list[Finding]:
    """Run heuristic rules over a strings+pe result pair. Deterministic order."""
    findings: list[Finding] = []

    s_apis = [a.lower() for a in strings.get("suspicious_apis", [])]
    art_counts = strings.get("artifact_counts", {}) or {}
    he_count = int(strings.get("high_entropy_count", 0) or 0)
    pe_anomalies = pe.get("anomalies", []) or []
    sections = pe.get("sections", []) or []
    imports = pe.get("imports", []) or []

    # ---- strings -----------------------------------------------------------
    if he_count >= 5:
        findings.append(Finding(
            "SAP-S-HASE", "high-entropy strings suggesting encoded/encrypted blobs",
            "medium", "evasion",
            {"high_entropy_count": he_count}))
    elif he_count >= 1:
        findings.append(Finding(
            "SAP-S-HASE1", "high-entropy strings present", "low", "evasion",
            {"high_entropy_count": he_count}))

    if {"createremotethread", "virtualallocex", "writeprocessmemory"}.intersection(s_apis):
        findings.append(Finding(
            "SAP-S-INJAPI", "injection-related API strings", "high", "code-injection",
            {"apis": sorted(s_apis)}))
    if any(a in s_apis for a in ("regsetvalueexa", "regsetvalueexw")):
        findings.append(Finding(
            "SAP-S-REGSET", "registry persistence API strings", "medium", "persistence",
            {"apis": sorted(s_apis)}))
    if any(a in s_apis for a in ("winexec", "shellexecutea", "shellexecutew", "createprocessa", "createprocessw")):
        findings.append(Finding(
            "SAP-S-PROCEXEC", "process-spawning API strings", "low", "persistence",
            {"apis": sorted(s_apis)}))

    if art_counts.get("url"):
        url_ct = art_counts["url"]
        if url_ct >= 5:
            findings.append(Finding(
                "SAP-S-URLS", "embedded URLs (C2 / download candidates)", "high",
                "network-ioi", {"url_count": url_ct}))
        else:
            findings.append(Finding(
                "SAP-S-URL1", "embedded URL artifacts", "low", "network-ioi",
                {"url_count": url_ct, "sample": strings.get("artifacts", [{}])[0] if strings.get("artifacts") else None}))
    if art_counts.get("domain") or art_counts.get("ipv4"):
        findings.append(Finding(
            "SAP-S-NETIOI", "network IOC artifacts (domains/IPs) embedded",
            "medium", "network-ioi",
            {"domains": art_counts.get("domain", 0), "ips": art_counts.get("ipv4", 0)}))
    if art_counts.get("registry"):
        findings.append(Finding(
            "SAP-S-REG", "registry-path artifacts (persistence signal)",
            "medium", "persistence", {"reg_count": art_counts["registry"]}))

    # ---- PE ----------------------------------------------------------------
    high_ent_sections = [s for s in sections if s.get("entropy") and s["entropy"] > 7.2 and s["raw_size"] > 0]
    if high_ent_sections:
        findings.append(Finding(
            "SAP-P-PACK", "high-entropy sections (packing/encryption signal)",
            "high", "packing", {"sections": [s["name"] for s in high_ent_sections]}))
    hollow = [s for s in sections if s["raw_size"] == 0 and s["virtual_size"] > 0]
    if hollow:
        findings.append(Finding(
            "SAP-P-HOLLOW", "metadata-only sections (possible run-time decryption)",
            "medium", "packing", {"sections": [s["name"] for s in hollow]}))

    imports_flat = {f.lower() for imp in imports for f in imp.get("functions", [])}
    triad = {"virtualallocex", "writeprocessmemory", "createremotethread"}
    triad_hit = triad & imports_flat
    if len(triad_hit) >= 2:
        findings.append(Finding(
            "SAP-P-IMPTRIAD", "suspicious memory-injection import triad",
            "high", "code-injection", {"present": sorted(triad_hit)}))

    overlay = int(pe.get("overlay_size", 0) or 0)
    if overlay > 0:
        findings.append(Finding(
            "SAP-P-OVERLAY", "trailing overlay bytes (potential hidden payload)",
            "medium" if overlay > 64 * 1024 else "low", "structural",
            {"overlay_size": overlay}))

    for anom in pe_anomalies:
        text = anom.lower()
        if "entry point lives in a writable" in text:
            findings.append(Finding(
                "SAP-P-EPWRITE", "entry point in writable section",
                "high", "code-injection", {"anomaly": anom}))
        elif "import triad" in text or "checksum mismatch" in text:
            findings.append(Finding(
                "SAP-P-IMP2", anom, "low", "integrity", {"anomaly": anom}))
        elif "timestamp" in text:
            findings.append(Finding(
                "SAP-P-TSFAKE", anom, "low", "evasion", {"anomaly": anom}))

    if not pe.get("checksum_ok", True) and pe.get("timestamp"):
        findings.append(Finding(
            "SAP-P-CHKSUM", "PE checksum mismatch", "low", "integrity", {}))

    if intel_highest == "malicious":
        findings.append(Finding(
            "SAP-I-MAL", "known-malicious hash (intel)", "high", "intel", {}))
    elif intel_highest == "suspicious":
        findings.append(Finding(
            "SAP-I-SUS", "suspicious intel reputation", "medium", "intel", {}))

    findings.sort(key=lambda f: f.score_delta, reverse=True)
    return findings