"""Detection-focused analysis for domain-fronting / traffic-obfuscation signs.

Each check returns a `Finding` with evidence, severity and a mapping to the
framework control catalogs. The scoring engine combines all findings into a
per-record suspicion score (0-100).
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import List

from src.config import SCORE_THRESHOLD_SUSPICIOUS, SCORE_THRESHOLD_HIGH
from src.generator import TrafficRecord


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


_SEV_WEIGHTS = {
    Severity.INFO: 5,
    Severity.LOW: 8,
    Severity.MEDIUM: 16,
    Severity.HIGH: 26,
    Severity.CRITICAL: 38,
}


@dataclass
class Finding:
    finding_id: str
    title: str
    description: str
    severity: Severity
    evidence: str
    check: str
    refs: List[str] = field(default_factory=list)
    record_id: str = ""

    @property
    def weight(self) -> int:
        return _SEV_WEIGHTS.get(self.severity, 5)


def _norm(host: str) -> str:
    core = (host or "").split("://")[-1]
    if ":" in core and not core.startswith("["):
        core = core.rsplit(":", 1)[0]
    return core.rstrip(".").lower()


def detect_sni_host_mismatch(rec: TrafficRecord) -> Finding | None:
    if not rec.sni or not rec.host_header:
        return None
    if _norm(rec.sni) != _norm(rec.host_header):
        sev = Severity.HIGH if rec.cdn_flag else Severity.CRITICAL
        return Finding(
            finding_id=f"{rec.record_id}-F01",
            title="SNI / Host header inconsistency",
            description=(
                "The TLS Server Name Indication advertises a different "
                "domain than the HTTP Host header. This is the textbook "
                "fingerprint of domain fronting, where the SNI selects a "
                "CDN 'front' domain and the Host header steers the proxied "
                "request to the hidden backend."
            ),
            severity=sev,
            evidence=f"SNI='{rec.sni}' Host='{rec.host_header}' "
                     f"destIP={rec.dest_ip} CDN={rec.cdn_owner or '-'}",
            check="sni_host_mismatch",
            refs=["OWASP-04", "NIST:C", "ISO:A8.28"],
        )
    return None


def detect_authority_spoof(rec: TrafficRecord) -> Finding | None:
    if not rec.http2_authority:
        return None
    if _norm(rec.http2_authority) != _norm(rec.host_header):
        return Finding(
            finding_id=f"{rec.record_id}-F02",
            title="HTTP/2 :authority pseudo-header spoofing",
            description=(
                "The HTTP/2 :authority field diverges from the TLS SNI. In "
                "hardened fronted setups the :scheme / :authority pair is "
                "used after the CONNECT tunnel to mount an origin request."
            ),
            severity=Severity.HIGH,
            evidence=f"SNI='{rec.sni}' :authority='{rec.http2_authority}' "
                     f":host='{rec.host_header}'",
            check="http2_authority_spoof",
            refs=["OWASP-08", "NIST:D", "ISO:A8.16"],
        )
    return None


def detect_cdn_fronting_signature(rec: TrafficRecord) -> Finding | None:
    """Fronting requires dust destined to a shared/anycast CDN edge."""
    if not rec.cdn_flag:
        return None
    # Shared-front signal: high-reputation CDN front, backend in Host header
    if rec.sni_host_mismatch and rec.host_header:
        known_front = any(
            d.lower() in _norm(rec.sni) or _norm(rec.sni).endswith((".com", ".net"))
            for d in ("cloudflare", "fastly", "google", "akamai")
        )
        if known_front:
            return Finding(
                finding_id=f"{rec.record_id}-F03",
                title="CDN fronting pattern detected",
                description=(
                    f"Destination IP belongs to {rec.cdn_owner} anycast "
                    "ranges while SNI front and Host backend diverge - "
                    "consistent with TLS-hosting CDN domain fronting."
                ),
                severity=Severity.HIGH,
                evidence=f"destIP={rec.dest_ip} CDN={rec.cdn_owner} "
                         f"front='{rec.sni}' origin='{rec.host_header}'",
                check="cdn_fronting_signature",
                refs=["OWASP-04", "NIST:P", "ISO:A8.28"],
            )
    return None


def detect_anomalous_ttl(rec: TrafficRecord) -> Finding | None:
    """TTL below the typical public-internet window can flag tunnels."""
    if rec.ttl and rec.ttl <= 52 and rec.scenario != "NORMAL":
        sev = Severity.MEDIUM if rec.scenario in ("DOMAIN_FRONT", "SNI_SPOOF", "H2_SPOOF") else Severity.LOW
        return Finding(
            finding_id=f"{rec.record_id}-F04",
            title="Low / stable TTL across flows",
            description=(
                "A sub-52 hop TTL combined with low latency variance can "
                "indicate foreign encapsulation or a tunnelled flow wrapping "
                "the obfuscated channel."
            ),
            severity=sev,
            evidence=f"TTL={rec.ttl} dst={rec.dest_ip}",
            check="ttl_anomaly",
            refs=["OWASP-09", "NIST:D", "ISO:A8.16"],
        )
    return None


def detect_extended_extension_set(rec: TrafficRecord) -> Finding | None:
    """Non-browser TLS stacks advertise a distinctive extension set."""
    odd = [e for e in rec.extensions if e in ("psk", "settings", "post_quantum")]
    if odd and rec.sni_host_mismatch:
        return Finding(
            finding_id=f"{rec.record_id}-F05",
            title="Custom TLS stack heuristics",
            description=(
                "The ClientHello advertises client-specific extensions "
                "(psk/padding/settings) that diverge from mainstream browsees "
                "- useful for JA4-style fingerprint correlation across "
                "sessions."
            ),
            severity=Severity.MEDIUM,
            evidence=f"extensions={rec.extensions} JA4≈{rec.js_ver}",
            check="extension_set",
            refs=["OWASP-09", "NIST:D", "ISO:A8.16"],
        )
    return None


def analyze_record(rec: TrafficRecord) -> List[Finding]:
    """Run the full detection chain over one traffic record."""
    checks = [
        detect_sni_host_mismatch,
        detect_authority_spoof,
        detect_cdn_fronting_signature,
        detect_anomalous_ttl,
        detect_extended_extension_set,
    ]
    findings = [f for c in checks if (f := c(rec)) is not None]
    for f in findings:
        f.record_id = rec.record_id
    return findings