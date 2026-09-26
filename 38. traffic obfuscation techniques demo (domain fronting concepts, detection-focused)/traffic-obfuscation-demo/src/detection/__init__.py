"""Detection modules for the traffic obfuscation demo."""

from .analyzers import (
    detect_sni_host_mismatch,
    detect_authority_spoof,
    detect_cdn_fronting_signature,
    detect_anomalous_ttl,
    detect_extended_extension_set,
    analyze_record,
    Severity,
    Finding,
)

__all__ = [
    "detect_sni_host_mismatch",
    "detect_authority_spoof",
    "detect_cdn_fronting_signature",
    "detect_anomalous_ttl",
    "detect_extended_extension_set",
    "analyze_record",
    "Severity",
    "Finding",
]