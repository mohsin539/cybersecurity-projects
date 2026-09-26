"""Security, integrity and compliance controls for the extractor.

This package implements the technical controls referenced by the compliance
matrix in :mod:`sec.compliance`:

* Tamper-evident, hash-chained audit logging (ISO 27001 A.8.15).
* SHA-256 evidence hashing and manifests (NIST SP 800-86, RFC 3227).
* HTML/CSV output escaping to defeat injection (OWASP A03:2021).
"""

__all__ = ["integrity", "audit", "compliance"]
