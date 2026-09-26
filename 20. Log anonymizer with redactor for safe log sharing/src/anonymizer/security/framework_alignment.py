"""Security framework alignment reference for the codebase.

Maps implemented controls to OWASP Top 10 (2021), NIST SP 800-53 R5 /
CSF 2.0, and ISO 27001:2022 Annex A. Use for compliance evidence and
security reviews.

```
┌─────────────────────────────┬───────────────────────────────────────────────┐
│ Implementation              │ Framework References                          │
├─────────────────────────────┼───────────────────────────────────────────────┤
│ InputValidator              │ OWASP A03 (Injection), ISO A.8.26             │
│ (input_validation.py)       │ A.8.26 Application security requirements      │
├─────────────────────────────┼───────────────────────────────────────────────┤
│ PatternDetector /           │ ISO A.8.11 Data masking, GDPR Art.25          │
│ Redactor (7 strategies)     │ Privacy by design; PCI-DSS Req 3.4            │
├─────────────────────────────┼───────────────────────────────────────────────┤
│ AuditTrail (append-only,    │ OWASP A09 (Logging Failures), ISO A.8.15      │
│ hash-chain / Merkle proofs) │ NIST AU-2/AU-6/AU-12, NIST CSF PR.PT           │
├─────────────────────────────┼───────────────────────────────────────────────┤
│ hash_original (salt HMAC)   │ OWASP A02 (Crypto Failures), ISO A.8.24,      │
│ never stores raw values     │ GDPR Art.32, PCI-DSS Req 3.2                  │
├─────────────────────────────┼───────────────────────────────────────────────┤
│ PolicyEngine (RBAC/class)   │ OWASP A01 (Broken Access Control), ISO        │
│ declarative policies        │ A.5.15/A.8.2, NIST AC-3/AC-6 (least priv.)    │
├─────────────────────────────┼───────────────────────────────────────────────┤
│ RedactionContext token salt │ ISO A.8.11, NIST SC-28, GDPR pseudonymization │
│ (per-tenant isolation)      │ pseudo-randomization (Recital 26/28)          │
├─────────────────────────────┼───────────────────────────────────────────────┤
│ FastAPI TLS-ready /         │ OWASP A05 (Misconfig), NIST SC-8 (transit),   │
│ API key + CORS controls     │ ISO A.8.3 (access restriction)                │
├─────────────────────────────┼───────────────────────────────────────────────┤
│ Tests (conftest + data)     │ OWASP A06 (Vulnerable Components) via CI,     │
│                             │ NIST SA-11 (developer testing), ISO A.8.25    │
└─────────────────────────────┴───────────────────────────────────────────────┘
```
"""
