# AegisLB — Security Posture & Audit (preservation artifact)

*Purpose:* preserved security posture, audit-chain tail, recent security events, and framework mapping status. Full analysis in `docs/02-security-architecture-and-threat-model.md` and `docs/03-framework-traceability.md`.

Last updated (UTC): 2026-09-17T07:51:57Z

## Posture Summary

| Item | Status |
|---|---|
| Hardened mode (AEGIS_HARDENED) | True |
| Admin API authZ | requires scoped API key (config/ops/auditor roles) |
| Rate limiting | 120 / min per client |
| Transport (default) | bind 127.0.0.1; TLS recommended at edge (see docs/02 §6) |
| Secrets | env-injected; never logged or persisted in plaintext (cache redacts) |

## Compliance Mapping Status

| Framework | Coverage | Primary artifact |
|---|---|---|
| OWASP Top 10 (2021) | A01–A10 controls implemented & test-mapped | docs/03 §2 |
| NIST SP 800-207 (Zero Trust) | 7 tenets + 5 pillars by design | docs/02 §2, docs/03 §3 |
| NIST SP 800-53 Rev5 | ~50 selected controls w/ evidence | docs/03 §4 |
| ISO/IEC 27001:2022 Annex A | SoA ~42 applicable controls | docs/03 §5 |
| NIST CSF 2.0 | GOVERN/IDENTIFY/PROTECT/DETECT/RESPOND/RECOVER | docs/03 §6 |

## Audit Chain

- Entries recorded (process lifetime): 0
- Chain tail (SHA-256): `GENESIS`
- Method: hash-chain append-only ledger; each entry = SHA-256(prev || JSON body).
- API surface exposes `audit:read` only; no update/delete path exists.

## Recent Security Events (latest 100)

| t(s) | eid | type | severity | detail |
|---|---|---|---|---|

## Threats Exercised (see docs/02 §4)

- N1 Probe-target poisoning  → PROBE_TOKEN_MISMATCH events, N-of-M agreement
- N2 Health-state flapping → hysteresis + min-state-hold
- N3 Admin API abuse → PDP role enforcement + audit
- N4 Probe-URI/SSRF → no user-supplied URLs (schema-validated paths only)
- N5 Supply chain → SBOM/signing gates (docs/02 §9)
- N6 Insider audit tampering → hash-chained WORM-style audit

---
