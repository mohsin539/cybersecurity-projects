# security.md

Reserved — security model for the **Traffic Obfuscation Techniques Demo** (Domain Fronting Concepts, Detection-Focused).

---

## 1. Purpose & Scope

Educational lab demonstrating how TLS-level traffic obfuscation (domain fronting and
related techniques) appears in network telemetry, and how a detection-centric pipeline
can surface it. The project **does not** contact real domains, emit real network traffic,
or capture real packets.

## 2. Trust & Data Model

| Property | Value |
|---|---|
| Synthetic data only | `src/generator/` builds deterministic TLS ClientHello metadata records in memory |
| Real network I/O | None — zero sockets, zero DNS, zero HTTP calls in any module |
| PII / sensitive material | None — all hostnames use `.example` reserved TLDs or fictional CDN IPs |
| Persistence | Only user-invoked report exports on the local disk (`.xlsx/.csv/.html/.json`) |
| Secrets handling | No API keys, tokens, or credentials anywhere in the codebase |

## 3. Threat / Misuse Model

The demo models **side of an attacker who uses these techniques** and the **defender who detects them**:

| Technique | Detection signal | Risk indicator |
|---|---|---|
| Domain fronting | SNI vs Host header divergence on shared anycast CDN edge | Indicators of obfuscated C2 / hidden service access |
| SNI spoofing | High-reputation SNI with internal/unrelated Host | Evasion of egress allow-lists |
| HTTPS CONNECT tunneling | 443 flows without coherent SNI/Host pairing | Encapsulated relay / covert channel |
| H2 `:authority` spoofing | `:authority` diverges from SNI and Host | Route / origin-steering abuse (OWASP A08, A10) |

Verdicts (`benign / suspicious / fronted`) are **heuristic indicators, never attribution**.

## 4. Framework Compliance Map

Every finding carries control references resolved by `src/frameworks/`:

| Framework | Control IDs used | Demo role |
|---|---|---|
| OWASP Top 10 (2021) | A01, A02, A03, A04, A05, A06, A07, A08, A09, A10 | Rule-level mapping on each finding |
| NIST CSF 2.0 | GV, ID, PR, DE, RS, RC | Function-level coverage of the detection workflow |
| ISO/IEC 27001:2022 | A5.2, A5.10, A8.9, A8.10, A8.16, A8.20, A8.24, A8.28 | Annex A controls the capability exercises |

Exported with every report: Overview, Flow Verdicts, Findings, Framework Mapping, Raw Records.

## 5. Secure-By-Design Properties of the Code

1. **Deterministic** — dataset and scores are reproducible across runs (no RNG in detection path).
2. **Least privilege** — GUI writes only to `Reports/` beside the exe; no registry, no admin rights.
3. **Defense-in-depth posture** — scoring is severity-weighted with conservative thresholds
   (`suspicious >= 40`, `fronted >= 70`) to reduce false attribution.
4. **Supply chain minimalism** — runtime dependencies: `openpyxl` only (pure-Python, no native code).
5. **Fails closed** — GUI disables export until an analysis run completes; exceptions surface to the user.
6. **No hidden exfiltration** — analyzer makes no outbound calls; `--selftest` writes a marker file only.

## 6. Hardening Checklist for a Defensive Build

- [ ] Enable TLS 1.3 enforcement and pin certificates at egress (NIST PR, ISO A8.24).
- [ ] Treat Encrypted Client Hello (ECH) as a detection blind spot — pair with DNS analytics.
- [ ] Add strict `Host`/`:authority` allow-lists at origin reverse proxies (OWASP A03/A10).
- [ ] Do not use SNI as an identity or authentication token (OWASP A07).
- [ ] Stream SNI/Host/JA4 telemetry into the SIEM (OWASP A09, ISO A8.16).
- [ ] Version-lock `openpyxl` and rebuild the exe on CVE disclosures (OWASP A06).
- [ ] Sign the delivered exe (Authenticode) before putting it in user hands.

## 7. Incident Response Pointer

Play to respond when a `fronted` verdict is real (NIST RS/RC): isolate the origin from the CDN
routing path, rotate routing trust, quarantine the violating client, then recover the routing
baseline and repair monitoring rules.

## 8. Operational Guards

- Run only inside a sandboxed/segmented lab if real capture is later added.
- Keep synthetic data flags explicit (`scenario`) so lab vs production traces remain distinguishable.
- Retain report exports per organizational retention policy before deletion (ISO A8.10).