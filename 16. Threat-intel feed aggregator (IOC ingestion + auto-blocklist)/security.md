# Project 16 — Security Posture

Controls mapped to **NIST CSF 2.0**, **ISO 27001:2022 Annex A**, and **OWASP Top 10**.

---

## 1. Threat Model Summary

| Asset | Trust boundary | Main threats |
|-------|----------------|--------------|
| Feed content (external MISP/OTX/fixtures) | Untrusted third-party | Malicious IOCs (feed poisoning), malformed data, TLP abuse |
| Blocklist + audit log | Local FS | Tampered audit trail, blocklist filled with junk = DoS |
| Consumer drivers (pfSense, DNS, WAF, cloud) | Network/API | Auto-blocking benign IPs (self-DoS), rollback gap |
| Blocklist API (future) | Network | Unauthorized reads, SSRF to internal consumers |
| Internal feeds (honeypot, SIEM) | Internal | Spoofed internal sender → blocklist bloat |

CORE SAFETY PRINCIPLE: **Safety over comprehensiveness** — never auto-block internal infra, own ranges, or suspicious/amber TLP IOCs. Guards before tiering, audit after every decision.

---

## 2. Controls — NIST CSF 2.0

| CSF Function | Control | Implemented |
|--------------|---------|-------------|
| **Govern** | GV.RM | trust tiers defined in config; `quarantine` for median requires human approval |
| **Identify** | ID.RA | Feed health tracked (degraded feed → no auto-drop but flagged) |
| **Protect** | PR.DS-1 integrity | Blocklist append-only JSONL + audit trail (blocklist_audit.jsonl) |
| **Protect** | PR.PT-4 logging | Every apply/retire logged with reason, source, tier |
| **Detect** | DE.CM | Confidence + multi-source agreement feed detection |
| **Respond** | RS.MI-1 | retire → rollback (remove from consumers) with audit |
| **Recover** | RC.RP | Rollback plan per record recorded at apply time |

## 3. Controls — ISO 27001:2022 Annex A

| Clause | Domain | Control |
|--------|--------|---------|
| A.8.16 | Monitoring | Continuously consumes internal + external signals; blocklist reflects live intel |
| A.8.28 | Secure coding | `ipaddress` strict parsing; version guards; no eval; typed IOC dataclass |
| A.8.15 | Logging | `blocklist_audit.jsonl` records all decisions + reasons |
| A.8.34 / A.8.35 | Data protection / privacy | TLP enforced at ingest (amber/red never auto-promote); no personal data in IOC payloads |
| A.8.12 | Info leakage prevention | Feed creds via env; secrets never in blocklist output |
| A.6.8 | Compliance (blocking posture) | Rollback plan recorded per block → reversible action satisfies compliance-minded ops |

## 4. OWASP Top 10

| OWASP | Risk | Mitigation |
|-------|------|------------|
| A01 Broken Access Control | Future API could be abused to flip tiers | All current mutation via internal CLI; future API requires mTLS + scoped roles |
| A03 Injection | Feed values could carry payload strings | IOCs are typed dataclasses; values validated with ipaddress, regex; never executed |
| A04 Insecure Design | Blacklist = single point of failure | Tier quarantine human-approval for median; consumer drivers idempotent + diff-only |
| A06 Vulnerable Components | Python runtime | stdlib only; SBOM = interpreter; version pin ≥3.10 |
| A08 Data Integrity | Blocklist tampered by compromised host | append-only files, audit chain, rollback records; permissions on data/ (OS ACL) |
| A09 Logging | Missed feed outages | Feed health + `blocklist_audit` counters (state.md metric section) |
| A10 SSRF | Consumer destination could be malicious URL | Driver dest validated (json/pf local paths today); cloud drivers TBD with URL allow-list |

## 5. Implementation Notes

1. **`ipaddress` version guard**: `is_internal` never compares v4 `.subnet_of(v6)` etc. — explicit `p.version != net.version → continue`. Fix verified in smoke test (would have crashed on mixed feeds).
2. **Guards run BEFORE tiering** — a rouge feed claiming `10.0.0.1` at conf 0.99 ends up `suspected` (never blocklisted), because `promote_ok` runs on the `active` path. Verified.
3. **`promote_ok` also rejects amber/red TLP and `.internal/.local/.localhost` domains**.
4. **Rollback is first-class**: every record gets `rollback_plan` at apply; lifecycle `retired` triggers removal from consumers — audited, not silent.
5. **No secrets in code**: feed creds + webhook tokens via env (HONEYPOT_BLOCKLIST_TOKEN etc.); fixtures never include real credentials.

## 6. Incident Response Notes

1. **Benign IP auto-blocked** (classic): change tier to `quarantined` via approve queue; consumer driver removes on next sync (diff-only → reversible).
2. **Feed poisoning identified**: raise `ip_feed_tlp` for that feed to amber/red (blocks promotion), quarantine all its fired records, audit provenance shows which.
3. **Blocklist flooded** (DoS): drop stale feeds, raise `auto_confidence`, quarantine median tier (requires human approval).
4. **Rollback requirement** (temporary block): `evaluate_lifecycle` on demand → retire → consumer remove — fully audited path.