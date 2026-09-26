# Project 11 — Security Posture

Security controls mapped to **NIST CSF 2.0**, **ISO/IEC 27001:2022 (Annex A)**, and **OWASP Top 10** for the application-class aspects of the correlator.

---

## 1. Threat Model Summary

| Asset | Trust boundary | Main threats |
|-------|----------------|--------------|
| Ingestion sources (files, syslog) | OS file system / network | Forged events, path injection, DoS via flood |
| Normalizer | same process as input | Malformed input → crash / ReDoS / schema evasion |
| Rule engine | internal (trusted) | Rule → arbitrary eval (if rules become code) |
| Alert store + alerting | filesystem / outbound HTTP | Tampered evidence, exfil of alert content, secret leakage |
| API surface (future) | network | Unauthorized reads of events/alerts, SSRF, injection |

Untrusted input arrives **twice**: raw logs and JSON-formatted events. All parsing must be fail-closed and non-escalating.

---

## 2. Controls — NIST CSF 2.0 Mapping

| CSF Function | Control (NIST 800-53) | Implemented |
|--------------|-----------------------|-------------|
| **Govern** | GV.RM, programs aligned to risk appetite | Rule severity floors configurable (`--min-severity`); risk-ranked output |
| **Identify** | ID.AM-2 software inventory, ID.AM-5 resources | `package.json` pins language/version; repo manifests |
| **Protect** | PR.AC-1/4 identity & access (syslog/API), PR.DS-1/2 data at rest via FS ACLs, PR.DS-2 logging | Quarantine + event store write under dedicated `data/`; optional webhook TLS + bearer token |
| **Protect** | PR.PT-1 audit logging | Every step can be traced: `events.jsonl` → `alerts.jsonl` → `quarantine.jsonl` with source+seq provenance |
| **Detect** | DE.CM-1 monitoring, DE.AE-1 anomaly | Correlation rules + alert dedupe/suppression |
| **Respond** | RS.CO chains, RS.MI-1 incident handling | Alerts carry incident_id + evidence trail for handoff |
| **Recover** | RC.RP recovery plan | Offset replay = crash recovery (at-least-once, dedupe by source+seq) |

## 3. Controls — ISO 27001:2022 Annex A Mapping

| Clause | Domain | Our control |
|--------|--------|-------------|
| A.8.2 | Information classification | CES is normalized/classified; quarantine stores unparsed raw separately |
| A.8.9 / A.8.10 | Management of technical vulnerabilities | Parser corpus must be fuzz-tested; regex length + timeouts |
| A.8.16 / A.8.17 | Monitoring activities / clock sync | All events timestamped UTC ISO-8601; ingestion source carries seq for reordering |
| A.8.15 | Logging | Pipeline is itself logged (raw→normalized→alert counts) |
| A.8.28 | Secure coding (new: SDLC) | Code review checklist below; env-var config, no secrets in source |
| A.5.15 / A.5.16 | Access control / supplier (feeds) | Webhook only with HTTPS + token; deny-list for URL hosts |
| A.5.24 | Incident management | Alert schema → incident_id enables IR workflow |

## 4. OWASP Top 10 — Application-facing Controls

The correlator is not a web app today, but its **ingest surface and future API** must satisfy:

| OWASP | Risk | Mitigation here |
|-------|------|-----------------|
| A01 Broken Access Control | Future API leaks event data | Design: API behind mTLS + scoped keys (Token per CI env); no anonymous reads |
| A02 Cryptographic Failures | Event plaintext on disk / webhook cleartext | `WebhookWriter` forces `https://`; at-rest JSONL meant for FS ACL + optional volume encryption; secrets only via env vars |
| A03 Injection | Rule-controlled string building | Rules are **data-driven JSON filters on fixed CES fields only** — no eval, no SQL; `filter` values validated against an allow-list of CES field names |
| A04 Insecure Design | Unbounded window state = memory DoS | `WindowCounter` TTL purge + LRU bounds; bounded ingest queue (backpressure) |
| A05 Security Misconfiguration | Insecure defaults | Fail-open normalization → **quarantine quarantine bucket (fail-closed storage)**; no bind-to-all defaults; dedupe window sane default |
| A06 Vulnerable Components | Python runtime | Kernel/OS patched; stdlib-only keeps SBOM trivial; pin python ≥3.10 |
| A07 Auth Failures | Webhook creds | Fixed, non-guessable bearer; rotation documented in ops runbook |
| A08 Data Integrity Failures | Tampered evidence | Source+seq provenance chain; store append-only; snapshot per scan (future) |
| A09 Logging & Monitoring Failures | Detection blind spots | Pipeline metrics section in `state.md`; structured counters on every stage |
| A10 SSRF | Future webhook URL from config | `WebhookWriter` rejects non-HTTPS + host allow-list (config) |

## 5. Project-specific Source-Code Security Checklist

- [ ] Parser regexes have sizes and use `re` with timeout-wrapped matching for fuzz corpora (retry test: 1 MB single line).
- [ ] Never eval user/rule/JSON content. Rule filters whitelist CES field names.
- [ ] JSON decode errors → quarantine (fail-open) but **never crash** the worker.
- [ ] No secrets in code or docs; ingest/alert/secrets injected via environment variables.
- [ ] Output paths validated and constrained to `--out`; no absolute writes from untrusted input.
- [ ] Webhook URLs HTTPS-only by default (can be overridden only via explicit config).
- [ ] Follow OWASP Secure Coding Practices: input validation, least privilege, secure defaults.

## 6. Incident Response Notes for This Project

1. On anomaly (parse-fail spike, alert flood): pull `data/quarantine/*.jsonl` and `data/alerts_index.jsonl`; correlate via `incident_id`.
2. Suspected forged logs: replay with `--print-enriched` and inspect source+seq provenance.
3. Rule regression: goldens under `tests/` (see `state.md`) must pass before shipping a rules update.
4. Credential compromise: rotate webhook tokens, rotate any `data/` volume keys, rebuild from clean image.