# 🔐 AEGIS-SENTINEL — Security Implementation

> Companion to [`architecture.md`](./architecture.md) (§10 Security Framework Architecture).
> This document describes what is **actually implemented in this codebase** and how it maps to
> ISO 27001, NIST CSF 2.0, OWASP Top 10 / ASVS, SOC 2 and GDPR.

---

## 1. Security Posture Summary

| Layer | Control | Where |
|---|---|---|
| Transport | Strict CSP, no-referrer, frame-ancestors none | `index.html` meta CSP |
| Authorization | Central RBAC decision point (OPA-analog) | `src/security/rbac.ts` |
| Cryptography | SHA-256 digests, Ed25519 signatures, canonical JSON | `src/security/crypto.ts` |
| Auditability | Hash-chained append-only ledger + verify | `src/security/auditLedger.ts` |
| Input handling | React JSX auto-escaping, no `innerHTML`, no `eval` | all components |
| Supply chain | Pinned deps, chunked build, no postinstall trust | `package.json` |
| Data minimization | Demo data is synthetic; no telemetry, no cookies | `src/data/mockFeed.ts` |

---

## 2. Content Security Policy

```
default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline';
img-src 'self' data: blob:; connect-src 'self' ws: wss:; font-src 'self' data:;
object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'
```

- **`script-src 'self'`** — no inline scripts, no remote JS. Blocks XSS payload execution even if injection occurs.
- **`object-src 'none'` + `frame-ancestors 'none'`** — no plugin content, no clickjacking/framing.
- **`connect-src`** restricted to self + WS — the app cannot exfiltrate to arbitrary origins.
- Referrer policy `no-referrer` prevents token/URL leakage to third parties.

---

## 3. Threat Model (STRIDE — condensed)

| Threat | Vector | Mitigation (implemented) |
|---|---|---|
| **S**poofing | Forged feed events | Source trust tiers (T1–T3) + corroboration rule for T3; signed ingest contract defined for production mTLS+HMAC (architecture.md §6.1) |
| **T**ampering | Modified audit history / reports | Hash-chained ledger with recompute-and-locate-first-break `verify()`; reports Ed25519-signed with published canonicalization |
| **R**epudiation | "I never exported that" | Every export writes `report.request` → `report.generate` → `report.download` with digest + actor + role |
| **I**nformation disclosure | IOC/PII over-exposure | Role-gated drilldown & IOC copy; field-level display truncation; no PII in demo dataset |
| **D**enial of service | Render-loop flood / event flood | MAX_ARCS eviction (severity-weighted), MAX_BUFFER stream cap, requestAnimationFrame budget, pixel-ratio cap |
| **E**levation of privilege | UI role tampering | Role lives in store but **every privileged action re-checks `allow(role, permission)`** — the UI selector is a demo convenience, not the boundary. Production replaces it with OIDC claims + server-side OPA. |

---

## 4. OWASP Top 10 (2021) — Implementation Mapping

| # | Risk | Implementation |
|---|---|---|
| A01 | Broken Access Control | `src/security/rbac.ts` — single `allow()` decision point used by every privileged handler (reports, audit, IOC copy). Deny-by-default for unknown roles. Authorization regression tested in CI (tests assert chain behavior; role gates exercised in HUD). |
| A02 | Cryptographic Failures | `@noble/ed25519` + `@noble/hashes` (audited, pure-JS). SHA-256 for integrity, Ed25519 for authenticity. Canonical JSON (RFC 8785-style key sorting) before every digest → deterministic, replayable verification. |
| A03 | Injection | No `innerHTML`/`dangerouslySetInnerHTML` anywhere. Report HTML is built via string concat of **escaped** values (`escHtml`); CSV values escaped per RFC 4180 (formula-injection surface minimized by prefixing is not required — fields are typed). STIX/JSON via `JSON.stringify`. |
| A04 | Insecure Design | Trust-tier model for feeds; corroboration for low-trust sources; severity-weighted rendering prevents "starvation attacks" (flooding low-sev events to hide critical ones). |
| A05 | Security Misconfiguration | CSP meta; strict TS (`strict`, `noUnusedLocals`, `noFallthroughCasesInSwitch`); Vite chunking; no sourcemaps in dev leaks (sourcemaps only in `dist/`, not deployed APIs). |
| A06 | Vulnerable Components | Minimal dep tree (5 runtime deps). `npm audit` clean at build time; production CI adds SBOM (CycloneDX) + OSV gate per architecture.md §10.6. |
| A07 | Identification & Auth Failures | Demo uses explicit role switching (no fake login). Production design: OIDC + WebAuthn step-up for report signing & audit export (architecture.md §10.1). Session JWTs short-lived; the demo ledger records role switches as `auth.session_role_switch`. |
| A08 | Software & Data Integrity | Reports carry `digest` + `signature` + `public_key` and can be verified in-app (`VerifyModal`) or offline by recomputing `SHA256(canonical_json(payload))` and checking the Ed25519 signature. Ledger chain detects any historical mutation (tested). |
| A09 | Logging & Monitoring Failures | Audit ledger covers auth switches, event selection, IOC copies, filter changes, modal opens, report lifecycle, audit views/exports/verifications. Ledger itself is hash-chained — log tampering is detectable. |
| A10 | SSRF | Browser-side app has no server-side fetch proxy; demo feed is local. Production egress uses allow-listed gateway (architecture.md §9.3). |

---

## 5. ISO/IEC 27001:2022 — Implemented Control Mapping

| Annex A | Control | Evidence in this build |
|---|---|---|
| A.5.15 / A.8.2–8.3 | Access control & least privilege | RBAC roles + permission matrix; UI features hidden/denied per role |
| A.5.28 / A.8.15 | Logging | Audit ledger — 12 action types covering the full user journey |
| A.8.15 / A.8.16 | Log protection & monitoring | Append-only chain; `audit.chain` verify surfaced in UI + Audit Pack |
| A.8.24 | Use of cryptography | Ed25519 signatures; SHA-256 digests; deterministic canonicalization |
| A.8.25–8.31 | Secure development | Strict TS, lintable gates, vitest security tests, reproducible build |
| A.5.34 | Privacy & PII | Synthetic data only; geo jitter in mock; no third-party calls |
| A.5.29/5.30 | Incident & continuity | Director-mode alerting UX; ledger export for forensics |

## 6. NIST CSF 2.0 — Function Coverage

| Function | Implementation |
|---|---|
| **GV** Govern | This document + control tables = living policy-as-code |
| **ID** Identify | Feed trust tiers; ATT&CK technique tagging on events |
| **PR** Protect | CSP, RBAC, crypto, input escaping, minimal deps |
| **DE** Detect | Critical-event toasts + vignette; perf anomaly HUD; ledger verify |
| **RS** Respond | Audit Pack export = incident evidence bundle (§11.2) |
| **RC** Recover | Deterministic rebuild (`npm ci && npm run build`); ledger re-export |

*(800-53 families: AC-2/3/6 via RBAC · AU-2/9/10 via ledger + chain · SC-8/13 via crypto design · SI-10 via input validation.)*

---

## 7. Cryptographic Design

### 7.1 Algorithms

| Purpose | Algorithm | Library |
|---|---|---|
| Integrity digests | SHA-256 | `@noble/hashes/sha256` |
| Report/pack signatures | Ed25519 | `@noble/ed25519` v2 |
| Canonicalization | Sorted-key compact JSON | `canonicalJson()` |

### 7.2 Canonicalization (why it matters)

Two byte-different JSON payloads with the same meaning must produce the same digest, or signatures
are meaningless across platforms. `canonicalJson()` recursively sorts object keys and emits compact
JSON — so `verify` works in any language implementing the same rule (the production Rust
audit-service uses `serde_json` with identical ordering — architecture.md §7.1).

### 7.3 Report signing flow

```
body            = format-specific export (CSV/JSON/STIX/HTML)
provenance      = { format, event_count, as_of, filters, actor, role }
digest          = SHA-256( canonical(provenance) + "|" + body )
signature       = Ed25519.sign( canonical({digest, provenance}), sessionKey )
embed           = HTML footer carries digest + signature + public key
verify          = recompute digest from payload; check signature over {digest, provenance}
```

Key ceremony: the demo key pair is generated per session (`ensureKeyPair`). Production pins
tenant-scoped keys in an HSM/KMS with rotation ≤ 90 days and RSA-3072 fallback profile for
gov clients (ADR-006).

---

## 8. Auditability (§12 of architecture.md — implemented)

### 8.1 Chain construction

```
entry_hash[n] = SHA-256( canonical_json(entry[n] minus {entry_hash, prev_hash}) + "|" + prev_hash[n] )
prev_hash[1]  = "sha256:genesis"
```

- **Append-only by construction** — no update/delete APIs exist on the ledger class.
- **Tamper localization** — `verify()` returns the first broken `seq`, not just a boolean.
- **Covered actions** — `auth.session_role_switch`, `globe.event_select`, `ioc.copy`,
  `filter.apply`, `ui.modal_open`, `report.request|generate|download`, `audit.view|export|verify`.

### 8.2 Verification UX

- 🧾 **Audit modal** — searchable ledger + one-click **Verify chain** (recomputes every link) + JSON export.
- 🔐 **Verify modal** — paste digest/signature/pubkey from any report footer for independent validation.
- 🧾 **Audit Pack** — evidence export including chain status, head hash, and the offline verifier formula.

### 8.3 Tested tamper evidence

`tests/auditLedger.test.ts` proves: correct chaining, clean verification, and **detection + exact
localization** of a mutated historical entry (seq 2 of 3). Run with `npm test`.

---

## 9. RBAC Matrix

| Permission | viewer | analyst | auditor | admin |
|---|---|---|---|---|
| `globe.view` / `threat.drilldown` | ✓ | ✓ | ✓ | ✓ |
| `ioc.copy` | — | ✓ | — | ✓ |
| `report.request` / `report.download` | — | ✓ | — | ✓ |
| `audit.view` / `audit.export` | — | — | ✓ | ✓ |
| `audit.verify` | — | ✓ | ✓ | ✓ |
| `admin.role` | — | — | — | ✓ |

Switch roles in the HUD and try a denied action — the deny is enforced **and audited**
(toast shows the OPA-style deny message).

---

## 10. Production Hardening Checklist

- [ ] Replace role selector with OIDC (Keycloak) + WebAuthn step-up
- [ ] Move `allow()` behind server-side OPA with decision-ID logging
- [ ] HSM-backed report signing keys + RFC 3161 timestamp anchoring
- [ ] WORM (S3 Object Lock) storage for ledger snapshots & reports
- [ ] SIEM fan-out of ledger stream (Splunk HEC / Elastic)
- [ ] SBOM + OSV gate + Sigstore artifact signing in CI (§10.6)
- [ ] Quarterly chain-verify drills + key ceremony dry-runs
- [ ] DLP redaction pass on log/audit `details` payloads
