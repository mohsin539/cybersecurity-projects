# security.md — Implementation Security Reference

Status: Active · Owner: Security Architecture · Scope: the implemented application (`server.js`, `public/`)
Complements `04-security-architecture.md` (design-level) with **implementation-level** verification. Status markers: ✅ implemented · 🟡 reserved/partial (documented path) · 🔲 org/cloud responsibility.

---

## 1. OWASP Top 10 (2021) — implementation mapping

### A01 Broken Access Control
- ✅ Tenant derived **only** from session claims (`server.js` routeApi); `X-Tenant` honored **only** for role `auditor`; others → 403. Cross-tenant object access → 404.
- ✅ Default-deny permission table (`PERMISSIONS`); `ingest:write` granted to **no human role**.
- ✅ ABAC: tier1 cannot disposition `critical` band (`canDispositionBand`).
- ✅ RLS analog: every store query filters `tenantId`; isolation test below.
- ✅ Auditor cross-tenant = counts only, no payload data.
- 🔲 Prod target: PostgreSQL RLS backstop (03 §2.3) — this demo enforces at API layer only.

### A02 Cryptographic Failures
- ✅ SHA-256 only for hashing (dedup keys, audit chain, inputs hash); `crypto.randomUUID()` for ids; `crypto.randomBytes(32)` for session ids and CSRF tokens (256-bit).
- ✅ Timing-safe comparison for CSRF (`crypto.timingSafeEqual` via `timingSafeEqualStr`).
- ✅ No secrets in code; cookie flags `HttpOnly; SameSite=Strict; Max-Age`.
- 🟡 TLS termination assumed at reverse proxy; `Secure` cookie flag is set only when `req.socket.encrypted` — set `NODE_ENV=production` behind TLS to enforce.
- 🔲 HSM/KMS, per-tenant DEKs (04 §5) — production targets.

### A03 Injection
- ✅ No SQL (JSON store); no string-built commands; **no `innerHTML`/`eval`/`Function`** anywhere in `public/app.js` — all rendering via `createElement`/`textContent` (Trusted-Types-compatible pattern).
- ✅ Strict input validation on ingest (required fields, types, length caps, clamps); JSON parse failure → 400.
- ✅ Audit chain uses canonical JSON (stable key order) — prevents hash ambiguity.
- ✅ Structured error responses; no stack traces to clients (SI-11).
- ✅ Normalizer-style canonicalization: hosts lowercased/domain-stripped, users lowercased (02 §2).

### A04 Insecure Design
- ✅ Non-destructive dedup: duplicates stored + linked; `split-duplicate` restores visibility (README invariant #2).
- ✅ Append-only ledgers: dispositions, scores, links (`unlinkedAt` instead of delete), audit events.
- ✅ Fail-mode matrix implemented per ADR-001: audit write failure ⇒ mutation blocked; scoring keeps deterministic core.
- ✅ Bounded self-amplification: f8 log-scaled, capped; context multiplier capped ×1.5.
- ✅ Invariants self-check endpoint: `GET /api/meta/invariants`.

### A05 Security Misconfiguration
- ✅ Security headers on every response: CSP `default-src 'self'` (no inline, no third-party), `X-Frame-Options: DENY`, `nosniff`, `Referrer-Policy: no-referrer`, `Permissions-Policy`.
- ✅ Body size budget 256 KB (payload cap, T01); 404 default route; 405 for non-GET on static.
- ✅ Path traversal guard on static handler (`file.startsWith(PUBLIC)` after normalize).
- ✅ Minimal info leakage: login is identity-agnostic (same error for unknown user).
- 🔲 Prod: IaC baselines, CIS scans, PSS `restricted` (04 A05).

### A06 Vulnerable & Outdated Components
- ✅ **Zero npm dependencies** — supply-chain surface is Node stdlib only. SBOM = runtime itself.
- ✅ No client-side third-party JS; assets self-hosted (SRI-compatible by construction).
- 🔲 Prod: SCA pipeline, patch SLAs (04 A06).

### A07 Identification & Authentication Failures
- ✅ Server-side sessions; 12 h absolute + 30 min idle expiry; purge on expiry; logout erases immediately (volatile `Map` ⇒ instant revocation).
- ✅ 256-bit random session identifiers; no user enumeration on login.
- 🟡 **Demo authentication**: identity selection without password — acceptable **only** because this is a demo with synthetic data. Production path documented: OIDC SSO + mandatory MFA + WebAuthn step-up for privileged roles (04 §4 A07). Do not expose demo beyond localhost.
- 🔲 IdP integration, credential hygiene tooling — prod targets.

### A08 Software & Data Integrity Failures
- ✅ Hash-chained audit log per tenant (`prevHash`/`entryHash`, SHA-256 canonical JSON); chain verified on boot and via `/api/audit`; **refuses to start if chain broken** (fail-closed integrity, state.md §6).
- ✅ Audit chain doubles as tamper evidence for scoring changes (T03 posture).
- ✅ Weights/thresholds changes are versioned (`scoreVersion` bump) + audited with before/after.
- 🔲 Prod: signed rule bundles, Sigstore, SLSA provenance (04 A08).

### A09 Security Logging & Monitoring Failures
- ✅ Every state change audited: ingest, dedup link, split, disposition, assign, config change, login/logout, errors — with actor/action/before/after/reason.
- ✅ Audit export as JSONL (WORM-compatible format) with `Content-Disposition: attachment`.
- ✅ Chain-validity surfaced in UI (audit view chip).
- ✅ Fail-closed audit: `appendAudit` throws ⇒ mutation blocked (AU-5).
- 🔲 Prod: real-time SIEM export, UEBA on analysts (T08/T11).

### A10 SSRF
- ✅ No user-supplied URL is ever fetched server-side; no outbound HTTP calls exist in the server at all (smallest possible SSRF surface).
- 🔲 Prod: egress proxy allowlist for TI/CMDB fetchers (04 A10).

## 2. NIST SP 800-53 — implementation-relevant controls

| Control | Status | Implementation |
|---|---|---|
| AC-3 Access Enforcement | ✅ | default-deny permission table + per-object tenant check |
| AC-4 Information Flow | ✅ | tenant from token only; auditor counts-only path |
| AC-5 Separation of Duties | ✅ | tier1 restricted on critical band; lead vs analyst permissions |
| AC-6 Least Privilege | ✅ | `ingest:write` not granted to any human role; export gated |
| AC-12 Session Termination | ✅ | 12 h/30 min, server-side instant revocation |
| AU-2/AU-3 Event content | ✅ | who/action/object/before/after/reason on every state change |
| AU-5 Response to Audit Failure | ✅ | mutations blocked (fail-closed) |
| AU-9 Protection of Audit Info | ✅ | append-only structures; no update/delete paths in code |
| AU-10 Non-repudiation (partial) | ✅ | hash chain per tenant; export for custody |
| AU-11 Retention | 🟡 | store snapshot persistence; WORM target prod |
| AU-12 Audit Generation | ✅ | synchronous audit on mutation |
| IA-2/IA-5 | 🟡 | demo auth; prod = OIDC+MFA+WebAuthn |
| SC-8 Transmission | 🟡 | TLS assumed at proxy |
| SC-28 At Rest | 🟡 | filesystem store; prod = AES-256-GCM + field-level |
| SI-10 Input Validation | ✅ | allowlist fields, type/length/clamp checks |
| SI-11 Error Handling | ✅ | structured errors, no internals leaked |
| SI-7 Integrity | ✅ | audit hash chain + boot verification |

## 3. NIST CSF 2.0 — where the implementation contributes

- **PR.AA** (identity/access): sessions, RBAC/ABAC, default deny.
- **PR.DS** (data security): hashing, integrity chain, export controls.
- **DE.AE/DE.CM**: the alert pipeline itself (scoring/dedup) + audit analytics.
- **RS.MA/RS.AN**: prioritization (bands) + evidence export.
- **GV/ID/RC**: process-level — see `05-compliance-nist.md`.

## 4. ISO/IEC 27001:2022 Annex A — implementation highlights

- 5.3 segregation of duties ✅ · 5.12/5.13 classification/labelling ✅ (bands, sensitivity flags) · 5.15/8.3 access restriction ✅ · 5.17 authentication info ✅ (no secrets in code) · 5.28 evidence collection ✅ (audit export) · 5.33 protection of records ✅ (chain) · 5.34 PII protection ✅ (minimized payloads, no raw originals persisted) · 8.2 privileged access ✅ (role gates) · 8.10 deletion ✅ (no-deletion-by-design + export) · 8.15/8.16 logging/monitoring ✅ · 8.24 cryptography ✅ (SHA-256/random via Node crypto) · 8.25–8.29 secure SDLC/testing ✅ (this repo's gates) · 8.31/8.33 environment separation ✅ (demo data only).
- Full Annex A mapping lives in `06-compliance-iso27001.md` (SoA input).

## 5. STRIDE quick reference (implementation status)

| Threat | Implementation status |
|---|---|
| T01 spoofed ingest | ✅ ingest not reachable by human roles; payload budgets; validation |
| T02 dedup key poisoning | ✅ keys derived server-side from validated input; tenant-scoped |
| T03 scoring tamper | ✅ weights via audited config only; version bump; chain evidence |
| T04 XSS/session theft | ✅ text-only rendering, strict CSP, HttpOnly cookie |
| T05 cross-tenant IDOR | ✅ server-side tenant + object checks; auditor restriction |
| T06 audit tampering | ✅ hash chain + boot refusal + append-only |
| T07 feedback replay | 🔲 reserved (HMAC webhook not implemented) |
| T08 insider misuse | 🟡 role gates + audit; UEBA is prod target |
| T09 adversarial ML | ✅ ML overlay fixed at 0 (reserved field) |
| T10 TI poisoning | 🔲 TI is static seed data here; prod allowlist path in 04 |

## 6. Verification runbook (executed in Session 2, see memory.md)

```bash
node server.js &                                     # start
curl -sc cookies.txt -X POST localhost:8080/api/auth/login \
  -H 'Content-Type: application/json' -d '{"userId":"lead@t1"}'   # → csrf
# subsequent calls: -H "X-CSRF-Token: <csrf>" -b cookies.txt
curl -b cookies.txt localhost:8080/api/queue                       # tenant t1 queue
curl -b cookies.txt -X POST localhost:8080/api/ingest \
  -H "X-CSRF-Token: $C" -H 'Content-Type: application/json' \
  -d '{"source":"edr","ruleId":"EDR-CRED-DUMP-01", ...}'          # → deduped:true
curl -b cookies.txt -H 'X-Tenant: t2' localhost:8080/api/queue     # → 403 (spoof blocked)
# CSRF-less POST → 403; auditor X-Tenant:* → counts only
node server.js # on restart: "audit chain OK" proves integrity verification
```

Negative tests verified: cross-tenant read → 404/403 · CSRF missing → 403 · invalid status → 400 · oversized body → connection destroy · traversal path → 403/404.

## 7. Known limitations (demo scope)

1. Demo auth (no passwords) — localhost use only; prod path documented above.
2. Single-process, in-memory sessions; store snapshot is not a concurrent-writer database.
3. Fuzzy dedup, ML overlay, SOAR/feedback webhooks reserved (state.md §5).
4. `X-Tenant: *` auditor stats leak only counts — verified no payload fields present.
