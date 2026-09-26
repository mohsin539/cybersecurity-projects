# Security Implementation — RansomLens Portable Workbench

**Version:** 1.0
**Applies to:** `dist\RansomLens.exe` + `src\` (the portable workbench slice of `architecture.md`)
**Security baseline:** ISO/IEC 27001:2022, NIST CSF 2.0, OWASP Top 10 (2021), NIST SP 800-53 (informative)

---

## 1. Scope and position in the architecture

This build is the **non-executing forensic slice** of the reference architecture:

| architecture.md section | Delivered here | Notes |
|------------------------|----------------|-------|
| 6.1 Sample Collector | Partial — local intake only | Public-repo pull is out of scope for the portable build |
| 6.2 Malware Vault | Yes | Hash-first, deduped, quarantined, read-only access |
| 6.3 Orchestrator | Static job flow (thread pool) | KB: no live detonation |
| 6.4 Static Analyzer | Yes | Entropy, strings, minimal PE parse, crypto/ransom hints |
| 6.5 Behavior & Pattern Analyzer | Yes (structural) | Entropy/header/extension/evidence-pair heuristics |
| 6.6 Report Generator | Yes | Markdown + JSON, schema `sba.pattern.v1` |
| 6.7 Web Portal / API | No | Replaced by the local GUI; no network surface |
| 7 (detonation, Zone 0) | **Deliberately omitted** | Live execution of malware requires the hypervisor farm in architecture.md §7 and is NOT part of this binary |
| 15.2 Audit Ledger | Yes | Hash-chained JSONL with built-in verify |

**Fundamental safety property:** the tool **never executes** the files it analyzes. Every pipeline stage treats input as inert bytes (read → parse → hash → report). There is no `subprocess`, no `os.system`, no `ctypes` invocation of sample code, no LOAD-library call.

---

## 2. Threat model (what this build defends)

| Asset | Threats | Controls |
|-------|---------|----------|
| Analysed files (samples/evidence) | Accidental execution, leakage outside vault, PII exposure | Read-only handling, quarantine copy, hash-first dedupe, 128 MiB analysis cap, no network egress |
| Analyst's workstation | Malicious file exploiting parser/crypto hashing | Stdlib-only parsing, size cap, no code eval, entropy/hash are constant-time-ish memory-only ops |
| Evidence integrity | Tampering with results, forged reports | Hash-chained ledger + built-in `verify()`, report environment fingerprint, emitted SHA-256 |
| The workbench itself | Unauthorized access, config tampering | Config stored under `%LOCALAPPDATA%\RansomLens` (user-scope), no admin rights required, no secrets |

### STRIDE summary (per component)

- **S**poofing — internal actor constant `analyst`; no remote identity surface (local GUI only).
- **T**ampering — ledger hash chain detects any post-hoc edit; vault files keyed by SHA-256.
- **R**epudiation — ledger appends are attributable (actor + UTC timestamp + immutable chain).
- **I**nfo disclosure — no network calls at all; report export is analyst initiated and ledgered.
- **D**oS — 128 MiB per-file bound; block-wise entropy keeps memory bounded; worker thread isolated.
- **E**levation — no privileged operations; workspace lives under the user's profile.

Deliberately out of scope (see architecture.md §17 residual risks): live detonation, C2 handling, and YARA-feed ingestion require the controlled sandbox farm and a policy engine — risk is transferred to that (separate) deployment.

---

## 3. OWASP Top 10 (2021) coverage — this build

| # | Category | Implementation |
|---|----------|----------------|
| A01 Broken Access Control | Local RBAC-by-design: analyst-only surface; no sensitive object enumeration; separate approve flows intentionally minimal |
| A02 Cryptographic Failures | TLS n/a (offline); at-rest artifacts protected by OS-level user permissions; ledger integrity via SHA-256; no home-grown *encryption* (only hashing, which is the correct primitive for integrity) |
| A03 Injection | No SQL strings from user input (SQLite via parameter binding only); report rendering is plain-text Markdown (no HTML eval); JSON written through `json.dumps` (no manual string contatanation) |
| A04 Insecure Design | Threat model in §2; secure defaults (never execute, no network); capabilities enumerated in security posture panel |
| A05 Security Misconfiguration | Single binary, no service config; workspace auto-created under user profile; config file minimal |
| A06 Vulnerable Components | Runtime uses **Python stdlib only**; PyInstaller bundles a pinned Python 3.12.7; build files pinned via `requirements.txt`; SAST/SCA gates described in §7 |
| A07 Identification & Auth Failures | Local single-user app; OS session is the trust boundary; MFA/SIAM belongs to the hosted web variant (architecture.md §11) |
| A08 Software & Data Integrity | Reports embed tooling + schema + environment fingerprint; ledger tamper-evident; build hash recorded in `state.md` |
| A09 Logging & Monitoring Failures | Hash-chained ledger for every ingest/analysis/export action; verify button in GUI; no PII written to logs |
| A10 SSRF | Not applicable — **zero network egress** (offline by design). Egress allow-lists belong to the collector/sandbox deployment |

---

## 4. Data flow security

```
User files ──► SHA-256 ──► AV-worthy sanity (size cap) ──► Vault copy (dedupe, immutable name = hash.bin)
      │
      └──► read-only parse (entropy/strings/PE) ──► fingerprint (JSON, schema pinned)
                       │
                       ├──► Markdown report (signed-environment header) ──► reports/
                       └──► analysis row ──► SQLite (parameterized) ──► dashboard
   every step ──► audit event ──► ledger.jsonl (prev-hash chained)
```

- **Read-only invariant** is enforced structurally: analyzers receive `bytes` and never paths they can write; vault copy is created once (`copy2`) and thereafter only read.
- **Quarantine discipline:** analysis always runs against the *vault copy*, never against the original path, so the evidence set is stable and hash-bound to the report.

---

## 5. Integrity, audit & reproducibility

- **Ledger (ISO A.8.15/A.8.2):** JSONL append-only, each entry contains `prev_hash` of the previous entry; SHA-256 over canonical payload. `Ledger.verify()` re-checks the whole chain; any rewritten entry breaks verification and is surfaced in the GUI.
- **Evidence chaining:** fingerprints embed sample SHA-256 + schema version + tooling; reports are reproducible because the input is the same vault blob and the environment fingerprint is recorded.
- **No secrets:** the binary stores no credentials; config holds only workspace path + optional evidence path (user owns the data).

---

## 6. Distribution & deployment hardening

- Build command: `.\build.ps1` (PyInstaller onefile, windowed, stdlib-only runtime → small attack surface).
- Verified artifact (this build):
  - Path: `dist\RansomLens.exe`
  - Size: 11.76 MB
  - SHA-256: `EAD4F401A391A7706A64CB2D1392AD2565586C9CA85369C56BE250E48A5C6B4B`
- Recommendation before external distribution: sign the exe with your organisation's Authenticode certificate; publish the SHA-256 on a trusted channel; distribute over an internal authenticated path (no casual sharing of an executable).
- The binary is portable (single file, no install, no admin rights). Workspace is created per-user under `%LOCALAPPDATA%\RansomLens_Workspace`; nothing writes outside the user profile.

---

## 7. Assurance pipeline (as mapped from architecture.md §14)

| Gate | Check | Status for this build |
|------|-------|-----------------------|
| Compile | module byte-compile | PASS |
| Unit/lint (health) | headless smoke of every core module | PASS (see `state.md`) |
| E2E (GUI flow) | intake→analyze→report→ledger under Tk | PASS |
| Dependency scan (SCA) | runtime deps = 0 third-party; build dep = PyInstaller (pinned) | PASS |
| SAST | static review of this repo (no dynamic input to interpreter) | manual review done |
| DAST | not applicable (no network surface) | n/a |
| Runtime verify | binary launches, provisions workspace, stays stable | PASS |

---

## 8. Operational guidance for the analyst

1. Only feed **quarantined/expected-malicious or synthetic fixture** files you are authorised to handle.
2. Treat the vault folder as needing the same access control as the source artifacts.
3. Run `Audit Ledger → Verify hash-chain integrity` before relying on any report set.
4. Do **not** copy vault blobs out without a ledgered export note (exports are recorded).
5. Submit derived deception/testing samples to the *controlled* Sandbox (architecture.md Zone 0) when live behavioural telemetry is required — never to this desktop tool.

---

## 9. Deviations from architecture.md (fielded, signed decisions)

| Requirement | Deviation | Justification | Risk owner |
|-------------|-----------|---------------|------------|
| Zone 0 detonation + kernel telemetry | Not implemented in the portable build | Cannot be made safe in a single portable exe; belongs to the server farm | Platform security owner |
| Public-repo collection | Out of scope | Requires hash-scoped feeds + sanitizer + one-way egress design (Z1) | AppSec owner |
| Web portal + RBAC/SSO | Replaced by local GUI | Local tool; user session is the boundary; SSO path exists in reference arch §11 | IAM owner |

*All remaining architecture.md security controls are inherited by design intent; any divergence must go through the Security Architecture Review Board.*