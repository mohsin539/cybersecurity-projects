# Architecture: Password Strength Auditor & Wordlist-Based Cracker (Own Hashes Only)

Revision: 1.0
Status: Implemented (Milestone M1-M3)
Date: 2026-09-18

---

## 1. Mission & Hard Scope Boundary

| Feature | Scope |
|---|---|
| **Auditing** | Analyze passwords for strength per NIST SP 800-63B + entropy models |
| **Cracking** | Wordlist, rule/mangling, mask (bounded) attacks against hashes |
| **Legal boundary** | **Own hashes only** — hard-enforced: attestation gate, workspace tagging, audit logging, report watermarking |
| **Not in scope** | Online attacks, phishing recovery, live system enumeration, cloud hash-dumping |

The "own hashes only" constraint is the single most important design feature. It converts a
dual-use tool into a defensible audit/compliance instrument.

## 2. Chosen Delivery Standard (from Options below)

**Option A — Portable offline GUI executable (desktop).**

- Offline-first: hashes and cracked plaintexts never leave the machine.
- Implementation: Python 3.12 core, stdlib-only, Tkinter GUI, packaged as a
  portable single-file `.exe` via PyInstaller.
- Same core is CLI-usable and can later be compiled to WASM / thin web wrapper
  (documented under Section 10) without logic changes.

Rationale: strongest data-protection story for the compliance audit (no data in
transit, no server attack surface), simplest to demonstrate in a masterclass.

## 3. Reference Frameworks

- **ISO/IEC 27001:2022 (Annex A)**: A.5.8 (security in development lifecycle),
  A.5.15 (access control), A.8.2 (information classification), A.8.10 (info
  transfer), A.8.24 (crypto controls), A.8.28 (secure coding), A.8.29 (security
  testing), A.8.30 (outsourced development), A.12.4 (logging & monitoring),
  A.12.6 (vulnerability management).
- **NIST**: SP 800-63B (password guidelines: length over complexity; blocklist of
  common/known passwords; screen outs), SP 800-53 (AC-6 least privilege, AU-2/6
  audit, SC-8/28 transit & at-rest protection, SI-7 integrity), NIST CSF.
- **OWASP Top 10 (2021)**: A01 Broken Access Control, A02 Cryptographic Failures,
  A07 Identification & Authentication Failures, A08 Software & Data Integrity
  Failures, A09 Logging & Monitoring Failures.

Compliance is bi-directional:
1. The tool itself is built securely (OWASP, ISO A.8.28, SDL gates).
2. The tool's outputs audit the operator's *own* password posture (NIST 800-63B).

## 4. Component Map

```
                     ┌──────────────────────────────────────┐
   Load             │ 1. HASH INGESTION                    │
   hashes ─────────►│    file/paste, format sniffing,      │
                     │    size caps, line limits, binary    │
                     │    detection, duplicate removal      │
                     └──────────────┬───────────────────────┘
                                    ▼
                     ┌──────────────────────────────────────┐
                     │ 2. HASH IDENTIFIER                  │
                     │    regex + length fingerprint:      │
                     │    MD5 / NTLM / SHA-1 / SHA-224 /   │
                     │    SHA-256 / SHA-384 / SHA-512 /    │
                     │    bcrypt / argon2 / $sha$ formats  │
                     └──────────────┬───────────────────────┘
                                    ▼
   ┌──────────────────────────────────────────────────────┐
   │ 3. CRACKING ENGINE (core, threaded)                   │
   │   ┌──────────────┐ ┌────────────┐ ┌────────────────┐  │
   │   │ Wordlist     │ │ Rule /     │ │ Mask (bounded) │  │
   │   │ attack       │ │ mangling   │ │ brute-force    │  │
   │   └──────────────┘ └────────────┘ └────────────────┘  │
   │   generators     + ThreadPoolExecutor workers         │
   │   + progress/submit callbacks + stop/cancel           │
   └──────────────┬───────────────────────────────────────┘
                  ▼
   ┌──────────────────────────────────────────────────────┐
   │ 4. STRENGTH AUDITOR                                    │
   │   - NIST SP 800-63B checks (length >=8, blocklist     │
   │     screening, no dictionary words, no repeat seqs)   │
   │   - entropy estimate (charset + length, penalty terms)│
   │   - crack-time estimate per algorithm (guess-rate     │
   │     model, configurable)                              │
   └──────────────┬───────────────────────────────────────┘
                  ▼
   ┌──────────────────────────────────────┐ ┌────────────────────────────┐
   │ 5. REPORT GENERATOR                   │ │ 6. WORKSPACE & INTEGRITY   │
   │   - self-contained HTML, CSV, JSON    │ │   - append-only chained     │
   │   - watermark (operator, ts, scope)   │ │     audit log (JSONL)       │
   │   - optional DPAPI-encrypted bundle   │ │   - DPAPI workspace bundle  │
   └──────────────────────────────────────┘ └────────────────────────────┘
```

## 5. Core Modules (implementation)

`src/core/hashes.py`  — hash identification + candidate generation per algorithm
`src/core/ntlm.py`    — NTLM (MD4 of UTF-16LE) via Windows BCrypt, pure-Python fallback
`src/core/wordlists.py` — wordlist loading, validation, zip-bomb/size guards, dedupe
`src/core/cracker.py` — attack engines (wordlist / rules / mask) + thread pool
`src/core/auditor.py` — strength scoring, NIST 800-63B checks, crack-time model
`src/core/report.py`  — HTML/CSV/JSON report generation + watermarking
`src/compat/win.py`   — Windows DPAPI (CryptProtectData) + BCrypt MD4, ctypes only
`src/compat/workspace.py` — workspace dir, config, append-only chained audit log
`src/gui/app.py`      — Tkinter GUI (attestation gate, tabs, progress, results)
`src/cli.py`          — command-line interface (packaging + scripting)

## 6. Supported Hash Formats

| Algorithm | Input hash | Cracking supported offline |
|---|---|---|
| MD5 | 32 hex | yes |
| NTLM | 32 hex (MD4 UTF-16LE) | yes |
| SHA-1 | 40 hex | yes |
| SHA-224 | 56 hex | yes |
| SHA-256 | 64 hex | yes |
| SHA-384 | 96 hex | yes |
| SHA-512 | 128 hex | yes |
| bcrypt | `$2a$/$2b$/$2y$` | optional (needs `bcrypt` pip package) |
| argon2id | `$argon2id$` | optional (needs `argon2-cffi`) |
| salted john-style `hash:salt` | detected | appends/prepends salt |

Note: 32-hex hashes are ambiguous between MD5 and NTLM; the engine tests both and
reports which matched, or leaves it unresolved.

## 7. Security Architecture

### 7.1 Threat model

| Threat | Mitigation |
|---|---|
| Other user on same PC reads session/reports | Per-user DPAPI data protection, auto-clear of plaintext workspace on close, encrypted report bundle |
| Malicious wordlist (zip-bomb / huge) | Size caps, line count caps, binary detection, dedupe, sample validation |
| Exfiltration of hashes/plaintexts | Offline-first design; watermarks; audit log; encrypted bundle exports |
| Tampering with audit log | Append-only + SHA-256 hash-chained entries |
| Replay / forge evidence | Attestation gate recorded at session start; operator binding in reports |

### 7.2 Crypto controls (ISO A.8.24, SP 800-53 SC-8/28)

- At-rest exports: AES via **Windows DPAPI** (`CryptProtectData`, per-user, TPM-backed
  where available) — no keys managed/stored by the app.
- Source integrity: append-only hash-chained audit log; report watermark includes
  operator + session id + workspace fingerprint.
- No housing of plaintext: cracked plaintexts are kept in memory only and cleared
  from the session when closed; persisted only inside the encrypted bundle.

### 7.3 OWASP Top 10 mapping (applied to tool)

| ID | Finding | Control |
|---|---|---|
| A02 | Crypto failures | No custom crypto; DPAPI; documented blocklists; no secrets in code |
| A03 | Injection | Hash/wordlist lines parsed strictly as data; size caps; no eval |
| A07 | Auth failures | Attestation gate + operator binding; audit trail |
| A08 | Integrity failures | Hash-chained audit log; signed-style watermarks; validated wordlists |
| A09 | Logging failures | Immutable JSONL audit log with sequence + prev-hash chaining |

### 7.4 Audit logging (ISO A.12.4, NIST AU)

Every session records: operator, session id, timestamps, hash counts, algorithms,
wordlist fingerprints, rules, results summary, exports. Never logs raw plaintext
candidates for unresolved hashes.

## 8. Non-Functional Requirements

- **Portability**: single portable exe, no installer, no registry, no admin rights, no network calls.
- **Performance**: threaded workers; bounded mask spaces; early-exit on match; checkpoint-free resume by re-run.
- **Usability**: wizard-like tabs (Load → Identify → Attack → Audit → Report), live progress.
- **Resource limits**: thread cap, wordlist caps, mask keyspace guard (default ≤ 1e12).
- **Data minimization**: delete-workspace action; zero telemetry; offline-only.
- **Unicode**: UTF-8 wordlist handling; NTLM UTF-16LE encoding.

## 9. Compliance Matrix (traceability)

| Framework control | Implemented by | Evidence |
|---|---|---|
| ISO A.8.2 Info classification | Hash/plaintext marked "confidential — own data" | Watermark + report banner |
| ISO A.8.24 Crypto controls | DPAPI-encrypted exports | security.md + code |
| ISO A.12.4 Logging & monitoring | Hash-chained append-only audit log | security.md + tests |
| ISO A.8.28 Secure coding | Stdlib-only, minimal attack surface, SAST-able | tests, security.md |
| NIST SP 800-63B | Length>=8, blocklist screening, entropy check | auditor compliance tests |
| NIST SP 800-53 SC-8/28 | DPAPI at rest; offline (no transit) | security.md |
| OWASP Top 10 | Section 7.3 | security.md |

## 10. Future Paths (documented, not built)

- **WASM build** of the same core for a fully client-side web delivery (no data egress).
- **Server edition** for multi-user enterprise with RBAC + OIDC + SIEM export.
- Rule engine extension (hashcat `.rule` syntax subset), GPU backends (CUDA/ROCm).

## 11. Roadmap Status

| Milestone | Status |
|---|---|
| M1 — core: ingest, identify, wordlist cracker, auditor, CLI | Implemented |
| M2 — Tkinter GUI (portable exe) + rules + mask | Implemented |
| M3 — reporting, audit chain, DPAPI bundle, watermark | Implemented |
| M4 — WASM / web edition | Not started |