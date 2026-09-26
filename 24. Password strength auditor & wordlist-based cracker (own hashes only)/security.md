# Security.md — PasswordGuardian Security Framework

Revision: 1.0 · Date: 2026-09-18 · Owner: project team
Audience: developers, reviewers, compliance/ISO 27001 assessors, auditors.

This document states the **security framework** of the tool: policy, controls,
implementation mapping against ISO/IEC 27001:2022, NIST (SP 800-63B, SP 800-53),
and OWASP Top 10, plus the responsible-use guardrails that make the tool safe to
distribute and operate.

---

## 1. Security Objective & Policy

**Policy statement.** PasswordGuardian assesses passwords and hashes owned by the
operator (or explicitly authorized). The application is offline-first, keeps
secrets in memory only, encrypts at-rest exports with the Windows data-protection
API, and produces a tamper-evident audit trail. No plaintext or hash material is
transmitted anywhere.

**Data classification (ISO A.8.2 / A.8.12).** All loaded hashes, plaintext
candidates, and reports are classified **CONFIDENTIAL**. Reports carry a
classification banner "OWN / AUTHORIZED DATA ONLY" and are bound to the operator.

**Scope boundary (purpose limitation).** Attacks run only against locally loaded
hash values. There is no network capability; therefore online attacks, hash
dumping, and exfiltration are structurally excluded.

---

## 2. Threat Model (STRIDE-lite)

| # | Attacker | Motivation / method | Asset at risk | Mitigation |
|---|---|---|---|---|
| T1 | Local user of same OS account | Read RAM, read report files | plaintext, hashes | In-memory only results; DPAPI-protected at rest; wipe action |
| T2 | Malicious wordlist author | Zip-bomb, huge list, control chars | tool availability, memory | size/line caps, binary detection, dedupe, UTF-8 validation |
| T3 | Insider / unauthorized operator | Use tool for others' hashes | legal posture of org | ownership attestation gate, watermark, audit trail |
| T4 | Software supply chain | Tampered dependency | integrity of tool | stdlib-only core, pinned toolchain, hashable build, SBOM (Section 8) |
| T5 | Output-tamperer | Edit logs/reports to hide evidence | audit integrity | append-only hash-chained JSONL log, verify function |
| T6 | Network adversary | Intercept reports/telemetry | confidentiality | NO network calls (offline); encrypted bundle if exported |

---

## 3. Cryptographic Controls (ISO A.8.24 / NIST SP 800-53 SC-8, SC-28, SC-13)

| Use | Choice | Rationale |
|---|---|---|
| At-rest report/evidence bundle | Windows **DPAPI** (`CryptProtectData`, UI-forbidden, per-user; TPM-backable) | No app-managed key material; delegation to OS keystore |
| Audit integrity / chain | SHA-256 hash-chaining of JSONL entries | Tamper-evidence; trivial to verify |
| NTLM/MD4 (Windows) | BCrypt `MD4` via ctypes | Matches system crypto provider; fallback = pure-Python MD4 (tested against RFC vectors) |
| Password hashing in reports | never — tool stores the *input hash algorithm* only | no new credential hashing introduced |
| In transit | N/A | tool is offline; no transport |

No custom cryptography is introduced. Any key that exists is managed by the
operating system (DPAPI), not by the application.

---

## 4. OWASP Top 10 (2021) Mapping

| ID | Concern | Where addressed | Verifiable evidence |
|---|---|---|---|
| A02 — Cryptographic Failures | Offline tool; DPAPI at rest; no custom crypto; MD4 via OS BCrypt; pure-Python fallback validated with vectors | `src/compat/win.py`, `src/core/ntlm.py` | tests `test_md4_vectors`, `test_bundle_roundtrip` |
| A03 — Injection | Text parsed strictly as data (hash/wordlist); no eval; control-char and length validation on wordlists | `src/core/hashes.py`, `wordlists.py` | test `test_load_guards_and_blocklist` |
| A07 — Identification & Auth failures | Ownership attestation gate binds operator identity; operator recorded in audit + reports | `src/compat/workspace.py`, `src/gui/app.py` | test `test_attest_and_chain` |
| A08 — Software & Data integrity | Append-only hash-chained audit log; verified on demand; report watermark binds operator/session | `src/compat/workspace.py`, `src/core/report.py` | tests `test_attest_and_chain` |
| A09 — Logging & Monitoring failures | event log records sessions, loads, attacks, exports; never logs unresolved plaintext | `workspace.audit(...)` | `state.md` sample log |
| A01 — Broken Access Control | Single-user desktop; every critical flow re-checks attestation state | code review | — |
| A05/A06 — Misconfig & Vulnerable components | Stdlib-only runtime → minimal attack surface; supply chain section below | `requirements`/design | — |
| A10 — SSRF | Not applicable (no outbound fetch) | design | — |

---

## 5. NIST Mapping

### 5.1 NIST SP 800-63B (password guidelines)

Implemented in `src/core/auditor.py::nist_checks` and `analyze`:

1. Minimum length 8 (screen-out of shorter), recommended 15+.
2. **Blocklist screening** — passwords are rejected/flagged if present in the
   embedded common-password blocklist or the operator's loaded wordlist
   (approximates the required breach/known-password screening).
3. No composition-rule over-reliance (NIST explicitly de-emphasizes curated
   complexity; the tool reports classes as *information*, not as the primary
   strength driver).
4. Passphrase-friendly guidance surfaced via crack-time estimates.

### 5.2 NIST SP 800-53 (selected)

| Control | Implementation |
|---|---|
| AC-6 Least privilege | Single-user; no elevated privileges required; no admin install |
| AU-2/AU-6 Audit events & review | JSONL event chain; verify-integrity operation; GUI "Security Log" tab |
| SC-8 Transmission protection | N/A — offline (no transmission path) |
| SC-28 Protection at rest | DPAPI-encrypted bundle exports |
| SI-7 Integrity | Hash-chained audit log; PyInstaller build with bundled data |

### 5.3 NIST CSF

- **Identify**: data classification + own-hashes scope declared.
- **Protect**: DPAPI, attestation, audit, minimal surface.
- **Detect**: chain verification surfaces tampering; warning banner on failure.
- **Respond/Recover**: wipe-workspace and incident note in `state.md#incidents`.

---

## 6. ISO/IEC 27001:2022 Annex A Mapping

| Control | Requirement | Implementation & evidence |
|---|---|---|
| A.5.8 Security in Dev Lifecycle | Secure SDLC gates | Threat model (Section 2), SDL checklist (Section 9), SAST-able code |
| A.5.15 Access control | Restrict capabilities | Attestation gate; per-session identity binding |
| A.6.8 Security awareness | Users trained on responsible use | Splash/attestation text in-app |
| A.8.2 Info classification | Label data | Report banner "OWN / AUTHORIZED DATA ONLY" |
| A.8.6 + A.8.7 Sensitive info / media | Protect sensitive data | Confidential-only handling; no persistence of plaintext |
| A.8.10 Info transfer | No unauthorized transfer | Offline design; DPAPI bundle if exported |
| A.8.12 DLP | Prevent leakage | Wipe action; in-memory-only results; watermark |
| A.8.24 Crypto | Use approved crypto | DPAPI (OS-managed); SHA-256 chains |
| A.8.28 Secure coding | Minimize vulns | Stdlib-only, fuzz-tested parsers, no dynamic eval |
| A.8.29 Security testing | Test controls | 22 automated tests; manual pentest table in Section 10 |
| A.8.34 Protection of info systems during audit testing | Bound the scope of testing | "Own hashes only"; test targets generated locally |
| A.12.4 Logging & monitoring | Log & protect | Append-only hash-chained audit log |
| A.12.5 OS control | Hardened runtime | No admin rights; portable, no registry |

---

## 7. Secure Development Lifecycle (A.5.8 / A.8.28)

Gate checklist used for every change:

1. Threat-model delta reviewed (Section 2).
2. Inputs fuzz/property-tested (hash parsers, wordlist loader, report builder).
3. Static hygiene: no `eval`/`exec`; no hardcoded secrets; stdlib-only deps.
4. Tests run: `python -m unittest discover -s tests -v`.
5. Build reproducible: pinned PyInstaller version; `--clean` onefile build.
6. Runtime smoke tested (frozen exe launches, attestation + tabs render).

No secrets are stored in the repository.

---

## 8. Supply Chain & Integrity

- Runtime dependencies: **Python standard library only** (reduces A06/SI-7 surface).
- Build tooling: PyInstaller pinned in build script; source of truth = `main.py` + `src/`.
- Artifacts: `dist/PasswordGuardian.exe` (~12 MB onefile). Suggested for release:
  Authenticode code-signing and SHA-256 manifest (documented as process note).
- **SBOM**: for a masterclass/enterprise

 release, attach `pyinstaller --log-level` + dependency list; since runtime is
 stdlib-only, the SBOM is trivially small.

---

## 9. Operational Security Controls

| Control | Behavior |
|---|---|
| Attestation gate | Mandatory dialog at launch; operator must confirm own/authorized data and enter identity; recorded to audit |
| Audit events | session_start, attestation, wordlist_loaded, attack_completed, attack_error, report_generated, session_end |
| Chain integrity | Each entry stores `sha256(prev_entry || payload)`; `verify_chain()` recomputes |
| Wipe | Deletes audit + config; destroys in-memory targets/results |
| Report watermark | `PasswordGuardian Report | operator | session | ts` + classification banner |
| Rates/limits | Wordlist 25 MB / 2M lines; mask ≤ 1e12 keyspace; worker cap 16 |

---

## 10. Security Testing

Automated (in `tests/test_core.py`):
- MD4 RFC vectors + NTLM known values
- Hash identification incl. salted / modular / forced 32-hex
- Wordlist crack, rules crack, mask crack, salted crack, stop, mask-guard
- Auditor entropy + NIST checks + blocklist clamp
- Audit chain integrity + tamper detection + wipe
- DPAPI bundle round-trip
- HTML watermark / CSV export

Manual (recommended before release):
- Run frozen exe; complete attestation; load; crack; export all formats; verify chain after doing each.
- Attempt to edit `workspace/audit.jsonl` then re-verify chain (must fail).
- Attempt oversized / binary wordlist (must be rejected).

---

## 11. Incident Handling (A.5.24 / A.5.29)

If a violation is suspected (unauthorized data loaded):
1. Do not wipe; preserve the audit log (`workspace/audit.jsonl`).
2. Run chain verification; screenshots/notes into incident record.
3. Isolate machine, revoke access, escalate per org policy.
4. Use the report watermark to retrace which operator/session generated evidence.

All "security.md" process claims are evidenced by the artefacts referenced;
update this file whenever the implementation changes.