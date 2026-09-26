# Security

Security design for the **Agent check-in jitter and sleep study** portable app:
a local, deterministic simulator whose only network-free outputs are report
files and (optionally) an AES-256-GCM encrypted bundle. This document maps every
implemented defense to OWASP Top 10 (2021), NIST CSF 2.0 functions, and the
ISO/IEC 27001:2022 Annex A controls that correspond.

## 1. Threat model (local data-product app)

| # | Threat | Asset | Likelihood | Impact |
|---|---|---|---|---|
| T1 | Malicious report contents (formula/code injection via open in Excel/HTML) | user terminal, downstream tools | Medium** | High |
| T2 | Report tampering / repudiation of an official run | exported artifacts, audit trail | Low | High |
| T3 | Exfiltration of results at rest or in transfer | bundle.zip (results) | Low-Medium | Medium |
| T4 | Local attacker alters scenario or binary inputs | scenario.yml, exe | Low | Medium |
| T5 | Passphrase guessing (low-entropy KDF) | vault bundle | Low | Medium |
| T6 | Environment/cwd tampering via `AGENTSTUDY_DATA_DIR` | data + audit chain separation | Low-Medium | Low |

** = primary drive-by vector; report files are intended to be opened by other humans/tools.

## 2. Mappings

### OWASP Top 10 (2021)

| OWASP ID | Title | Defense implemented | Module |
|---|---|---|---|
| A02 | Cryptographic Failures | AES-256-GCM authenticated encryption; scrypt KDF (N=2^15, r=8, p=1), random 16B salt, 12B nonce; SHA-256 artifact hashing | `src/security/vault.py` |
| A03 | Injection | CSV formula-injection guard (prefix `=,+,-,@,`,\t,\r,\n` with `'`); HTML error-safe escaping of every interpolated value; CSP `script-src 'none'` ⇒ no script execution in reports | `src/security/sanitize.py`, `src/reporting/html_writer.py`, `src/reporting/csv_writer.py` |
| A07 | Identification/AuthN Failures | Local actor model: every audit entry signed by chain hash; passphrase optional, never stored | `src/security/audit.py` |
| A08 | Software/Data Integrity Failures | Append-only, hash-linked audit log verified on open; SHA-256 manifest for every artifact; deterministic seeds logged | `src/security/audit.py`, `src/reporting/bundle.py` |
| A09 | Security Logging & Monitoring Failures | JSON structured audit events (`study.export`, `study.run`) with run_id, artifact hashes, config hash, actor | `src/security/audit.py` |

### NIST Cybersecurity Framework 2.0 functions

| Function | Implementation |
|---|---|
| GOVERN (GV) | Separation of run/export/anomaly logic; strategy + config validated by pydantic; audit = evidence ledger |
| IDENTIFY (ID) | Input validation (bounds ge/le on all scenario fields); scenario hash recorded in the manifest |
| PROTECT (PR) | AES-256-GCM at rest, scrypt KDF, CSP-hardened HTML, CSV/HTML injection guards, YAML-safe loader |
| DETECT (DE) | Audit chain verification on open (`verify()` walks and re-hashes every link) |
| RESPOND/RECOVER (RS/RC) | Deterministic seeds ⇒ any compromised artifact can be regenerated from source + scenario |

### ISO/IEC 27001:2022 Annex A

| Control | Title | How met |
|---|---|---|
| A.5.8 | Information security in project management | Security designed into architecture.html blueprint; gates in `build.ps1` (tests + build) |
| A.5.10 | Malware protection | Reports execute no macros/scripts; CSP `script-src 'none'`; disabling DDE not needed for CSV (guard) |
| A.6.8 | Information security event reporting | Structured audit events with run_id + hashes for forensics |
| A.7.11 | Data masking (applies to logs) | No PII/natural-person data collected; telemetry disabled |
| A.8.8-8.9 | Management of technical vulnerabilities | Pinned requirements.txt; scipy/matplotlib intentionally excluded; PyInstaller console=False |
| A.8.15 | Logging | `audit.log` append-only, hash-chained, JSON-schema-ish stable payload |
| A.8.16 | Monitoring activities | `verify()` integrity self-check on open + sha256.manifest.json |
| A.8.17 | Clock synchronisation | Uses UTC ISO timestamps (`ts`) in audit events |
| A.8.24 | Use of cryptography | AES-256-GCM cipher, scrypt KDF, SHA-256 digests, documented keys/params |
| A.8.29 | Security in development / SDLC | Unit tests (21) + test gate before build; deterministic seeds; no network calls |

## 3. Implementation detail

### CSV injection guard (`src/security/sanitize.py`)
A cell is prefixed with `'` when its first char is `=`, `+`, `-`, `@`, tab, CR, LF,
or when it starts with a digit followed by `,` (DDE/CSV metachar patterns).
Note: legitimate negative numbers (e.g. `-8.95`) also receive the prefix —
documented behavior, verified parse-clean with `csv.reader`.

### HTML hardening (`src/reporting/html_writer.py`)
- `escape_html()` (XML char filtering + entity escape) applied to every metric,
  scenario string and path injected into the page.
- Full `<meta http-equiv="Content-Security-Policy" content="script-src 'none'">`.
- Self-contained (inline CSS only, no external resources). SVG chart closed over
  only numeric path data.
- Non-trusted content is never placed into `href`/`src` (no external asset refs).

### Audit log (`src/security/audit.py`)
Each line is `{hash, payload, prev}` where `hash = sha256(canonical_json(payload) + prev) + "│" + counter`-style chain.
`verify()` re-derives the chain and reports `True` on open. Append-only: entries
are never rewritten; a truncated/tampered chain fails verification.

### Vault (`src/security/vault.py`)
- `encrypt_bytes()`: `salt(16) || nonce(12) || AESGCM(ciphertext)`, key from
  `scrypt(passphrase, salt, N=2**15, r=8, p=1)` → 32 bytes.
- GCM authenticates; wrong passphrase ⇒ `InvalidTag` at decrypt time.
- Graceful no-op degrades when `cryptography` is absent (GUI disables passphrase),
  keeping the offline feature path safe.

## 4. Ops notes

- Data dir: `%LOCALAPPDATA%\AgentJitterStudy`; override with `AGENTSTUDY_DATA_DIR`
  (T6: treat as untrusted only for write targets — keep audit log separate from
  `out` folders; scenario files re-validated by pydantic on load).
- Keep `scenarios/` as the reviewable config surface; scenario config hash is
  embedded in `manifest.csv` and the audit payload — changes between runs are
  visible.
- Rebuild provenance: `sha256.manifest.json` lists every artifact digest;
  regenerate any run from source + scenario + seeds.
- The exe is windowed (`console=False`); CLI mode `--cli` prints to stdout when
  launched from a terminal but never exposes secrets.

## 5. Residual risks

- Windows Defender/AV heuristics on the unsigned onefile exe (sign with a
  code-signing cert before broad distribution).
- Reports opened by users who disable CSP or edit HTML — outside our control.
- Password manager not integrated; passphrase handling is manual.
- Local-level actor (same-machine) attacks are out of scope by design.