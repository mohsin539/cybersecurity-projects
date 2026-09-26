# Phishing Email Analyzer — Security Document

**Version:** 1.0 — matches the implemented application (Python 3.12 / Tkinter / PyInstaller portable build).

This document complements [`docs/architecture.md`](architecture.md) and describes the **security controls that are actually implemented in code**, the threat model assumptions, the at-rest encryption scheme, and operational security guidance for the portable `.exe` deployment.

---

## 1. Scope & Deployment Model

The deliverable is a **portable, single-file Windows executable** (`PhishingEmailAnalyzer.exe`) that:

- Runs entirely **offline by default** (no telemetry, no updates phone-home).
- Stores all persisted state under `%LOCALAPPDATA%\PhishingEmailAnalyzer` (overridable via the `PEA_DATA_DIR` environment variable).
- Performs analysis locally: header (SPF/DKIM/DMARC), URL triage, and attachment triage.

Because the tool analyzes **attacker-controlled inputs** (raw email bytes), it follows the principle of **hostile input by default** — every parser fails closed, nothing above INFO severity is emitted on faith, and verdicts never default to "allow" when evidence is missing.

---

## 2. Implemented Security Controls

### 2.1 Identity, Authentication & Access Control (A07 / OWASP, AC / ISO A.9)

| Control | Implementation |
|---|---|
| No default credentials | `IdentityStore.create_profile()` is the only way to create a vault; there is no backdoor or factory password. |
| Strong password gate | Enforced by PBKDF2-HMAC-SHA256 key derivation plus a minimum length policy (`MIN_PASSWORD_LEN`). |
| Authentication == decryption | The profile body is AES-256-GCM encrypted under `K = PBKDF2(password)`. Successful GCM authentication **is** login; there is no cleartext password verifier to steal. |
| Brute-force lockout (AC-7) | `LOGIN_MAX_ATTEMPTS` failed attempts trigger a `LOGIN_LOCKOUT_SECONDS` lockout tracked in `lockout.dat`; the counter survives restarts. |
| Role-based access (RBAC) | Roles `admin` / `analyst` with per-action allow-lists (`C.ALLOWED_ROLE_BY_ACTION`); destructive actions (e.g. delete case) are admin-only. |
| Password rotation | Changing the password re-encrypts the profile body under the new `K`; the random `data_key` is preserved inside the body so encrypted cases/audit/settings stay decryptable. |

### 2.2 At-Rest Encryption (SC-28 / A.10.1 / A02)

Every persisted artifact is **AES-256-GCM** encrypted with an authenticated, nonced container:

| Artifact | Path | Keying |
|---|---|---|
| Identity profile | `profile.dat` | `PBKDF2(password)` — body holds `data_key` |
| Audit log chain | `audit/batch-*.bin`, `audit.head` | HMAC/SHA-256-derived `head_key` |
| Settings vault | `settings.dat` | SHA-256(`"pea-settings" + data_key`) |
| Case documents | `cases/*.case` | `data_key` |
| Raw EML | `raw/*.raw` | `data_key` (fresh nonce per file) |

Each encrypted container embeds: magic, random salt (16 B), random nonce (12 B), ciphertext, and a 16-byte GCM tag. Additional Authenticated Data (AAD) binds every blob to its context (`pea-profile.v1`, `pea-case.v1`, …) so a container cannot be replayed into a different slot.

`secure_erase()` (overwrite + delete) is used for retention purges and case deletion.

### 2.3 Tamper-Evident Audit Logging (AU / ISO A.12.4)

- Entries are batched into encrypted, sequential files `batch-000001.bin`, … .
- Each entry embeds a SHA-256 hash of the previous entry (hash chain).
- `audit.head` is separately encrypted under a key derived independently from the data key — a tampered batch or head is detectable via `AuditLog.verify()`, which returns the list of violations (never silently "clean").
- All privileged interactions emit `AUDIT_EVENTS` (login, lock, case analyzed/viewed/deleted/exported, verdict override, settings change, purge, export).

### 2.4 Input Validation & Injection Resistance (SI-10 / A.14.2.5 / A03)

- Raw email size cap, NUL-byte rejection, and line-count budget prevent bombs and parser abuse (`validate_email_bytes`).
- Filenames are sanitized before any use (`sanitize_filename`).
- **Email bodies are rendered as plain text only** — HTML is never rendered by the GUI (XSS / A03 by construction). All widget text passes `to_text_safe_for_ttk`.
- String/text findings are length-limited (`sanitize_text`).

### 2.5 SSRF Hardening (A10)

- The URL engine **never fetches arbitrary URLs**. Reputation lookups are pinned to an explicit allowlist of HTTPS hosts (`ALLOWED_REPUTATION_HOSTS`), TLS-verified.
- `is_private_ip()` blocks private/loopback/link-local/multicast/reserved/metadata (169.254.169.254, etc.) literals and returns a `SSRF_BLOCK_IP` HIGH finding.
- DNS helpers are non-blocking with timeouts; everything fails closed when DNS is unavailable (SPF/DKIM/DMARC "unavailable" rather than "pass").

### 2.6 Fail-Closed Verdicts (A04)

- Scoring weights: header 0.25, url 0.30, attachment 0.30, content 0.15; severity → points (INFO 0 … CRITICAL 4), capped at 100.
- Decision matrix (deterministic, auditable):
  - any CRITICAL or ≥2 HIGH malicious signals, or a HIGH + multi-signal → **QUARANTINE**
  - single HIGH or ≥3 MEDIUM → **SANDBOX**
  - risk score ≥ 40 → **FLAG**
  - otherwise → **ALLOW** (with evidence logged)
- DMARC is only reported as *fail* when a DMARC policy is actually published; absence of a policy is `DMARC_NONE` (informational), preventing over-blocking of legitimate mail.

---

## 3. Threat Model Summary (STRIDE)

| STRIDE | How it is handled |
|---|---|
| **S**poofing | SPF/DKIM/DMARC verification, display-name vs domain brand mismatch (`DISPLAY_SPOOF`), Reply-To / Return-Path mismatch. |
| **T**ampering | GCM authentication on every persisted blob; hash-chained, tamper-evident audit. |
| **R**epudiation | Actor/role/action cascade with chain-hash audit entries. |
| **I**nformation disclosure | All state encrypted at rest; bodies rendered as plain text; no secret logging. |
| **D**enial of service | Input caps (size/NUL/line count), retry/lockout, disk-space pre-check (refuse under 50 MB free). |
| **E**levation of privilege | RBAC action matrix, admin-only destructive operations. |

### 3.1 Assumptions & Residual Risk

- The workstation itself is trusted at runtime (the GUI has access to the unwrapped `data_key` in memory while a session is open). Screen-lock + OS-level encryption (e.g. BitLocker) is expected in production.
- DNS integrity: SPF/DKIM/DMARC results depend on the resolver's DNS. In a hostile network, use DNS-over-HTTPS on the host or a trusted resolver.
- The portable `.exe` is still the application; it does not harden Windows itself (no auto-update chain protection required since there is no update channel).

---

## 4. Operational Security Guidance

### 4.1 Running the portable build

```
PhishingEmailAnalyzer.exe            # GUI analyst console
PhishingEmailAnalyzer.exe --self-test   # headless engine/security self-check
```

Set `PEA_DATA_DIR` to redirect all encrypted state to a protected volume:

```powershell
$env:PEA_DATA_DIR = "D:\Encrypted\PEA" ; .\PhishingEmailAnalyzer.exe
```

### 4.2 First-time setup

1. Launch → create an administrator profile. **Choose a strong passphrase** (≥ 12 chars recommended over `MIN_PASSWORD_LEN`).
2. The profile is the single gate — losing the password loses the vault (this is intentional: there is no back door). Back up nothing that is a secret in plaintext.
3. Add optional VirusTotal API key via Settings; it is stored encrypted with the session data key.

### 4.3 Incident response workflow (ISO A.5.26 / NIST SP 800-61)

1. Analyze suspicious `.eml` → verdict with evidence trail.
2. **Quarantine**: copy the encrypted case (or export) rather than deleting the source email.
3. Export the case as JSON for the SIEM / ticketing system; keep raw EML only as long as `raw_retention_days` allows.
4. An analyst (or admin) overrides a verdict only with a recorded `VERDICT_OVERRIDE` audit event.

---

## 5. Supply-Chain & Build Integrity (SSDF PW.4 / SI-2)

- Runtime dependencies are **version-pinned** in `requirements.txt` (`cryptography`, `dnspython`, `requests`).
- Build is reproducible via `build\build.bat`, which runs the self-test and pytest gates **before** packaging and refuses to proceed on any failure.
- The resulting artifact's SHA-256 is printed by the build script; record it before distribution.
- A pristine rebuild from source is always preferable to trusting a downloaded `.exe`. There is no auto-update channel.

---

## 6. Verification

Run from the project root with Python 3.12:

```powershell
py -3.12 -m src.app.main --self-test   # in-app engine/security self-tests
py -3.12 -m pytest -q                  # pytest suite (37 tests)
```

Both must pass before any release build (enforced by `build\build.bat`).