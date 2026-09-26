# Session Memory

Track 2 / Task 21 — Phishing Email Analyzer.

Context and architecture decisions that must be retained across sessions so work
continues coherently.

---

## Objective

Deliver a **portable Windows GUI** (`PhishingEmailAnalyzer.exe`) that triages raw
`.eml` into evidence-backed, explainable verdicts across header / URL / attachment
domains, aligned to NIST SP 800-53, ISO/IEC 27001:2022, and OWASP Top 10.

## Environment (memorize)

- OS: Windows; Python **3.12.7 only** via `py -3.12` (bare `python` is a Store stub).
- Installed: tkinter 8.6, pyinstaller 6.22.2, pytest 9.1.1, requests, dnspython 2.8.0, cryptography 50.0.1.
- Requirements pinned as: `cryptography==45.0.4`, `dnspython==2.8.0`, `requests==2.32.5`.
  Note: the installed `cryptography` (50.x) and pinned one (45.0.4) differ; tests pass with the installed version.
- Module entry: `py -3.12 -m src.app.main`; frozen entry: `launcher.py`.
- App data dir: `%LOCALAPPDATA%\PhishingEmailAnalyzer` or `PEA_DATA_DIR` override.

## Security Model (do not regress)

- Single-credential vault: authentication **is** successful GCM decryption of the profile body;
  no cleartext password verifier anywhere.
- Constant random `data_key` (AES-256) is stored inside the profile body; password rotation
  re-encrypts the body under a new PBKDF2 key and **preserves** the data key.
- All persisted state (profile, audit, settings, cases, raw) is AES-256-GCM, AAD-bound,
  nonce-randomized; tampering ⇒ decryption fails.
- Lockout state lives in plaintext `lockout.dat` (AC-7 style) so wrong passwords never
  re-encrypt the body.
- Email bodies render as plain text ONLY (anti-XSS by construction).
- URL engine never dials arbitrary URLs (SSRF-averse; allowlist + `is_private_ip`).
- Verdicts fail closed; DMARC “none” is informational, not a fail.

## Gotchas Learned (memorize — these bit us)

1. **`_split_tags` tag names are multi-char.** Regex must be `([a-z][a-z0-9]*)\s*=\s*…`, NOT
   `([a-z])`. The old single-char regex silently renamed `bh=` → `h`, breaking DKIM body-hash checks.
2. **Identity instance state must be re-synced after write.** `create_profile()` and
   `change_password()` must call `self.load()` after `_save_blob()`, otherwise the same
   process cannot `authenticate()` (stale `_body_enc` / salt / iterations ⇒ GCM failure).
3. **`_relay_chain(res, meta, received)`** — argument order at the call site must match; a swap
   caused `KeyError: 0` because a dict was indexed as the received list.
4. **Header meta plumbing:** display/reply-to/return-path must go into the `meta` dict consumed
   by `_impersonation`, not only into `res.meta`.
5. RFC 6376 canonicalization test vectors: empty simple body → `b"\r\n"`, hash base64
   `frcCV1k9oG9oKj3dpUqdJg1PxRT2RSN/XKdLCPjaYaY=`; empty relaxed body → `b""`, hash base64
   `47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=`. Relaxed header `From: X` → `from:X`.
6. `is_private_ip()` uses `getattr(addr, "is_site_local", False)` (IPv4-only attribute).
7. `AuditLog.append(action, actor, role, target, result, detail)` — positional kwargs;
   `C.AUDIT_EVENTS` whitelist gates actions.
8. Build-time `cryptography` import hook: ensure `cryptography.hazmat.backends.openssl._legacy`
   is a PyInstaller hidden import.

## Verification Commands

```powershell
py -3.12 -m src.app.main --self-test   # 57 checks, must print "SELF-TEST PASS"
py -3.12 -m pytest -q                  # 37 tests, must pass
build\build.bat                        # gates + PyInstaller -> dist\PhishingEmailAnalyzer.exe
```

## Remaining Work

1. Update `README.md`.
2. Build the `.exe` via `build\build.bat` and verify launch + `--self-test` on the frozen artifact.
3. Record artifact SHA-256.