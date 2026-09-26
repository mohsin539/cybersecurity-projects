# 📌 State — SecureNote Pro (as of 2026-09-23)

> Reservation snapshot for future engineering sessions. Read this first.

## 1. Current status ✅ DONE

- [x] Portable single-file exe built **and certified**:
      `dist/SecureNotePro.exe` (≈ 35.9 MB, windowed, no install)
- [x] Built-in artifact certification: `SecureNotePro.exe --selftest` → `SELFTEST PASSED`
      (exercises setup → CRUD → lock/unlock → audit verify → PDF/CSV/JSON/ZIP reports
      → passphrase rotation → secure wipe)
- [x] GUI verified to launch (auto-close smoke test passed)
- [x] Headless CLI: `SecureNotePro.exe --cli`
- [x] `architecture.md` (design) + `security.md` + `state.md` + `memory.md`
- [x] Smoke test harness: `smoke_test.py` (source-mode)

## 2. Deliverables layout

```
Secure note-taking app (local encryption, biometric lock)/
├── architecture.md          # full colored architecture (Mermaid)
├── security.md              # implemented security model + limitations
├── state.md                 # this file
├── memory.md                # learned conventions / gotchas
├── main.py                  # entry (gui / --cli / --selftest)
├── build.spec               # PyInstaller spec (onefile, windowed)
├── build.bat                # one-click rebuild
├── requirements.txt
├── smoke_test.py            # source-mode E2E (slow: includes Argon2)
├── src/secure_note/         # app package
│   ├── app.py               # controller (orchestrates everything)
│   ├── auth.py              # biometric (WinRT) + rate limiter + lockout
│   ├── audit.py             # hash-chained, HMAC-signed ledger
│   ├── crypto_core.py       # AES-256-GCM / Argon2id / HKDF / HMAC
│   ├── dpapi_binding.py     # Windows DPAPI device binding (ctypes)
│   ├── policy.py            # ISO/NIST/OWASP compliance scoring
│   ├── report.py            # PDF/CSV/JSON/ZIP + ECDSA P-256 signing
│   ├── ui.py                # tkinter GUI (5 tabs)
│   └── vault.py             # key hierarchy + encrypted note store
├── dist/SecureNotePro.exe   # 🚀 portable artifact
└── build/ ...               # PyInstaller intermediates (regenerable)
```

## 3. Runtime data layout (auto-created)

Data dir = `SECURENOTE_HOME` env var if set, else writable folder next to exe,
else `~/.secure_note`. Files (all under data dir):

| File | Purpose |
|---|---|
| `vault.bin` | JSON: salt + verifiers + wrapped keys + AEAD `body` (notes) |
| `dk.bin` | DPAPI-sealed device key (root of trust) |
| `audit.bin` | AEAD-encrypted, hash-chained event ledger |
| `audit.key` | DPAPI-sealed HMAC key |
| `authstate.json` | failure counters + lockout until |
| `signer.key` | DPAPI-sealed ECDSA P-256 report signer |
| `reports/` | generated report exports (choose folder in UI) |

## 4. How to verify / rebuild

```powershell
# verify the shipped exe (fast, full pipeline)
.\dist\SecureNotePro.exe --selftest    # -> SELFTEST PASSED

# source-mode smoke test (slower due to Argon2)
python smoke_test.py

# rebuild portable exe
.\build.bat                             # -> dist\SecureNotePro.exe
```

Python env: **Python 3.12.7 x64** at `C:\Users\mohsi\AppData\Local\Programs\Python\Python312`
(venv is **not** used; installs are global on this machine).

## 5. In-flight / next (not built yet)

- [ ] FIDO2/WebAuthn security-key support
- [ ] Zero-knowledge encrypted cross-device sync
- [ ] Real Secure Enclave/TPM seal instead of DPAPI-lite (hardening note in security.md §4)
- [ ] Anomaly-detection (ML) on unlock patterns
- [ ] App icon + rich manifest (`SHELL32`/codepage enum) and About dialog
- [ ] i18n (l10n) strings

## 6. Open risks / watch-items

- WinRT packages (`winrt-runtime 3.x`) must be pinned on rebuild — API surface
  shifted (no `check_availability` static on some bindings; handled defensively).
- fpdf2 pulls in `unittest` (`fpdf.sign`) — do NOT exclude `unittest` from PyInstaller.
- Argon2id (~1.5 s/factor) is run on the GUI thread for passphrase unlock; acceptable
  now, but a worker-thread + progress cue is a later UX polish.