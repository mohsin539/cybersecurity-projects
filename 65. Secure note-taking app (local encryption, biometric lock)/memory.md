# 🧠 Memory — SecureNote Pro (project reserve / learned conventions)

> Persistent lessons & conventions to carry into every future session.

## 1. Non-negotiable design laws (from architecture.md, enforced here)

1. **Never persist plaintext.** Every envelope touching disk is AES-256-GCM.
2. **Never reuse nonces.** `aead_dump()` mints a fresh 96-bit IV per call.
3. **Fail closed.** Any auth/crypto anomaly locks or wipes — never downgrades.
4. **Two factors.** Biometric + passphrase; biometric alone never absorbed.
5. **Every security-relevant action is audited** in the hash-chained ledger.
6. **Keys are zeroized on lock / wiped on lockout** (overwrite + fsync + delete).
7. **Zero cloud.** No network egress; SSRF class eliminated by design.

## 2. Build & runtime gotchas (learned the hard way)

- **DPAPI via ctypes:** `CryptProtectData` output blob must be freed with
  `LocalFree`; the *input* blob is ctypes-owned — freeing it → `STATUS_HEAP_CORRUPTION`
  (exit `0xC0000374`). Use explicit `argtypes` (`wintypes.DWORD`, not `ctypes.c_dword`).
- **PyInstaller excludes:** `unittest` must NOT be excluded — `fpdf.sign` imports it.
- **WinRT bindings (3.x):** static methods live on the class; operations expose
  `.wait()` + `.get_results()`; some enums expose constants (e.g. `_AVA.AVAILABLE`)
  rather than `.EnumName`; `check_availability` is absent on some packages — probe with
  `hasattr` and degrade gracefully.
- **fpdf2 / Helvetica:** built-in core font covers only latin-1 — sanitize text with
  `_pdf_safe()` before `cell()` or it throws on U+FFFD/emoji.
- **Argon2id cost:** memory-hard by design; the smoke test takes ~5 s per derivation —
  keep trace/test expectations generous, never lower the parameters to speed tests up.
- **PowerShell shell:** no `&&`, no `<<` heredocs; chain with `;` / `if ($?)`, pass code
  via `-c` or files. `&` (call operator) needed for paths with spaces.
- **Data dir resolution:** env `SECURENOTE_HOME` override → next-to-exe if writable →
  `~/.secure_note`. Never hard-code AppData in the app; keep the exe genuinely portable.

## 3. Code conventions

- Type hints everywhere; no third-party logging (print + audit-ledger).
- `secure_note.*` modules are UI-agnostic; `ui.py` is the only Tkinter code.
- Errors are surfaced as `dict {"ok": bool, "msg": str, ...}` everywhere.
- `_audit(action, result, details, category)` is the single funnel for events.
- CSC: `crypto_core` never imports `vault`/`ui` (no cycles; keeps it auditable).
- Passphrases and keys are `bytes`/`str` with no accidental stringification of secrets.

## 4. Decision log (why we did it this way)

| Decision | Why |
|---|---|
| Python + PyInstaller (onefile) | fastest to an auditable, portable exe; deps bundled |
| tkinter (stdlib) over Qt/Electron | zero extra runtime, smaller exe, no web stack |
| DPAPI as enclave-lite | hardware-ish binding with zero extra native deps |
| Whole-file re-chunk AES instead of streaming | simplicity + correctness for notebook-sized data |
| `policy.py` scored at runtime | compliance reports can cite live evidence |
| ECDSA P-256 report signing | matches architecture §11; keys sealed via DPAPI |

## 5. Testing quick-reference

| Command | Checks |
|---|---|
| `python smoke_test.py` | full E2E (source), incl. lockout & rotation |
| `dist\SecureNotePro.exe --selftest` | certified artifact E2E (fast path) |
| `dist\SecureNotePro.exe --cli` | environment / data-dir check, prints bio state |
| `python -m PyInstaller --noconfirm --clean build.spec` | regenerate exe |
| `build.bat` | one-click rebuild + verify |

## 6. Security operational reminders

- Never commit/vault the `data/` folder, `*.key`, `warn-build.txt` or `__pycache__`.
- Reports contain sensitive posture metadata — they are meant for the device owner
  and optionally an external auditor (attestation ZIP is signed for that purpose).
- When changing crypto constants, update `security.md` §1 and `crypto_core.py` tuning
  block in the SAME commit; `policy.collect_evidence` reads them as live evidence.