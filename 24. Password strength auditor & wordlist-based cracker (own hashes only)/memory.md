# memory.md — Project Memory (persistence for future sessions)

Use this file to restore context quickly. Read `ARCHITECTURE.md`, `security.md`,
`state.md` for the full picture.

## 1. What the project is

**PasswordGuardian** — a portable, offline **password strength auditor** and
**wordlist-based cracker** restricted to "own hashes only". Built for a security
masterclass. Purposefully dual-use-safe: attestation gate, audit trail,
watermarks, no network.

Chosen delivery standard: **Option A — portable GUI .exe** (Python 3.12 +
Tkinter + PyInstaller onefile). Decision rationale documented in
`ARCHITECTURE.md` §2.

## 2. Key decisions (do not silently reverse)

- **Stdlib-only runtime** by design (security posture + zero supply chain).
  Optional bcrypt/argon2 cracking intentionally deferred.
- **Own-hashes-only** is a hard scope boundary — attestation dialog gates use and
  every report is watermarked with operator + session.
- **DPAPI** (not app-managed keys) for at-rest encryption; pure-Python MD4 fallback
  exists and is RFC-vector-tested.
- **Append-only hash-chained audit log** — never log unresolved plaintext.
- **Mask attack guarded ≤ 1e12 keyspace**; wordlists capped at 25 MB / 2M lines.
- NTLM/MD5 32-hex ambiguity resolved by user forcing (`--force32` / GUI combobox);
  `auto` mode tests both.

## 3. Layout & conventions

```
main.py                 entry (GUI, or --cli)
src/
  core/   hashes.py ntlm.py wordlists.py cracker.py auditor.py report.py
  compat/ win.py (DPAPI, BCrypt-MD4) workspace.py (audit chain)
          paths.py (bundled-data + workspace dir)
  gui/    app.py (Tkinter, AttestationDialog, 5 tabs)
  cli.py  identify|crack|audit|report
data/       common_passwords.txt (sample wordlist)  sample_hashes.txt (demo)
tests/test_core.py        22 tests
build_portable.ps1        PyInstaller onefile build
dist/PasswordGuardian.exe portable build (12 MB)
```

- **Code style**: no comments in source; functional, explicit, stdlib imports only.
- **Run tests**: `python -m unittest discover -s tests -v`
- **Rebuild exe**: `powershell -File .\build_portable.ps1`

## 4. Commands / workflows

```powershell
python main.py --cli crack data\sample_hashes.txt --wordlist data\common_passwords.txt --force32 ntlm
python main.py --cli audit -p "Tr0ub4dor&3" --algo MD5
python main.py --cli report data\sample_hashes.txt --out reports --operator "alice@acme" --results data\last_results.json
```

## 5. Security invariants (see security.md for detail)

1. No network functionality of any kind.
2. Results live in memory only; only watermarked reports + DPAPI bundles persist.
3. Every session/attack/export is appended to `workspace/audit.jsonl` with a
   SHA-256 chain; `verify_chain()` is exercised by tests.
4. All 22 tests must stay green; MD4/NTLM vectors are pinned in tests.
5. CLI `--json` piped through PowerShell writes UTF-16; the results loader in
   `cli.py::_load_json_file` is BOM-aware — keep it that way.

## 6. Environmental facts

- Windows 11, Python 3.12.7, tkinter 8.6, PyInstaller 6.22.2.
- `hashlib` has **no MD4** on this build → NTLM via BCrypt/ctypes or pure Python.
- `dist/PasswordGuardian.exe` is a `--windowed` onefile; CLI mode exits cleanly
  but its stdout is hidden (useful for scripting exit codes only).
- Working dir for the shell sees the project root; paths with spaces must be
  double-quoted in PowerShell.

## 7. Open questions / candidates for next session

- Add bcrypt/argon2 optional cracking and keep tests green?
- WASM delivery of the same core (M4)?
- SIEM export + code signing?

## 8. Session log

| Date | Work done |
|---|---|
| 2026-09-18 | ARCHITECTURE.md · all core + GUI + CLI · tests (22 pass) · portable exe built & smoke-tested · security.md / state.md / memory.md |
| 2026-09-18 (fix) | Startup bug: attestation `Toplevel` stayed `withdrawn` (unmapped) → no visible window. Root cause: `attributes("-topmost", True)` combined with `grab_set()` on this Windows Tk build pinwheeled the dialog into `withdrawn`. Fix: removed `-topmost`; kept root mapped behind the modal; `update()` before `wait_window()`. Verified `mapped=1 viewable=1` via user32 probe. Rebuilt exe as `dist\PasswordGuardian_v2.exe` because the OLD `dist\PasswordGuardian.exe` is held locked by two stale elevated processes (PIDs 18020 / 21284) that cannot be killed from a non-elevated shell — user must end them in Task Manager, then the name can be reused. |