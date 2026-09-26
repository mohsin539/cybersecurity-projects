# state.md — Project State

Last updated: 2026-09-18
Companion files: `ARCHITECTURE.md` (design), `security.md` (framework), `memory.md` (session memory).

## 1. Milestone Status (per ARCHITECTURE.md roadmap)

| Milestone | Content | Status |
|---|---|---|
| M1 | Core: hash ingest + identifier + wordlist cracker + auditor + CLI | ✅ Implemented |
| M2 | Tkinter GUI (portable exe) + rules + mask attacks | ✅ Implemented |
| M3 | Reporting, audit chain, DPAPI bundle, watermark | ✅ Implemented |
| M4 | WASM build / web edition | ⏳ Not started |

## 2. Deliverables in repo

| Path | What |
|---|---|
| `main.py` | Entry point (GUI default, `--cli` for headless) |
| `src/core/` | hashes · ntlm (MD4) · wordlists · cracker · auditor · report |
| `src/compat/` | win (DPAPI + BCrypt) · workspace (audit chain) · paths |
| `src/gui/app.py` | Tkinter GUI: 5 tabs + attestation gate |
| `src/cli.py` | CLI: identify · crack · audit · report |
| `data/common_passwords.txt` | bundled common-password wordlist (sample) |
| `data/sample_hashes.txt` | demo hash file (generated from public common passwords) |
| `tests/test_core.py` | 22 automated tests |
| `build_portable.ps1` | PyInstaller onefile build script |
| `dist/PasswordGuardian_v2.exe` | **Current working portable exe (built after startup fix, ~12 MB)** |
| `dist/PasswordGuardian.exe` | Stale pre-fix build, file locked by two elevated running processes (PIDs 18020/21284) — end them in Task Manager, then delete/overwrite |

## 3. Verification Evidence

- `python -m unittest discover -s tests -v` → **22 tests, all OK**.
- CLI end-to-end on `data/sample_hashes.txt` (6 targets): identify = 6; wordlist
  crack = 5 cracked / 139 candidates / 0.0 s (NTLM target needs `--force32 ntlm`);
  audit of `Tr0ub4dor&3` → 72.3 bits, score 80, Strong, crack@MD5 ≈ 180,241 y.
- Frozen exe smoke tests: `--cli identify` exits 0; GUI process launches and stays up.

## 4. How to run

```powershell
python main.py                          # GUI (working portable exe = dist\PasswordGuardian_v2.exe)
python main.py --cli identify data\sample_hashes.txt
python main.py --cli crack data\sample_hashes.txt --wordlist data\common_passwords.txt --force32 ntlm
python main.py --cli audit -p "Tr0ub4dor&3" --algo MD5
python main.py --cli report data\sample_hashes.txt --out reports --operator "alice@acme" --results <results.json> --force32 ntlm
python .\build_portable.ps1             # rebuild dist\PasswordGuardian.exe
```

## 5. Test matrix of demo artifacts

| Artifact | Content |
|---|---|
| `reports/report_cli.html | .csv | .json` | sample report outputs |
| `workspace/audit.jsonl` | created on first GUI/CLI workspace use; hash-chained |
| `data/last_results.json` | (regenerable) results map used by `report` CLI |

## 6. Known limitations / notes

- **32-hex ambiguity**: MD5 vs NTLM detected by forcing `--force32 md5|ntlm` (auto
  tests both).
- **Salted formats**: john-style `hash:salt` supported for MD5/SHA-family
  (order = `password + salt`, see `hashes.compute(order=...)`).
- **bcrypt / argon2** are identified but NOT cracked offline (they need optional
  `bcrypt`/`argon2-cffi` pip packages; out of the stdlib-only scope).
- **MD4 on Windows** uses BCrypt; fallback pure-Python MD4 passes RFC test vectors.
- Mask attack guarded at 1e12 keyspace; wordlist capped 25 MB / 2M lines.
- DPAPI bundle export only works on Windows (graceful skip elsewhere).

## 7. Backlog / next steps (M4+)

- Compile the same core to WASM for a fully client-side web edition.
- GPU backends (CUDA/ROCm) and hashcat `.rule`-style rule subsets.
- Sigma/CEF export of audit events to a SIEM.
- Code-signing + SHA-256 release manifest for the exe.

## 8. Change log

| Date | Change |
|---|---|
| 2026-09-18 | v1.0.0 — core, GUI, reporting, audit chain, DPAPI, tests, portable exe built |
| 2026-09-18 | **Bug fix**: attestation dialog was created `withdrawn` (invisible) → GUI "not launching". Caused by `-topmost` + `grab_set` on this Tk/Windows build. Removed `-topmost`, kept root mapped behind modal, added `update()` before `wait_window()`. Verified visible via user32; 22 tests still green. Rebuilt as `dist\PasswordGuardian_v2.exe`. |