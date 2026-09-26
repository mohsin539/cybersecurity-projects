# 📌 Project State — StaticLab

Current implementation status, verified artifacts, and outstanding work.
This is the source of truth for what exists and what is trusted.

> Last updated: **2026-09-22**

---

## 1. Deliverables (built & verified)

| Item | Path | Status |
| :--- | :--- | :--- |
| Architecture blueprint | `../architecture.md` | ✅ complete |
| GUI app source | `static-lab/app/` | ✅ complete |
| Headless CLI | `python -m app --cli FILE [--format html\|json\|txt] [--no-lookup]` | ✅ verified |
| **Portable .exe** | `static-lab/dist/StaticLab.exe` (~12.6 MB, onefile) | ✅ built & smoke-tested |
| Build script | `static-lab/build.ps1` | ✅ builds clean |
| HTML report sample | regenerated on demand | ✅ verified (17 KB, escapes strings) |
| Unit tests | `static-lab/tests/test_core.py` | ✅ **12/12 pass** |
| Security doc | `static-lab/security.md` | ✅ |
| State doc | `static-lab/state.md` | ✅ |
| Memory doc | `static-lab/memory.md` | ✅ |

## 2. Verified behavior (evidence-level)

- CLI on a real PE (`python.exe`): exit code `0`; valid JSON; verdict, hashes, PE64+, sections, audit chain all present (`chain hash …b8b2c698e2 … verified: true`).
- Packaged `StaticLab.exe`: same headless JSON run returns `exit 0`; GUI process stays alive (launch test).
- Audit tamper detection proven by unit test (payload rewrite → `verify_chain()` → `False`).
- DPAPI secret round-trip passes on this Windows host.

## 3. Pipeline stages (implemented)

1. Read + stream hashes (MD5/SHA-1/SHA-256/SHA-512)
2. PE header parse (pefile) + Rich header decode
3. Overall Shannon entropy
4. Strings: ASCII + UTF-16LE, flags (url/ip/email/guid/registry/base64/suspicious)
5. Local heuristic verdict (implied-import heuristics, overlay/embedded PE, section entropy, unsigned)
6. Threat-intel lookups (VirusTotal v3, MalwareBazaar, OTX, Hybrid Analysis) — hash only, no sample upload
7. Audit append + whole-chain verification
8. Report export (HTML/JSON/TXT)

## 4. GUI surface

Tabs: `Overview` · `PE Headers` · `Sections` · `Imports` · `Strings` · `Lookups` · `Audit`.
Menus: File (Open / Export HTML·JSON·TXT / Export Full Strings / Exit) · Tools (API Keys, Audit Viewer, Verify Chain) · Help.

## 5. Known limitations / notes

- `get_imphash()` may return empty for certains CMOSS-imported binaries (e.g. `python.exe` bootloader) → shown as `-` (accurate; not a bug).
- `is_driver` flag uses `IMAGE_FILE_SYSTEM (0x1000)`; fixed after first pass.
- Sekret vault requires Windows (DPAPI). Non-Windows fallback is intentionally refused (fail-closed).
- String runs immediately adjacent to ASCII may absorb one extra printable char under UTF-16LE pairing (GNU `strings -el` semantics).
- MalwareBazaar/OTX/Hybrid require API keys; VT requires a key. Without keys lookups are recorded as `no_key`.

## 6. Backlog / next milestones

| Priority | Item |
| :--- | :--- |
| High | Move YARA/Sigma rules into the pipeline (already in parent architecture) |
| High | Fresh VM module: dynamic sandbox (the other half of architecture.md) |
| Medium | Authenticode signature verification (WinVerifyTrust) |
| Medium | Evidence `.zip` bundle with manifest + detached signature |
| Medium | API server mode (REST layer per architecture §15) |
| Low | Drag-and-drop file input on the GUI |
| Low | Multi-VM pool orchestration (Hyper-V adapter)