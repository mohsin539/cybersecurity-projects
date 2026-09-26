# Browser Artifact Extractor — Memory (persistent working knowledge)

**Purpose:** durable working memory for future sessions — commands, conventions,
invariants and decisions. Read this before modifying the codebase. Update this
file whenever an invariant, decision or gotcha changes.

---

## 1. Identity & runnable surface

Project root: `49. Browser artifact extractor (history, cookies, cache parser)`

```
main.py                    # entry: `python main.py`  → GUI   |  `--cli` → headless
build_portable.py          # `python build_portable.py --clean` → both .exe in dist/
dist/
├── BrowserArtifactExtractor.exe        GUI  (windowed one-file)
└── BrowserArtifactExtractor-CLI.exe    CLI  (console one-file)  e.g. `...\BrowserArtifactExtractor-CLI.exe --cli --out ... --formats html,csv,json`
```

Runtime-friendly commands:
```powershell
python main.py --cli --out .\out --max-records 25 --decrypt --formats html,csv,json --case C1 --operator me
python -m pyflakes core sec report ui main.py build_portable.py   # static check (installed)
python -m compileall -q core sec report ui main.py                # bytecode check
```

---

## 2. Non-negotiable invariants (do not break)

1. **Read-only evidence.** Originals are never opened for write. All SQLite reads
   go through `core.extractors._open_db` → `core.winio.copy_any` (temp copy).
2. **Zero network.** Never add socket/http/urllib/requests code.
3. **Worker threads never touch Tk.** UI updates only via `queue.Queue` + `root.after`.
4. **Secrets masked by default.** `ScanOptions.decrypt_secrets` gates all plaintext
   cookie/password output; always pass a *status* alongside plaintext
   (`decrypt_value → (value, status)`).
5. **Sanitise every report value.** HTML via `templates._e` (html.escape); XML via
   SAX escape; CSV via `QUOTE_ALL`; Markdown escapes `|`.
6. **Records carry provenance.** Every artifact record sets `_browser` / `_profile`.
7. **Audit everything.** Meaningful actions → `AuditLogger.log(...)`; the log is a
   SHA-256 hash chain, so never re-write/append out-of-order.
8. **stdout contract (CLI):** one line per report path; summary block with
   `Audit chain:`; structure stays machine-browsable.

---

## 3. Module quick-reference

| Module | Key symbols | Notes |
|---|---|---|
| `core/models.py` | `ScanOptions`, `ScanResult`, `EvidenceItem`, `BrowserProfile` | dataclasses; `to_dict()` used by exporters |
| `core/paths.py` | `discover_browsers()`, `CHROMIUM_ROOTS`, `CHROMIUM_ARTIFACTS` | platform key: `win/mac/linux`; Arc path uses bounded wildcard glob |
| `core/decrypt.py` | `load_master_key(local_state)`→(key,status), `decrypt_value(enc,key)`→(txt,status) | statuses: `ok/empty/no_key/v20_appbound/dpapi/error`; DPAPI via ctypes Crypt32 |
| `core/winio.py` | `copy_any(src,dst,allow_vss)`→strategy name, `EvidenceLocked`, `is_admin()` | ladder: shared→backup→plain→VSS (elevated WMI) |
| `core/extractors.py` | `extract_*` per category, `_open_db()` | copies `-wal/-shm/-journal` sidecars; rows decode `errors="replace"` |
| `core/engine.py` | `Engine.run(profiles)`, `Engine._collect`, `Engine._master_key` | key cached per `user_data` in memory |
| `sec/integrity.py` | `sha256_file`, `build_manifest`, `HashChain.verify`, `sign_manifest`, `new_scan_id` | `scan_id` = `BAE-<ts>Z-<8hex>` |
| `sec/audit.py` | `AuditLogger(path, actor, severity_floor)` `.log/.info/.security/.verify` | JSONL; chain bound to previous line |
| `sec/compliance.py` | `CONTROLS` (20), `assessment()`, `FRAMEWORKS` | source of in-app Compliance view |
| `report/exporters.py` | `SCHEMAS`, `bundle()`, `export_all()`, `EXPORTERS` | add a format here = share it everywhere |
| `report/templates.py` | `HTML_DOC`, `section()`, `table()`, `stat_card()` | single source of HTML look |
| `ui/theme.py` | dir `C`, `CATEGORY_COLORS`, `apply_theme()` | colour tokens only here |
| `ui/widgets.py` | `StatCard`, `ArtifactTable`, `SidebarNav` | reusable controls |
| `ui/app.py` | `App`, `run()`, `ExportDialog`, `base_dir()` | frozen-aware output anchor |

---

## 4. Decisions worth remembering (ADR-lite)

| ID | Decision | Consequence to guard |
|---|---|---|
| D1 | Temp-copy-then-open SQLite | Must also copy `-wal`/`-shm`; otherwise stale data. Done in `_open_db`. |
| D2 | Two executables (windowed + console) | A `--windowed` bootloader detaches stdout; CLI needs its own build. |
| D3 | ctypes DPAPI instead of pywin32 | Keeps runtime dependency-free; `dpapi_decrypt` raises `OSError` on failure. |
| D4 | Schema-driven projections (`SCHEMAS` + `_project`) | Adding a field = update schema + `_project`, not each exporter. |
| D5 | GUI auto-export to `BAE_Output/scan_<ID>` | Deterministic layout: `<out>/report_<ts>.<ext>`, `<out>/csv_<ts>/*.csv`, manifest. |
| D6 | Secrets status taxonomy surfaced to UI/reports | UI colours `ok/no_key/v20_appbound` distinctly. |
| D7 | Limits: `0` = unlimited; PDF prints ≤800 rows | Documented so nobody "fixes" it away. |
| D8 | Strings always utf-8 tolerant (`errors="replace"`) | Browser data is arbitrary bytes. |
| D9 | Parse cache via Simple-Cache header (`f_*` files) + URL regex | Chrome: magic + key at offset 20; Firefox cache2: scan for URLs. |

---

## 5. Known gotchas (hurt someone before — be careful)

- **Windows exclusive locks:** Chrome/Edge `Cookies` are locked when running
  (`CreateFileW` → error 32); even `robocopy /B` fails. Do **not** kill the
  browser. Ladder handles it; expect a warning for non-elevated runs.
- **`cryptography` lazy import:** `_aes_gcm_decrypt` imports inside the function;
  build script pins it via `--hidden-import` + `--collect-submodules`.
- **Tk threading:** any Tk call off the main thread corrupts the UI. Route through
  the worker `queue`; update tables only in `_on_complete`.
- **One-file exe first launch is slow** (PyInstaller extraction). In CI/smoke runs
  allow ≥8 s before asserting the process lives.
- **CSV Excel:** must be `utf-8-sig` (BOM) or Excel mangles Unicode.
- **Chromium timestamps:** microseconds since 1601 (`chrome_time`); Firefox PRTime
  is µs since 1970 (`firefox_time`). Mixing them silently misdates rows.
- **SQLite WAL:** a live DB's committed rows live in `-wal`; copy sidecars, never
  open the original read-write.

---

## 6. Conventions

- Python 3.12, stdlib-first; type hints on public signatures; docstrings on modules
  and public functions.
- Imports: stdlib → third-party → local; no wildcard imports.
- No comments unless they explain *why*; docstrings carry the "what/why".
- Strings: single quotes preferred for dict keys/values literals; f-strings for
  interpolation; never rely on default encoding — explicit `encoding="utf-8"`.
- Errors: raise domain errors (`EvidenceLocked`, `OSError` with Win32 code) instead
  of bare asserts in shipping paths.
- Categories are the single vocabulary: `history, downloads, cookies, bookmarks,
  autofill, logins, search_terms, cache` (order matters for UI/schemas).
- Colour tokens come only from `ui/theme.py` — never hard-code hex in views.

---

## 7. How to verify a change (quick checklist)

1. `python -m pyflakes core sec report ui main.py build_portable.py` → clean.
2. `python -m compileall -q core sec report ui main.py`.
3. CLI smoke: `python main.py --cli --out <tmp> --max-records 15
   --formats html,csv,json --case smoke` → prints `Audit chain: VALID`.
4. GUI smoke (hidden-window manner): build `App`, `discover()`, `start_scan()`,
   poll `app.result` (see state.md §2 methodology).
5. If exporting: re-open XLSX via openpyxl; count XML `<record>` vs total.
6. Rebuild exe only when packaging-affecting changes land:
   `python build_portable.py --clean`.

---

## 8. Glossary

- **Chain of custody** — chronological record of who handled evidence when; here:
  manifest + audit + report header.
- **Hash chain** — each record's digest binds the previous digest (tamper evidence).
- **WAL** — SQLite write-ahead log; holds latest committed pages for live DBs.
- **DPAPI** — Windows Data Protection API; protects Chrome's wrapped key for the
  current user.
- **App-Bound (v20)** — Chrome 127+ bound-encryption; unreadable without the
  browser's own service store.
- **NSS** — Firefox's crypto store (`key4.db`); holds login master password keys.
- **VSS** — Volume Shadow Copy; point-in-time volume snapshot (requires admin).