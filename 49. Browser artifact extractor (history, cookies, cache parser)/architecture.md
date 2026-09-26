# Browser Artifact Extractor — Architecture

**Document status:** published · **Version:** 1.0.0 · **Owner:** engineering
**Audience:** developers, maintainers, architects, peer reviewers.

This document is the normative description of the system. If code and this
document disagree, the code is the source of truth and this document must be
updated.

---

## 1. Purpose & scope

A **portable, offline, forensic** desktop tool that:

1. Discovers installed browsers and their profiles without executing them.
2. Collects **history, cookies, cache, downloads, bookmarks, autofill, saved
   logins and search terms** strictly **read-only**.
3. Decrypts supported Chromium secrets on the local Windows user context.
4. Produces **six report formats** plus integrity manifests and a tamper-evident
   audit log.
5. Ships as **single-file, dependency-free Windows executables**.

Non-goals: live network interception, remote collection, browser control,
password recovery for third-party NSS stores, and deletion/modification of any
evidence.

---

## 2. Quality attributes (architectural drivers)

| Attribute | Decision |
|---|---|
| **Portability** | Python 3.12 stdlib-first; only `cryptography`, `openpyxl`, `reportlab`, `Pillow` for advanced features; frozen with PyInstaller (one-file) |
| **Evidence integrity** | SHA-256 per artifact, canonical JSON manifest, HMAC signing option, hash-chained audit logs |
| **Offline / privacy** | No socket, no URL fetch, no outbound calls anywhere in the codebase |
| **Non-invasive** | Sources are copied to isolated temp dirs; originals opened read-only |
| **Fault tolerance** | Per-category try/except; a locked artifact degrades to a warning, never aborts the run |
| **Resilience** | Acquisition ladder for live/locked files: shared-read → backup semantics → VSS |
| **Secrets-by-default-safe** | Masked unless the operator explicitly opts in; v20 App-Bound and NSS values detected and flagged |

---

## 3. Technology stack

| Layer | Choice | Rationale |
|---|---|---|
| Language | Python 3.12 | stdlib `sqlite3`, `tkinter`, `ctypes`, `hashlib` |
| GUI | Tkinter + ttk (clam theme) | ships with CPython, no runtime dep for an .exe |
| Crypto | `cryptography` (AES-GCM) + ctypes DPAPI | FIPS-family primitives; DPAPI needs no pywin32 |
| SQLite access | stdlib `sqlite3`, read-only copies | no locking of the live profile |
| Reports | stdlib + `openpyxl`, `reportlab`, `Pillow` | XLSX/PDF fidelity |
| Packaging | PyInstaller 6.x (one-file, windowed + console) | fully portable .exe |
| Testing | ad-hoc smoke + CLI integration (no CI harness yet) | see state.md |

---

## 4. Module map

```
main.py
├── build_parser()          CLI argument contract (--cli, --out, --formats, ...)
├── run_cli()               headless engine run, summary printing, auto-export
└── main()                  dispatches to UI (default) or CLI
```

### core/ — extraction engine
| Module | Responsibility | Key symbols |
|---|---|---|
| `core.models` | Pure data contracts | `BrowserProfile`, `EvidenceItem`, `ScanResult`, `ScanOptions` |
| `core.paths` | Browser discovery, per-platform roots, artifacts mapping | `discover_browsers()`, `_map_artifacts()` |
| `core.decrypt` | DPAPI unwrap, AES-GCM, timestamps | `dpapi_decrypt()`, `load_master_key()`, `decrypt_value()`, `chrome_time()`, `firefox_time()` |
| `core.winio` | Locked-file acquisition ladder, VSS | `copy_any()`, `copy_vss()`, `EvidenceLocked`, `is_admin()` |
| `core.extractors` | Read-only parsers per family | `_open_db()`, `extract_*` per category |
| `core.engine` | Orchestration, hashing, stats, evidence recording | `Engine.run()`, `_collect()`, `_master_key()` |

### sec/ — security & compliance
| Module | Responsibility |
|---|---|
| `sec.integrity` | `sha256_file`, `build_manifest`, `HashChain`, `sign_manifest` (HMAC) |
| `sec.audit` | `AuditLogger` — hash-chained JSONL, severity floor, `verify()` |
| `sec.compliance` | 20-control catalogue; `assessment()` coverage summary |

### report/ — exporters
| Module | Responsibility |
|---|---|
| `report.templates` | Escaped, colourised HTML shell; stat cards, section builders |
| `report.exporters` | `SCHEMAS`, `bundle()`, per-format exporters, `export_all()` registry |

### ui/ — GUI console
| Module | Responsibility |
|---|---|
| `ui.theme` | Palette `C`, ttk theme application, category accents |
| `ui.widgets` | `StatCard`, `ArtifactTable` (filter/sort), `SidebarNav`, `Badge` |
| `ui.app` | `App` main window, threaded scan, auto-export, `ExportDialog` |

---

## 5. Runtime architecture (scan flow)

```
 Operator                       GUI / CLI                    Engine                     Host
 ─────────                      ───────                      ──────                     ────
   consent                          │                          │                          │
   opts --------------------------->│   ScanOptions            │                          │
      discover <────────────────────┼── discover_browsers() ──>│────────── read-only ────>│ dirs / profiles.ini
                                   │                          │                          │
   start    ---------------------->│ Engine.run(profiles)      │                          │
                                   │        │  for each profile x category:              │
                                   │        │    ✓ path lookup (core.paths)              │
                                   │        │    ✓ master key cache (core.decrypt)       │
                                   │        │    ✓ winio.copy_any(source) ─────────────>│ disk
                                   │        │    ✓ temp SQLite copy (no -wal/-shm skip)  │
                                   │        │    ✓ extract_* (read-only queries)         │
                                   │        │    ✓ sha256_file(source) ────────────────>│ disk
                                   │        │    ✓ EvidenceItem + AuditLogger.log        │
                                   │        ├── progress(msg, fraction) via queue        │
                                   │        ▼                                            │
                                   │  ScanResult (artifacts+evidence+integrity)          │
  auto-export -------------------->│ exporters.export_all(BAE_Output\scan_<ID>, result)  │
   report files <──────────────────┼─────────────────────────────────────────────────────┤
```

**Threading model (GUI):** the scan runs on a worker `threading.Thread`; the UI
polls a `queue.Queue` every 120 ms via `root.after`. Only UI updates happen on the
main thread. The CLI runs synchronously with an inline progress printer.

**Key cache:** the DPAPI-unwrapped Chromium master key is cached per
`user_data` directory and lives only in memory for the process lifetime
(`core/engine.py:_key_cache`).

---

## 6. Locked-file acquisition ladder (`core/winio.copy_any`)

Windows-only ladder used by every DB open:

1. `copy_shared` — `CreateFileW` with `FILE_SHARE_READ|WRITE|DELETE`.
2. `copy_backup` — enables `SeBackupPrivilege`, opens with
   `FILE_FLAG_BACKUP_SEMANTICS` (bypasses ACL-denied reads).
3. `copy_plain` — stdlib read (works for non-locked files everywhere).
4. `copy_vss` — **elevation only**: WMI `Win32_ShadowCopy.Create('ClientAccessible')`,
   copy from the shadow device, self-delete the snapshot.
5. Any residual failure raises `EvidenceLocked` with an operator-actionable
   message; the engine records it as a category warning and continues.

**Verified behaviour on the dev host:** Chrome/Edge `Cookies` are open with a hard
exclusive lock (`ERROR_SHARING_VIOLATION = 32`) while the browser runs — the ladder
degrades gracefully and other categories complete.

---

## 7. Data model

```
ScanResult
├── scan_id            BAE-YYYYMMDDTHHMMSSZ-<8 hex>   (sec.integrity.new_scan_id)
├── host, platform, operator, case_ref, authorize_reference
├── browsers[]         BrowserProfile{ browser, profile, root, kind, available{} }
├── artifacts[][]      category -> list[dict]           (records carry _browser/_profile)
├── evidence[]         EvidenceItem{ category, source_path, source_sha256, record_count, collected_at }
├── errors[]
├── statistics         { profiles_scanned, categories_requested, total_records,
│                        elapsed_seconds, per_category{} }
└── integrity
    ├── manifest       { algorithm, item_count, manifest_sha256, items[], generated_at }
    ├── compliance     assessment() output incl. 20 controls
    ├── audit_chain_valid
    └── audit_entries
```

`ScanOptions` drives collection: `categories[]`, `profile_filter[]`,
`decrypt_secrets`, `extract_cache_urls`, `max_records_per_category`.

---

## 8. Report pipeline

`exporters.bundle(scan)` produces `(category, headers, rows)` tuples against the
`SCHEMAS` printer contract; every exporter consumes the identical stream, so all
formats stay in sync and carry the same header metadata.

| Format | File pattern | Notes |
|---|---|---|
| HTML | `report_<ts>.html` | escaped values, category palettes, evidence + compliance sections |
| CSV | `csv_<ts>/<category>.csv` + `all_artifacts_long.csv` | UTF-8 BOM (Excel), `QUOTE_ALL` |
| JSON | `report_<ts>.json` | full `ScanResult` fidelity |
| XML | `report_<ts>.xml` | SAX-escaped tags |
| XLSX | `report_<ts>.xlsx` | Summary + per-category sheets, autofilter, freeze |
| PDF | `report_<ts>.pdf` | landscape A4, page-per-category, capped at 800 rows/table |
| Markdown | `report_<ts>.md` | escaping of `\|` in cells |
| Manifest | `evidence_manifest_<ts>.json` | `scan.integrity` subtree |
| Audit | `audit_log.jsonl` | raw hash-chained records |

---

## 9. Packaging & deployment

```
python build_portable.py --clean
  -> dist/BrowserArtifactExtractor.exe      (GUI, windowed, one-file)
  -> dist/BrowserArtifactExtractor-CLI.exe  (console, one-file; for automation)
```

- `--onefile`, hidden imports for lazily-imported libs, `--collect-submodules` for
  `cryptography`, `openpyxl`, `reportlab`; heavyweight analysis-only packages excluded.
- `-CLI.exe` variant exists because a `--windowed` bootloader detaches stdout.
- Frozen detection: `ui/app.py:base_dir()` uses `sys.frozen` to anchor the
  `BAE_Output` folder next to the executable.

---

## 10. Supporting conventional decisions

| # | Decision | Rationale / invariant |
|---|---|---|
| 1 | Reports write into `BAE_Output/` next to the binary | portable, self-contained evidence folder |
| 2 | Every record carries `_browser`/`_profile` provenance | chain-of-custody in every row |
| 3 | All secrets pass through `decrypt.decrypt_value` returning `(value, status)` | status taxonomy: `ok/empty/no_key/v20_appbound/dpapi/error` |
| 4 | UI communication only via `queue.Queue` in worker threads | no Tk calls off the main thread |
| 5 | Text handling is `utf-8, errors="replace"` and `utf-8-sig` for CSV | browser data can contain arbitrary bytes |
| 6 | HTML/XML output is always escaped through templates | OWASP A03 injection prevention |
| 7 | `max_records`=0 means unlimited; PDF print tables cap at 800 rows | print pragmatics |