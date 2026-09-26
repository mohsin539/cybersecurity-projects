# Memory: Persistent Engineering Knowledge — ACSV

**Document ID:** ACSV-MEM-001
**Version:** 1.0
**Classification:** Internal
**Date:** 2026-09-22

---

## 1. Purpose

Persistent knowledge for future work sessions: decisions, gotchas, conventions,
workflows, and the "why" behind non-obvious code. Read this before starting a
new task on this codebase. Supersedes relying on recall alone.

---

## 2. Hard-Won Gotchas (read these first)

### 2.1 fpdf2 horizontal space errors
`multi_cell(w=0)` breaks: after an early multi-line cell, `pdf.x` sits at the
right margin and the next `multi_cell` throws "Not enough horizontal space".
**Always use `pdf.epw` and `new_x="LMARGIN"` explicit.** See
`acsv/report/exports.py::_write_para` — never change it back to `w=0`.

### 2.2 DPAPI ctypes on x64
`LocalFree` MUST be declared `argtypes=[wintypes.HLOCAL], restype=wintypes.HLOCAL`
before use, else return-value truncation misses allocations and can corrupt the
heap / drop the final pointer on 64-bit. See `acsv/crypto.py::DPAPIStore`.
Entropy is `b"ACSV-v1"`; flag `0x00` = current-user binding (not machine-wide).

### 2.3 Redaction must keep JSON valid
Secret patterns were toggled through several designs. Final working form:
- The value group is one of `("..." )`, `'...'`, or an unquoted `\S+` token:

```
(?i)(?P<key>(authorization|password|passwd|pwd|secret|token|bearer|api[_-]?key))
["\']?\s*[:=]\s*(?P<val>(?:"[^"]*")|(?:'[^']*')|\S+)
```

- Replacement rebuilds `prefix + lead_quote + "[REDACTED]" + lead_quote`
  (lead is `"` or `'` when the value was quoted) so the enclosing JSON string
  stays well-formed — no leftover fragments like `Bearer` cut mid-value.
- Greedy alternative groups, NOT lazy `[^"]+?`: lazy matched one char and cut
  values (e.g. `"B` from `"Bearer 123456"`), breaking JSON and triggering a
  per-node fallback that then failed to redact.
- Keep patterns quote-aware; the bare `(Authorization)[:\s]+\S+` form does NOT
  match inside JSON because the char after the key is a quote, not a colon.

### 2.4 report SHA-256 vs whole-file hash
`reports` default layout wraps the document in `_meta` (+ `report_sha256`
top-level). The **file's byte hash** differs from the embedded `report_sha256`
(which is the hash of the canonical inner document). Verification must use
`IntegrityService.sha256_hex(raw_bytes)` for the file and compute the inner
canonical separately. The test asserts both. See `tests/test_report.py`.

### 2.5 canonical_bytes must round-trip through JSON
`json.dumps` natively converts int dict-keys and tuples, so in-memory data
(tuples in `top_apis`, int keys in `threads`) hashed differently from the same
data read back from a file (lists, str keys). `canonical_bytes` now does
`json.loads(json.dumps(obj, sort_keys=True, separators=(",",":"), default=str))`
then re-serializes. Do not "simplify" this back to a single dumps call.

### 2.6 coverage_matrix shape
Clients must consume `{framework: {"rows": [...], "summary": {...}}}`, never the
raw row list. Consumers: `ui/compliance_console.py` and the HTML/PDF exporters.
A coverage *summary* aggregates counts for the dashboard.

### 2.7 store row integrity
- `AuditStore` sets `conn.row_factory = sqlite3.Row` BEFORE any reads.
- `sessions` requires a `status` column filled at insert (`"running"`).
- Event `seq` is per-session and monotonic; KV table tracks `{sid}:last_seq` and
  `{sid}:set_hash` for event-set integrity.

### 2.8 Session lifecycle / generator
`CaptureRunner.create_session(sample_id)` returns a dict with
`session_id`, `sample_id`, `started_ns`, `status`, `policy_hash`, `name`.
`run_trace(sid, events)` requires `seq`/`ts_ns`/`tid`/`category`/`api` fields and
audits `CAPTURE_END`.

---

## 3. Conventions

- No code comments unless asked; docstrings describe *why*, not *what*.
- Internal packages import via absolute package path (`acsv.*`); never `sys.path`
  hacks in app code. When running tools from repo root, set
  `$env:PYTHONPATH="<repo>"` first (PowerShell).
- Data-dir policy: portable if `./data` exists → `./data`; else
  `%LOCALAPPDATA%\ACSV`; `ACSV_DATA` env overrides. GUI smoke tests must run
  from a temp dir with `data/` to avoid polluting the analyst store.
- Policy fail-closed: load → validate (deep merge with defaults) → audit
  `POLICY_LOAD`/`POLICY_CHANGE`. Unknown TOML keys → warning, defaults win.
- Audit is **append-only**; tampered tail aborts (`RuntimeError`) instead of
  silently truncating.
- All exports must record `REPORT_DOWNLOAD`/`REPORT_CREATE` audit events.
- Version single-sourced in `acsv/version.py`.

---

## 4. Verification Workflows

```powershell
# 1) tests (gate for everything)
python -m pytest tests -q

# 2) headless end-to-end
python -m acsv demo --events 600 --out data        # build demo session + trace
python -m acsv report --session <sid> --fmt pdf --out data\reports
python -m acsv audit-verify

# 3) GUI (from repo root, writeable data/):        python -m acsv
```

Known clean exit paths: CLI commands return exit codes; GUI closes via window
close. On headless/CI there is no X — GUI tests are manual smoke only.

---

## 5. Current Build Pipeline

- `build.ps1`: runs pytest gate → PyInstaller
  `--onefile --windowed --name ACSV --icon data/icon.ico` .
- **Entry point is `launcher.py` (repo root), NOT `acsv/app.py`.** The package
  uses relative imports; freezing `acsv/app.py` directly makes PyInstaller run
  it as a top-level script and die with
  `ImportError: attempted relative import with no known parent package`
  (bootloader shows "Unhandled exception in script"). Keep the top-level
  launcher stable. It also wraps `main()` to write `crash.log` next to the data
  dir and show a dialog instead of a silent bootloader failure.
- **Missing `data/icon.ico`** — historical blocker; icon now ships (PIL-generated).
- Install deps: `pip install -r requirements.txt`
  (PySide6>=6.7,<7 · fpdf2>=2.7 · pyinstaller>=6.6 · pytest>=8.0).
- Debug recipe: build a console `--console` variant and run it; windowed exe
  suppresses all stderr so "Unhandled exception" gives no stack.

---

## 6. Design Memory (why it's shaped this way)

- **Architecture doc (`architecture.md`)** allows Tauri/Rust OR Python+PySide6.
  Rust/cargo is unavailable on this machine → **PySide6** (see `state.md`).
  Revisit Tauri if the requirement shifts to a ~5–10 MB exe with a webview UI.
- **v1.0 never executes the sample.** Everything is offline replay of synthetic
  or imported traces; capture engine (ETW/hooks/sandbox) is a v1.1 native
  sidecar. The event schema (`parent_seq`, timestamp) already anticipates it.
- **Deliberate dual-capture**: analysis pipeline reads from the same SQLite
  store the GUI reads; a separate `audit.db` keeps integrity independent of
  analyst data (ISO A.8.15 separation of logging).
- **STIX 2.1 export** exists to satisfy ISO A.5.7 (threat intel) and OWASP A06
  evidence sharing; SARIF is optional later.

---

## 7. Open Questions / Reserved Work

- Icon asset for the exe.
- SQLCipher vs DPAPI-only for DB at rest (NIST SC-28) — decision deferred.
- Event schema versioning & JSON Schema files under `schemas/` (currently
  code-embedded, files awaiting content).
- Report templates under `templates/` (currently code-embedded in exporters).
- RBAC identities & roles audit attributes (research seam already present).

*End of memory document.*