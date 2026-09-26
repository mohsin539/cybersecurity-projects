# 🧠 PEM-CAT Long-Term Memory — Reservation File

> **Reservation purpose:** the *durable* memory of the **Persistence Mechanism Catalog & Matching
> Detection Engine** project — vocabulary, design decisions, data model, conventions and gotchas.
> Load this file first in any new session; pair with `state.md` (current state) and
> `security.md` (security posture) for full context. This is **the project memory** for the
> machine (AI) and for future maintainers.

**Project root:**
`D:\AI Masterclass\Project\18-09-2026\41. Persistence mechanism catalog + matching detection rules (registry, cron, services)\`
Core deliverables live under `app\`.

---

## 1. Identity & Purpose

**PEM-CAT** = *Persistence Mechanism Catalog*. A portable desktop security utility that:

1. **Enumerates** persistence points on the host it runs on (registry autostart, services,
   scheduled tasks/cron, startup folders, WMI subscriptions).
2. **Normalizes + fingerprints** every artifact into a canonical record (`fingerprint_sha256` of
   sorted normalized fields → dedupe + change detection).
3. **Matches** artifacts against a declarative **detection rule engine** (baseline-aware, scoring +
   confidence, MITRE ATT&CK-tagged).
4. **Reports** in **.xlsx**, **.csv**, **.html** with audit trail; security posture mapped to
   OWASP Top 10 / NIST CSF & SP 800-53 (800-171 overlay) / ISO 27001 Annex A.

V1 scope = local single-host, single-actor, GUI + headless CLI. **No network listeners, no
remediation** (detection only, human-in-the-loop).

---

## 2. Vocabulary (speak consistently)

| Term | Meaning |
|------|---------|
| artifact (PersistenceRecord) | canonical catalog entry; a dict with `artifact_type`, `mechanism`, `image_path`, `command_line`, `payload`, fingerprint, seen counts |
| artifact_type | enum: `registry`, `service`, `scheduled_task`, `cron`, `startup`, `wmi`, `os_internal` |
| mechanism | human-readable descriptor, e.g. `service:AarSvc (...)` or `HKCU\Software\...\Run\Updater` |
| fingerprint_sha256 | deterministic hash over normalized whitespace/lowercased fields (excludes host/timestamps) |
| baselined | `is_baselined=1`; artifact seen ≥ `BASELINE_SEEN_THRESHOLD`(3) scans AND not matched — trusted |
| allowlist | explicit trusted fingerprint (`allowlist` table) — bypasses ALL rules |
| match / alert | row in `matches`; `status ∈ open/a/cked`→`acked`, `fp`; dedup key = (fingerprint, rule_id) while status is `open`/`acked` |
| new_only | rule flag: only fires on non-baselined artifacts (baseline-deviation detection) |
| rule DSL | declarative rule dict: `artifact_type`, `mechanism_contains`, `image_path_contains`, `payload_contains`, `command_line_regex`, `impersonation{names,writable}`, `new_only` |
| confidence | `min(0.4 + 0.2*len(reasons), 1.0)`; score = `SEVERITY_BASE[sev] * confidence` |
| severity base | critical 100 / high 70 / medium 45 / low 20 |

---

## 3. Architecture In One Breath

```
collect (winreg + sc/schtasks + powershell-WMI + fs) 
  → catalog.Storage (SQLite: artifacts, matches, rules, allowlist, audit)
  → rules.run_matching (evaluate_rule per artifact × active rules)
  → report (openpyxl .xlsx · csv bundle · escaped .html)
  → ui (Tkinter, 6 tabs) — worker queue: threading.Thread → queue.Queue → after(200) poller
```

- **SQLite schema** (5 tables) — see `catalog.py::_init_schema`. Never rename columns without
  updating both `list_*` mappers and `report._write_sheet` column lists.
- **SQLite locations** (priority): env `PEMCAT_DATA_DIR` → `--data-dir` → `default_data_dir()`
  (`%LOCALAPPDATA%\PEMCAT` on Windows, `~/.pemcat` on POSIX, falls back to `./data` if unwritable).
- **Purpose of seeds:** `Storage.seed_rules(BUILTIN_RULES)` UPSERTs built-in rules on every boot so
  rule edits in `rules.py` propagate to existing DBs; custom user rules (`owner='user'`) persist.

---

## 4. Key Coding Conventions (MUST follow)

1. **No shell interpolation in subprocess**: always pass list args to `_run`; `CREATE_NO_WINDOW`
   flag on Windows; PowerShell scripts are *constant strings* (fixed, no artifact data embedded).
2. **HTML output always escaped**: any new dynamic value in `report_html` must use `html.escape`.
   Do NOT add `<script>` — the HTML report is static + CSS only.
3. **SQL is parameterized everywhere** — no f-string SQL with user input.
   Rules storing `logic_json` are parsed **not evaluated**.
4. **GUI threads**: long operations run in `threading.Thread`, results via `self.worker_queue.put(...)`;
   the UI thread only reads via `_poll_worker` → `_on_worker_event` → `refresh_all`.
5. **Windows-only guards**: all `winreg`/`schtasks`/PowerShell logic is behind `if os.name != "nt":
   return …`; POSIX cron enumerator exists and is inert on Windows.
6. **No comments in code unless explicitly requested** (team rule); self-document via names and the
   reservation docs.
7. `report_xlsx` uses lowercase sheet/column sets; `report_csv` writes `utf-8-sig` (Excel-friendly).

---

## 5. Module Map & Responsibilities

| Module | Owns | Watch out for |
|--------|------|---------------|
| `catalog.Storage` | schema, upsert/dedup, baseline refresh, allowlist, matches lifecycle, rules CRUD, audit | `list_matches` LEFT JOIN maps 15 columns by index — changing the SELECT breaks everything downstream |
| `collect` | enumerators + `host_id()` | WMI uses `CimSystemProperties.ClassName` (not `__RELPATH`); `schtasks` keys are locale-dependent |
| `rules` | `BUILTIN_RULES` seed, `evaluate_rule`, `run_matching`, `summarize` | `run_matching` returns **only newly-inserted** matches (dedup); empty on second run by design |
| `report` | exporters + `build_report_data` (+ `COMPLIANCE_MAP`) | keep `SEVERITY_COLORS`, `KPI_FILLS`, `_HTML_TEMPLATE` placeholders aligned |
| `ui` | all widgets + worker wiring | any widget that renders dynamic text — keep ids as string `iid` (evt ids, rule ids, fingerprint) |
| `audit` | event constants (`EVENT_SCAN_*`, `EVENT_REPORT_*`) | `log(storage, ...)` helper |
| `main` | arg parsing, headless runner, `PEMCAT_DATA_DIR` resolution | headless prints to file when `sys.stdout is None` (windowed exe) |

---

## 6. Gotchas & Lessons (hard-won this session)

1. **PyInstaller windowed exe has `sys.stdout=None`** → `run_headless` writes a log file then;
   `main()` error handler writes `pemcat_gui_error.log`.
2. **CIM `__RELPATH` is NOT selectable via `Select-Object`** on `Get-CimInstance` results —
   `Select-Object __RELPATH` returns `None`. Use `$_.CimSystemProperties.ClassName` and/or the
   `name` column. This cost a debugging cycle; do not regress the WMI collector.
3. **`FilterToConsumerBinding`'s `filter`/`consumer`** serialize as full embedded CIM objects,
   not relpaths (even with computed props) — the consumers-only approach in `enumerate_wmi` avoids
   this entirely.
4. **`schtasks /fo LIST /v` output** must be split into blocks by non-indented `Key: value` lines;
   `_parse_list_blocks` implements that and is locale-sensitive; test on any non-English host.
5. **T1036 impersonation FP bomb**: an earlier rule matched any `svchost` service. Lesson: rules
   report a match ONLY if *reasons* were gathered. Impersonation requires BOTH a spoofed name AND a
   writable directory (`impersonation` logic block) — verified count dropped 265→0 on this host.
6. **Rule UPSERT** (`ON CONFLICT DO UPDATE`) is what makes edited built-in rule logic actually
   apply to existing databases. If someone re-uses `INSERT OR IGNORE`, stale logic lingers.
7. **Dedup must live in the store**, not the engine, otherwise repeat scans flood the `matches`
   table — `add_match` early-returns `None` on existing `open`/`acked` pair.
8. **Report HTML is 100 % escape-disciplined**; XSS check in test = assert no `<script` in output.
9. **Do not write via `Write` tool without JSON-escaping `\`** — code strings like `r"CurrentVersion\Run"`
   must be escaped as `\\` in the tool payload; past hiccups here truncated file writes mid-stream.

---

## 7. Reference Data Points

- **Built-in rules (9):** PEM-CAT-0001 registry autostart writable-location (T1547.001,
  `new_only`) · 0002 service from writable dir (T1543.003) · 0003 cron writable dir (T1053.003)
  · 0004 scheduled task elevated-from-temp (T1053.005) · 0005 WMI command-line consumer (T1546.001,
  critical) · 0006 startup payload in AppData (T1547.001) · 0007 AppInit/IFEO/Winlogon (T1546.002)
  · 0008 encoded PowerShell (T1059.001) · 0009 impersonation requires name+dir (T1036.005).
- **Rule DSL keys:** `artifact_type, mechanism_contains, image_path_contains, payload_contains
  (list of [key, needle]), command_line_regex, impersonation{names,writable}, new_only`.
- **Regression beacon (host MOHSINIT-PC):** fresh scan = 910 artifacts, 56 matches
  (high 55 / medium 1); techniques T1053.005:7 T1547.001:18 T1546.002:30 T1543.003:1.

---

## 8. Compliance Constants

| Framework | Controls exercised in v1 |
|-----------|--------------------------|
| OWASP Top 10 2021 | A01 access control (actor/audit), A03 injection (param SQL, no eval, escaped HTML), A08 integrity (fingerprints, rule UPSERT), A09 logging (audit ledger) |
| NIST CSF 2.0 / 800-53 R5 | ID.AM-06 inventory, PR.DS-01 data protection, DE.CM-07 monitoring, DE.AE anomaly detection, IR-4 status workflow; 800-171 overlay for CUI deployments |
| ISO 27001:2022 | 6.8 event reporting, 7.9/7.10 data/malware protection, 8.15 security controls access + 8.28 secure coding |

Full mapping lives in `security.md §3–4` — keep it in lock-step whenever the app surface changes.

---

*Memory reserved at PEM-CAT v1.0.0. Refresh this file on every milestone that changes the data
model, rule DSL, trust boundaries, or build procedure.*