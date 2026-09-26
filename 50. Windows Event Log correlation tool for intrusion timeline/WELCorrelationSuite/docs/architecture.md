# Architecture

This document is a **reference-only, code-free projection** of the suite's internal structure,
data model and computation. It is written to stay useful across future refactors without needing
line-number accuracy.

---

## 1. Purpose & boundary

The suite is a **local-first, portable incident-response tool** whose job is:

1. ingest Windows Event Log data (live or forensic),
2. normalise and fingerprint every record,
3. run MITRE-mapped correlation rules and produce an intrusion timeline,
4. expose a hardened local browser UI, and
5. export tamper-evident, auditable executive reports.

The trust boundary is the machine it runs on: all state lives in RAM or a local directory,
and the web surface binds to `127.0.0.1` behind a single-use session token.

## 2. Topology (static view)

```
main.py
 │
 ├─ AppServer  (ThreadingHTTPServer, 127.0.0.1)
 │   ├─ Handler  (BaseHTTPRequestHandler)
 │   │   ├─ token gate → 403
 │   │   ├─ route: /api/*  →  self._api()
 │   │   └─ route: /*      →  self._static()  [whitelisted web dir]
 │   │
 │   ├─ Case  (in-memory workspace state)
 │   │   ├─ events[]           ← ingested/normalised records
 │   │   ├─ analysis{}         ← last correlate.analyse() result
 │   │   ├─ source_report{}    ← provenance metadata
 │   │   ├─ rules[]            ← loaded from rules_registry
 │   │   ├─ framework{}        ← compliance.tool_framework_compliance()
 │   │   └─ build_case_dict()  ← assembles dict for report generators
 │   │
 │   ├─ AuditTrail  (append-only JSONL + SHA-256 chain)
 │   │   ├─ .path     →  <work_dir>/audit/audit_trail.jsonl
 │   │   ├─ .entries() / .stats()
 │   │   ├─ .append()         ← immutable per-entry chaining
 │   │   └─ .verify()         ← replays hash chain
 │   │
 │   └─ report module  (HTML, CSV, JSON generators)
 │
 ├─ idle watchdog (thread, 30 min timeout → safe_shutdown)
 ├─ browser launcher (thread, 1.2 s delay)
 └─ os._exit(0) on clean shutdown in frozen mode
```

## 3. Data flow (dynamic view)

```
Live collection (wevtutil)
          │
          ▼
┌────────────────────────────┐
│ events.collect_live()      │  subprocess → XML → parse_wevtutil_xml()
│ events.import_evtx(path)   │  subprocess (wevtutil qe /lf:true) → XML
│ events.import_csv(fileobj) │  csv.DictReader → _row_to_event()  (alias mapper)
│ events.import_json(raw)    │  JSON list/bundle → normalised dict list
└───────────┬────────────────┘
            │  events[] (list of normalised event dicts)
            ▼
┌────────────────────────────┐
│ correlate.analyse()        │
│  ├─ _cluster()             │  time-window + rule/stage clustering → campaigns[]
│  ├─ _detect_spikes()       │  rolling-window burst detection → spikes[]
│  ├─ _mitre_matrix()        │  rule.mitre → {tactic: {technique: count}}
│  ├─ _mitigation()          │  mitigations from phase clusters
│  └─ _summary()             │  counts, risk composite, phase band
└───────────┬────────────────┘
            │  analysis{} (summary, incidents, phases, campaigns, mitre, spikes, risk)
            ▼
┌────────────────────────────┐
│ Case.build_case_dict()     │  merges events + analysis + coverage + audit
└───────────┬────────────────┘
            │  case dict
            ▼
┌────────────────────────────┐
│ report.html_report(case)   │  → bytes (full HTML with embedded CSS)
│ report.csv_events(case)    │  → bytes (UTF-8 BOM)
│ report.csv_timeline(case)  │  → bytes (UTF-8 BOM)
│ report.json_case(case)     │  → bytes (UTF-8, indented)
└───────────┬────────────────┘
            │  artefact bytes
            ▼
   SHA-256 sidecar + audit entry + HTTP Content-Disposition download
```

## 4. Normalised event schema

Every ingestion path produces a dict with these fields:

| Field | Type | Notes |
|---|---|---|
| `id` | uuid4 | Unique; never reused across runs |
| `ts` | str | ISO-8601 UTC (e.g. `2026-09-15T09:00:05Z`) |
| `ts_epoch` | float | Unix epoch seconds (for sorting) |
| `channel` | str | Lower-cased (`security`, `system`, `powershell`, ...) |
| `event_id` | int | Windows Event ID (e.g. 4624, 4688, 1102) |
| `provider` | str | Event source provider name |
| `computer` | str | Hostname |
| `level` | int/str | Event severity |
| `source_ip` | str | Normalised from field alias list |
| `target_user` | str | Primary subject |
| `subject_user` | str | Action initiator |
| `process` | str | Image / process path |
| `commandline` | str | Process command line |
| `data` | dict | All raw event fields (EID-specific) |
| `message` | str | Human-readable rendered message |
| `imported` | str | `"live"` / `"evtx"` / `"csv"` / `"json"` |
| `hash` | str | SHA-256 of canonical `{"system":...,"data":...}` or of `data` |

## 5. Rule schema (rules_registry.py)

Each rule dict has these keys:

| Key | Type | Purpose |
|---|---|---|
| `id` | str | Stable identifier (e.g. `R-001`) |
| `name` | str | Short label shown in incidents |
| `severity` | int | 1–100 (feeds risk composite) |
| `stage` | str | Kill-chain phase (one of the 9 phases) |
| `mitre` | dict | `{technique_id: description}` (e.g. `{"T1078": "Valid Accounts"}`) |
| `iso` | list | ISO 27001 Annex A control IDs this rule evidences |
| `nist` | list | NIST CSF 2.0 category IDs |
| `note` | str | Analyst-facing explanation |
| `matches` | list | One or more matcher dicts per event |

Matcher keys: `channel`, `event_id`, `opts` (dict of field → operator).

## 6. Match operator semantics (rules.match_op)

| Operator | Meaning |
|---|---|
| `""` or `None` | Field present and non-empty |
| `~substr` | `substr` contained (case-insensitive substring) |
| `!x` | NOT-equal (case-insensitive); `!` alone means field is empty |
| `>N` | Numeric strictly greater |
| `<N` | Numeric strictly less |
| (literal) | Exact match (case-insensitive) |

## 7. Nine-phase intrusion timeline

```
reconnaissance → execution → persistence → privilege_escalation →
credential_access → discovery → defense_evasion → lateral_movement → impact
```

Each incident carries `stage` from its rule. The phase band shows the ordered distinct
phases present in the analysis. Phases are coloured for the UI and the HTML report.

## 8. Risk scoring

`_summary()` computes a 0–100 composite from:
- normalised incident count,
- severity distribution (weighted),
- number of distinct phases hit,
- breadth of campaign clusters,
- surge (anomaly) intensity.

Rounded to one decimal. Thresholds: `>=85` critical, `>=65` high, `>=40` moderate, `>=20` low.

## 9. Module map

| Module | Responsibility |
|---|---|
| `main.py` | Portable entrypoint, `resource_path`, work-dir bootstrap, idle watchdog, browser launch |
| `server.py` | `AppServer` (HTTPServer), `Handler` (routing, API, static, security headers), `Case` |
| `events.py` | Ingestion (wevtutil subprocess), parsing (XML/CSV/JSON), normalisation, SHA-256 |
| `rules.py` | `Rule` class, `load_rules()`, `match_op()` |
| `rules_registry.py` | 40 rule dicts (R-001..R-040) |
| `correlate.py` | `analyse()`, clustering, spike detection, MITRE matrix, mitigation, risk |
| `compliance.py` | ISO 27001 / NIST CSF / OWASP mappings, `coverage_matrix`, `tool_framework_compliance` |
| `audit.py` | `AuditTrail`, append-only JSONL hash chain, `verify()` |
| `report.py` | `html_report()`, `csv_events()`, `csv_timeline()`, `json_case()` |
| `web/index.html` | Dashboard shell |
| `web/style.css` | Cyber theme (CSS custom properties) |
| `web/app.js` | Client SPA: tab routing, fetch wrappers, canvas charts, SVG gauge |

## 10. Threading model

- `AppServer` extends `ThreadingHTTPServer` — one daemon thread per HTTP request.
- Idle watchdog: single daemon thread, polls `server.last_request` every 30 s.
- Browser launcher: single daemon thread, fires once at startup after 1.2 s delay.
- No shared mutable state beyond `Case` object (single-user design; concurrent API calls are
  serialised by Python's GIL on the `events[]` write paths).
- Shutdown: `/api/shutdown` or idle timeout calls `server.safe_shutdown()` → `server.shutdown()`,
  which makes `serve_forever()` return in the handler's thread, triggering `server_close()` and
  `os._exit(0)` in frozen mode.

## 11. Storage layout

```
# Source mode
WELCorrelationSuite/
  workspace/
    audit/audit_trail.jsonl    ← audit trail
    tmp/                       ← transient temp files
    *.html.sha256              ← report sidecars (after first download)

# Frozen exe (next to .exe)
welics_case_data/
    audit/audit_trail.jsonl
    tmp/
    *.sha256
    _startup.log               ← on error only (windowed: no console)
```

## 12. API surface (REST)

| Method | Path | Purpose | Body |
|---|---|---|---|
| GET | `/api/status` | Case state + uptime + rule count | — |
| POST | `/api/collect` | Live wevtutil collection | `{"max_per_channel": 300}` |
| POST | `/api/import` | Import file (multipart or raw JSON) | Multipart `file` field, or JSON body |
| POST | `/api/analyze` | Run correlation engine | `{}` |
| GET | `/api/events` | Paginated event list | Query: `start`, `limit` |
| GET | `/api/audit` | Audit trail + stats | — |
| GET | `/api/framework` | Compliance coverage + hardening checklist | — |
| GET | `/api/report?type=...` | Download report (`html`/`csv`/`timeline.csv`/`json`) | — |
| POST | `/api/case/reset` | Clear current case state | — |
| POST | `/api/shutdown` | Graceful server exit | `{}` |

All paths require the session token prefix (`/tk-<token>/...`).

## 13. Extension points

- **Add a rule:** append to `rules_registry.py` (follow the dict schema; tag `iso`/`nist`/`mitre`).
- **Add a match operator:** extend `match_op()` in `rules.py`.
- **Add a channel:** append to `DEFAULT_CHANNELS` in `events.py`.
- **Add a report type:** implement in `report.py`, add a route in `Handler._download_report()`
  and a download button in `app.js`.
- **Add a CSV alias:** extend `_CSV_ALIAS` in `events.py`.
- **Add an API endpoint:** add a route in `Handler._api()`, implement a `_api_*()` method.

## 14. Build & packaging

- `build.ps1` runs PyInstaller: `--onefile --windowed`, `--add-data "app/web;web"`.
- The frozen app uses `resource_path()` for web assets (resolved from `sys._MEIPASS/web/`).
- `main.py` uses a `__package__ is None` guard so the same entry works both as
  `python app/main.py` (relative import) and as a frozen top-level script (absolute import).
- `os._exit(0)` is called at exit in frozen mode to guarantee clean process teardown.
- Optional env vars: `WELICS_PORT` (int), `WELICS_TOKEN` (32-char hex) for automation.