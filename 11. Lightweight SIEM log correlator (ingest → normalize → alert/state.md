# Project 11 — State

Snapshots what exists today, what runs, what is stubbed, and the roadmap. Merge this file at every milestone (suggested: weekly).

## 1. Component Status

| Component | Status | Notes |
|-----------|--------|-------|
| `model.py` (CES Event/Alert, validation) | ✅ Implemented | `validate_event` enforces canonical fields |
| `ingest.py` (FileTailer, OffsetTracker, Quarantine) | ✅ Implemented | Poll-based tailing, at-least-once offsets |
| `ingest.py` SyslogLive listener | 🕐 Stub | Socket class designed but not wired to CLI |
| `normalize.py` (json / auth_syslog / apache) | ✅ Implemented | 3 parsers registered |
| `normalize.py` enrichers (GeoIP, asset, CVE) | 🕐 Not started | Placeholder in architecture; no enrichment module |
| `correlate.py` (threshold rules, window) | ✅ Implemented | Single-event rules NOT yet implemented |
| `alerting.py` (Router, Console, Jsonl, Webhook) | ✅ Implemented | Webhook HTTPS+token ready |
| `store.py` (EventStore day-partition, AlertIndex) | ✅ Implemented | JSONL append-only |
| `main.py` CLI | ✅ Implemented | `--ingest-dir/--rules/--out/--run-once` |
| Web dashboard / REST API | 🔲 Not started | Architecture only |

## 2. Verified Behavior (SMOKE TEST dated 2026-09-13)

Command:
```
py main.py --ingest-dir samples --rules rules --out data --run-once
```
Result: 12 raw → 12 normalized, 0 quarantined, alerts fired:
- `BRUTE_FORCE_SSH` (high) — 4 auth failures +1 success from 203.0.113.5
- `AUTH_SUCCESS_AFTER_FAIL` (high) — fired twice (203.0.113.5 and 10.0.0.51 — the second is a **known false positive**, see Risks)
- Alert summary + duration printed; `data/alerts_index.jsonl` written.

Regression note: first run produced **0 alerts** (syslog parser outer regex consumed the host). Fixed in `normalize.py` — see `memory.md` §2. Golden fixture added under `samples/`.

## 3. Known Gaps & Risks

| Risk | Impact | Remediation |
|------|--------|-------------|
| `AUTH_SUCCESS_AFTER_FAIL` false positive on benign internal dev logins | Noise / analyst fatigue | Add asset allow-list enrichment before rule match; require dest_port==22 in sample |
| No single-event rules yet | Evasion of threshold logic | Implement `single` rule type next |
| Window state in-memory only (no snapshot now) | Correlator restart loses windows | Persist WindowCounter snapshot per architecture §2.3 |
| Enrichment missing (GeoIP/CVE/asset) | Weak context on alerts | Add `enrich` step with cached lookups |
| Live syslog UDP not wired | No real-time ingest | Enable `socket_ingest` flag in main.py |

Priorities: (1) snapshot window state, (2) single-event rule type, (3) enrichment, (4) live syslog.

## 4. Metrics & Observability

- [x] raw / normalized / quarantined counters printed per run
- [x] alerts summary + incident_id in alert writer
- [ ] pipeline metric endpoint (planned: per-stage EPS, queue depth)
- [ ] structured JSONL access log for the operator/journal

## 5. Open Questions / Decisions Pending

1. Storage backend: keep JSONL partitions or move to ClickHouse/Parquet at scale?
2. Should quarantine entries be searchable from the future dashboard (fail-open policy)?
3. Default dedupe window (now 60s) — tune per severity?

## 6. Definition of Done for Next Milestone

- [ ] Window-counter crash persistence
- [ ] Single-event rule type + goldens
- [ ] Dockerfile + health endpoint
- [ ] Live syslog ingestion smoke test