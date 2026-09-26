# Project 16 — State

## 1. Component Status

| Component | Status | Notes |
|-----------|--------|-------|
| `normalize.py` (classify, normalize, promote_ok, is_internal) | ✅ Implemented | version-guard fixed, TLP guard, internal-ranges |
| `ingest.py` (fixture json, csv, honeypot event) | ✅ Implemented | honeypot webhook payload accepted |
| `decision.py` (Blocklist tiers, lifecycle, audit) | ✅ Implemented | critical/high/median/suspected + rollback plan |
| `consumers.py` (JsonDiff, PfSense-style) | ✅ Implemented | idempotent diff-only sync + rollback |
| `main.py` | ✅ Implemented | `--self-test`, `--ingest-fixture`, `--config`, `--state` |
| External adapters (MISP API, OTX, TAXII 2.x, RSS) | 🔲 Not started | architecture.md §2.1 — local csv/fixture path works |
| Foriegn feeds health monitor | 🔲 Planned | separate worker desired |
| Approve/rollback API + dashboard | 🔲 Not started | architecture.md §4 |
| DNS sinkhole (Pi-hole) driver | 🔲 Planned | consumer add-on |
| WAF (modsec) driver | 🔲 Planned | consumer add-on |

## 2. Verified Behavior (SMOKE TEST dated 2026-09-13)

`py main.py --self-test` → **PASS**:
- classification (ipv4/cidr/domain/file_hash)
- internal guard: `10.0.0.1` conf 0.99 → promote_ok False (never blocklist)
- TLP amber → promote_ok False
- public IP high conf → promote_ok True
- honeypot event payload → applies tier active

`py main.py --config config/feeds.json --state data --ingest-fixture fixtures/honeypot_ioc.json`:
- 4 IOCs ingested → 3 active (high), 1 suspected (`10.0.0.1`, correct)
- consumer push=3 remove=0; `data/blocklist.json` contains exactly 3 entries (no internal IP)
- `data/blocklist_audit.jsonl` logs each decision + reason

Regression verified: IPv4↔IPv6 `.subnet_of` crash fixed by version guard (would crash mixed feeds).

## 3. Known Gaps & Risks

| Gap | Risk | Priority |
|-----|------|----------|
| Only local fixture/csv ingest | No live MISP/OTX/TAXII | High (adapter workstream) |
| No DNS/WAF driver | Blocklist doesn't reach DNS sinkhole yet | Medium |
| Feed health monitor absent | Degraded feed invisible until blocked | Low |
| Single-host in-memory state | No HA / shared state | Low (scale decision later) |
| GUI is local-only desktop | No team-wide dashboard/approval | Low (API workstream) |

Priorities: (1) MISP/OTX adapters, (2) approve-queue CLI + API, (3) Pi-hole DNS driver, (4) feed health monitor.

## 4. Definition of Done — current milestone (GUI, 2026-09-16)

**Done:**
- [x] GUI dashboard `gui.py` (tkinter, stdlib only) — tabs: Blocklist / Ingest / Feed Config / Consumer / Audit / Log
- [x] `aggregator/api.py` shared pipeline (CLI + GUI one code path; `feed_settings`, `run_pipeline`, `approve_record`, `drop_record`, `sync_consumer`)
- [x] Per-feed config honored (was silently dropped — memory.md §6 A)
- [x] Lifecycle 75%-TTL `active→expiring`, then `retired` (memory.md §6 B)
- [x] Idempotent apply — no JSONL churn, sources merged → multi-feed `critical` (memory.md §6 C/D)
- [x] Approve (quarantine→active) + Drop/rollback (→retired) in GUI + API — resolves gap #2

**Next milestone (upstream adapters):**
- [ ] MISP `events` pull adapter (read-only API) + OTX pulse adapter with rate-limit
- [ ] Pi-hole-style DNS sinkhole driver outputting `/etc/pihole/custom.list`
- [ ] Feed health: `GET metrics` endpoint (alerts per feed, quarantine queue depth)