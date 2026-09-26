# Project 16 — Memory (Development Journal)

## 1. Architecture Decisions

| Decision | Rationale |
|----------|-----------|
| Two-headed store (research IOC store + consumer blocklist) | Enforcement conservative; research complete (architecture.md §7) |
| Tier → auto or quarantine gate | Human-in-loop for median prevents self-DoS |
| Idempotent diff-only consumer drivers | Never full-table replace; convergence via repeated sync |
| **internal intel (honeypot/SIEM) outranks 3rd-party** | Your own detection knows your environment better |
| Rollback as first-class audited process | Reversibility is a compliance and IT-ops requirement |

## 2. Gotchas (hard-won, 2026-09-13)

0. **`Blocklist` records load as objects, apply() saw them as dicts** — `existing.get("sources")` crashed on a `BlocklistRecord` (`AttributeError`). Rule: in `apply()`, handle BOTH shapes (`isinstance(existing, dict)` check) — a record already added in a previous run is a `BlocklistRecord`, a brand-new key is `{}`. Re-verify with a SECOND run after the first (idempotent path) — the first run never touches the object path.
1. **`ipaddress.subnet_of` crashes on mixed IPv4/IPv6 versions** — `203.0.113.9/32 .subnet_of(::1/128)` raises TypeError. MUST guard `p.version != net.version → continue`. This bit immediately on a mixed private-networks list.
2. **`ip_network` normalizes host bits** — `203.0.113.9` becomes `203.0.113.9/32` when parsed; store normalized values (`normalize_ioc`) or consumer lists show `/32` suffixes everywhere. Keep consistent: normalize at ingest, compare on normalized form.
3. **TLP discipline**: amber/red must gate promotion BEFORE confidence math; a conf-0.99 amber IOC must NOT block. `promote_ok` enforces after tiering (belt & suspenders — also check earlier to avoid wasted work).
4. **Honeypot event contract**: Project 15 pushes `{source:"honeypot", ioc_type, value, confidence, tags}`. Don't rename fields — both repos import this shape.
5. **consumer state file**: `JsonDiffConsumer` persists last-synced set in `<dest>.state`; a corrupt state file silently becomes empty set → re-adding everything. Guard with try/except on read (restores empty, docs says "re-add acceptable" — diff is idempotent).

## 3. Conventions

- IOC types canonical: `ipv4 | ipv6 | cidr | domain | url | file_hash`.
- Dedupe key: `f"{ioc_type}:{normalized}"`; URL normalizes to host (so `https://x/a` and `http://x/b` dedupe to same domain — INTENTIONAL; document in UI).
- TLP: `white < green < amber < red`, only white/green auto-block.
- Audit/state files: `blocklist.jsonl` (records), `blocklist_audit.jsonl` (actions), `<dest>.state` (consumer last-sync).
- All consumer syncs are diff-based on normalized values only.

## 4. Cross-Project Hooks

- **Project 15** honeypot critical IOC → this aggregator (webhook path in EventExporter/WebhookPusher).
- **Project 11** alert index → internal source (planned `siem_hook` ingest).
- **Project 14** firewall rule audit findings → can feed `blocklist` overrides later (never block own infra; curated exceptions).
- **Project 13** phase-final alerts → potential critical IOC source (IPs).

## 5. Warning for Future Developers

- NEVER let a feed's `confidence: 1.0` + TLP white auto-block an internal IP. `is_internal` runs in `promote_ok` for active tier — keep it valid on the whole promotion path, not just ingest.
- Don't remove the version guard "because it's obvious" — it isn't; v4/v6 mixed feeds are the norm in 2026.
- Blocklist UI must surface `rollback_plan` and `sources` (provenance) on every record — a block without provenance is an ops bomb.
- Deployment: blocklist `data/` must be write-limited (service user); never run as root.

## 6. Bug-Fix Log (GUI milestone, 2026-09-16)

The CLI pipeline *ran* but made the wrong calls — "working" and "correct" were not the
same thing. Root causes, each reproduced before fixing:

| # | Symptom seen | Root cause | Fix |
|---|--------------|-----------|-----|
| A | Honeypot conf-0.5 IOC landed `median/quarantined` instead of auto-blocking | `main.run()` did `config.get("auto_confidence")` → returned the **float** 0.7, then the `isinstance(cfg, dict)` guard dropped it to `{}` — per-feed settings were never read | `feed_settings(config, feed_id)` in `aggregator/api.py` merges per-feed overrides over global defaults; `run_pipeline` applies it |
| B | Every record flipped `active→expiring` on the first lifecycle pass (a 2099 expiry was "expiring") | `evaluate_lifecycle` promoted unconditionally; the 75%-TTL check was a comment, not code | `_past_ttl_75()` compares `(now-added)/(expires-added)`; only then `expiring`; `expired` → `retired` |
| C | `blocklist.jsonl` grew every run (11 duplicate lines for one key) and provenance was lost | `apply()` re-persisted identical records and replaced `sources` with the newest feed only | idempotent `_changed()` guard (no write if identical), `added_at` preserved, sources **merged** `[otx,misp]` → cross-feed agreement upgrades to `critical` |
| D | CLI exit code 1 on success when run without a tty | `_pause_on_windows()` `input()` raised `EOFError` | wrapped in try/except EOFError |
| E | Approval queue had no UI (state.md gap #2) | no `approve`/`drop` path | `Blocklist.approve()/drop()` + GUI buttons |

New entrypoint: `py gui.py` (or `run_gui.bat`) — tkinter dashboard with Blocklist
(review/approve/drop), Ingest (manual IOC, JSON/CSV fixture, Project-15 honeypot event
pastable), Feed Config (per-feed thresholds now honored), Consumer (json/pf diff-sync),
Audit, and Log tabs. All operations run through `aggregator/api.py` so CLI and GUI share
one code path; long tasks run on a background thread, UI polls a result queue.