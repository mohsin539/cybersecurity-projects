# Project 11 — Memory (Development Journal)

Working memory for future developers: decisions, traps, conventions, and lessons.

## 1. Architecture Decisions (why we went this way)

| Decision | Rationale | Re-evaluate when |
|----------|-----------|------------------|
| Stateless normalize, stateful correlate | Correlation windows are the only shared state; normalizers parallelize | Multi-node scale-out |
| Declarative JSON rules (no code) | Analysts write rules without deploys; safe: filters map to fixed CES fields only | Rules need function calls |
| At-least-once + dedupe by `(source,seq)` | Simple correctness; offsets persisted per-file | Exactly-once semantics required |
| Fail-open normalization → quarantine file | Losing evidence is worse than a wrong event | Quarantine grows unbounded |
| JSONL partitions hot/warm/cold | Trivial retention; no schema migration burden | >10k EPS sustained |

## 2. Lesson: syslog parser must capture the whole message

Bug (fixed 2026-09-13): the outer regex
`^(?P<ts>\S+ \S+|\S+)\s+(?:(?P<host>\S+)\s+)?(?P<msg>.*)$`
greedily took `"2026-09-13T08:11:01Z sshd"` as ts, then treated `"Failed"` as the *host*, leaving `msg="password for …"` — the inner `Failed password` search always missed and every event normalized to empty fields.

Fix: take first whitespace token as ts, everything after as `msg`. **Rule:** in log parsers, prefer "first token = timestamp, rest = message" and don't try to guess a host field unless the format is strictly RFC 3164 with a host position.

## 3. Conventions

- Events: ISO-8601 UTC (`utcnow()`). Never local time.
- Severity ladder: `info < low < medium < high < critical` (SEE `SEVERITY_ORDER`).
- Categories/regexes normalized `lowercase underscore`.
- Parsers registered via `@register("name")` — new source = new module + decorator, no core edits.
- Output dirs: `--out/events/<YYYY-MM-DD>/events.jsonl`, `--out/alerts_index.jsonl`, `--out/quarantine/quarantine.jsonl`.
- Keys framework: `inc-<rule>-<epoch>` incident ids must stay unique per window restart.

## 4. Gotchas / Trap List

1. **Python `re` backtracking on huge lines** — wrap parsing with size caps; OWASP A03 context. Long-line fuzz test planned.
2. **`datetime.fromisoformat`** in `correlate._ts_to_epoch` — assumes ISO-8601; events with 'Z' suffix from fixtures need `.replace('Z','+00:00')`. NotImplemented, see state.md.
3. **Win/POSIX offset tracking** — byte offsets vs `utf-8` line lengths measured with `line.encode().__len__()`; on files with multi-byte chars this is right, on Windows CRLF it counts CR (`\r\n` vs `\n`). Fixtures use `\n`.
4. **Dedupe window is global (60s)** — per-severity windows planned.
5. **`Auth success after failure` threshold=1** — trivially matches benign patterns. Do NOT ship as-is for production; gate on asset allow-list (asset enrichment).

## 5. Cross-Project Hooks

- Alert schema (`Alert.to_json`) is designed as the same CES used by:
  - Project 12 HIDS reporter → pushes `auth_failures`/exec signals to the same schema.
  - Project 13 phase-final alert enrichment script.
  - Project 16 `siem_hook` ingest adapter consumes alerts here.
- WebhookWriter and Router are candidates for extraction into a shared `secplatform` package (see Roadmap in state.md).

## 6. Cheat Sheet for New Devs

| File | What it contains | Tests run |
|------|------------------|-----------|
| `siem_correlator/model.py` | CES dataclasses | `py -c "import siem_correlator.model"` |
| `siem_correlator/normalize.py` | parsers + builder | `py main.py --print-enriched` |
| `siem_correlator/correlate.py` | RuleEngine window | smoke test (samples/access.log) |
| `siem_correlator/store.py` | partitions | run-once then inspect data/ |

Runtime: `py main.py --ingest-dir samples --rules rules --out data --run-once`