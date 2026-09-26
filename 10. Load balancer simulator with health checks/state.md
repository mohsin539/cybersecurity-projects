# AegisLB — System State (auto-preserved snapshot)

Generated (UTC): 2026-09-17T07:51:57Z  |  Run id: 194ebde0f8cf  |  Status: running  |  Paused: false

## Run

| Field | Value |
|---|---|
| seed | 41394 |
| rps (target) | 60.0 |
| rps (measured) | 54.7 |
| speed | 1.0 |
| arrival model | POISSON |
| policy | LEAST_CONNECTIONS |
| sim time (s) | 42.4 |
| health agreement sources | 2 |

## Health Spec (active)

| Parameter | Value |
|---|---|
| interval_ms | 5000 |
| fail_threshold | 3 |
| pass_threshold | 2 |
| grace_degraded_ms | 1500 |
| backoff_max_ms | 60000 |
| circuit_cooldown_s | 10.0 |
| quarantine_threshold | 3 |

## Backends

| Name | ID | State | Active | W(eff) | Cap(eff) | EWMA(ms) | ErrRate | Sessions | Errors | Probes OK/Fail | Breaker | Failure |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| web-1 | b-b8816e70 | HEALTHY | 3 | 100 | 800.0 | 35.5 | 0.0 | 551 | 0 | 8/0 | CLOSED | NONE |
| web-2 | b-ce571a51 | HEALTHY | 1 | 100 | 900.0 | 42.4 | 0.0 | 711 | 4 | 8/0 | CLOSED | NONE |
| web-3 | b-7b5d1869 | HEALTHY | 0 | 60 | 700.0 | 52.3 | 0.02 | 615 | 4 | 9/0 | CLOSED | NONE |
| api-1 | b-975b804b | HEALTHY | 0 | 17 | 260.8 | 133.8 | 0.0 | 163 | 2 | 8/0 | CLOSED | NONE |

## Metrics

| Metric | Value |
|---|---|
| sessions_total | 2040 |
| errors_total | 10 |
| rejects_total | 429 |
| decisions_total | 2044 |
| probes_ok | 0 |
| probes_fail | 0 |

## Alerts (recent)

- `7.0s` **warn** `SESSION_REJECT` SESSION_REJECT 
- `7.0s` **warn** `SESSION_REJECT` SESSION_REJECT 
- `7.0s` **warn** `SESSION_REJECT` SESSION_REJECT 
- `7.05s` **warn** `SESSION_REJECT` SESSION_REJECT 
- `7.1s` **warn** `SESSION_REJECT` SESSION_REJECT 
- `7.15s` **warn** `SESSION_REJECT` SESSION_REJECT 
- `7.15s` **warn** `SESSION_REJECT` SESSION_REJECT 
- `7.15s` **warn** `SESSION_REJECT` SESSION_REJECT 
- `7.15s` **warn** `SESSION_REJECT` SESSION_REJECT 
- `11.05s` **warn** `STATE_TRANSITION` STATE_TRANSITION 
- `16.6s` **warn** `STATE_TRANSITION` STATE_TRANSITION 
- `28.95s` **warn** `STATE_TRANSITION` STATE_TRANSITION 

---
Preserved by AegisLB `PersistentStore`; regenerated each flush. Companion docs: `docs/01` (architecture), `docs/02` (security), `docs/03` (framework traceability).
