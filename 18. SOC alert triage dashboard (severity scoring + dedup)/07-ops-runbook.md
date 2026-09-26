# 07 — Operations Runbook

Status: Approved v1.0 · Owner: Platform SRE + SOC Leads · Review cadence: quarterly (and after every game day)

---

## 1. SLOs & paging alerts

| Alert | Condition | Severity | First actions |
|---|---|---|---|
| IngestLagHigh | Kafka consumer lag > 60 s for 5 min | page (P2) | check normalizer pods; scale; if poison-message storm → verify DLQ counters; check upstream burst |
| DedupFailOpen | Redis unavailable / dedup error rate > 1% | page (P2) | expect duplicates in queue (fail-open); verify dedup_mode switch state; restore Redis; replay DLQ after recovery |
| ScoringDegraded | OPA bundle fetch failing / engines on stale bundle | page (P2) | confirm last-good bundle version in use (fail-closed); check config svc + signature chain; roll forward or back |
| AuditWriteFail | audit sink errors > 0 for 1 min | **page (P1)** | mutations are blocked by design; restore WORM path; DO NOT disable fail-closed; comms to SOC leads |
| ScoreShift | score distribution KS-test p < 0.01 vs 7-day baseline | page (P3) | suspect rule/config change or TI source anomaly; check recent deploys; freeze rules if unexplained |
| DedupPrecisionDrop | weekly sampled precision < 95% | ticket → review | review oversampled fuzzy links; tighten θ or enable kill switch per rule family |
| ExportAnomaly | export volume/calls exceed tenant baseline 3× | page (P2) | possible exfiltration (T11); follow IR quick-reference; preserve audit chain |
| AuthAnomaly | analyst impossible-travel / token misuse | page (P2) | revoke sessions server-side; involve IdP team |

P1/P2 acknowledge SLA: 15 min. All alerts link to the relevant section below (runbook-as-code: alert payloads carry this doc's anchor).

## 2. Kill switches & degradation switches (all are audited config changes)

| Switch | Scope | Effect | When to use |
|---|---|---|---|
| `dedup_mode = off \| exact_only \| full` | global / tenant / rule-family | stops suppression (off) or fuzzy stage (exact_only) | precision incident, poisoned keys (T02) |
| `scoring.ml_overlay = on/off` | global / tenant | disables ML re-rank; deterministic base only | suspected model drift/adversarial features (T09) |
| `ti_source.<id>.enabled` | per TI source | removes that source from f4 factor | TI poisoning (T10) |
| `export.enabled` | tenant | disables bulk export endpoints | suspected exfiltration (T11) |
| `ingest.<source>.paused` | per source | pauses that collector (raw topic retains 7 d) | malicious/looping source (T01) |

Procedure: switch flips require two-person approval in-product (except P1 incident path: on-call may flip solo, retro-approved ≤ 24 h). Every flip emits an audit event and a queue banner to analysts (UI must always show degraded state honestly).

## 3. Tuning procedures (governed)

1. **Threshold/weight change**: PR to `triage-rules` with motivation + analyst-observed cases → CI differential replay (7-day sample) → score-distribution diff attached → 2 approvals (SOC lead + detection eng) → merge → signed bundle → staged rollout → ScoreShift alarm monitored for 24 h.
2. **Emergency rollback**: pin previous bundle hash via config svc; verify engines report `bundle_version` match; file retro-PR.
3. **Per-tenant override**: time-boxed (default 30 d, hard max 90 d), expiring automatically; override registry reviewed monthly (SOC leads).
4. **Backfill re-scoring**: explicit operation, approval from SOC lead + platform owner, rate-limited, produces before/after audit records; never part of a deploy.

## 4. Common operational scenarios

- **Flood of duplicates (dedup loop upstream)**: check `duplicate_of` link rate per rule family → if > 20× baseline, suspect source loop → pause source → verify canonical occurrence counts stop inflating → inspect dedup keys for timestamp-included fields (anti-pattern: volatile fields in keys — fix in mapping pack, version bump).
- **Score reproducibility drift (nightly check fails)**: freeze rules, diff `factor_breakdown` of drifted sample vs golden vectors, suspect live-config hot-reload mismatch or malicious edit (T03) → verify bundle signature chain → involve IR if signature verification failed.
- **Queue unreadable (API down)**: fallback export of critical-band queue via notifier path; SOC works from notifier + case mgmt; status page updated; RTO 60 min.
- **Poison alert payload crashing normalizer**: DLQ quarantine, schema validation fix, versioned mapping pack bump, replay from DLQ (never silent drop).
- **Analyst reports wrong dedup link**: split-duplicate action (one click, audited) → the link becomes part of oversampled weekly precision audit → threshold adjustment if pattern repeats.

## 5. DR drills (quarterly, evidence recorded for ISO/NIST audits)

| Drill | Asserts |
|---|---|
| Postgres PITR restore to scratch env | RPO ≤ 5 min; RLS policies intact post-restore |
| Kafka replay from `raw.*` | derived state (Redis dedup, queue views, scores) rebuilt bit-consistent for sampled window |
| Full AZ loss simulation | 99.9% availability maintained; no fail-mode violations (audit stays fail-closed) |
| Dedup Redis wipe | fail-open behavior correct; backlog suppressed correctly after rebuild (no false re-canonicalization) |
| Config svc outage | engines hold last-good signed bundle (fail-closed) |
| WORM outage | mutations blocked (correct fail-closed); recovery procedure ≤ 30 min |

## 6. Weekly & monthly ops checklist

Weekly: dedup precision sample (n=400, oversampled fuzzy), score-distribution review with SOC leads, patch-SLA burn-down, alert-noise review (top 10 rule families by volume after dedup).
Monthly: per-tenant override registry review, access-review diff (with IdP), capacity headroom review vs model (01 §9), switch-state audit (all kill switches in expected positions).
