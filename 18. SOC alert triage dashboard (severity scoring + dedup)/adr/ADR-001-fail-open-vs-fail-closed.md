# ADR-001 — Fail-open vs fail-closed per component

Status: Accepted · Date: 2026-09-18 · Deciders: Security Architecture, Platform, SOC Leads

## Context

Each component can fail in ways that either hide alerts or flood analysts. A single global policy is wrong: alert loss and analyst trust have different costs at different points in the pipeline.

## Decision

| Component | Mode | Rationale |
|---|---|---|
| Dedup (Redis/pgvector) | **fail-open** | Missing alerts are worse than duplicates; analysts see noise but nothing is lost |
| Enrichment | degrade to unknowns | Never fabricate context; surface `degraded_context` flag |
| Scoring | **fail-closed** to last-good signed bundle; else static base severity + `unscored` flag | Never invent scores |
| Audit pipeline | **fail-closed**: block mutating action | Auditability is an invariant, not a feature |
| Triage API/Dashboard | fail-closed (reject), no degraded auth | No bypass paths |
| Export | fail-closed | Exfiltration risk |

Every mode is verified by chaos drill (07 §5) and surfaced in the UI so analysts always know the system's degraded state.

## Consequences

- Duplicates appear in the queue during Redis outages — SOC leads accepted this; a queue banner is mandatory.
- Blocking mutations on audit failure adds a hard dependency on the audit sink — mitigated by redundant local spool with at-least-once retry before blocking (bounded 60 s buffer).
- The matrix is binding: any new component must declare its fail mode in its ADR before production rollout.
