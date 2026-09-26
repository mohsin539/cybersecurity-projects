# ADR-002 — Deterministic scoring core + bounded ML overlay

Status: Accepted · Date: 2026-09-18 · Deciders: Security Architecture, Detection Engineering, SOC Leads

## Context

Pure rule-based scoring is transparent but mis-ranks within bands; pure ML ranking is adaptive but unexplainable and gameable. Compliance and analyst trust require explainable, reproducible severity decisions.

## Decision

- Deterministic factor model (02 §4.2) is the **single source of truth for the band** (critical/high/medium/low/informational).
- ML (monotonic-constrained GBM) provides **bounded re-rank within a band (±10 pts max)** and sub-band ordering only; it can never move an alert across a band boundary or suppress it.
- Every score persists its full `factor_breakdown` including `ml_adjustment`; nightly reproducibility check re-computes a 1% sample and asserts equality.
- Governance: weights in Git, signed bundles, 2-person approval, differential replay CI gate, per-tenant overrides time-boxed and expiring.

## Consequences

- Scores are fully explainable to analysts and auditors; audits resolve with stored inputs + version, not live config.
- ML influence is intentionally limited — accepted trade-off of adaptivity for auditability; revisit only via new ADR.
- Anti-gaming: server-side-only velocity features; no free-text features; protected-class attributes excluded.
