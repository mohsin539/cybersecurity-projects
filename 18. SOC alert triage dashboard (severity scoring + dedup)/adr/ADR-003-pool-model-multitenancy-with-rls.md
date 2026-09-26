# ADR-003 — Pool-model multi-tenancy with RLS as the hard boundary

Status: Accepted · Date: 2026-09-18 · Deciders: Security Architecture, Platform

## Context

Silo (database-per-tenant) maximizes isolation at high cost and operational complexity; pool (shared) is efficient but risks cross-tenant leakage through application bugs.

## Decision

- Pool model with **row-level security as the enforcement backstop**: every tenant-owned table carries `tenant_id`; app role sets `app.tenant_id` per transaction; RLS policy enforces scoping even if API-layer checks fail.
- Tenant prefixing on all derived stores (Redis keys, Kafka partition keys, pgvector filter columns).
- A dedicated cross-tenant isolation test suite runs in CI and must fail to find each other's data.
- Per-tenant rate limits and ANN candidate caps prevent noisy neighbors.
- Cross-tenant analytics only on k-anonymized (k ≥ 25) aggregates or synthetic data.

## Consequences

- Cheaper to operate at ≤ 500 tenants (assumption A3); revisited if regulated tenants require silo — that becomes a new ADR with a silo deployment profile.
- RLS misconfiguration is the single highest-consequence misfire risk; mitigations: policy versioning in migrations, PR checklist, isolation suite, quarterly access review includes an RLS policy diff.
