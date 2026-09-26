# -*- coding: utf-8 -*-
"""sap.security — cross-cutting security services (architecture.md §9/§10).

Central chokepoints for the four invariants the pipeline cannot negotiate on:

1. Evidence is opened READ-ONLY, never modified (architecture.md P1/P2).
2. Every write resolves inside the reserved sandbox root (zone model §9.2).
3. Every action is recorded in a hash-chained audit ledger (A.8.15/A.8.16).
4. Egress for intel lookups is hashed-only, allowlisted and throttled (P3).

All modules fail closed: any policy/integrity/chain violation raises rather
than continuing (architecture.md P7).
"""