# -*- coding: utf-8 -*-
"""sap.intel — threat-intel lookup subsystem (architecture.md §8).

Design contract (privacy + ops):
- Local bloom BPF + fact vault are always consulted first (air-gap friendly).
- Cloud sources are OPT-IN, hashed-only (sha256 hex), allowlisted and throttled
  through the EgressGate (policy.py). Raw sample bytes never egress (P3).
- Every lookup is recorded in the audit ledger (INTEL_LOOKUP_DONE / INTEL_EGRESS).
"""