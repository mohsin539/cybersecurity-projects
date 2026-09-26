# -*- coding: utf-8 -*-
"""sap.rules — versioned, signature-verified detection logic (architecture.md §6).

Heuristic bundles map engine signals to findings with a classic control mapping.
Bundles are version-locked: every run pins bundle_ref + bundle_sha so a later
rule change cannot retroactively alter triage cards (A08 / P4).
"""