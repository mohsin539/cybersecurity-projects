# -*- coding: utf-8 -*-
"""sap.orchestration — pipeline spec, bounded scheduler, risk aggregator.

Determinism + reproducibility (architecture.md P4):
a run pins spec_id + bundle_sha; re-running the same sample with the same spec
produces byte-identical cards (memory.md §3 / state.md W1).
"""