# -*- coding: utf-8 -*-
"""sap.engines — static analysis engines (architecture.md §5).

Each engine is deterministic, scheme-validateable and isolated: a failure is
captured as a status=error result, never an exception that takes down the
pipeline (memory.md §5 guarantees).
"""