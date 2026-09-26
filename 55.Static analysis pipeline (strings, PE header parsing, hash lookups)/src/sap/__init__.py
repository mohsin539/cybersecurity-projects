"""sap — Static Analysis Pipeline (portable).

Portable-executable solution for static triage of suspicious binaries:
strings intelligence, PE header parsing, and hashed threat-intel lookups.

Layout (architecture.md §14):
- security/   integrity · audit · policy · crypto  (fail-closed chokepoints)
- engines/    strings · PE parser · hashing
- intel/      bloom BPF + opt-in throttled hashed-only sources
- rules/      versioned heuristic bundles + risk building blocks
- orchestration/  spec engine · bounded scheduler · risk aggregator
- data/       sandbox · SQLite CaseDB · HTML/JSON/CSV/STIX reporting
"""

__version__ = "1.0.0"
APP_NAME = "SAP"
APP_TITLE = "Static Analysis Pipeline"