#!/usr/bin/env python3
"""Chain-of-Custody Sequence state machine for the DIHT tool (see state.md)."""

from __future__ import annotations

from typing import List, Tuple

# Legal/forensic lifecycle states (mirrors architecture.md state machine).
LIFECYCLE = {
    "case_created":        ["ledger_created"],
    "ledger_created":      ["acquisition_completed"],
    "acquisition_completed": ["verification_pending", "sealed", "stored"],
    "verification_pending": ["verification_pass", "verification_fail"],
    "verification_pass":   ["sealed", "stored", "transferred", "returned"],
    "verification_fail":   ["acquisition_completed"],  # re-acquire/re-verify
    "sealed":              ["stored", "transferred", "unsealed"],
    "unsealed":            ["examined", "sealed"],
    "examined":            ["sealed", "stored", "report_exported"],
    "stored":              ["transferred", "returned", "destroyed"],
    "transferred":         ["stored", "examined", "sealed"],
    "report_exported":     ["sealed", "returned", "destroyed"],
    "returned":            ["destroyed"],
    "destroyed":           [],
}

def allowed_next(state: str) -> List[str]:
    return LIFECYCLE.get(state, [])

def coerce_state(action: str) -> str:
    for key in LIFECYCLE:
        if action.startswith(key):
            return key
    return "case_created"


def describe(action: str) -> Tuple[str, str]:
    """Map a ledger action onto the lifecycle state and a short note."""
    for key in LIFECYCLE:
        if action.startswith(key):
            return key, key.replace("_", " ").title()
    return "case_created", action.replace("_", " ").title()