"""Pipeline spec engine — versioned, hash-pinned execution context.

architecture.md §5.4 / §6: spec triples (parser set, rule bundle, heuristics)
are hash-locked. A scan that cannot reproduce its own spec refuses to start.
"""
from __future__ import annotations

from sap.rules.bundle import BUNDLE, BUNDLE_ID, BUNDLE_VERSION, verify_bundle
from sap.security.integrity import canonical_json, sha256_text

SPEC_ID = "sap-static-v1"
SPEC_VERSION = "1.0.0"


def _core_spec() -> dict:
    return {
        "id": SPEC_ID,
        "version": SPEC_VERSION,
        "stages": ["strings", "pe", "intel", "rules"],
        "engines": {
            "strings": "charset-entropy-regex.1.0",
            "pe": "pefile-pe-parse.1.0",
            "intel": "bloom-blocklist.1.0",
        },
        "bundle_ref": BUNDLE_ID,
        "bundle_version": BUNDLE_VERSION,
        "sample_cap_bytes": 2 * 1024 * 1024 * 1024,
    }


def resolve_spec() -> dict:
    """Return the spec dict with its content-derived spec_id."""
    core = _core_spec()
    return {**core, "spec_id": sha256_text(canonical_json(core))[:16]}


def verify_spec(expected_id: str) -> bool:
    """Fail-closed: the resolved spec matches the pinned id."""
    return resolve_spec()["spec_id"] == expected_id


def resolve_bundle_sha() -> str:
    return BUNDLE["sha256"]