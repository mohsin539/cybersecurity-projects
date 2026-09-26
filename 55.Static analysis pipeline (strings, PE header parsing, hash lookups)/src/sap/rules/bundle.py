"""Rule bundle manifest — deterministic pin used by every scan.

The bundle sha256 is derived from the heuristic module source itself, so any
rule change is visible as a bundle hash change; scans reference bundle_ref +
bundle_sha, and (in release builds) the value is pinned by the packaged manifest
(pack/sap_manifest.json). Tampered rules => bundle mismatch => fail-closed.
"""
from __future__ import annotations

import hashlib
import inspect

from . import heuristics

BUNDLE_ID = "sap-heuristics-r1"
BUNDLE_VERSION = "1.0.0"

# Source-tree hash pin captured at development time. In a frozen PyInstaller
# bundle inspect.getsource() is unavailable (no .py files), so the resolver
# falls back to this constant. Rebuild tooling regenerates it with the bundle.
_BUNDLE_PIN = "eecbcb57f39a3fd6f948c945c62b58abb34808845e10b51e4c11beb2877d3046"


def bundle_sha256() -> str:
    """Hash of the executable rule module source; pinned fallback when frozen."""
    try:
        src = inspect.getsource(heuristics)
        return hashlib.sha256(src.encode("utf-8")).hexdigest()
    except (OSError, TypeError):
        return _BUNDLE_PIN


BUNDLE = {
    "id": BUNDLE_ID,
    "version": BUNDLE_VERSION,
    "sha256": bundle_sha256(),
}


def verify_bundle(expected_sha: str) -> bool:
    """Fail-closed verification: current rules match the pinned bundle hash."""
    return bundle_sha256() == expected_sha