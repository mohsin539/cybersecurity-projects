"""One-click recipe catalog (ARCHITECTURE.md §3.6) — all PURE risk class."""
from __future__ import annotations

CATALOG: list[dict] = [
    {"id": "b64decode", "label": "Base64 decode", "steps": [{"op": "b64_decode"}]},
    {"id": "b32decode", "label": "Base32 decode", "steps": [{"op": "b32_decode"}]},
    {"id": "b85decode", "label": "Base85 decode", "steps": [{"op": "b85_decode"}]},
    {"id": "hexdecode", "label": "Hex decode", "steps": [{"op": "hex_decode"}]},
    {"id": "urldecode", "label": "URL decode", "steps": [{"op": "url_decode"}]},
    {"id": "rot13", "label": "ROT13", "steps": [{"op": "rot13"}]},
    {"id": "b64chain", "label": "Base64 x3 decode", "steps": [{"op": "b64_decode"}] * 3},
    {"id": "hexb64", "label": "Hex -> Base64 decode", "steps": [
        {"op": "hex_decode"}, {"op": "b64_decode"}]},
]


def get(rid: str) -> dict | None:
    return next((r for r in CATALOG if r["id"] == rid), None)
