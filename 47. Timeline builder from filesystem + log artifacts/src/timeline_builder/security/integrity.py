from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from .hashing import sha256_file


def hash_artifacts(paths: Iterable[str | Path], max_bytes: int | None = None) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for raw in paths:
        path = Path(raw)
        try:
            size = path.stat().st_size
            digest = sha256_file(path, max_bytes=max_bytes)
        except OSError as exc:
            entries.append({"path": str(path), "error": str(exc)})
            continue
        entries.append({"path": str(path), "size": size, "sha256": digest})
    return entries


def build_manifest(paths: Iterable[str | Path], case_id: str = "", max_bytes: int | None = None) -> dict[str, Any]:
    return {
        "product": "TimelineBuilder",
        "case_id": case_id,
        "created": datetime.now(timezone.utc).isoformat(),
        "algorithm": "sha256",
        "artifacts": hash_artifacts(paths, max_bytes=max_bytes),
    }


def write_manifest(destination: str | Path, manifest: dict[str, Any]) -> Path:
    dest = Path(destination)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return dest


def verify_manifest(manifest: dict[str, Any]) -> dict[str, Any]:
    ok = 0
    failures: list[dict[str, str]] = []
    missing = 0
    for entry in manifest.get("artifacts", []):
        path = Path(entry["path"])
        if "sha256" not in entry:
            continue
        if not path.exists():
            missing += 1
            failures.append({"path": str(path), "reason": "missing"})
            continue
        actual = sha256_file(path)
        if actual == entry["sha256"]:
            ok += 1
        else:
            failures.append({"path": str(path), "reason": "hash_mismatch", "expected": entry["sha256"], "actual": actual})
    return {"ok": not failures, "verified": ok, "missing": missing, "failures": failures}
