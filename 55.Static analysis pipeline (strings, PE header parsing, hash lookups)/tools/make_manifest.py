"""Build-time integrity manifest generator.

Writes pack/sap_manifest.json covering every bundled data file so that the
frozen bundle's self_integrity_check() can fail closed (P9) at runtime.

Usage from the repo root:
    python tools/make_manifest.py [source_dir] [manifest_path]

    source_dir   - directory whose files get hashed (default: pack)
    manifest_path- where the manifest is written (default: pack/sap_manifest.json)

The SAP.spec regenerates this automatically; the tool is here for CI builds and
for auditing the payload before the exe is assembled.
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path


def build_manifest(source_dir: str | Path, manifest_path: str | Path) -> Path:
    source = Path(source_dir)
    out = Path(manifest_path).resolve()
    manifest = {"app": "SAP", "version": "1.0.0", "files": {}}
    out.parent.mkdir(parents=True, exist_ok=True)
    for f in sorted(source.rglob("*")):
        if f.is_file() and f.resolve() != out:
            digest = hashlib.sha256(f.read_bytes()).hexdigest()
            rel = f.relative_to(source).as_posix()
            manifest["files"][f"pack/{rel}"] = digest
    out.write_text(json.dumps(manifest, indent=2, sort_keys=True),
                   encoding="utf-8")
    return out


if __name__ == "__main__":
    source = sys.argv[1] if len(sys.argv) > 1 else "pack"
    target = sys.argv[2] if len(sys.argv) > 2 else "pack/sap_manifest.json"
    result = build_manifest(source, target)
    print(f"manifest written: {result}")