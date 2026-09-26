""".rekt project export/import (M2 leftover; ARCHITECTURE.md §3.8).

Format: a ZIP with manifest.json + blobs/<sha256>; optionally encrypted as
REKTPROJ header + salt + AES-256-GCM over the whole ZIP (passphrase KDF:
scrypt via platform.crypto). Every blob is hash-verified on export AND import
(integrity, OWASP A08) with bomb guards on total size and file count.
"""
from __future__ import annotations

import io
import json
import os
import time
import zipfile
from pathlib import Path

from rekt.platform.crypto import MAGIC as _ENC_MAGIC
from rekt.platform.crypto import decrypt, derive_key, new_salt
from rekt.platform.store import ProjectStore

HEADER = b"REKTPROJ\x00"
FORMAT = "rekt-project"
VERSION = 1
MAX_TOTAL_BYTES = 512 * 1024 * 1024
MAX_FILES = 4096
MAX_BLOB_BYTES = 64 * 1024 * 1024  # matches the analysis cap


class ProjectFileError(Exception):
    pass


def export_project(store: ProjectStore, out_path: Path,
                   passphrase: str | None = None) -> dict:
    """Export artifacts + findings. Returns stats. Hash-verifies every blob."""
    out_path = Path(out_path)
    manifest: dict = {"format": FORMAT, "version": VERSION, "created": time.time(),
                      "artifacts": [], "findings": [], "skipped": []}
    final = io.BytesIO()
    with zipfile.ZipFile(final, "w", zipfile.ZIP_DEFLATED) as zf:
        for a in store.list_artifacts():
            if len(manifest["artifacts"]) >= MAX_FILES:
                manifest["skipped"].append("file count cap reached")
                break
            sha = a["sha256"]
            data = store.get_artifact(sha)
            if data is None:
                manifest["skipped"].append(f"{sha[:12]}: blob missing")
                continue
            if ProjectStore.sha256(data) != sha:
                manifest["skipped"].append(f"{sha[:12]}: blob hash MISMATCH — not exported")
                continue
            if len(data) > MAX_BLOB_BYTES:
                manifest["skipped"].append(f"{sha[:12]}: exceeds per-blob cap")
                continue
            zf.writestr(f"blobs/{sha}", data)
            manifest["artifacts"].append({"sha256": sha, "size": a["size"],
                                          "note": a["note"]})
            manifest["findings"].extend(store.findings_for(sha))
        zf.writestr("manifest.json", json.dumps(manifest, indent=2))
    raw = final.getvalue()

    if passphrase:
        salt = new_salt()
        key = derive_key(passphrase, salt)
        payload = HEADER + salt + __encrypt(key, raw)
    else:
        payload = raw
    out_path.write_bytes(payload)
    return {"artifacts": len(manifest["artifacts"]),
            "findings": len(manifest["findings"]),
            "skipped": len(manifest["skipped"]),
            "encrypted": bool(passphrase), "bytes": out_path.stat().st_size}


def __encrypt(key: bytes, plaintext: bytes) -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    nonce = os.urandom(12)
    return _ENC_MAGIC + nonce + AESGCM(key).encrypt(nonce, plaintext, None)


def import_project(path: Path, store: ProjectStore,
                   passphrase: str | None = None) -> dict:
    """Import a .rekt file into the current store (merge, duplicate-safe)."""
    path = Path(path)
    raw = path.read_bytes()
    if raw.startswith(HEADER):
        if not passphrase:
            raise ProjectFileError("encrypted project — passphrase required")
        salt = raw[len(HEADER):len(HEADER) + 16]
        key = derive_key(passphrase, salt)
        try:
            raw = decrypt(key, raw[len(HEADER) + 16:])
        except Exception as e:  # noqa: BLE001 — wrong passphrase/tamper
            raise ProjectFileError(f"decryption failed (wrong passphrase or "
                                   f"tampered file): {type(e).__name__}") from e
    stats = {"imported": 0, "findings": 0, "warnings": []}
    total = 0
    try:
        zf = zipfile.ZipFile(io.BytesIO(raw))
    except (zipfile.BadZipFile, ValueError) as e:
        raise ProjectFileError(f"not a valid .rekt archive: {e}") from e
    names = zf.namelist()[:MAX_FILES]
    try:
        manifest = json.loads(zf.read("manifest.json").decode("utf-8"))
    except (KeyError, json.JSONDecodeError) as e:
        raise ProjectFileError(f"manifest missing/corrupt: {e}") from e
    if manifest.get("format") != FORMAT:
        raise ProjectFileError(f"unknown format {manifest.get('format')!r}")
    blob_names = {n: n for n in names if n.startswith("blobs/")}
    for a in manifest.get("artifacts", []):
        sha = a.get("sha256", "")
        entry = f"blobs/{sha}"
        if entry not in blob_names:
            stats["warnings"].append(f"{sha[:12]}: blob absent from archive")
            continue
        info = zf.getinfo(entry)
        if info.file_size > MAX_BLOB_BYTES or total + info.file_size > MAX_TOTAL_BYTES:
            stats["warnings"].append(f"{sha[:12]}: size cap exceeded — skipped")
            continue
        with zf.open(info) as src:
            data = src.read(MAX_BLOB_BYTES + 1)
        total += len(data)
        if ProjectStore.sha256(data) != sha:
            stats["warnings"].append(f"{sha[:12]}: hash MISMATCH — skipped (tamper?)")
            continue
        store.put_blob(sha, data)
        store.add_artifact(data, note=a.get("note", ""))
        stats["imported"] += 1
        existing = {f["detail"] for f in store.findings_for(sha)}
        for f in manifest.get("findings", []):
            if f.get("artifact_sha256") == sha and f.get("detail") not in existing:
                store.add_finding(sha, f.get("source", "import"),
                                  f.get("kind", "note"), f.get("detail", ""))
                stats["findings"] += 1
    return stats
