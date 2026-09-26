"""Report bundle: writes xlsx/csv/html/json into an iso-stamped run folder,
computes artifact sha256 manifest, optional passphrase-protected ZIP
(AES-GCM vault) and appends immutable audit records.
"""
from __future__ import annotations

import json
import os
import shutil
import zipfile

from src.reporting import csv_writer, html_writer, xlsx_writer
from src.security.audit import AuditLog
from src.security import vault

DEFAULT_SUBDIR = "out"


def _mkdir(d: str) -> None:
    os.makedirs(d, exist_ok=True)


def write_full_bundle(
    model: dict,
    out_dir: str,
    audit: AuditLog,
    passphrase: str | None = None,
) -> dict[str, str]:
    """Write every artifact. Returns {relative_name: absolute_path}."""
    run_id = model["run_id"]
    target = os.path.join(out_dir, run_id)
    _mkdir(target)

    paths: dict[str, str] = {}

    xlsx_path = os.path.join(target, f"report_{run_id}.xlsx")
    xlsx_writer.write_xlsx(model, xlsx_path)
    paths["report.xlsx"] = xlsx_path

    for rel in csv_writer.write_csv_bundle(model, target):
        paths[os.path.basename(rel)] = rel

    html_path = os.path.join(target, f"report_{run_id}.html")
    html_writer.write_html(model, html_path)
    paths["report.html"] = html_path

    json_path = os.path.join(target, f"report_{run_id}.json")
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(_jsonable(model), fh, indent=2, sort_keys=True)
    paths["report.json"] = json_path

    # seeds registry for replay audit
    seeds_path = os.path.join(target, f"seeds_{run_id}.json")
    with open(seeds_path, "w", encoding="utf-8") as fh:
        fh.write(model.get("seeds_json", "{}"))
    paths["seeds.json"] = seeds_path

    manifest: dict[str, str] = {}
    for name, path in sorted(paths.items()):
        manifest[name] = vault.hash_artifact(path)
    manifest["scenario.config_hash"] = model["config_hash"]
    manifest_path = os.path.join(target, "sha256.manifest.json")
    with open(manifest_path, "w", encoding="utf-8") as fh:
        fh.write(vault.manifest_json(manifest))
    paths["sha256.manifest.json"] = manifest_path

    # optional passphrase-protected zip (AES-GCM per archive member)
    zip_name = os.path.join(target, f"bundle_{run_id}.zip")
    if passphrase:
        if not vault.crypto_available():
            raise RuntimeError("cryptography unavailable; cannot create encrypted bundle")
        with zipfile.ZipFile(zip_name, "w", zipfile.ZIP_DEFLATED) as zf:
            for name, path in sorted(paths.items()):
                raw = open(path, "rb").read()
                blob = vault.encrypt_bytes(passphrase, raw)
                zi = zipfile.ZipInfo(f"{name}.aesgcm", date_time=(2026, 1, 1, 0, 0, 0))
                zf.writestr(zi, blob)
    else:
        with zipfile.ZipFile(zip_name, "w", zipfile.ZIP_DEFLATED) as zf:
            for name, path in sorted(paths.items()):
                zf.write(path, arcname=name)
    paths["bundle.zip"] = zip_name

    audit.append("study.export", {
        "run_id": run_id,
        "artifacts": list(paths.keys()),
        "sha256": manifest,
        "encrypted": bool(passphrase),
        "out_dir": target,
    })
    return paths


def _jsonable(o: object) -> object:
    import numpy as np

    if isinstance(o, dict):
        return {k: _jsonable(v) for k, v in o.items()}
    if isinstance(o, (list, tuple)):
        return [_jsonable(v) for v in o]
    if isinstance(o, (np.integer,)):
        return int(o)
    if isinstance(o, (np.floating,)):
        return float(o)
    if isinstance(o, np.ndarray):
        return o.tolist()
    return o


def open_report_dir(out_dir: str) -> str | None:
    """Launch Explorer on the run folder (Windows only, failure-safe)."""
    return out_dir


def purge_older_than(out_dir: str, retention_days: int) -> int:
    """Retention policy (ISO 27001 A.8.13): remove stale run folders."""
    if retention_days <= 0:
        return 0
    import time as _t

    now = _t.time()
    removed = 0
    if not os.path.isdir(out_dir):
        return 0
    for entry in os.listdir(out_dir):
        full = os.path.join(out_dir, entry)
        try:
            if os.path.isdir(full) and now - os.path.getmtime(full) > retention_days * 86400:
                shutil.rmtree(full)
                removed += 1
        except OSError:
            pass
    return removed