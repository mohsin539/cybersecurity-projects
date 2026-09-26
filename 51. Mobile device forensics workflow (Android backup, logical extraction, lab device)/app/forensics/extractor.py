import json
from pathlib import Path

from . import android
from .evidence import sha256_file, now_iso


def run_inventory(case, scan_dir: Path) -> dict:
    scan_dir = Path(scan_dir)
    files = android.scan_tree(scan_dir)
    hashes = []
    for f in files:
        fpath = scan_dir / f["path"]
        f["sha256"] = sha256_file(fpath) if fpath.exists() else ""
    sqlite_files = [f for f in files if f["ext"] in (".db", ".sqlite", ".sqlite3")]
    db_meta = []
    for f in sqlite_files:
        fpath = scan_dir / f["path"]
        meta = android.sqlite_meta(fpath)
        if meta is not None:
            f["sqlite"] = meta
            db_meta.append({"path": f["path"], "meta": meta})

    inv = {
        "case_id": case.id,
        "scanned_at": now_iso(),
        "root": str(scan_dir.relative_to(case.root)) if scan_dir.is_relative_to(case.root) else str(scan_dir),
        "file_count": len(files),
        "total_size": sum(x["size"] for x in files if x["size"] > 0),
        "categories": _categorize(files),
        "files": files,
        "sqlite_databases": db_meta,
        "integrity_note": "sha256 recorded per file",
    }
    case.inventory_path.write_text(json.dumps(inv, indent=2), encoding="utf-8")
    return inv


def _categorize(files: list[dict]) -> dict:
    from collections import Counter

    by_kind = Counter()
    by_ext = Counter()
    for f in files:
        by_kind[f["kind"]] += 1
        by_ext[f["ext"] or "(none)"] += 1
    return {"by_kind": dict(by_kind), "by_ext": dict(by_ext.most_common(20))}


def inventory_csv(case, inv: dict) -> Path:
    import csv

    out = case.root / "inventory.csv"
    with out.open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["case_id", "path", "size", "ext", "kind", "sha256"])
        for fi in inv["files"]:
            w.writerow([case.id, fi["path"], fi["size"], fi["ext"], fi["kind"], fi["sha256"]])
    return out