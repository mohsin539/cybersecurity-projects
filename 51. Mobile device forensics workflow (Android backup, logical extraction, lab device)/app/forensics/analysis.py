from datetime import datetime
from pathlib import Path

SIZE_LIMIT = 4 * 1024 * 1024


def search_in_dir(root: Path, needle: str, kind_filter: str = "all") -> list[dict]:
    root = Path(root)
    needle_l = needle.lower()
    hits = []
    if not root.exists():
        return hits
    for p in sorted(root.rglob("*")):
        if not p.is_file():
            continue
        if p.stat().st_size > SIZE_LIMIT:
            continue
        ext = p.suffix.lower()
        if kind_filter == "text" and ext in (".db", ".sqlite", ".sqlite3", ".ab"):
            continue
        if kind_filter == "media" and ext not in (".txt", ".log", ".json", ".xml", ".csv", ".html", ".js", ".sql"):
            continue
        try:
            raw = p.read_bytes()
            if needle_l.encode("utf-8") in raw:
                hits.append(
                    {
                        "path": str(p.relative_to(root)),
                        "size": len(raw),
                        "needle": needle,
                    }
                )
        except OSError:
            continue
    return hits


def build_timeline(root: Path) -> list[dict]:
    root = Path(root)
    rows = []
    if not root.exists():
        return rows
    for p in sorted(root.rglob("*")):
        if not p.is_file():
            continue
        try:
            st = p.stat()
        except OSError:
            continue
        rows.append(
            {
                "ts": datetime.fromtimestamp(st.st_mtime).isoformat(sep=" "),
                "path": str(p.relative_to(root)),
                "size": st.st_size,
            }
        )
    rows.sort(key=lambda r: r["ts"])
    return rows