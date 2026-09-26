import shutil
import sqlite3
from pathlib import Path

SAFE_MEDIA_DIRS = [
    "DCIM",
    "Pictures",
    "Movies",
    "Download",
    "Documents",
    "Music",
    "WhatsApp",
    "Telegram",
    "Android/media",
]

NON_TEXT_EXT = {
    ".db", ".ab", ".png", ".jpg", ".jpeg", ".gif", ".webp", ".mp4", ".mkv",
    ".avi", ".mov", ".mp3", ".m4a", ".wav", ".zip", ".jar", ".apk", ".pdf",
    ".doc", ".docx", ".xls", ".sqlite",
}


def adb_binary() -> str | None:
    found = shutil.which("adb")
    if found:
        return found
    candidates = [
        str(Path.home() / "AppData" / "Local" / "Android" / "Sdk" / "platform-tools" / "adb.exe"),
        r"C:\platform-tools\adb.exe",
        r"C:\Program Files (x86)\Android\android-sdk\platform-tools\adb.exe",
    ]
    for c in candidates:
        if Path(c).exists():
            return c
    return None


def adb_available() -> bool:
    return adb_binary() is not None


def list_devices() -> list[str]:
    exe = adb_binary()
    if not exe:
        return []
    import subprocess

    out = subprocess.run([exe, "devices", "-l"], capture_output=True, text=True, timeout=30).stdout
    serials = []
    for line in out.splitlines()[1:]:
        line = line.strip()
        if line and not line.startswith("*"):
            serials.append(line.split()[0])
    return serials


def run_adb(args: list[str]) -> str:
    import subprocess

    exe = adb_binary()
    if not exe:
        raise RuntimeError("adb not found")
    proc = subprocess.run([exe] + args, capture_output=True, text=True, timeout=600)
    return proc.stdout + proc.stderr


def acquire_backup(target_file: Path, include_apk: bool, include_shared: bool) -> str:
    flags = ["-noapk"] if not include_apk else ["-apk"]
    if include_shared:
        flags.append("-shared")
    args = ["backup"] + flags + ["-all", "-system", "-f", str(target_file)]
    try:
        output = run_adb(args)
    except RuntimeError as exc:
        raise RuntimeError(f"adb backup failed: {exc}") from exc
    if not target_file.exists():
        raise RuntimeError("backup produced no file (device backup may be restricted)")
    return output


def logical_pull(serial: str, target_dir: Path, media_dirs: list[str] | None = None) -> dict:
    if serial:
        args_prefix = ["-s", serial]
    else:
        args_prefix = []
    pulled = {}
    for sub in (media_dirs or SAFE_MEDIA_DIRS):
        dest = target_dir / sub
        dest.mkdir(parents=True, exist_ok=True)
        try:
            run_adb(args_prefix + ["pull", f"/sdcard/{sub}", str(dest)])
            pulled[sub] = "ok"
        except RuntimeError:
            pulled[sub] = "missing/unavailable"
    return pulled


def sqlite_meta(path: Path) -> dict | None:
    try:
        con = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=3)
        try:
            tables = [
                r[0]
                for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
            ]
            tinfo = {}
            for t in tables[:60]:
                try:
                    n = con.execute(f'SELECT COUNT(*) FROM "{t}"').fetchone()[0]
                except sqlite3.Error:
                    n = -1
                tinfo[t] = n
            return {"tables": len(tables), "table_rows": tinfo}
        finally:
            con.close()
    except sqlite3.Error:
        return None


def scan_tree(root: Path) -> list[dict]:
    root = Path(root)
    items = []
    if not root.exists():
        return items
    for p in sorted(root.rglob("*")):
        if p.is_file():
            try:
                size = p.stat().st_size
            except OSError:
                size = -1
            ext = p.suffix.lower()
            kind = "media" if ext in NON_TEXT_EXT and ext != ".ab" else "data"
            if ext == ".ab":
                kind = "android-backup"
            items.append(
                {
                    "path": str(p.relative_to(root)),
                    "size": size,
                    "ext": ext,
                    "kind": kind,
                    "modified": None,
                }
            )
    return items