"""Trusted external analysis tools (M2 leftover: UPX unpacker integration).

Runs vetted, argv-only commands against a scratch COPY of a sample — the same
trust class as the Ghidra bridge: user-installed tool, consent implied by the
explicit GUI action, audited, hard timeout, output size caps. No shell ever
(OWASP A03). Tool discovery: REKT_UPX_HOME env var, tools/upx.exe next to the
app, or PATH.
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

MAX_OUTPUT_BYTES = 64 * 1024 * 1024  # unpacked size cap (A04)
TIMEOUT_S = 120


def find_upx() -> Path | None:
    """Locate upx executable: env override, tools/ dir, then PATH."""
    home = os.environ.get("REKT_UPX_HOME", "")
    candidates: list[Path] = []
    if home:
        exe = "upx.exe" if sys.platform == "win32" else "upx"
        candidates.append(Path(home) / exe)
        candidates.append(Path(home))
    exe = "upx.exe" if sys.platform == "win32" else "upx"
    app_tools = Path(__file__).resolve().parents[2] / "tools" / exe
    candidates.append(app_tools)
    from shutil import which
    path_hit = which("upx")
    if path_hit:
        candidates.append(Path(path_hit))
    for c in candidates:
        if c.exists() and c.is_file():
            return c
    return None


def upx_decompress(sample_copy: Path, scratch: Path) -> tuple[bytes, str]:
    """Run `upx -d` on the copy. Returns (unpacked_bytes, log)."""
    upx = find_upx()
    if upx is None:
        return b"", ("UPX not found — install it (https://upx.github.io) or set "
                     "REKT_UPX_HOME to the folder containing upx.exe")
    out_path = scratch / "unpacked.bin"
    cmd = [str(upx), "-d", "-o", str(out_path), str(sample_copy)]
    try:
        proc = subprocess.run(  # noqa: S603 — argv list, no shell
            cmd, capture_output=True, timeout=TIMEOUT_S,
            creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0,
        )
    except subprocess.TimeoutExpired:
        return b"", f"upx exceeded {TIMEOUT_S}s — killed"
    except OSError as e:
        return b"", f"upx launch failed: {e}"
    log = (proc.stdout or b"").decode("utf-8", "replace")[-2000:] + \
          (proc.stderr or b"").decode("utf-8", "replace")[-500:]
    if proc.returncode != 0 or not out_path.exists():
        # UPX prints "NotPackedException"/"CantUnpackException" for non-packed files
        return b"", f"upx failed rc={proc.returncode}: {log.strip()[-300:]}"
    data = out_path.read_bytes()[:MAX_OUTPUT_BYTES]
    return data, f"unpacked {len(data):,} bytes\n{log.strip()[-300:]}"
