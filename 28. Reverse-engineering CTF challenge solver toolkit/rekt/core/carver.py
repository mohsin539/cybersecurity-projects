"""Carver: embedded-file carving (PNG/JPEG/ZIP) with bomb guards (A04)."""
from __future__ import annotations

import io
import zipfile
from pathlib import Path

MAX_CARVE_TOTAL = 256 * 1024 * 1024  # absolute cap on extracted bytes
MAX_ENTRIES = 4096


def carve_zip(data: bytes, out_dir: Path, max_depth: int = 8) -> list[Path]:
    """Safely extract ZIP payloads (zip-bomb + path-traversal guards, OWASP A01/A04)."""
    out: list[Path] = []
    total = 0
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except (zipfile.BadZipFile, ValueError):
        return out
    infos = zf.infolist()[:MAX_ENTRIES]
    for info in infos:
        if info.is_dir():
            continue
        # zip-slip guard: resolved target must stay inside out_dir
        target = (out_dir / info.filename).resolve()
        try:
            target.relative_to(out_dir.resolve())
        except ValueError:
            continue  # traversal attempt — skip, do not crash
        if total + info.file_size > MAX_CARVE_TOTAL:
            break
        depth = len(info.filename.replace("\\", "/").split("/"))
        if depth > max_depth:
            continue
        try:
            out_dir.mkdir(parents=True, exist_ok=True)
            with zf.open(info) as src, open(target, "wb") as dst:
                remaining = info.file_size
                while remaining > 0:
                    chunk = src.read(min(65536, remaining))
                    if not chunk:
                        break
                    dst.write(chunk)
                    remaining -= len(chunk)
                    total += len(chunk)
            out.append(target)
        except (OSError, zipfile.BadZipFile, RuntimeError):
            continue
    return out


PNG_SIG = b"\x89PNG\r\n\x1a\n"
PNG_END = b"IEND\xaeB`\x82"
JPEG_SOI, JPEG_EOI = b"\xff\xd8\xff", b"\xff\xd9"


def carve_images(data: bytes, out_dir: Path) -> list[Path]:
    """Carve embedded PNG/JPEG by signature. Bounded total size."""
    out: list[Path] = []
    out_dir.mkdir(parents=True, exist_ok=True)
    pos, idx = 0, 0
    while len(out) < 128:
        p = data.find(PNG_SIG, pos)
        if p == -1:
            break
        end = data.find(PNG_END, p)
        end = end + len(PNG_END) if end != -1 else min(p + 2 * 1024 * 1024, len(data))
        blob = data[p:end]
        if len(blob) > 32 * 1024 * 1024:
            pos = end
            continue
        target = out_dir / f"carved_{idx}.png"
        target.write_bytes(blob)
        out.append(target)
        pos, idx = end, idx + 1
    pos = 0
    while len(out) < 256:
        p = data.find(JPEG_SOI, pos)
        if p == -1:
            break
        end = data.find(JPEG_EOI, p + 3)
        end = end + 2 if end != -1 else min(p + 2 * 1024 * 1024, len(data))
        blob = data[p:end]
        if 2 <= len(blob) <= 32 * 1024 * 1024:
            target = out_dir / f"carved_{idx}.jpg"
            target.write_bytes(blob)
            out.append(target)
            idx += 1
        pos = end
    return out
