"""Generate assets/app.ico - app icon for the portable GUI build.

Pure-python PNG encoder (zlib + struct) wrapped in an ICO container, so no
Pillow dependency is required. Draws a dark signal/radar glyph on a
violet->cyan gradient tile.
"""

from __future__ import annotations

import struct
import zlib
from pathlib import Path

W = H = 256


def _lerp(c0, c1, t):
    return tuple(round(a + (b - a) * t) for a, b in zip(c0, c1))


def _build_pixels() -> list[bytes]:
    rows = []
    for y in range(H):
        row = bytearray([0])
        for x in range(W):
            r, g, b, a = _pixel(x, y)
            row += bytes((r, g, b, a))
        rows.append(bytes(row))
    return rows


def _pixel(x: int, y: int) -> tuple:
    # rounded-square mask
    inset = 6
    if inset <= x < W - inset and inset <= y < H - inset:
        # gradient background (violet -> cyan diagonal)
        t = (x + y) / (2 * H)
        r, g, b = _lerp((109, 40, 217), (34, 211, 238), t)
        o = 1.0
    else:
        return (0, 0, 0, 0)

    # white signal glyph
    cx, cy = 128, 138
    white = (240, 245, 255)
    d = ((x - cx) ** 2 + (y - cy) ** 2) ** 0.5
    # base dot
    if d < 20:
        return (*white, 255)
    # concentric arc rings (annulus band between top 240deg and bottom-fixed)
    for rad in (42, 72, 102):
        if rad - 7 <= d <= rad + 7:
            ang = __import__("math").atan2(y - cy, x - cx)
            ang_deg = (ang * 180 / 3.14159) % 360
            top = (340 if x < cx else 200) / 10  # narrow band near top
            if 100 <= ang_deg <= 260 or ang_deg >= 340 or ang_deg <= 20:
                return (*white, 255)
    # subtle inner glow
    if d < 34:
        return (*_lerp(white, (r, g, b), 0.6), 255)
    return (r, g, b, round(255 * o))


def _chunk(tag: bytes, data: bytes) -> bytes:
    return (struct.pack(">I", len(data)) + tag + data
            + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF))


def make_png() -> bytes:
    ihdr = struct.pack(">IIBBBBB", W, H, 8, 6, 0, 0, 0)
    idat = zlib.compress(b"".join(_build_pixels()), 9)
    return (b"\x89PNG\r\n\x1a\n"
            + _chunk(b"IHDR", ihdr)
            + _chunk(b"IDAT", idat)
            + _chunk(b"IEND", b""))


def make_ico(png: bytes) -> bytes:
    # single 256x256 PNG-compressed entry
    header = struct.pack("<HHH", 0, 1, 1)
    entry = struct.pack("<BBBBHHII", 0, 0, 0, 0, 1, 32, len(png), 22)
    return header + entry + png


def main() -> None:
    out = Path(__file__).resolve().parent.parent / "assets" / "app.ico"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(make_ico(make_png()))
    print(f"icon written: {out} ({out.stat().st_size} bytes)")


if __name__ == "__main__":
    main()