"""Generate assets/honeypot.ico (stdlib-only, no Pillow).

Draws an amber honey-hexagon on transparent background at 16/32/48/64px.
USAGE: py scripts/make_icon.py
"""
from __future__ import annotations

import struct
from pathlib import Path

BGRA = tuple  # (B, G, R, A)


def inhex(x: float, y: float, cx: float, cy: float, r: float) -> bool:
    px, py = x - cx, y - cy
    return (abs(px) <= r * 0.866 and abs(py) <= r * 0.5
            and abs(py) <= r * 0.866 - abs(px) / 1.732)


def render_icon(size: int) -> list[BGRA]:
    cx, cy = size / 2, size / 2
    r = size * 0.42
    px_out: list[BGRA] = []
    for y in range(size):
        for x in range(size):
            inside = inhex(x + 0.5, y + 0.5, cx, cy, r)
            if not inside:
                px_out.append((0, 0, 0, 0))
                continue
            if inhex(x + 0.5, y + 0.5, cx, cy, r * 0.62):
                px_out.append((110, 200, 250, 255))
                continue
            edge = (abs((x + 0.5) - cx) > r * 0.866 - 1.6
                    or abs((y + 0.5) - cy) > r * 0.5 - 1.6
                    or abs((y + 0.5) - cy) > r * 0.866 - abs((x + 0.5) - cx) / 1.732 - 1.6)
            px_out.append((0, 84, 150, 255) if edge else (0, 169, 242, 255))
    return px_out


def _bmp_body(pixels: list[BGRA], size: int) -> bytes:
    rows = []
    for y in range(size - 1, -1, -1):
        row = b"".join(struct.pack("<BBBB", b, g, r, a)
                       for b, g, r, a in pixels[y * size:(y + 1) * size])
        rows.append(row)
    return b"".join(rows)


def build_ico(sizes=(16, 32, 48, 64)) -> bytes:
    frames = []
    for size in sizes:
        pixels = render_icon(size)
        header = struct.pack("<IiiHHIIiiII",
                             40, size, size * 2, 1, 32, 0, len(pixels) * 4,
                             0, 0, 0, 0)
        mask_row = ((size // 8 + 3) // 4) * 4
        frames.append((size, header + _bmp_body(pixels, size) + b"\x00" * (mask_row * size)))

    count = len(frames)
    out = struct.pack("<HHH", 0, 1, count)
    offset = 6 + 16 * count
    blobs = b""
    for size, data in frames:
        bw = bh = 256 if size >= 256 else size
        out += struct.pack("<BBBBHHII", bw & 0xFF, bh & 0xFF, 0, 0, 1, 32,
                           len(data), offset)
        offset += len(data)
        blobs += data
    return out + blobs


def main() -> int:
    dest = Path(__file__).resolve().parent.parent / "assets" / "honeypot.ico"
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(build_ico())
    print(f"wrote {dest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())