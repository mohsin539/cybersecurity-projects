"""Signature-based file carving over unallocated regions.

Algorithm:
  1. Build a byte-level *scan region list* (free-space ranges from the FS
     engine or a whole partition for image files).
  2. Read the region in fixed-size chunks with an overlap >= longest magic.
  3. On magic match → hunt for the footer end-marker inside the max-size
     window; if absent, clamp to max_size (low confidence) or discard for
     footer-mandatory types.
  4. Only one carve per overlapping header is ever reported; a bitmap of
     produced spans prevents double-capture of the same bytes.
"""

from __future__ import annotations

import hashlib
import math
import struct
from dataclasses import dataclass
from typing import Callable, Iterator, List, Optional, Tuple

from .signatures import FileSig, SIGNATURES, validate_signature

CHUNK = 8 * 1024 * 1024
LONGEST_MAGIC = max(len(s.magic) + s.magic_offset for s in SIGNATURES)
MAGIC_OVERLAP = max(len(s.magic) for s in SIGNATURES) - 1
PROBE_STEP = 1 * 1024 * 1024       # incremental footer-probe step
MAX_ARTIFACT = 512 * 1024 * 1024   # absolute cap for any carved artifact
FOOTERLESS_MAX = 32 * 1024 * 1024  # only trust footer-less carves up to this


@dataclass
class CarvedFile:
    sig: str
    ext: str
    size: int
    confidence: str
    anchor: str
    start: int
    sha256: str = ""
    region_end: int = 0

    @property
    def display(self) -> str:
        return f"{self.sig} · {self.ext} · {self.size} B"


class Carver:
    def __init__(self, src, regions: List[Tuple[int, int]],
                 group_filter: Optional[str] = None,
                 ext_filter: Optional[str] = None,
                 progress: Callable[[str, float], None] = None,
                 stop_flag: Optional[Callable[[], bool]] = None):
        self.src = src
        self.regions = [r for r in regions if r[1] - r[0] > 64]
        self.group_filter = group_filter
        self.ext_filter = (ext_filter or "").lower().lstrip(".")
        self.progress = progress or (lambda a, b: None)
        self.stop_flag = stop_flag or (lambda: False)
        self._sigs = self._select()
        if not self._sigs:
            raise ValueError("no carving signatures selected")

    def _select(self) -> List[FileSig]:
        list_ = []
        for s in SIGNATURES:
            if self.group_filter and s.group != self.group_filter:
                continue
            if self.ext_filter and s.ext != self.ext_filter:
                continue
            list_.append(s)
        return list_

    # ------------------------------------------------------------------
    def _find_magic(self, window: bytes, abs_base: int,
                    occupied: List[Tuple[int, int]]):
        """Yield (sig, header_offset) for every magic in `window`.

        Each signature uses the C-level ``bytes.find`` (memchr) — repeated
        over the same 8 MB window this is far faster and more predictable
        than a single huge regex alternation over adversarial binary data."""
        for sig in self._sigs:
            st = 0
            while True:
                idx = window.find(sig.magic, st)
                if idx < 0:
                    break
                pos = idx - sig.magic_offset
                if pos < 0:
                    st = idx + 1
                    continue
                header = abs_base + pos
                if any(a <= header < b for a, b in occupied):
                    st = idx + 1
                    continue
                yield sig, header
                st = idx + 1

    def _plausible(self, sig: FileSig, header: int, window: bytes,
                   abs_base: int) -> bool:
        """Cheap gate that kills random-data false positives before any
        footer probe or large read is attempted."""
        rel = max(0, header - abs_base)
        sample = window[rel: rel + 8192]
        ext = sig.ext
        try:
            if ext == "exe":
                if b"PE\x00\x00" not in (sample[0x3C:0x3C + 4] or b""):
                    if len(sample) >= 0x40:
                        pe = int.from_bytes(sample[0x3C:0x40], "little")
                        if not (0 < pe < len(sample) and sample[pe:pe + 4] == b"PE\x00\x00"):
                            return False
            elif sig.name == "ZIP Archive":
                if b"PK" not in sample[4:1024]:
                    return False
            elif ext == "ico":
                if len(sample) >= 8:
                    reserved, kind, count = struct.unpack_from("<HHH", sample, 0)
                    if not (reserved == 0 and kind in (1, 2) and 1 <= count <= 256):
                        return False
                    w, h = sample[6], sample[7]
                    if not (0 <= w <= 256 and 0 <= h <= 256):
                        return False
                else:
                    return False
            elif ext == "bmp":
                if len(sample) >= 26:
                    w, h = int.from_bytes(sample[0x12:0x16], "little", signed=True), \
                           int.from_bytes(sample[0x16:0x1A], "little", signed=True)
                    if not (1 <= abs(w) <= 20000 and 1 <= abs(h) <= 20000):
                        return False
            elif ext == "pdf":
                if len(sample) >= 1024 and sample.count(b"\x00") > 700:
                    return False
            elif ext == "png":
                if len(sample) >= 24:
                    w = int.from_bytes(sample[16:20], "big"); h = int.from_bytes(sample[20:24], "big")
                    if not (1 <= w <= 200000 and 1 <= h <= 200000):
                        return False
            elif sig.name == "ID3 / MP3":
                if len(sample) < 10 or sample[6:10] == b"\x00\x00\x00\x00":
                    return False
            elif ext == "mp4" or ext == "mov" or ext == "mkv":
                if len(sample) >= 32 and sample[8:32].count(b"\x00") > 20:
                    return False
        except Exception:
            return False
        return True

    def _resolve_end(self, sig: FileSig, header: int, region_end: int) -> Tuple[int, bool]:
        """Locate footer (stepwise, memory-bounded) / hard cap.

        Returns ``(end_exclusive, footer_found)`` or ``(0, False)`` to skip
        the candidate.  Probing is incremental so hostile/unallocated data
        with false-positive headers can never balloon RAM usage.
        """
        probe_cap = min(sig.max_size if sig.max_size is not None else region_end - header,
                        region_end - header, MAX_ARTIFACT)
        if probe_cap <= sig.min_size + 32:
            return (0, False)
        if sig.footer is not None:
            # Stepwise footer scan (1 MB steps) up to probe_cap.
            pos = header + sig.magic_offset + len(sig.magic)
            neigh = 0
            while pos + PROBE_STEP <= header + probe_cap and neigh < 512:
                winb = self.src.read(pos, PROBE_STEP)
                if len(winb) < len(sig.footer):
                    break
                idx = winb.find(sig.footer)
                if idx >= 0:
                    return (pos + idx + len(sig.footer), True)
                pos += PROBE_STEP - len(sig.footer)
                neigh += 1
            # Tail after the loop.
            if pos + len(sig.footer) <= header + probe_cap:
                tail = self.src.read(pos, header + probe_cap - pos)
                idx = tail.find(sig.footer)
                if idx >= 0:
                    return (pos + idx + len(sig.footer), True)
            # Footer is declared for this type and must be found.
            return (0, False)
        # Header-only signature: carve the (bounded) full span.
        cap = min(probe_cap, FOOTERLESS_MAX)
        if cap <= sig.min_size + 32:
            return (0, False)
        return (header + cap, False)

    # ------------------------------------------------------------------
    def carve(self, verify: bool = True) -> List[CarvedFile]:
        results: List[CarvedFile] = []
        occupied: List[Tuple[int, int]] = []
        total = sum(b - a for a, b in self.regions)
        done = 0
        for a, b in self.regions:
            if self.stop_flag and self.stop_flag():
                break
            span = b - a
            pos = a
            while pos < b:
                if self.stop_flag and self.stop_flag():
                    break
                size = min(CHUNK, b - pos)
                window = self.src.read(pos, size)
                if len(window) < 8:
                    break
                seen = 0
                for sig, header in self._find_magic(window, pos, occupied):
                    if not self._plausible(sig, header, window, pos):
                        continue
                    end, anchored = self._resolve_end(sig, header, pos + len(window))
                    if end <= header + sig.min_size:
                        continue
                    take = min(end - header, pos + len(window) - header, 64 * 1024 * 1024)
                    if take <= sig.min_size:
                        continue
                    data = self.src.read(header, take)
                    ok = validate_signature(sig, data) if verify else True
                    if not ok:
                        continue
                    confidence, anchor = sig.capability(anchored)
                    h = hashlib.sha256(data).hexdigest() if len(data) <= 128 * 1024 * 1024 else ""
                    results.append(CarvedFile(
                        sig=sig.name, ext=sig.ext, size=len(data),
                        confidence=confidence, anchor=anchor, start=header,
                        sha256=h, region_end=(pos + len(window)),
                    ))
                    occupied.append((header, header + take))
                    seen += 1
                    if seen > 20_000:
                        break
                done += size
                pos += max(1, size - MAGIC_OVERLAP)
                if self.progress and span:
                    self.progress(
                        f"Carving… {min(100, int(100 * done / total))}%   {len(results)} files",
                        (done / total) if total else 1.0,
                    )
        return results


def build_free_space_regions_from_fat(fat, found: List[dict]) -> List[Tuple[int, int]]:
    """Free-space ranges derived from the FAT free-cluster bitmap."""
    bpb = fat.bpb
    assert bpb
    n = bpb.cluster_count + 2
    regions: List[Tuple[int, int]] = []
    start = None
    for c in range(2, n):
        if fat.is_free_cluster(c):
            if start is None:
                start = c
        else:
            if start is not None:
                regions.append((fat.base_offset + bpb.cluster_sector(start) * bpb.bytes_per_sector,
                                fat.base_offset + bpb.cluster_sector(c) * bpb.bytes_per_sector))
                start = None
    if start is not None:
        regions.append((fat.base_offset + bpb.cluster_sector(start) * bpb.bytes_per_sector,
                        fat.base_offset + (bpb.first_data_sector + bpb.cluster_count * bpb.sectors_per_cluster) * bpb.bytes_per_sector))
    return regions


def build_free_space_regions_from_boot(src, base_offset: int, total_bytes: int) -> List[Tuple[int, int]]:
    """Whole-partition region (used for pure carving on images)."""
    return [(base_offset, base_offset + total_bytes)]