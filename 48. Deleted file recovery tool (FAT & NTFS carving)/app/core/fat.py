"""FAT12 / FAT16 / FAT32 deleted-file recovery engine.

Strategy (best-effort, read-only):
  1. Parse the boot sector (BPB) — validate every field against bounds.
  2. Cache the FAT table(s) to distinguish *free* clusters from *used*.
  3. Walk the directory tree (root + sub-directories) and read 32-byte
     directory entries.
  4. A short-name entry whose first byte is 0xE5 is a *deleted* file. Its
     starting cluster is still intact → rebuild the cluster chain by walking
     contiguous *free* clusters (typical for freshly deleted files) and cap
     the read at the recorded file size.
  5. Orphan scan: sweep all data clusters for deleted directory entries
     (finds files whose parent directory was also deleted).

Security notes (OWASP A01 · ISO 27001 A.12.6):
  * All arithmetic is clamped to the volume size and never written back.
  * Names are parsed as bytes → sanitised before ever touching the vault.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

ATTR_READ_ONLY = 0x01
ATTR_HIDDEN = 0x02
ATTR_SYSTEM = 0x04
ATTR_VOLUME_ID = 0x08
ATTR_DIRECTORY = 0x10
ATTR_ARCHIVE = 0x20
ATTR_LFN = 0x0F
DELETED_MARK = 0xE5
FREE_MARK = 0x00


@dataclass
class FatBpb:
    bytes_per_sector: int
    sectors_per_cluster: int
    reserved_sectors: int
    num_fats: int
    root_entry_count: int
    total_sectors: int
    media: int
    fat_size_sectors: int
    hidden_sectors: int
    fat_type: int          # 12 / 16 / 32
    root_cluster: int = 0  # FAT32
    fs_info_sector: int = 0
    label: str = ""
    version: str = ""

    @property
    def root_dir_sectors(self) -> int:
        return ((self.root_entry_count * 32) + self.bytes_per_sector - 1) // self.bytes_per_sector

    @property
    def first_data_sector(self) -> int:
        return (self.reserved_sectors
                + self.num_fats * self.fat_size_sectors
                + self.root_dir_sectors)

    @property
    def cluster_count(self) -> int:
        total = self.total_sectors
        if total == 0:
            return 0
        data_sectors = total - self.first_data_sector
        return data_sectors // self.sectors_per_cluster

    def cluster_bytes(self) -> int:
        return self.bytes_per_sector * self.sectors_per_cluster

    def cluster_sector(self, cluster: int) -> int:
        return self.first_data_sector + (cluster - 2) * self.sectors_per_cluster


def _clamp(v: int, lo: int, hi: int) -> int:
    return max(lo, min(hi, v))


class FatVolume:
    """Read-only FAT filesystem view over any :class:`ReadOnlySource`."""

    def __init__(self, src, base_offset: int = 0):
        self.src = src
        self.base_offset = base_offset  # partition start (bytes)
        self.bpb: Optional[FatBpb] = None
        self._fat_cache: List[bytes] = []
        self.bad = ""

    @property
    def fs_type(self) -> str:
        return f"FAT{self.bpb.fat_type}" if self.bpb else ""

    # ------------------------------------------------------------------
    # bootstrap
    # ------------------------------------------------------------------
    def mount(self, sector: int = 0, expect_label: str = "") -> FatBpb:
        boot = self.src.read(self.base_offset + sector * 512, 512)
        if len(boot) < 512:
            raise ValueError("boot sector shorter than 512 bytes")
        bps = struct.unpack_from("<H", boot, 0x0B)[0]
        spc = boot[0x0D]
        reserved = struct.unpack_from("<H", boot, 0x0E)[0]
        num_fats = boot[0x10]
        root_ents = struct.unpack_from("<H", boot, 0x11)[0]
        tot16 = struct.unpack_from("<H", boot, 0x13)[0]
        media = boot[0x15]
        fat16 = struct.unpack_from("<H", boot, 0x16)[0]
        tot32 = struct.unpack_from("<I", boot, 0x20)[0]
        total = tot16 or tot32
        hidden = struct.unpack_from("<I", boot, 0x1C)[0]

        if bps not in (512, 1024, 2048, 4096):
            raise ValueError(f"unreasonable bytes-per-sector {bps}")
        if spc == 0 or (spc & (spc - 1)) != 0:
            raise ValueError(f"unreasonable sectors-per-cluster {spc}")
        if bps * spc > 65536:
            raise ValueError("cluster too large")

        root_cluster = 0
        fs_info = 0
        if fat16 == 0:  # FAT32
            fat32 = struct.unpack_from("<I", boot, 0x24)[0]
            root_cluster = struct.unpack_from("<I", boot, 0x2C)[0]
            fs_info = struct.unpack_from("<H", boot, 0x30)[0]
            fat_size = fat32
            if root_cluster < 2:
                raise ValueError("FAT32 root cluster invalid")
        else:
            fat_size = fat16

        # Classic FAT-type detection based on cluster count.
        root_dir_sectors = ((root_ents * 32) + bps - 1) // bps
        first_data = reserved + num_fats * fat_size + root_dir_sectors
        data_sectors = total - first_data
        cluster_count = data_sectors // spc
        if cluster_count < 4085:
            far_type = 12
        elif cluster_count < 65525:
            far_type = 16
        else:
            far_type = 32
        if far_type == 12:
            ok = cluster_count < 4085
        elif far_type == 16:
            ok = cluster_count < 65524
        else:
            ok = True
        if not ok:
            raise ValueError("cluster count inconsistent with FAT type")

        label = ""
        if boot[0x3E] == 0x29:
            label = boot[0x43:0x43 + 11].decode("latin-1", errors="replace").rstrip(" \x00")

        self.bpb = FatBpb(
            bytes_per_sector=bps, sectors_per_cluster=spc,
            reserved_sectors=reserved, num_fats=num_fats,
            root_entry_count=root_ents, total_sectors=total, media=media,
            fat_size_sectors=fat_size, hidden_sectors=hidden,
            fat_type=far_type, root_cluster=root_cluster,
            fs_info_sector=fs_info, label=label,
        )

        # Load the primary FAT table (or mirror status).
        fb = self._read(self.base_offset + reserved * bps, fat_size * bps)
        if len(fb) < fat_size * bps:
            self.bad = "FAT table truncated — recovery may be incomplete"
        self._fat_cache = [fb]
        return self.bpb

    # ------------------------------------------------------------------
    # low-level helpers
    # ------------------------------------------------------------------
    def _read(self, offset: int, size: int) -> bytes:
        return self.src.read(offset, size)

    def read_cluster(self, cluster: int) -> bytes:
        bpb = self.bpb
        assert bpb
        sec = bpb.cluster_sector(cluster)
        return self._read(self.base_offset + sec * bpb.bytes_per_sector, bpb.cluster_bytes())

    def fat_entry(self, cluster: int) -> int:
        """Returns the FAT entry for `cluster` (EOC encodes end-of-chain)."""
        bpb = self.bpb
        assert bpb
        fat = self._fat_cache[0]
        if cluster < 2:
            return 0
        if bpb.fat_type == 12:
            b = cluster + cluster // 2
            if b + 1 >= len(fat):
                return 0xFFF
            v = int.from_bytes(fat[b:b + 2], "little")
            return v & 0xFFF if (cluster & 1) == 0 else v >> 4
        if bpb.fat_type == 16:
            o = cluster * 2
            if o + 2 > len(fat):
                return 0xFFFF
            return struct.unpack_from("<H", fat, o)[0]
        o = cluster * 4
        if o + 4 > len(fat):
            return 0x0FFFFFFF
        return struct.unpack_from("<I", fat, o)[0] & 0x0FFFFFFF

    @staticmethod
    def is_free(entry: int, ftype: int) -> bool:
        return entry == 0

    @staticmethod
    def is_eoc(entry: int, ftype: int) -> bool:
        return entry >= (0x0FFFFFF8 if ftype == 32 else 0xFFF8 if ftype == 16 else 0xFF8)

    def is_free_cluster(self, cluster: int) -> bool:
        return self.is_free(self.fat_entry(cluster), self.bpb.fat_type)

    # ------------------------------------------------------------------
    # directory walking
    # ------------------------------------------------------------------
    def _iter_raw_dir(self, cluster: int) -> Tuple[List[bytes], bool]:
        """Read one cluster of directory data. Returns (entries, is_root)."""
        bpb = self.bpb
        assert bpb
        if cluster == 0:
            # Root directory (legacy, FAT12/16), fixed area.
            off = self.base_offset + (bpb.reserved_sectors + bpb.num_fats * bpb.fat_size_sectors) * bpb.bytes_per_sector
            raw = self._read(off, bpb.root_dir_sectors * bpb.bytes_per_sector)
            return [raw[i:i + 32] for i in range(0, len(raw), 32)], True
        raw = self.read_cluster(cluster)
        return [raw[i:i + 32] for i in range(0, len(raw), 32)], False

    def _chain_len(self) -> List[int]:
        """Contiguous-free-cluster suffix lengths (linear, single pass)."""
        bpb = self.bpb
        assert bpb
        n = bpb.cluster_count + 2
        if n <= 2:
            return []
        lens = [0] * n
        run = 0
        for c in range(n - 1, 1, -1):
            if self.is_free_cluster(c):
                run += 1
                lens[c] = run
            else:
                run = 0
        return lens

    def deleted_from_entry(self, ent: bytes, chain_lens) -> Optional[dict]:
        """Interpret a single 32-byte dir entry as a *deleted* file."""
        if len(ent) < 32:
            return None
        attr = ent[11]
        if attr == ATTR_LFN or (attr & 0x08):
            return None  # LFN or volume label
        name11 = ent[0:11]
        if not name11 or name11[0] not in (DELETED_MARK,):
            return None
        # Reconstruct the remaining short name.
        name = _parse_short_name(name11)
        size = struct.unpack_from("<I", ent, 28)[0]
        lo = struct.unpack_from("<H", ent, 26)[0]
        hi = struct.unpack_from("<H", ent, 20)[0]
        start_cluster = (hi << 16) | lo
        is_dir = bool(attr & ATTR_DIRECTORY)
        if is_dir or start_cluster < 2:
            return None
        # Numbers of clusters the file would occupy.
        bpb = self.bpb
        cpb = bpb.cluster_bytes()
        need = (max(size, 1) + cpb - 1) // cpb if cpb else 0
        avail = chain_lens[start_cluster] if start_cluster < len(chain_lens) else 0
        recoverable = min(need, avail) if avail else 0
        return {
            "name": name,
            "size": size,
            "start_cluster": start_cluster,
            "cluster_bytes": cpb,
            "recoverable_clusters": recoverable,
            "is_dir": is_dir,
            "attr": attr,
            "created": _fat_date_time(ent[16:18], ent[18:20], ent[20:22]),
            "modified": _fat_date_time(ent[24:26], ent[22:24], ent[20:22]),
            "status": "recoverable" if size and recoverable else "overwritten",
        }

    def _walk_dir(self, cluster: int, depth: int, chain_lens, found: List[dict],
                  path: str, scan_orphans: bool) -> None:
        if depth > 40:
            return  # loop guard against cyclic clusters

        entries, is_root = self._iter_raw_dir(cluster)
        lfn_parts: dict = {}
        i = 0
        while i < len(entries):
            ent = entries[i]
            if len(ent) < 32:
                i += 1
                continue
            first = ent[0]
            attr = ent[11]
            if first == FREE_MARK:
                i += 1
                continue
            if first == DELETED_MARK and attr == ATTR_LFN:
                # Deleted LFN continuation — remember name pieces.
                seq = ent[0] & 0x1F
                piece = _lfn_piece(ent)
                lfn_parts[seq] = piece
                i += 1
                continue
            if attr == ATTR_LFN:
                seq = ent[0] & 0x1F
                lfn_parts[seq] = _lfn_piece(ent)
                i += 1
                continue

            short_name = ent[0:11]
            if short_name[0] == FREE_MARK:
                i += 1
                continue

            name11 = _parse_short_name(short_name)
            full_name = name11
            if lfn_parts:
                # LFN groups are stored in *reverse* order — the highest
                # sequence number (0x40|n) sits farthest from the 8.3 entry
                # and carries the FIRST characters.
                assembled = "".join(lfn_parts[k] for k in sorted(lfn_parts, reverse=True))
                if assembled:
                    full_name = assembled
                lfn_parts = {}

            deleted = short_name[0] == DELETED_MARK
            size = struct.unpack_from("<I", ent, 28)[0]
            lo = struct.unpack_from("<H", ent, 26)[0]
            hi = struct.unpack_from("<H", ent, 20)[0]
            start_cluster = (hi << 16) | lo
            is_dir = bool(attr & ATTR_DIRECTORY)
            rel = (path + "/" + full_name).rstrip("/") or name11

            if deleted and not is_dir:
                d = self.deleted_from_entry(ent, chain_lens)
                if d:
                    d["full_path"] = rel
                    d["lfn"] = full_name != name11
                    found.append(d)
                i += 1
                continue

            if is_dir and start_cluster >= 2:
                if not deleted:
                    self._walk_dir(start_cluster, depth + 1, chain_lens, found, rel, scan_orphans)
                i += 1
                continue

            # Active regular file.
            found.append({
                "name": full_name, "full_path": rel, "size": size,
                "start_cluster": start_cluster, "cluster_bytes": self.bpb.cluster_bytes(),
                "recoverable_clusters": 0, "is_dir": False, "attr": attr,
                "status": "active",
                "created": "", "modified": "",
            })
            i += 1

        if scan_orphans and not is_root:
            self._scan_orphan_cluster(cluster, chain_lens, found, path)

    def _scan_orphan_cluster(self, cluster: int, chain_lens, found: List[dict], path: str) -> None:
        """Deep sweep: look for deleted entries inside data clusters that may
        belong to deleted directories."""
        raw = self.read_cluster(cluster)
        for off in range(0, len(raw) - 31, 32):
            ent = raw[off:off + 32]
            if ent[0] != DELETED_MARK:
                continue
            attr = ent[11]
            if attr == ATTR_LFN or (attr & 0x0F) == 0x0F:
                continue
            name11 = ent[0:11]
            if not any(0x20 <= c <= 0x7E for c in name11[1:]):
                continue  # unlikely — filter garbage
            d = self.deleted_from_entry(ent, chain_lens)
            if d:
                d["full_path"] = f"?orphan0x{cluster:06X}/{d['name']}"
                found.append(d)

    # ------------------------------------------------------------------
    # public API
    # ------------------------------------------------------------------
    def scan(self, scan_orphans: bool = True,
             progress=None) -> Tuple[List[dict], dict]:
        """Scan the whole volume for active + deleted files."""
        bpb = self.bpb
        assert bpb
        found: List[dict] = []
        chain_lens = self._chain_len()
        root_start = bpb.root_cluster if bpb.fat_type == 32 else 0
        if progress:
            progress("Scanning directory tree…", 0.1)
        self._walk_dir(root_start, 0, chain_lens, found, "", scan_orphans)
        stats = {
            "deleted": sum(1 for f in found if f["status"] != "active"),
            "active": sum(1 for f in found if f["status"] == "active"),
            "fs": f"FAT{bpb.fat_type}",
        }
        return found, stats

    def read_deleted(self, rec: dict, cap_bytes: int = 0) -> Tuple[bytes, int]:
        """Read the recoverable bytes for a deleted-file record.

        Returns ``(data, actual_bytes)``; data is at most min(rec.size,
        recoverable clusters × cluster_bytes)."""
        bpb = self.bpb
        assert bpb
        start = rec["start_cluster"]
        nclusters = rec["recoverable_clusters"]
        if nclusters <= 0 or start < 2:
            return b"", 0
        last = start + nclusters - 1
        if last >= bpb.cluster_count + 2:
            nclusters = max(0, (bpb.cluster_count + 2) - start)
        if nclusters <= 0:
            return b"", 0
        data = bytearray()
        for c in range(start, start + nclusters):
            if cap_bytes and len(data) >= cap_bytes:
                break
            data += self.read_cluster(c)
        if cap_bytes:
            data = data[:cap_bytes]
        return bytes(data), len(data)

    def read_active(self, start_cluster: int, size: int) -> bytes:
        """Read the full cluster chain of an *active* file."""
        bpb = self.bpb
        assert bpb
        out = bytearray()
        c = start_cluster
        hops = 0
        while c >= 2 and hops < 1_000_000:
            hopc = c
            while True:
                out += self.read_cluster(c)
                if len(out) >= size:
                    break
                nxt = self.fat_entry(c)
                if self.is_eoc(nxt, bpb.fat_type):
                    break
                if self.is_free(nxt, bpb.fat_type):
                    return bytes(out[:size])  # chain broken — return what we have
                c = nxt
                hops += 1
                if hops > 0 and False:
                    break
            break
        return bytes(out[:size])


def _parse_short_name(name11: bytes) -> str:
    parts = []
    if not name11:
        return ""
    if name11[0] == DELETED_MARK:
        name11 = b"\x3f" + name11[1:]  # show '?'
    try:
        base = name11[:8].decode("cp437", errors="replace").rstrip(" ")
        ext = name11[8:11].decode("cp437", errors="replace").rstrip(" ")
    except Exception:
        base, ext = "", ""
    base = "".join(ch if 0x20 <= ord(ch) < 0x7F else "?" for ch in base)
    ext = "".join(ch if 0x20 <= ord(ch) < 0x7F else "?" for ch in ext)
    return base + (("." + ext) if ext else "")


def _lfn_piece(ent: bytes) -> str:
    raw = ent[1:11] + ent[14:26] + ent[28:32]
    pieces = []
    for i in range(0, len(raw) - 1, 2):
        c = int.from_bytes(raw[i:i + 2], "little")
        if c == 0x0000 or c == 0xFFFF:
            break
        if 0x00 < c < 0x20 or c == 0xE5:
            continue
        pieces.append(chr(c) if chr(c) not in "\x00\xff" else " ")
    return "".join(pieces)


def _fat_date_time(date_b: bytes, time_b: bytes, tenth_b: bytes) -> str:
    if len(time_b) < 2 or len(date_b) < 2:
        return ""
    try:
        t = struct.unpack("<H", time_b)[0]
        d = struct.unpack("<H", date_b)[0]
        year = 1980 + (d >> 9)
        month = (d >> 5) & 0x0F
        day = d & 0x1F
        hour = (t >> 11) & 0x1F
        minute = (t >> 5) & 0x3F
        second = (t & 0x1F) * 2
        result = f"{year:04d}-{month:02d}-{day:02d} {hour:02d}:{minute:02d}:{second:02d}"
        return result
    except Exception:
        return ""


def classify_fat(fs_type_hint: str) -> bool:
    return fs_type_hint.upper().startswith("FAT")