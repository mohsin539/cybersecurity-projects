"""MBR + GPT partition table parser.

Pure read-only parsing used to enumerate usable filesystems on physical
drives and forensic images.  All offsets are validated against the source
size before use (OWASP A01:2004 numeric range validation).
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import List, Optional

SECTOR = 512
PART_TYPE_EMPTY = 0x00
PART_TYPE_GPT_PROTECTIVE = 0xEE
GPT_HEADER_SIGNATURE = b"EFI PART"

FAT_TYPE_MAP = {
    0x01, 0x04, 0x06, 0x0B, 0x0C, 0x0E,  # FAT12/16, FAT16 LBA
    0x0F,                                 # EBR
}
FAT32S = {0x0B, 0x0C}
NTFS_TYPE = {0x07}


@dataclass
class Partition:
    source_path: str
    index: int
    start_sector: int
    end_sector: int
    size_bytes: int
    fs_type_code: int
    fs_name: str
    gpt: bool = False
    guid: str = ""
    name: str = ""

    @property
    def offset(self) -> int:
        return self.start_sector * SECTOR

    @property
    def display(self) -> str:
        return f"Partition {self.index} · {self.fs_name} · {self.size_bytes / 1024 / 1024:.0f} MB"

    def is_fat(self) -> bool:
        return self.fs_type_code in FAT_TYPE_MAP or self.fs_type_code in FAT32S

    def is_ntfs(self) -> bool:
        return self.fs_type_code in NTFS_TYPE


def _clamp_sectors(start: int, count: int, source_size: int) -> int:
    """Clamp partition end to source size (defensive against crafted MBRs)."""
    end = start + count
    max_sectors = source_size // SECTOR
    return min(end, max_sectors)


def parse_mbr_partitions(source, source_size: int) -> List[Partition]:
    """Parse standard MBR (4 primary entry slots)."""
    boot = source.read(0, SECTOR)
    if len(boot) < SECTOR or boot[-2:] != b"\x55\xaa":
        return []
    parts: List[Partition] = []
    for i in range(4):
        ent = boot[446 + i * 16: 446 + i * 16 + 16]
        if len(ent) < 16:
            continue
        ftype = ent[4]
        start = struct.unpack_from("<I", ent, 8)[0]
        count = struct.unpack_from("<I", ent, 12)[0]
        if ftype == PART_TYPE_EMPTY or count == 0 or start == 0:
            continue
        end = _clamp_sectors(start, count, source_size)
        size = max(0, (end - start) * SECTOR)
        parts.append(Partition(
            source_path=source, index=i + 1,
            start_sector=start, end_sector=end, size_bytes=size,
            fs_type_code=ftype, fs_name=fs_type_name(ftype),
        ))
    return parts


def parse_gpt_partitions(source, source_size: int) -> List[Partition]:
    """Parse GPT using the protective MBR (LBA 0) + primary header (LBA 1)."""
    # Locate primary GPT header at LBA 1.
    lba1 = source.read(SECTOR, SECTOR)
    if len(lba1) < SECTOR or lba1[0:8] != GPT_HEADER_SIGNATURE:
        return []
    (sig, rev, hdr_size, crc, resv,
     cur_lba, backup_lba, first_usable, last_usable,
     disk_guid, part_ent_lba, num_entries, entry_size, crc_array) = struct.unpack(
        "<8sIIIIQQQQ16sQII", lba1[:92]
    )
    if num_entries <= 0 or entry_size < 128 or num_entries > 4096:
        return []  # unreasonably sized table — reject
    entries_bytes = num_entries * entry_size + 16  # guard room
    if entries_bytes > (16 * 1024 * 1024):
        return []
    tbl_off = part_ent_lba * SECTOR
    if tbl_off + entries_bytes > source_size:
        return []  # table lies beyond source boundary
    raw = source.read(tbl_off, min(entries_bytes, 4 * 1024 * 1024))
    parts: List[Partition] = []

    def gpart(index: int, raw: bytes, off: int) -> Optional[Partition]:
        if len(raw) < off + entry_size:
            return None
        type_guid = raw[off:off + 16]
        if type_guid == b"\x00" * 16:
            return None  # unused entry
        entry_guid = raw[off + 16:off + 32]
        first = struct.unpack_from("<Q", raw, off + 32)[0]
        last = struct.unpack_from("<Q", raw, off + 40)[0]
        end = _clamp_sectors(first, last - first + 1, source_size)
        size = max(0, (end - first) * SECTOR) if last >= first else 0
        name_b = raw[off + 56: off + 56 + 72]
        name = name_b.decode("utf-16-le", errors="replace").rstrip("\x00")
        return Partition(
            source_path=source, index=index,
            start_sector=first, end_sector=end, size_bytes=size,
            fs_type_code=0xEE if type_guid[:4] != b"\xA2\xA0\xD0\xEB" else 0x07,
            fs_name=gpt_type_name(type_guid),
            gpt=True,
            guid=str(entry_guid.hex()),
            name=name,
        )

    for i in range(num_entries):
        p = gpart(i + 1, raw, i * entry_size)
        if p:
            parts.append(p)
    return parts


def fs_type_name(code: int) -> str:
    names = {
        0x00: "Empty", 0x01: "FAT12", 0x04: "FAT16 (small)", 0x05: "Extended",
        0x06: "FAT16", 0x07: "NTFS", 0x0B: "FAT32", 0x0C: "FAT32 LBA",
        0x0E: "FAT16 LBA", 0x0F: "Extended LBA", 0x11: "Hidden FAT12",
        0x14: "Hidden FAT16", 0x1B: "Hidden FAT32", 0x1C: "Hidden FAT32 LBA",
        0x27: "Windows RE", 0x82: "Linux swap", 0x83: "Linux", 0xEE: "GPT",
    }
    return names.get(code, f"0x{code:02X}")


def gpt_type_name(type_guid: bytes) -> str:
    g = type_guid.hex()
    known = {
        "ebd0a0a2b9e5443387c068b6b72699c7": "Microsoft NTFS/FAT",
        "de94bba406d1d40aa16abfd50179d6ac": "Windows RE",
        "c12a7328f81f11d2ba4b00a0c93ec93b": "EFI System",
        "0fc63daf848347728e793d69b8477de4": "Linux filesystem",
    }
    return known.get(g, "GPT partition")


def parse_partitions(source, source_size: int) -> List[Partition]:
    """Auto-detect MBR vs GPT and return usable partitions."""
    mbr = parse_mbr_partitions(source, source_size)
    if mbr and any(p.fs_type_code == PART_TYPE_GPT_PROTECTIVE for p in mbr):
        gpt = parse_gpt_partitions(source, source_size)
        if gpt:
            return gpt
    # Rebuild sources pointing at this backing store are handled by caller.
    return mbr