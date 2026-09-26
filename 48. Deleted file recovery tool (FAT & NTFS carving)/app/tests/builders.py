"""Synthetic image builders — generate FAT12/16/32 and NTFS disk images
entirely in Python so the recovery engine can be exercised *without*
admin rights or real drives (forensic-lab best practice: test on media that
was intentionally constructed — see NIST SP 800-88 sanitization workflow).

The builders intentionally create already-*deleted* directory entries and
cleared FAT chains / MFT records so recovery results are deterministic.
"""

from __future__ import annotations

import os
import struct
import tempfile


# ==========================================================================
# helpers
# ==========================================================================
def _boot_fat(bps: int = 512, spc: int = 1, reserved: int = 64, num_fats: int = 2,
              root_entries: int = 0, media: int = 0xF8, total_sectors: int = 0,
              fat_size: int = 0, fat_type: int = 32, root_cluster: int = 2,
              label: str = "DEMO", serial: int = 0x12345678) -> bytes:
    b = bytearray(512)
    b[0] = 0xEB
    b[1] = 0x3C
    b[2] = 0x90
    b[3:11] = b"RECOVPRO"
    struct.pack_into("<H", b, 0x0B, bps)
    b[0x0D] = spc
    struct.pack_into("<H", b, 0x0E, reserved)
    b[0x10] = num_fats
    struct.pack_into("<H", b, 0x11, root_entries)
    struct.pack_into("<H", b, 0x13, 0 if fat_type == 32 else total_sectors)
    b[0x15] = media
    struct.pack_into("<H", b, 0x16, 0 if fat_type == 32 else fat_size)
    struct.pack_into("<I", b, 0x1C, 0)
    struct.pack_into("<I", b, 0x20, total_sectors)
    if fat_type == 32:
        struct.pack_into("<I", b, 0x24, fat_size)
        b[0x28] = 0
        b[0x2A] = 0
        struct.pack_into("<I", b, 0x2C, root_cluster)
        struct.pack_into("<H", b, 0x30, 1)   # FSInfo sector
        struct.pack_into("<H", b, 0x32, 0)   # backup boot
        b[0x42] = 0x29
        struct.pack_into("<I", b, 0x43, serial)
        b[0x47:0x52] = label.upper().ljust(11, " ").encode("ascii")
        b[0x52:0x5A] = b"FAT32   "
    else:
        b[0x26] = 0x29
        struct.pack_into("<I", b, 0x27, serial)
        b[0x2B:0x36] = label.upper().ljust(11, " ").encode("ascii")
        b[0x36:0x3E] = {12: b"FAT12   ", 16: b"FAT16   "}[fat_type]
    b[0x1FE:0x200] = b"\x55\xaa"
    return bytes(b)


def _dir_entry(name11: bytes, attr: int, first_cluster: int, size: int,
               time_val: int = 0x6C64, date_val: int = 0x5636) -> bytes:
    e = bytearray(32)
    if len(name11) < 11:
        name11 = name11.ljust(11, b" ")
    e[0:11] = name11[:11]
    e[11] = attr
    struct.pack_into("<H", e, 14, time_val)
    struct.pack_into("<H", e, 16, date_val)
    struct.pack_into("<H", e, 18, date_val)
    struct.pack_into("<H", e, 20, (first_cluster >> 16) & 0xFFFF)
    struct.pack_into("<H", e, 22, time_val)
    struct.pack_into("<H", e, 24, date_val)
    struct.pack_into("<H", e, 26, first_cluster & 0xFFFF)
    struct.pack_into("<I", e, 28, size)
    return bytes(e)


def _lfn_entry(seq: int, text: str) -> bytes:
    """One LFN directory entry carrying up to 13 UTF-16 characters.

    Name fields are UTF-16LE arrays: 10 bytes at 0x01, 12 bytes at 0x0E,
    4 bytes at 0x1C (5+6+2 = 13 code units)."""
    e = bytearray(32)
    e[0] = seq
    e[11] = 0x0F
    e[13] = 0
    up = text.encode("utf-16-le")
    chunk = (up + b"\xff\xff" * 13)[:26]
    e[1:11] = chunk[0:10]
    e[14:26] = chunk[10:22]
    e[28:32] = chunk[22:26]
    return bytes(e)


def _deleted_name(name8: str, ext3: str) -> bytes:
    """8.3 name with first byte set to the 0xE5 deleted marker."""
    full = (name8[:8].encode().ljust(8, b" ") + ext3[:3].encode())[:11].ljust(11, b" ")
    return b"\xe5" + full[1:]


# ==========================================================================
# FAT32 image
# ==========================================================================
def build_fat32_image(path: str, total_sectors: int = 70000,
                      label: str = "DEMO") -> dict:
    """Builds a FAT32 image (~34 MB) with active, deleted and carve targets."""
    bps, spc = 512, 1
    reserved, num_fats = 64, 2
    root_entries, hidden, media = 0, 0, 0xF8
    root_cluster = 2

    # Solve FAT size so cluster count lands > 65524 (FAT32 classification).
    fat = 512
    for _ in range(5):
        clusters = total_sectors - reserved - num_fats * fat
        fat = max(1, (clusters * 4 + bps - 1) // bps)
    total_sectors = reserved + num_fats * fat + clusters
    first_data = reserved + num_fats * fat
    img = bytearray(total_sectors * bps)

    # boot
    img[0:512] = _boot_fat(bps=bps, spc=spc, reserved=reserved, num_fats=num_fats,
                           media=media, total_sectors=total_sectors, fat_size=fat,
                           fat_type=32, root_cluster=root_cluster, label=label)

    # FAT tables (all zero = every cluster free)
    fat_sector = bytearray(fat * bps)
    # initialise reserved markers: cluster 0/1 always 0x0FFFFFFF
    def fat_entry_32(buf, cluster, val):
        struct.pack_into("<I", buf, cluster * 4, val)
    fat_entry_32(fat_sector, 0, 0x0FFFFFF8)
    fat_entry_32(fat_sector, 1, 0x0FFFFFFF)
    for f in range(num_fats):
        img[reserved * bps + f * fat * bps: reserved * bps + (f + 1) * fat * bps] = fat_sector

    def cluster_base(c):
        return (first_data + (c - root_cluster) * spc) * bps

    # ---- build directory content (root cluster = 2) ----
    entries = bytearray(512)
    # active file  NOTES.TXT  (clusters 3)
    notes = b"Q3 numbers are stable. Review attached report.\n" * 20
    struct.pack_into("<I", fat_sector, 3 * 4, 0x0FFFFFFF)
    img[cluster_base(3):cluster_base(3) + 512] = notes.ljust(512, b"\x00")[:512]
    entries[0:32] = _dir_entry(b"NOTES    TXT", 0x20, 3, len(notes))

    # deleted file REPORT.DOC (started cluster 5)
    report = (b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\ntrailer\n"
              b"<< /Root 1 0 R >>\n%%EOF\n") + b"X" * 700
    report = report[:1500]
    for i, c in enumerate(range(5, 5 + (len(report) + 511) // 512)):
        img[cluster_base(c):cluster_base(c) + 512] = report[i * 512:(i + 1) * 512].ljust(512, b"\x00")
        # FAT is left zero → cluster chain broken → looks *deleted*.
    entries[32:64] = _dir_entry(_deleted_name("REPORT", "DOC"), 0x20, 5, len(report))  # deleted via 0xE5

    # deleted JPEG (carve target) — FAT cleared, so live in "free space"
    jpeg = (b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
            + b"\x00" * 1800 + b"\xff\xd9")
    jpeg = jpeg.ljust(2048, b"\x00")[:2048]
    for c in range(20, 24):
        img[cluster_base(c):cluster_base(c) + 512] = jpeg[(c - 20) * 512:(c - 20 + 1) * 512]
    entries[64:96] = _dir_entry(_deleted_name("PHOTO", "JPG"), 0x20, 20, len(jpeg.strip(b"\x00")))

    # active file with LFN:  Q3-FINANCIALS.XLSX → short Q3FINA~1.XLS
    # LFN entries stored in reverse: seq 0x42 (first 13 chars) farthest,
    # seq 0x41 (last chars) nearest the 8.3 entry.
    lfn_parts = ["Q3-FINANCIALS", ".XLSX"]
    entries[96:128] = _lfn_entry(0x42, lfn_parts[0])
    entries[128:160] = _lfn_entry(0x41, lfn_parts[1])
    xlsx = b"PK\x03\x04" + b"\x00" * 400 + b"PK\x05\x06" + b"\x00" * 106
    for c in range(30, 32):
        img[cluster_base(c):cluster_base(c) + 512] = (
            xlsx if c == 30 else xlsx + b"\x00" * 300)[:512]
    struct.pack_into("<I", fat_sector, 30 * 4, 31)
    struct.pack_into("<I", fat_sector, 31 * 4, 0x0FFFFFFF)
    entries[160:192] = _dir_entry(b"Q3FINA~1XLS", 0x20, 30, len(xlsx))

    img[cluster_base(2):cluster_base(3)] = bytes(entries)

    # copy FAT into both tables
    for f in range(num_fats):
        img[reserved * bps + f * fat * bps: reserved * bps + (f + 1) * fat * bps] = fat_sector

    # FSInfo conventional fields (bonus realism)
    fsi_off = (reserved + 1) * bps
    img[fsi_off + 0x1E4:fsi_off + 0x1E8] = b"RRaA"
    img[fsi_off + 0x1E8:fsi_off + 0x1EC] = b"\x00" * 4
    img[fsi_off + 0x1EC:fsi_off + 0x1F0] = b"\x00\x00\x00\x00"
    img[fsi_off + 0x1F0:fsi_off + 0x1FD] = b"\x00" * 13
    img[fsi_off + 0x1FE:fsi_off + 0x200] = b"\x55\xaa"

    with open(path, "wb") as f:
        f.write(img)

    return {
        "path": path, "fat_type": 32, "total_sectors": total_sectors,
        "cluster_bytes": bps * spc, "deleted": {"REPORT.DOC": 5, "PHOTO.JPG": 20},
        "active": {"NOTES.TXT": 3, "Q3-FINANCIALS.XLSX": 30},
    }


def build_demo_fat32_image(path: Optional[str] = None) -> str:
    path = path or os.path.join(tempfile.gettempdir(), "recovpro_demo_fat32.img")
    build_fat32_image(path)
    return path


# ==========================================================================
# FAT16 image (smaller)
# ==========================================================================
def build_fat16_image(path: str, total_sectors: int = 4136,
                      label: str = "DEMO16") -> dict:
    bps, spc = 512, 1
    reserved, num_fats = 8, 2
    root_entries = 64
    fat = 16
    total_sectors = reserved + num_fats * fat + (root_entries * 32 // 512) + 4096
    first_data = reserved + num_fats * fat + (root_entries * 32 // 512)
    img = bytearray(total_sectors * bps)
    img[0:512] = _boot_fat(bps=bps, spc=spc, reserved=reserved, num_fats=num_fats,
                           root_entries=root_entries, media=0xF8,
                           total_sectors=total_sectors, fat_size=fat,
                           fat_type=16, label=label)
    fat_sector = bytearray(fat * bps)
    img[reserved * bps: (reserved + num_fats * fat) * bps] = fat_sector * num_fats

    def cluster_base(c):
        return (first_data + (c - 2) * spc) * bps

    # root directory at reserved+2*fat
    root_off = (reserved + num_fats * fat) * bps
    content = b"short FAT16 text payload\n" * 30
    img[cluster_base(2):cluster_base(3)] = content.ljust(512, b"\x00")[:512]
    img[root_off:root_off + 32] = _dir_entry(b"FAT16F~1TXT", 0x20, 2, len(content))
    img[root_off + 32:root_off + 64] = _dir_entry(_deleted_name("DELETED", "TXT"), 0x20, 3, 100)
    img[cluster_base(3):cluster_base(3) + 100] = b"i was deleted, recover me\n" * 5
    # mark cluster 2 chained
    struct.pack_into("<H", fat_sector, 2 * 2, 0xFFFF)
    img[reserved * bps: (reserved + num_fats * fat) * bps] = fat_sector * num_fats
    with open(path, "wb") as f:
        f.write(img)
    return {"path": path, "fat_type": 16, "deleted": {"DELETED.TXT": 3}}


# ==========================================================================
# NTFS image (minimal but valid enough for the engine)
# ==========================================================================
def _ntfs_record(flags: int, attrs: list, seq: int = 1) -> bytes:
    """attrs: list of (attr_type, bytes_content) → becomes resident attrs."""
    rec = bytearray(1024)
    rec[0:4] = b"FILE"
    rec[0x08] = 0
    struct.pack_into("<H", rec, 0x0A, 0)       # USA count 0 → no fixups
    struct.pack_into("<H", rec, 0x10, seq)
    struct.pack_into("<H", rec, 0x12, 1)
    p = 0x38
    for atype, content in attrs:
        total = 0x18 + len(content)
        struct.pack_into("<I", rec, p, atype)
        struct.pack_into("<I", rec, p + 4, total)
        rec[p + 8] = 0                      # resident
        rec[p + 9] = 0
        struct.pack_into("<H", rec, p + 10, 0)
        struct.pack_into("<H", rec, p + 12, 1)
        struct.pack_into("<H", rec, p + 14, 1)
        struct.pack_into("<I", rec, p + 0x10, len(content))
        struct.pack_into("<H", rec, p + 0x14, 0x18)
        rec[p + 0x18:p + 0x18 + len(content)] = content
        p += total
    struct.pack_into("<I", rec, p, 0xFFFFFFFF)
    struct.pack_into("<I", rec, p + 4, 8)
    struct.pack_into("<H", rec, 0x14, 0x38)   # first attribute offset
    struct.pack_into("<H", rec, 0x16, flags)
    struct.pack_into("<I", rec, 0x18, p + 8)
    struct.pack_into("<I", rec, 0x1C, 1024)
    return bytes(rec)


def _si(times: bytes = b"\x00" * 48) -> bytes:
    return times.ljust(48, b"\x00")[:48]


def _fn(parent: int, name: str) -> bytes:
    nb = name.encode("utf-16-le")
    flen = len(name) * 2
    b = struct.pack("<QQQQQQQII", parent, 0, 0, 0, 0, flen, flen, 0x20, 0)
    b += bytes([len(name), 1]) + nb
    return b


def _data_res(resident: bytes) -> bytes:
    return resident


def build_ntfs_image(path: str, total_clusters: int = 4096,
                     label: str = "DEMO-NTFS") -> dict:
    bps, spc = 512, 1
    mft_lcn = 4
    mft_records = 96            # clusters 4..99
    rec_size = 1024
    total_sectors = total_clusters
    img = bytearray(total_clusters * bps)

    # boot sector
    b = bytearray(bps)
    b[0] = 0xEB
    b[1] = 0x52
    b[2] = 0x90
    b[3:11] = b"NTFS    "
    struct.pack_into("<H", b, 0x0B, bps)
    b[0x0D] = spc
    struct.pack_into("<Q", b, 0x28, total_clusters)
    struct.pack_into("<Q", b, 0x30, mft_lcn)
    struct.pack_into("<Q", b, 0x38, mft_lcn)       # mirror
    b[0x40] = 0xF6                                     # record size → 2^-(-10)=1024 bytes
    b[0x44] = 0                                  # index buffer → 1024
    struct.pack_into("<I", b, 0x48, serial := 0x1234)
    b[0x50:0x58] = b"NTFS    "
    b[0x1FE:0x200] = b"\x55\xaa"
    img[0:bps] = bytes(b)

    mft_region = bps * mft_lcn   # absolute offset where MFT begins

    # --- record 0: $MFT with non-resident $DATA covering clusters mft_lcn..mft_lcn+n
    # attr payload: non-resident $DATA
    def nonres_file_record(flags, real_size, alloc_size, runs_encoded, extra_attrs=()):
        rec = bytearray(1024)
        rec[0:4] = b"FILE"
        struct.pack_into("<H", rec, 0x0A, 0)
        struct.pack_into("<H", rec, 0x10, 1)
        struct.pack_into("<H", rec, 0x12, 1)
        p = 0x38
        for atype, content in extra_attrs:
            total = 0x18 + len(content)
            struct.pack_into("<I", rec, p, atype)
            struct.pack_into("<I", rec, p + 4, total)
            rec[p + 8] = 0
            struct.pack_into("<I", rec, p + 0x10, len(content))
            struct.pack_into("<H", rec, p + 0x14, 0x18)
            rec[p + 0x18:p + 0x18 + len(content)] = content
            p += total
        # non-resident $DATA
        total = 0x40 + len(runs_encoded)
        struct.pack_into("<I", rec, p, 0x80)
        struct.pack_into("<I", rec, p + 4, total)
        rec[p + 8] = 1                    # non-resident
        struct.pack_into("<H", rec, p + 0x10, 0)          # start VCN
        last_vcn = max(0, (real_size + bps - 1) // bps - 1)
        struct.pack_into("<Q", rec, p + 0x18, last_vcn)
        struct.pack_into("<H", rec, p + 0x20, 0x40)       # runlist offset
        struct.pack_into("<H", rec, p + 0x22, 0)
        struct.pack_into("<Q", rec, p + 0x28, alloc_size)
        struct.pack_into("<Q", rec, p + 0x30, real_size)
        struct.pack_into("<Q", rec, p + 0x38, real_size)
        rec[p + 0x40:p + 0x40 + len(runs_encoded)] = runs_encoded
        p += total
        struct.pack_into("<I", rec, p, 0xFFFFFFFF)
        struct.pack_into("<I", rec, p + 4, 8)
        struct.pack_into("<H", rec, 0x14, 0x38)
        struct.pack_into("<H", rec, 0x16, flags)
        struct.pack_into("<I", rec, 0x18, p + 8)
        struct.pack_into("<I", rec, 0x1C, 1024)
        return bytes(rec)

    # runs encoding for MFT: clusters [mft_lcn, mft_lcn + mft_records)
    run_header = ((mft_records.bit_length() + 7) // 8) | (1 << 4)  # 1-byte len + 1-byte delta
    runs = bytes([run_header]) + mft_records.to_bytes(1, "little") + bytes([mft_lcn])
    mft_real = mft_records * rec_size
    rec0 = nonres_file_record(0x0001, mft_real, mft_records * bps, runs,
                              extra_attrs=[(0x30, _fn(5, "$MFT"))])
    img[mft_region:mft_region + rec_size] = rec0

    # --- record 1 $MFTMirr (mirror cluster 4) — minimal active record
    img[mft_region + rec_size:mft_region + 2 * rec_size] = _ntfs_record(
        0x0001, [(0x30, _fn(5, "$MFTMirr"))])

    # --- bitmap (record 6): resident, free clusters = 100..109, 200..203
    bitmap = bytearray((total_clusters + 7) // 8)
    for c in range(total_clusters):
        bitmap[c >> 3] |= 1 << (c & 7)
    for c in list(range(100, 110)) + list(range(200, 204)):
        bitmap[c >> 3] &= ~(1 << (c & 7))     # free
    rec6 = _ntfs_record(0x0001, [(0x10, _si()),
                                 (0x30, _fn(5, "$Bitmap")),
                                 (0x80, bytes(bitmap))])
    img[mft_region + 6 * rec_size: mft_region + 7 * rec_size] = rec6

    # --- record 25: deleted resident file
    hello = b"hello deleted forensic world\n"
    rec25 = _ntfs_record(0x0000, [(0x10, _si()),
                                  (0x30, _fn(5, "HELLO.TXT")),
                                  (0x80, hello)])
    img[mft_region + 25 * rec_size: mft_region + 26 * rec_size] = rec25

    # --- record 26: deleted non-resident file at clusters 100..109 (free)
    big = (b"BIG-DELETED-CONTENT-" + b"0123456789abcdef") * 310   # ~ 10 clusters
    for i, c in enumerate(range(100, 110)):
        img[c * bps:(c + 1) * bps] = big[i * bps:(i + 1) * bps].ljust(bps, b"\x00")
    enc_len = (10).to_bytes(1, "little")
    enc_off = bytes([0x64])                     # +100
    runs = bytes([(len(enc_len)) | (1 << 4)]) + enc_len + enc_off
    rec26 = nonres_file_record(0x0000, 5120, 10 * bps, runs,
                               extra_attrs=[(0x10, _si()), (0x30, _fn(5, "BIG.BIN"))])
    img[mft_region + 26 * rec_size: mft_region + 27 * rec_size] = rec26

    # --- record 27: active file (resident)
    active = b"active file, do not recover\n"
    rec27 = _ntfs_record(0x0001, [(0x10, _si()),
                                  (0x30, _fn(5, "ACTIVE.TXT")),
                                  (0x80, active)])
    img[mft_region + 27 * rec_size: mft_region + 28 * rec_size] = rec27

    with open(path, "wb") as f:
        f.write(img)
    return {"path": path, "fat_type": None, "fs": "NTFS",
            "deleted": {"HELLO.TXT": 25, "BIG.BIN": 26}, "active": {"ACTIVE.TXT": 27}}


def build_demo_ntfs_image(path: Optional[str] = None) -> str:
    path = path or os.path.join(tempfile.gettempdir(), "recovpro_demo_ntfs.img")
    build_ntfs_image(path)
    return path


# ==========================================================================
if __name__ == "__main__":
    p1 = build_demo_fat32_image()
    p2 = build_demo_ntfs_image()
    p3 = os.path.join(tempfile.gettempdir(), "recovpro_demo_fat16.img")
    build_fat16_image(p3)
    print("built:", p1)
    print("built:", p2)
    print("built:", p3)