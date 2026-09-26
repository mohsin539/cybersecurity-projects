"""NTFS deleted-file recovery engine.

Reads the raw $MFT directly (no OS filesystem driver), so it works on
volumes, physical partitions and forensic images alike, and can see
*deleted* file records whose "in use" flag was cleared.

Correctness guards (NIST IR / ISO A.12.6):
  * USN (update sequence) fixups are applied to every record.
  * Records use the on-disk record size from the boot sector.
  * Every cluster touched by a (possibly deleted) data run is checked
    against $Bitmap: clusters already re-allocated are treated as
    overwritten and never read past a re-used boundary.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple

SIG_FILE = b"FILE"
SIG_INDEX = b"INDX"

AT_STANDARD_INFO = 0x10
AT_ATTRIBUTE_LIST = 0x20
AT_FILE_NAME = 0x30
AT_OBJECT_ID = 0x40
AT_VOLUME_NAME = 0x60
AT_VOLUME_INFO = 0x70
AT_DATA = 0x80
AT_INDEX_ROOT = 0x90
AT_INDEX_ALLOC = 0xA0
AT_BITMAP = 0xB0
AT_END = 0xFFFFFFFF

FILE_ATTR_IN_USE = 0x0001
FILE_ATTR_DIRECTORY = 0x0002
FILE_ATTR_DELETED = 0x4000  # (informational; in-use bit cleared on delete)

_LONG_TIMES = 1_000_000
_EPOCH = datetime(1601, 1, 1)


def _filetime(ft_int: int) -> str:
    if ft_int == 0:
        return ""
    try:
        dt = _EPOCH + timedelta(microseconds=ft_int // 10)
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except (OverflowError, ValueError):
        return ""


@dataclass
class DataRun:
    vcn: int
    lcn: int          # -1 → sparse
    length: int       # in clusters


class NtfsVolume:
    def __init__(self, src, base_offset: int = 0):
        self.src = src
        self.base_offset = base_offset
        self.bps = 512
        self.spc = 8
        self.cluster_bytes = 4096
        self.mft_lcn = 0
        self.record_size = 1024
        self._mft_runs: List[DataRun] = []
        self._bitmap_runs: List[DataRun] = []
        self._bitmap_resident: bytes = b""
        self._mft_records_total = 0
        self._record_count_from_mft = 0

    # ------------------------------------------------------------------
    # mount
    # ------------------------------------------------------------------
    def mount(self, sector: int = 0) -> None:
        boot = self.src.read(self.base_offset + sector * self.bps, 512)
        if len(boot) < 512:
            raise ValueError("boot sector shorter than 512")
        oem = boot[3:11]
        if oem != b"NTFS    ":
            raise ValueError("not an NTFS boot sector")
        self.bps = struct.unpack_from("<H", boot, 0x0B)[0]
        self.spc = boot[0x0D]
        if self.bps not in (512, 1024, 2048, 4096) or self.spc == 0:
            raise ValueError("implausible NTFS geometry")
        self.cluster_bytes = self.bps * self.spc
        self.mft_lcn = struct.unpack_from("<Q", boot, 0x30)[0]
        clumfr = struct.unpack_from("<b", boot, 0x40)[0]
        if clumfr > 0:
            self.record_size = clumfr * self.cluster_bytes
        else:
            self.record_size = 1 << (-clumfr)

        if self.record_size not in (512, 1024, 2048, 4096, 8192, 16384, 32768):
            raise ValueError(f"implausible MFT record size {self.record_size}")

        # Record 0 = $MFT → its $DATA runlist locates the whole MFT.
        mft_rec = self._read_mft_record_raw(self.mft_lcn * self.cluster_bytes, 0)
        rec = self._fixup(mft_rec)
        if rec[0:4] != SIG_FILE:
            raise ValueError("$MFT record missing FILE signature")
        runs = self._attr_data_runs(rec)
        if not runs:
            raise ValueError("$MFT has no data runs")
        self._mft_runs = runs
        self._mft_total = sum(r.length for r in runs) * self.cluster_bytes

        # Record 6 = $Bitmap.
        mft_base = self.mft_lcn * self.cluster_bytes
        bm = self._read_mft_record_raw(mft_base, 6)
        bm = self._fixup(bm)
        if bm[0:4] != SIG_FILE:
            raise ValueError("$Bitmap record missing FILE signature")
        data, runs = self._attr_data_resident_or_runs(bm)
        self._bitmap_resident = data if runs is None else b""
        self._bitmap_runs = runs or []

        self._record_count_from_mft = self._mft_total // self.record_size

    # ------------------------------------------------------------------
    # low-level reads
    # ------------------------------------------------------------------
    def _read(self, abs_offset: int, size: int) -> bytes:
        return self.src.read(abs_offset, size)

    def _read_mft_record_raw(self, mft_base_offset: int, idx: int) -> bytes:
        """Read an MFT record at *base offset of the MFT buffer*."""
        off = mft_base_offset + idx * self.record_size
        return self._read(off, self.record_size)

    def _fixup(self, rec: bytes) -> bytes:
        if len(rec) < 48 or rec[0:4] != SIG_FILE:
            return rec
        usa_off, usa_count = struct.unpack_from("<HH", rec, 4)
        if usa_count < 2 or usa_off + usa_count * 2 > len(rec):
            return rec
        out = bytearray(rec)
        seq = struct.unpack_from("<H", rec, usa_off)[0]
        n_sectors = len(rec) // self.bps
        for i in range(1, min(n_sectors + 1, usa_count)):
            expected = struct.unpack_from("<H", rec, usa_off + i * 2)[0]
            pos = i * self.bps - 2
            if struct.unpack_from("<H", rec, pos)[0] == seq:
                out[pos:pos + 2] = struct.pack("<H", expected)
        return bytes(out)

    def mft_read(self, idx: int) -> bytes:
        return self._fixup(self._mft_read_raw(idx))

    def _mft_read_raw(self, idx: int) -> bytes:
        start = idx * self.record_size
        for run in self._mft_runs:
            rel = start - run.vcn * self.cluster_bytes
            if 0 <= rel < run.length * self.cluster_bytes:
                take = min(self.record_size, run.length * self.cluster_bytes - rel)
                if take < self.record_size:
                    return b""  # record crosses run boundary (shouldn't happen)
                lcn_off = self.base_offset + (run.lcn + rel // self.cluster_bytes) * self.cluster_bytes
                return self._read(lcn_off + rel % self.cluster_bytes, self.record_size)
        return b""

    def _attr_iter(self, rec: bytes):
        if len(rec) < 48:
            return
        p = struct.unpack_from("<H", rec, 0x14)[0]
        if p >= len(rec):
            return
        while p + 8 <= len(rec):
            atype, alen = struct.unpack_from("<II", rec, p)
            if alen < 16 or p + alen > len(rec):
                break
            if atype == AT_END:
                break
            yield p, atype, alen
            p += alen

    def _attr_data_runs(self, rec: bytes) -> List[DataRun]:
        for p, atype, alen in self._attr_iter(rec):
            if atype != AT_DATA:
                continue
            non_res = rec[p + 0x08]
            if not non_res:
                continue
            rl_off = struct.unpack_from("<H", rec, p + 0x20)[0]
            return self._parse_runs(rec[p + rl_off: p + alen])
        return []

    def _attr_data_resident_or_runs(self, rec: bytes):
        for p, atype, alen in self._attr_iter(rec):
            if atype != AT_DATA:
                continue
            if not rec[p + 0x08]:
                size = struct.unpack_from("<I", rec, p + 0x10)[0]
                c_off = struct.unpack_from("<H", rec, p + 0x14)[0]
                if p + c_off + size <= len(rec):
                    return rec[p + c_off: p + c_off + size], None
                return b"", None
            rl_off = struct.unpack_from("<H", rec, p + 0x20)[0]
            return b"", self._parse_runs(rec[p + rl_off: p + alen])
        return b"", None

    @staticmethod
    def _parse_runs(rl: bytes) -> List[DataRun]:
        runs: List[DataRun] = []
        p = 0
        vcn = 0
        lcn = 0
        while p < len(rl):
            hdr = rl[p]
            if hdr == 0:
                break
            lb = hdr & 0x0F
            ob = hdr >> 4
            p += 1
            if p + lb > len(rl):
                break
            length = int.from_bytes(rl[p:p + lb], "little")
            p += lb
            if ob:
                if p + ob > len(rl):
                    break
                delta = int.from_bytes(rl[p:p + ob], "little", signed=True)
                p += ob
                lcn += delta
                runs.append(DataRun(vcn, lcn, length))
            else:
                runs.append(DataRun(vcn, -1, length))  # sparse
            vcn += length
        return runs

    # ------------------------------------------------------------------
    # $Bitmap lookups
    # ------------------------------------------------------------------
    def _bitmap_cluster_used(self, cluster: int) -> bool:
        byte_idx = cluster >> 3
        bit = cluster & 7
        if self._bitmap_resident:
            if byte_idx >= len(self._bitmap_resident):
                return False
            return bool((self._bitmap_resident[byte_idx] >> bit) & 1)
        b = self._read_nonres_byte(self._bitmap_runs, byte_idx)
        return bool((b >> bit) & 1) if b is not None else False

    def _read_nonres_byte(self, runs: List[DataRun], byte_idx: int) -> Optional[int]:
        cluster = byte_idx // self.cluster_bytes
        for run in runs:
            if run.vcn <= cluster < run.vcn + run.length:
                if run.lcn < 0:
                    return 0
                off = self.base_offset + (run.lcn + (cluster - run.vcn)) * self.cluster_bytes
                rel = byte_idx % self.cluster_bytes
                raw = self._read(off + rel, 1)
                return raw[0] if len(raw) == 1 else None
        return None

    # ------------------------------------------------------------------
    # attribute value readers (for runlists)
    # ------------------------------------------------------------------
    def _read_runs(self, runs: List[DataRun], offset: int, size: int,
                   check_bitmap=False) -> Tuple[bytes, int]:
        """Read `size` bytes starting at `offset` within a data attribute.

        When ``check_bitmap`` is True, sparse/over-reallocated clusters are
        treated as a truncation point (stops reading).
        Returns (data, bytes_read) — the latter can be < size."""
        out = bytearray()
        remaining = size
        raw_offset = offset
        while remaining > 0:
            cluster = raw_offset // self.cluster_bytes
            run = None
            for r in runs:
                if r.vcn <= cluster < r.vcn + r.length:
                    run = r
                    break
            if run is None:
                break
            if run.lcn < 0:
                out += b"\x00" * min(remaining, self.cluster_bytes)
                raw_offset += self.cluster_bytes
                remaining = max(0, remaining - self.cluster_bytes)
                continue
            if check_bitmap and self._bitmap_cluster_used(run.lcn + (cluster - run.vcn)):
                break  # cluster re-used → file overwritten here
            cluster_rel = (cluster - run.vcn) * self.cluster_bytes
            chunk_start = raw_offset % self.cluster_bytes
            chunk = min(remaining, self.cluster_bytes - chunk_start,
                        run.length * self.cluster_bytes - cluster_rel)
            abs_off = self.base_offset + (run.lcn + cluster - run.vcn) * self.cluster_bytes + chunk_start
            data = self._read(abs_off, chunk)
            if not data:
                break
            out += data
            raw_offset += chunk
            remaining -= chunk
        return bytes(out), len(out)

    # ------------------------------------------------------------------
    # record → file summary
    # ------------------------------------------------------------------
    def _attr_file_name(self, rec: bytes) -> Optional[dict]:
        for p, atype, alen in self._attr_iter(rec):
            if atype != AT_FILE_NAME:
                continue
            if rec[p + 0x08]:
                continue
            c_off = struct.unpack_from("<H", rec, p + 0x14)[0]
            c_size = struct.unpack_from("<I", rec, p + 0x10)[0]
            if c_size < 0x42:
                continue
            c = rec[p + c_off: p + c_off + c_size]
            parent = struct.unpack_from("<Q", c, 0)[0] & 0xFFFFFFFFFFFF
            nlen = c[0x40]
            ns = c[0x41]
            name = c[0x42:0x42 + nlen * 2].decode("utf-16-le", errors="replace")
            if not name:
                continue
            return {"name": name, "parent": parent, "namespace": ns}
        return None

    def _attr_std_info_times(self, rec: bytes) -> Tuple[str, str, str]:
        for p, atype, alen in self._attr_iter(rec):
            if atype != AT_STANDARD_INFO:
                continue
            if rec[p + 0x08]:
                continue
            c_off = struct.unpack_from("<H", rec, p + 0x14)[0]
            c = rec[p + c_off: p + c_off + min(48, alen - p)]
            if len(c) >= 32:
                cr = struct.unpack_from("<Q", c, 0)[0]
                mf = struct.unpack_from("<Q", c, 8)[0]
                ac = struct.unpack_from("<Q", c, 24)[0]
                return _filetime(cr), _filetime(mf), _filetime(ac)
        return "", "", ""

    def _attr_data_info(self, rec: bytes) -> Tuple[Optional[List[DataRun]], int, bytes]:
        """Returns (runs|None, real_size, resident_data)."""
        for p, atype, alen in self._attr_iter(rec):
            if atype != AT_DATA:
                continue
            non_res = rec[p + 0x08]
            if not non_res:
                size = struct.unpack_from("<I", rec, p + 0x10)[0]
                c_off = struct.unpack_from("<H", rec, p + 0x14)[0]
                if p + c_off + size <= len(rec):
                    return None, size, rec[p + c_off: p + c_off + size]
                return None, size, b""
            real = struct.unpack_from("<Q", rec, p + 0x30)[0]
            rl_off = struct.unpack_from("<H", rec, p + 0x20)[0]
            return self._parse_runs(rec[p + rl_off: p + alen]), real, b""
        return None, 0, b""

    # ------------------------------------------------------------------
    # public scan + recovery
    # ------------------------------------------------------------------
    def scan(self, progress=None, want_active: bool = True,
             want_deleted: bool = True) -> Tuple[List[dict], dict]:
        found: List[dict] = []
        total = self._record_count_from_mft
        is_directory = False
        in_dirs = False
        last_pct = -1
        for idx in range(0, total):
            rec = self.mft_read(idx)
            if rec[0:4] != SIG_FILE:
                continue
            flags = struct.unpack_from("<H", rec, 0x16)[0]
            in_use = bool(flags & FILE_ATTR_IN_USE)
            is_directory = bool(flags & FILE_ATTR_DIRECTORY)
            if in_use and not want_active:
                continue
            if not in_use and not want_deleted:
                continue
            # Reserved system records (0–23) are internal.
            if idx < 24:
                continue
            info = self._attr_file_name(rec)
            if not info:
                continue
            created, modified, accessed = self._attr_std_info_times(rec)
            runs, real_size, res_data = self._attr_data_info(rec)
            rec_is_dir = is_directory
            found.append({
                "name": info["name"],
                "parent": info["parent"],
                "record": idx,
                "size": real_size,
                "is_dir": rec_is_dir,
                "status": "active" if in_use else "deleted",
                "data_runs": runs,
                "resident": res_data if runs is None else b"",
                "cluster_used": None,
                "recoverable": None,
                "created": created,
                "modified": modified,
                "accessed": accessed,
            })
            if progress and total:
                pct = (idx * 100) // total
                if pct != last_pct:
                    last_pct = pct
                    progress(f"Scanning NTFS $MFT… {pct}%", pct / 100.0)
        stats = {
            "deleted": sum(1 for f in found if f["status"] == "deleted"),
            "active": sum(1 for f in found if f["status"] == "active"),
            "fs": "NTFS",
        }
        return found, stats

    def recover(self, rec: dict) -> Tuple[bytes, int]:
        """Rebuild a (deleted) file from its data runs, honouring $Bitmap."""
        if rec["resident"]:
            return rec["resident"], len(rec["resident"])
        real = rec["size"]
        runs = rec["data_runs"]
        if not runs:
            return b"", 0
        # Work out theoretically recoverable regions: any cluster run whose
        # first cluster is still free in $Bitmap can produce contiguous data.
        data, got = self._read_runs(runs, 0, real, check_bitmap=True)
        return data, got

    def read_active_file(self, rec: dict) -> bytes:
        if rec["resident"]:
            return rec["resident"]
        data, _ = self._read_runs(rec["data_runs"] or [], 0, rec["size"], check_bitmap=False)
        return data