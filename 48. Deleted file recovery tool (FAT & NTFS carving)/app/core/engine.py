"""Scan/recovery orchestration engine.

Unifies logical volumes, physical drives and forensic images into a single
pipeline:

    SourceInfo → (partition bootstrap) → FatVolume | NtfsVolume → scan
                                               ↓
                      RecoveredItem model + carve results
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Callable, List, Optional, Tuple

from .disk import ReadOnlySource, SourceInfo, DiskError
from .partition import parse_partitions
from .fat import FatVolume, classify_fat
from .ntfs import NtfsVolume
from .carver import (Carver, build_free_space_regions_from_fat, build_free_space_regions_from_boot)
from .signatures import signature_lookup, validate_signature


@dataclass
class RecoveredItem:
    source_label: str
    name: str
    size: int
    fs: str            # FAT32 / NTFS / CARVE
    kind: str          # "deleted" | "active" | "carved"
    status: str        # "recoverable" | "overwritten" | "ok"
    method: str        # "metadata" | "signature"
    detail: str = ""
    record_id: str = ""
    confidence: str = "high"
    created: str = ""
    modified: str = ""
    recovered_bytes: int = 0
    sha256: str = ""
    _blob: bytes = b""

    @property
    def is_recoverable(self) -> bool:
        return self.status == "recoverable" and self.size > 0

    def quality(self) -> float:
        """0–1 heuristic used by the UI for row coloring."""
        if self.method == "signature":
            return {"high": 0.9, "medium": 0.6, "low": 0.35}.get(self.confidence, 0.5)
        if self.status == "overwritten":
            return 0.15
        return 1.0 if self.size else 0.0


@dataclass
class ScanResult:
    items: List[RecoveredItem] = field(default_factory=list)
    carved: List[dict] = field(default_factory=list)
    stats: dict = field(default_factory=dict)
    fs: str = ""
    warnings: List[str] = field(default_factory=list)


class RecoveryEngine:
    """Stateless per-scan engine. Holds no absolute source paths in memory
    beyond the caller-supplied context (audit layer handles logging)."""

    def __init__(self, src: ReadOnlySource, base_offset: int = 0,
                 source_label: str = ""):
        self.src = src
        self.base_offset = base_offset
        self.label = source_label or src.info.label or src.info.device_path
        self._fat: Optional[FatVolume] = None
        self._ntfs: Optional[NtfsVolume] = None
        self.fs_type = ""

    # ------------------------------------------------------------------
    def _detect_fs(self) -> str:
        """Identify filesystem by boot sector content at base_offset."""
        boot = self.src.read(self.base_offset, 512)
        if len(boot) < 512:
            return ""
        if boot[3:11] == b"NTFS    ":
            self.fs_type = "NTFS"
            return "NTFS"
        # FAT detection: BPB sanity.
        bps = struct.unpack_from("<H", boot, 0x0B)[0]
        spc = boot[0x0D]
        if bps in (512, 1024, 2048, 4096) and spc and (spc & (spc - 1)) == 0:
            fat16 = struct.unpack_from("<H", boot, 0x16)[0]
            tot16 = struct.unpack_from("<H", boot, 0x13)[0]
            tot32 = struct.unpack_from("<I", boot, 0x20)[0]
            if tot16 or tot32 or fat16:
                self.fs_type = "FAT"
                return "FAT"
        return ""

    def mount_fs(self) -> str:
        kind = self._detect_fs()
        if kind == "NTFS":
            self._ntfs = NtfsVolume(self.src, self.base_offset)
            self._ntfs.mount()
        elif kind == "FAT":
            self._fat = FatVolume(self.src, self.base_offset)
            self._fat.mount()
        else:
            raise ValueError(f"unsupported or unrecognised filesystem at offset {self.base_offset}")
        return self.fs_type

    @property
    def fat(self) -> Optional[FatVolume]:
        return self._fat

    @property
    def ntfs(self) -> Optional[NtfsVolume]:
        return self._ntfs

    # ------------------------------------------------------------------
    def metadata_scan(self, progress: Callable = None,
                      want_active: bool = True,
                      want_deleted: bool = True,
                      scan_orphans: bool = True) -> ScanResult:
        res = ScanResult(fs=self.fs_type)
        if self._fat:
            found, stats = self._fat.scan(scan_orphans=scan_orphans, progress=progress)
            for f in found:
                res.items.append(self._fat_to_item(f))
            res.stats = stats
            if self._fat.bad:
                res.warnings.append(self._fat.bad)
        elif self._ntfs:
            found, stats = self._ntfs.scan(progress=progress,
                                           want_active=want_active,
                                           want_deleted=want_deleted)
            for f in found:
                res.items.append(self._ntfs_to_item(f))
            res.stats = stats
        return res

    def _fat_to_item(self, f: dict) -> RecoveredItem:
        recoverable = f["status"] == "active" or (f["status"] == "recoverable" and f["recoverable_clusters"] > 0)
        if f["status"] == "active":
            return RecoveredItem(
                source_label=self.label, name=f.get("full_path", f["name"]), size=f["size"],
                fs=f"FAT{self._fat.bpb.fat_type if self._fat.bpb else ''}", kind="active",
                status="ok", method="metadata", record_id=f"cluster:{f['start_cluster']}",
                created=f.get("created", ""), modified=f.get("modified", ""),
                recovered_bytes=f["size"],
                _blob=b"" if f["size"] > 128 * 1024 * 1024 else self._fat.read_active(f["start_cluster"], f["size"]),
            )
        status = "recoverable" if f["recoverable_clusters"] else "overwritten"
        usable = f["recoverable_clusters"] * f["cluster_bytes"]
        if f["recoverable_clusters"] == 0 and f["size"] == 0:
            status, usable = "recoverable", 0
        return RecoveredItem(
            source_label=self.label, name=f.get("full_path", f["name"]), size=f["size"],
            fs=f"FAT{self._fat.bpb.fat_type if self._fat.bpb else ''}",
            kind="deleted", status=status, method="metadata",
            record_id=f"cluster:{f['start_cluster']}",
            created=f.get("created", ""), modified=f.get("modified", ""),
            recovered_bytes=usable,
            detail=f"{f['recoverable_clusters']} clusters · start 0x{f['start_cluster']:X}",
        )

    def _ntfs_to_item(self, f: dict) -> RecoveredItem:
        status = "recoverable" if (not f["is_dir"] or f["size"] > 0) else "overwritten"
        resident = f["resident"] != b""
        has_runs = f["data_runs"] not in (None, [])
        recoverable = has_runs or resident
        n = "overwritten" if not recoverable else ("recoverable" if resident else "recoverable")
        detail = "resident data" if resident else f"MFT#{f['record']}"
        if recoverable and not resident:
            detail = f"MFT#{f['record']} · data runs"
        return RecoveredItem(
            source_label=self.label, name=f["name"], size=f["size"],
            fs="NTFS", kind="deleted" if f["status"] == "deleted" else "active",
            status=n, method="metadata", record_id=f"MFT:{f['record']}",
            created=f.get("created", ""), modified=f.get("modified", ""),
            detail=detail,
            recovered_bytes=f["size"] if resident else f["size"],
        )

    # ------------------------------------------------------------------
    def recover_item(self, item: RecoveredItem, blob: bytes = b"") -> bytes:
        """Materialise recoverable bytes for a metadata item."""
        if item._blob:
            return item._blob
        if self._ntfs and item.fs == "NTFS" and item.record_id.startswith("MFT:"):
            idx = int(item.record_id.split(":")[1])
            data, _ = self._recover_ntfs_record(idx)
            if data:
                item.recovered_bytes = len(data)
            return data
        if self._fat and item.fs.startswith("FAT") and item.record_id.startswith("cluster:"):
            cluster = int(item.record_id.split(":")[1])
            size = item.size if item.kind == "active" else min(item.size, item.recovered_bytes)
            if item.kind == "active":
                return self._fat.read_active(cluster, size)
            if size <= 0:
                return b""
            need_clusters = (size + self._fat.bpb.cluster_bytes() - 1) // self._fat.bpb.cluster_bytes()
            rec = {"start_cluster": cluster, "recoverable_clusters": need_clusters,
                   "cluster_bytes": self._fat.bpb.cluster_bytes(), "size": size}
            data, _ = self._fat.read_deleted(rec, cap_bytes=size)
            item.recovered_bytes = len(data)
            return data
        return b""

    def _recover_ntfs_record(self, idx: int) -> Tuple[bytes, int]:
        rec = self._ntfs.mft_read(idx)
        if rec[0:4] != b"FILE":
            return b"", 0
        runs, real, resident = self._ntfs._attr_data_info(rec)
        if not (resident or runs):
            return b"", 0
        fake = {"resident": resident, "data_runs": runs, "size": real}
        return self._ntfs.recover(fake)

    # ------------------------------------------------------------------
    def carve(self, group_filter=None, ext_filter=None,
              progress: Callable = None, stop_flag: Callable = None,
              on_region=None) -> List[dict]:
        """Carve unallocated regions uncovered by the metadata scan."""
        regions: List[Tuple[int, int]] = []
        if self._fat:
            regions = build_free_space_regions_from_fat(
                self._fat, [i for i in [] if i])
        elif self._ntfs:
            regions = self._ntfs_free_regions()
        else:
            regions = [(self.base_offset, self.base_offset + self.src.info.size)]
        if not regions:
            return []
        regions = [r for r in regions if r[1] - r[0] > 1024]
        carve_src = self.src
        carver = Carver(carve_src, regions, group_filter=group_filter,
                        ext_filter=ext_filter, progress=progress,
                        stop_flag=stop_flag)
        return [c.__dict__ for c in carver.carve()]

    def _ntfs_free_regions(self) -> List[Tuple[int, int]]:
        ntv = self._ntfs
        n = ntv._record_count_from_mft  # not cluster count; use geometry
        cluster_total = self.src.info.size // ntv.cluster_bytes
        regions = []
        start = None
        for c in range(0, cluster_total):
            used = ntv._bitmap_cluster_used(c)
            if not used:
                if start is None:
                    start = c
            else:
                if start is not None:
                    regions.append((self.base_offset + start * ntv.cluster_bytes,
                                    self.base_offset + c * ntv.cluster_bytes))
                    start = None
        if start is not None:
            regions.append((self.base_offset + start * ntv.cluster_bytes,
                            self.base_offset + cluster_total * ntv.cluster_bytes))
        return regions


def scan_source_info(info: SourceInfo) -> ScanResult:
    """Convenience: full scan of a logical volume / image path."""
    with ReadOnlySource(info) as src:
        if info.kind in ("volume", "physical"):
            eng = RecoveryEngine(src, 0, info.label)
            kind = eng.mount_fs()
            return eng.metadata_scan()
        eng = RecoveryEngine(src, 0, info.label)
        try:
            kind = eng.mount_fs()
            return eng.metadata_scan()
        except ValueError:
            return ScanResult(warnings=["no supported filesystem in image root"])


def probe_engine_for_info(info: SourceInfo, img_path: Optional[str] = None) -> ReadOnlySource:
    return ReadOnlySource(info, img_path)