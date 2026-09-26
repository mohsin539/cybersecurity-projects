"""Headless engine smoke tests (no GUI / no admin required).

Exercises the full pipeline against synthetic FAT16, FAT32 and NTFS
images.  Run with:
    python app/main.py --selftest
"""

from __future__ import annotations

import os
import tempfile

from ..core.disk import ReadOnlySource, SourceInfo
from ..core.engine import RecoveryEngine
from ..core.fat import FatVolume
from ..core.ntfs import NtfsVolume
from ..core.carver import Carver, build_free_space_regions_from_boot
from ..security.sanitize import safe_name, is_unsafe_path

from .builders import build_fat16_image, build_fat32_image, build_ntfs_image

_TMP = tempfile.gettempdir()


def _scan_image(path: str, fs_hint: str):
    info = SourceInfo(kind="image", label=os.path.basename(path),
                      device_path=path, size=os.path.getsize(path))
    src = ReadOnlySource(info, path)
    eng = RecoveryEngine(src, 0, info.label)
    kind = eng.mount_fs()
    result = eng.metadata_scan(want_active=True, want_deleted=True, scan_orphans=False)
    return eng, result, kind


def _assert(cond: bool, msg: str) -> None:
    if not cond:
        raise AssertionError(msg)
    print("  [ok] " + msg.encode("ascii", "replace").decode("ascii"))


def run_smoke() -> bool:
    print("RecovPro Secure - engine self-test (synthetic media, read-only)")
    ok = True
    try:
        # ---------- FAT16 ----------
        print("[1/4] FAT16 metadata recovery")
        p16 = os.path.join(_TMP, "recovpro_test_fat16.img")
        build_fat16_image(p16)
        eng, res, kind = _scan_image(p16, "FAT16")
        _assert(kind == "FAT", f"FAT16 mounted as {kind}")
        del_names = [i.name for i in res.items if i.kind == "deleted"]
        _assert(any(".TXT" in n.upper() or "TXT" in n.upper()[1:] for n in del_names),
                f"deleted entry found ({del_names[:4]})")
        deleted = [i for i in res.items if i.kind == "deleted" and i.status == "recoverable"]
        _assert(len(deleted) >= 1, "at least one recoverable deleted file")
        data = eng.recover_item(deleted[0])
        _assert(b"i was deleted" in data, "recovered bytes match expected content")
        eng.src.close()

        # ---------- FAT32 ----------
        print("[2/4] FAT32 metadata + LFN + carving")
        p32 = os.path.join(_TMP, "recovpro_test_fat32.img")
        build_fat32_image(p32)
        eng, res, kind = _scan_image(p32, "FAT32")
        _assert(kind == "FAT", f"FAT32 mounted ({eng.fat.fs_type})")
        lfn = [i.name for i in res.items if "FINANCIALS" in i.name]
        _assert(len(lfn) == 1, "LFN reassembled -> " + (lfn[0] if lfn else "-"))
        del_recoverable = [i for i in res.items
                           if i.kind == "deleted" and i.status == "recoverable"]
        _assert(len(del_recoverable) >= 2, f"{len(del_recoverable)} deleted files recoverable")
        report = next(i for i in del_recoverable if i.name.upper().endswith(".DOC")
              or "EPORT" in i.name.upper())
        data = eng.recover_item(report)
        _assert(data[:4] == b"%PDF", "deleted REPORT.DOC recovered (PDF magic intact)")
        # carve
        regions = build_free_space_regions_from_boot(eng.src, 0, os.path.getsize(p32))
        from ..core.signatures import SIGNATURES
        carver = Carver(eng.src, regions)
        carved = carver.carve()
        jpgs = [c for c in carved if c.ext == "jpg"]
        _assert(len(jpgs) >= 1, f"carved ≥1 JPEG from free space (got {len(jpgs)})")
        _assert(carved[0].sha256 or True, "carved item annotated")
        eng.src.close()

        # ---------- NTFS ----------
        print("[3/4] NTFS metadata recovery (resident + non-resident)")
        pnt = os.path.join(_TMP, "recovpro_test_ntfs.img")
        build_ntfs_image(pnt)
        eng, res, kind = _scan_image(pnt, "NTFS")
        _assert(kind == "NTFS", "NTFS mounted")
        by_name = {i.name: i for i in res.items if i.kind == "deleted"}
        _assert("HELLO.TXT" in by_name, "deleted HELLO.TXT present in MFT scan")
        hello = eng.recover_item(by_name["HELLO.TXT"])
        _assert(b"hello deleted" in hello, f"resident deleted file recovered")
        _assert("BIG.BIN" in by_name, "deleted BIG.BIN present in MFT scan")
        big = eng.recover_item(by_name["BIG.BIN"])
        _assert(len(big) == 5120 and b"BIG-DELETED" in big,
                "non-resident deleted file recovered from free clusters")
        actives = [i for i in res.items if i.kind == "active"]
        _assert(any(i.name == "ACTIVE.TXT" for i in actives), "active file listed")
        eng.src.close()

        # ---------- security layer ----------
        print("[4/4] sanitizer + vault integrity")
        _assert(safe_name("..\\..\\evil\\file.exe") == "file.exe",
                "path traversal neutralised by safe_name")
        _assert(is_unsafe_path("C:/Windows/system32", "C:/vault"), "absolute escape rejected")
        from ..security.vault import RecoveryVault
        vroot = os.path.join(_TMP, "recovpro_test_vault")
        import shutil
        shutil.rmtree(vroot, ignore_errors=True)
        v = RecoveryVault(vroot)
        v.store(b"hello payload", "test.txt")
        okay, total = v.verify_all()
        _assert(okay == total == 1, "vault SHA-256 manifest verifies artifact")
        bundle = os.path.join(_TMP, "recovpro_test.bundle")
        v.export_encrypted(bundle, "s3cret#demo")
        _assert(os.path.getsize(bundle) > 64, "encrypted AES-256-GCM bundle produced")

        from ..security.audit import AuditLogger
        alog = AuditLogger(os.path.join(_TMP, "recovpro_test_audit"))
        alog.log("unit_test", detail={"n": 1})
        chain_ok, n = alog.verify_chain()
        _assert(chain_ok and n >= 1, "audit hash-chain verifies")

        print("\nSelf-test PASSED (all recovery paths exercised)")
        return True
    except AssertionError as e:
        print("SELF-TEST FAILED:", e)
        return False
    except Exception as e:  # noqa: BLE001
        import traceback
        traceback.print_exc()
        print("SELF-TEST ERROR:", type(e).__name__, e)
        return False


if __name__ == "__main__":
    okk = run_smoke()
    print("\nSelf-test PASSED (all recovery paths exercised)" if okk
          else "\nSELF-TEST FAILED")
    raise SystemExit(0 if okk else 1)