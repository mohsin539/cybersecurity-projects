#!/usr/bin/env python3
"""DIHT entry point.

Usage:
    diht                          launch portable GUI
    diht --self-test [dir]        headless self-test (writes self_test_result.json)
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import traceback


def _self_test(out_dir: str) -> dict:
    """End-to-end headless verification of the forensic pipeline.

    Creates a synthetic 8 MiB 'exhibit' file (no admin required), acquires it,
    verifies it, then verifies the reverse case (tampered image must FAIL),
    builds every report format, and audits the signed ledger.
    """
    from .config import MANIFEST_NAME
    from .workflow import Case

    work = out_dir
    os.makedirs(work, exist_ok=True)

    exhibit = os.path.join(work, "exhibit.bin")
    with open(exhibit, "wb") as fh:
        fh.write(os.urandom(8 * 1024 * 1024))

    case_dir = os.path.join(work, "SELFTEST-001")
    case = Case(case_dir, "SELFTEST-001", "Automated self-test case",
                "SelfTest Operator", "Tester", "Cyber Forensics Unit",
                "selftest-passphrase")

    steps = []
    try:
        res = case.acquire(exhibit, filename="evidence_selftest.dd",
                           algorithms=("sha256", "sha3_256", "blake2b"),
                           passphrase="selftest-passphrase",
                           writeblocker_confirmed=True)
        steps.append(("acquire", "ok", res["digests"]))

        match, digests = case.verify_exhibit(
            "evidence_selftest.dd", ("sha256", "sha3_256", "blake2b"),
            res["digests"], passphrase="selftest-passphrase")
        steps.append(("verify_clean", "ok" if match else "fail", match))

        # Tamper the image: appended byte MUST make verification fail.
        with open(os.path.join(case_dir, "evidence_selftest.dd"), "ab") as fh:
            fh.write(b"TAMPER")
        bad, _ = case.verify_exhibit(
            "evidence_selftest.dd", ("sha256",), {"sha256": res["digests"]["sha256"]},
            passphrase="selftest-passphrase")
        steps.append(("verify_tamper_detected", "ok" if not bad else "fail", not bad))

        files = case.ensure_reports()
        manifest = case.load_manifest()
        ok, problems = case.audit("selftest-passphrase")
        steps.append(("ledger_audit", "ok" if ok else "fail", problems or "intact"))
        steps.append(("reports", "ok", files))

    finally:
        pass

    result = {
        "tool": "Disk Image Acquisition & Hashing Toolkit",
        "version": "1.0.0",
        "selftest": "PASS" if all(s[1] == "ok" for s in steps) else "FAIL",
        "steps": [{"name": s[0], "status": s[1],
                   "detail": s[2] if len(s) > 2 else None} for s in steps],
        "case_dir": case_dir,
        "outputs": sorted(os.listdir(case_dir)) if os.path.isdir(case_dir) else [],
    }
    with open(os.path.join(work, "self_test_result.json"), "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2, ensure_ascii=False)
    return result


def main() -> int:
    args = sys.argv[1:]
    if "--self-test" in args or "--selftest" in args:
        out_dir = None
        for a in args:
            if a not in ("--self-test", "--selftest") and not a.startswith("-"):
                out_dir = a
                break
        if not out_dir:
            out_dir = os.path.join(tempfile.gettempdir(), "diht_selftest")
        try:
            res = _self_test(out_dir)
            print(json.dumps(res, indent=2))
            return 0 if res["selftest"] == "PASS" else 1
        except Exception:
            traceback.print_exc()
            return 2

    # GUI relies on a display; raise a clear message in headless frozen runs.
    try:
        import customtkinter  # noqa: F401
        from .ui import App
        app = App()
        app.mainloop()
        return 0
    except Exception:
        traceback.print_exc()
        return 3


if __name__ == "__main__":
    raise SystemExit(main())