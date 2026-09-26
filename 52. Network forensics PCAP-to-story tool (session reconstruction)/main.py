"""PCAP-to-Story portable suite — entry point (builds tkinter console).

CLI switches (useful for frozen-build verification):
  --selftest <out_dir>   run the full pipeline on the bundled sample capture,
                         write reports incl. PDF, then write SELFTEST_RESULT.json
                         and exit 0. No GUI window is opened.
  --gui-probe <file>     open the real GUI for ~3 s, record any startup/tk callback
                         errors to <file> and <data_dir>/pcapless_error.log, then
                         close cleanly. Exit 0 only if the GUI survived.

All GUI/background failures are written to pcapless_error.log instead of the
silent "unhandled exception" dialog.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import traceback
from pathlib import Path


def data_dir() -> Path:
    return Path(os.environ.get("PCAFLESS_DATA_DIR", Path.home() / ".pcapless"))


def error_log() -> Path:
    return data_dir() / "pcapless_error.log"


def _install_error_logging():
    """Redirect stdout/stderr and hook sys.excepthook to a persistent log file."""
    log = error_log()
    log.parent.mkdir(parents=True, exist_ok=True)

    class _Tee:
        def __init__(self, path):
            self.f = open(path, "a", encoding="utf-8")

        def write(self, data):
            self.f.write(data)
            self.f.flush()

        def flush(self):
            self.f.flush()

    if not getattr(sys, "_pcapless_redirected", False):
        sys.stdout = _Tee(log)
        sys.stderr = _Tee(log)
        sys._pcapless_redirected = True

    def _excepthook(exc_type, exc, tb):
        try:
            with open(log, "a", encoding="utf-8") as fo:
                fo.write("".join(traceback.format_exception(exc_type, exc, tb)) + "\n")
        except Exception:
            pass

    sys.excepthook = _excepthook


def selftest(out_dir: str) -> int:
    from app.core import audit, pcap_engine, reports, state, story_engine

    sample = next(
        (p for p in (
            os.path.join(os.path.dirname(sys.executable), "sample_triage.pcap"),   # next to frozen exe
            os.path.join(os.path.dirname(__file__), "sample_triage.pcap"),          # source tree
        ) if os.path.exists(p)),
        None,
    )
    if not sample:
        raise FileNotFoundError("sample_triage.pcap not found beside the executable")

    os.environ.setdefault("PCAFLESS_DATA_DIR", os.path.join(out_dir, "data"))
    db = state.StateDB()
    ab = audit.AuditBus(db, "selftest")

    res = pcap_engine.load_capture(sample)
    cap_id = db.add_capture("DEFAULT", os.path.basename(sample), res["capture_sha256"],
                            os.path.getsize(sample), res["total_frames"])
    for r in res["sessions"]:
        story_engine.build_story(r)
        db.add_session(cap_id, r)
    ab.log("INGEST_SELFTEST", os.path.basename(sample), evidence_hash=res["capture_sha256"])

    exported = []
    rep = os.path.join(out_dir, "reports")
    first = res["sessions"][0]
    for fmt in ("pdf", "html", "json", "csv", "md", "stix", "zip"):
        rid = reports.generate_report(first, fmt, rep, case_id="DEFAULT", analyst="selftest")
        db.add_report("DEFAULT", first["session_id"], fmt, rid["filename"], rid["sha256"], rid["size"])
        exported.append({"fmt": fmt, "file": os.path.basename(rid["path"]), "size": rid["size"]})
    ab.log("REPORT_SELFTEST", ",".join(x["fmt"] for x in exported))

    ok, bad = ab.verify()
    summary = {
        "ok": ok and len(exported) == 7,
        "audit_chain_ok": ok,
        "frames": res["total_frames"],
        "sessions": len(res["sessions"]),
        "decode_errors": res["decode_errors"],
        "audit_events": db.audit_count(),
        "exported": exported,
        "reports_dir": rep,
    }
    result_path = os.path.join(out_dir, "SELFTEST_RESULT.json")
    with open(result_path, "w", encoding="utf-8") as fo:
        json.dump(summary, fo, indent=2)
    db.close()
    return 0 if summary["ok"] else 1


def gui_probe(out_file: str) -> int:
    """Open the real GUI, pump events ~3 s, report success/failure. Exit 0 on clean run."""
    probe = {"ok": False, "phase": "startup", "error": None, "error_log": str(error_log())}
    try:
        from app.gui import SuiteApp

        os.environ.setdefault("PCAFLESS_DATA_DIR", str(data_dir()))
        app = SuiteApp()
        probe["phase"] = "running"

        def _finish():
            probe["ok"] = True
            probe["phase"] = "clean_exit"
            app.destroy()

        app.after(3000, _finish)
        app.mainloop()
    except Exception:
        tb = traceback.format_exc()
        probe["error"] = tb
        try:
            with open(error_log(), "a", encoding="utf-8") as fo:
                fo.write(tb + "\n")
        except Exception:
            pass
    with open(out_file, "w", encoding="utf-8") as fo:
        json.dump(probe, fo, indent=2)
    return 0 if probe["ok"] else 1


def run_gui() -> int:
    try:
        from app.gui import main as gui_main

        gui_main()
        return 0
    except Exception:
        tb = traceback.format_exc()
        try:
            with open(error_log(), "a", encoding="utf-8") as fo:
                fo.write(tb + "\n")
        except Exception:
            pass
        try:
            from tkinter import messagebox
            messagebox.showerror(
                "PCAP-to-Story Suite",
                f"A startup error occurred. Full details were written to:\n{error_log()}\n\n{tb}",
            )
        except Exception:
            pass
        return 1


def main() -> int:
    _install_error_logging()
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    if "--selftest" in sys.argv:
        out = args[0] if args else tempfile.mkdtemp(prefix="pcapless_selftest_")
        return selftest(out)
    if "--gui-probe" in sys.argv:
        out = args[0] if args else os.path.join(tempfile.gettempdir(), "gui_probe_result.json")
        return gui_probe(out)
    return run_gui()


if __name__ == "__main__":
    raise SystemExit(main())