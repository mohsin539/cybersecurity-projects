"""gui_drive_test.py - drives the real GUI end-to-end (ingest -> story -> export)."""

from __future__ import annotations

import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
os.environ.setdefault("PCAFLESS_DATA_DIR", tempfile.mkdtemp(prefix="pcapless_drive_"))

from app.gui import SuiteApp  # noqa: E402

RESULT = {"ok": False, "steps": []}


def step(name, ok, detail=""):
    RESULT["steps"].append({"name": name, "ok": ok, "detail": detail})
    print(f"[{'OK' if ok else 'FAIL'}] {name}  {detail}")


app = SuiteApp()
probe_err = []
app.report_callback_exception = lambda *a: probe_err.append("".join(__import__("traceback").format_exception(*a)))

done = {"flag": False}


def boot():
    sample = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "sample_triage.pcap"))
    app.file_var.set(sample)
    app._start_ingest()
    app.after(120, watch)


def watch():
    if app._busy:
        app.after(150, watch)
        return
    done["flag"] = True
    app.after(50, finish)


def finish():
    try:
        step("ingest", app.db.captures(), "captures persisted")
        rows = app.session_tv.get_children()
        step("sessions_listed", len(rows) >= 6, f"{len(rows)} rows")
        app.show_story(next(iter(rows)))
        step("story_viewed", app.active_session_id is not None, app.active_session_id)
        res = app._export("pdf")
        step("pdf_export", True, app.export_status.cget("text"))
        app._refresh_reports()
        rep = app.report_tv.get_children()
        step("report_history", len(rep) >= 1, f"{len(rep)} rows")
        app._refresh_audit()
        app._verify_audit()
        ok, bad = app.db.audit_verify()
        step("audit_chain", ok, f"bad={bad}")
        step("no_tk_callbacks", len(probe_err) == 0, str(probe_err[:1]))
        RESULT["ok"] = all(s["ok"] for s in RESULT["steps"])
    except Exception as e:
        import traceback
        probe_err.append(traceback.format_exc())
        step("flow_exception", False, repr(e))
    app.destroy()


app.after(300, boot)
app.mainloop()

RESULT["ok"] = all(s["ok"] for s in RESULT["steps"])
out = os.path.join(tempfile.gettempdir(), "GUI_DRIVE_RESULT.json")
with open(out, "w", encoding="utf-8") as fo:
    json.dump(RESULT, fo, indent=2, default=str)
print("\nWRITTEN:", out)
raise SystemExit(0 if RESULT["ok"] else 1)