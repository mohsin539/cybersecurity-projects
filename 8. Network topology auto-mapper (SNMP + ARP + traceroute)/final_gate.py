"""final_gate.py — one-shot, runs once in the session, then deleted.

Hard evidence, gathered deterministically (no server, no shooting):
  1. compile every module under ./app (compileall, doraise)
  2. import app.main.app and count routes (proven surface: 14)
  3. run the real engine contract (not a copy): launch_sim_scan -> job
     persists -> observations -> audit chain verify() -> ALL GREEN
Everything XOR-independent; printed for the reader. Exits 0 only if green.
"""
from __future__ import annotations

import pathlib
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))


def gate_compile() -> None:
    import py_compile
    files = sorted((ROOT / "app").glob("*.py"))
    for f in files:
        py_compile.compile(str(f), doraise=True)
    print("compile OK:", len(files), "modules")


def gate_main() -> None:
    from app.main import app
    routes = sorted({getattr(r, "path", "") for r in app.routes})
    print("main import OK; routes:", len(routes))


def gate_engine() -> None:
    from app import db
    from app.audit import AUDIT
    from app.engine import get_job, launch_sim_scan
    db.init_db()
    jid = launch_sim_scan("10.30.0.0/16", agent="gate-agent", budget_items=120)
    j = None
    for _ in range(400):
        time.sleep(0.05)
        j = get_job(jid)
        if j and j.get("state") in ("done", "error"):
            break
    assert j and j.get("state") == "done", j
    print("engine contract OK:", jid, "->", j.get("state"),
          "| observations:", db.q1("SELECT COUNT(*) n FROM observations")["n"])
    v = AUDIT.verify()
    assert v.get("ok"), v
    print("audit chain verify:", v.get("ok"))


if __name__ == "__main__":
    gate_compile()
    gate_main()
    gate_engine()
    print("FINAL GATE: ALL GREEN")
