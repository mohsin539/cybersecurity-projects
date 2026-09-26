"""Project 12 HIDS agent main loop.

Usage:
    python main.py --scopes scopes.json --rules rules.json --state data --cycles 1
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
os.chdir(Path(__file__).resolve().parent)

import hids.alert as alert
from hids.baseline import BaselineDB
from hids.fim import FimEngine, load_scopes
from hids.process import ProcMonitor


def main() -> int:
    ap = argparse.ArgumentParser(description="HIDS agent (FIM + processes)")
    ap.add_argument("--scopes", default="scopes.json")
    ap.add_argument("--rules", default="rules.json")
    ap.add_argument("--state", default="data")
    ap.add_argument("--cycles", type=int, default=1, help="scan cycles (1 = one-shot)")
    ap.add_argument("--interval", type=float, default=5.0)
    ap.add_argument("--no-proc", action="store_true")
    ap.add_argument("--baseline", action="store_true", help="first run: build baseline without findings")
    args = ap.parse_args()

    state_dir = Path(args.state)
    db = BaselineDB(state_dir / "baseline.db")

    scopes = load_scopes(Path(args.scopes))
    fim = FimEngine(db, scopes, baseline=args.baseline)

    known = set()
    if Path(args.rules).exists():
        rd = json.loads(Path(args.rules).read_text(encoding="utf-8"))
        known = set(rd.get("known_binary_hashes", []))

    # Wire hooks
    alert.register_hook(alert.JsonlHook(state_dir / "findings.jsonl"))
    alert.register_hook(alert.SyslogHook(state_dir / "syslog.out"))

    from hids.process import process_list
    monitor = ProcMonitor(known, alert.emit) if not args.no_proc else None

    cycle = 0
    first_cycle = True
    while cycle < args.cycles:
        cycle += 1
        n_fim = fim.snapshot()
        # First cycle warms up the process landscape (no findings); like `--baseline`
        # for files, this avoids flagging every process on the first scan.
        n_proc = monitor.scan(warmup=first_cycle) if monitor else 0
        first_cycle = False
        print(f"[cycle {cycle}] fim_findings={n_fim} proc_findings={n_proc}")
        if cycle < args.cycles:
            time.sleep(args.interval)

    db.close()
    for hook in alert._hooks:
        if hasattr(hook, "close"):
            hook.close()
    return 0


def _pause_on_windows() -> None:
    if (os.name == "nt" and not os.environ.get("TI_NO_PAUSE")
            and sys.stdin and sys.stdin.isatty()):
        try:
            input("\nPress Enter to exit...")
        except EOFError:
            pass


if __name__ == "__main__":
    try:
        _rc = main()
    except KeyboardInterrupt:
        _rc = 130
    finally:
        _pause_on_windows()
    raise SystemExit(_rc)