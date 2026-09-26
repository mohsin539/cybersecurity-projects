"""Project 11 CLI: run the ingest -> normalize -> correlate -> alert pipeline.

Usage:
    python main.py --ingest-dir samples --rules rules --out data
Removal of syslog capture: reuse --ingest-dir with plain log lines.

Security posture (see security.md): reads only explicitly configured paths,
writes only under --out, uses HTTPS for webhooks, no secrets in code.
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

from siem_correlator import ingest as ing
from siem_correlator.normalize import build_normalizer
from siem_correlator.correlate import RuleEngine
from siem_correlator.alerting import ConsoleWriter, JsonlWriter, Router
from siem_correlator.store import EventStore, AlertIndex, summarize_alerts


def main() -> int:
    ap = argparse.ArgumentParser(description="SIEM log correlator")
    ap.add_argument("--ingest-dir", default="samples", help="directory of log files to ingest")
    ap.add_argument("--rules", default="rules", help="directory of JSON rule files")
    ap.add_argument("--out", default="data", help="output directory (events, alerts, state)")
    ap.add_argument("--run-once", action="store_true", help="exit after draining ingest dir")
    ap.add_argument("--min-severity", default="medium", help="router floor")
    ap.add_argument("--print-enriched", action="store_true", help="print normalized events")
    args = ap.parse_args()

    out = Path(args.out)
    rules_dir = Path(args.rules)

    offsets = ing.OffsetTracker(out / "state")
    quarantine = ing.Quarantine(out / "quarantine")
    normalizer = build_normalizer(quarantine_io=quarantine)

    engine = RuleEngine()
    if not rules_dir.exists():
        print(f"rules dir not found: {rules_dir}", file=sys.stderr)
        return 2
    engine.load_rules(rules_dir)

    router = Router(min_severity=args.min_severity)
    router.add_channel(ConsoleWriter())
    router.add_channel(JsonlWriter(out / "alerts.jsonl"))

    events_db = EventStore(out / "events")
    alerts_idx = AlertIndex(out / "alerts_index.jsonl")

    def on_event(ev):
        if args.print_enriched:
            print("[EVT]", ev.to_json())
        events_db.append(ev)

    def on_alert(_engine, _ev, _rule, alert):
        router.route(alert)
        alerts_idx.add(alert)

    engine.on_alert = on_alert

    # ---- Ingest phase -----------------------------------------------------
    t0 = time.time()
    n_raw = n_evt = 0
    ingest_dir = Path(args.ingest_dir)
    if not ingest_dir.is_dir():
        print(f"ingest dir not found: {ingest_dir}", file=sys.stderr)
        return 2
    for path in sorted(ingest_dir.iterdir()):
        if not path.is_file() or path.suffix not in {".log", ".txt", ".jsonl", ".sys"}:
            continue
        tailer = ing.FileTailer(path, offsets)
        for raw in tailer:
            n_raw += 1
            ev = normalizer(raw)
            if ev is None:
                continue
            n_evt += 1
            on_event(ev)
            engine.handle(ev)

    alerts_idx.close()
    events_db.close()
    quarantine.close()

    summary = summarize_alerts(out / "alerts_index.jsonl", limit=50)
    print(f"\n--- pipeline summary -----------------------------")
    print(f"raw events read     : {n_raw}")
    print(f"normalized events   : {n_evt}")
    print(f"quarantined         : {n_raw - n_evt}")
    print(f"alerts produced     : {len(summary)} (recent)")
    for a in summary[:10]:
        print(f"  {a.get('severity','?'):>8} {a.get('rule_id','?'):<24} "
              f"{a.get('rule_name','?')}  count={a.get('count', 1)}")
    print(f"elapsed             : {time.time() - t0:.2f}s")
    return 0


def _pause_on_windows() -> None:
    if (os.name == "nt" and not os.environ.get("TI_NO_PAUSE")
            and sys.stdin and sys.stdin.isatty()):
        input("\nPress Enter to exit...")


if __name__ == "__main__":
    try:
        _rc = main()
    except KeyboardInterrupt:
        _rc = 130
    finally:
        _pause_on_windows()
    raise SystemExit(_rc)