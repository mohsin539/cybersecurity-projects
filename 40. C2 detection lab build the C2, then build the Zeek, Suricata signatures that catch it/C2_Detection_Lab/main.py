"""C2 Detection Lab - entry point.

GUI mode (default):  python main.py            -> portable desktop console
CLI/headless mode:   python main.py --headless -> runs one lab + reports
"""

from __future__ import annotations

import argparse
import json
import sys


def main() -> int:
    ap = argparse.ArgumentParser(description="C2 Detection Lab (portable console)")
    ap.add_argument("--headless", action="store_true",
                    help="run one full lab + reports, no GUI")
    ap.add_argument("--interval", type=float, default=5.0)
    ap.add_argument("--agents", type=int, default=3)
    ap.add_argument("--duration", type=float, default=30.0)
    ap.add_argument("--channel", type=str, default="http")
    ap.add_argument("--json", type=str, default="", help="dump run result JSON here")
    args = ap.parse_args()

    if args.headless:
        return headless(args)

    try:
        from gui.app import main as gui_main
        gui_main()
        return 0
    except Exception as exc:  # noqa: BLE001 - no display (e.g. CI/EC2)
        print(f"[gui unavailable] {exc}", file=sys.stderr)
        print("Falling back to headless run...", file=sys.stderr)
        return headless(args)


def headless(args: argparse.Namespace) -> int:
    from core.config import LabConfig
    from core.lab_runner import LabRunner
    from reporting.csv_report import write_csv
    from reporting.html_report import write_html
    from reporting.xlsx_report import write_xlsx

    cfg = LabConfig(beacon_interval=args.interval, agent_count=args.agents,
                    run_duration=args.duration, channel=args.channel,
                    outdir=f"labs/headless_{args.interval}s_{args.channel}")
    cfg.validate()
    runner = LabRunner(cfg)
    result = runner.run()

    m = result["metrics"]
    print("=" * 64)
    print(f"  run_id     : {result['run_id']}")
    print(f"  alerts     : {m['alerts']}   zeek={m['zeek_detections']} "
          f"suricata={m['suricata_detections']}")
    print(f"  TP={m['true_positives']} FP={m['false_positives']} "
          f"FN={m['false_negatives']}")
    print(f"  precision={m['precision']}  recall={m['recall']}  "
          f"F1={m['f1']}  accuracy={m['accuracy']}")
    print(f"  alerts/agent: {m['detected_per_agent']}")
    print("=" * 64)

    out = Path_of(cfg) / "reports"
    write_xlsx(result, out / "report.xlsx")
    write_csv(result, out)
    write_html(result, out / "report.html")
    print(f"  reports -> {out}")
    if args.json:
        (cfg.out_path / args.json).write_text(json.dumps(result, indent=2),
                                              encoding="utf-8")
    return 0


def Path_of(cfg):
    from pathlib import Path
    return Path(cfg.outdir)


if __name__ == "__main__":
    raise SystemExit(main())