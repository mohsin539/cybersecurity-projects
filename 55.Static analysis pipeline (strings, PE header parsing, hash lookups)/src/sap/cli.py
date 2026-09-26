"""Headless CLI — `SAP-cli.exe <command>` (portable console entry).

Subcommands:
  info     pipeline spec, bundle pin, backend availability
  doctor   fail-closed health check (exit 2 on any failed check)
  scan     full static pipeline over one sample
  verify   chain + bundle + spec verification (exit 2 on failure)
  seal     sign both ledgers and export the .sapcase package
  ioc      add a local IOC to the bloom + fact vault
  run-gui  launch the portable GUI

No subcommand -> launches the GUI (default UX of SAP.exe).
"""
from __future__ import annotations

import argparse
import json
import sys


def _launch_gui() -> int:
    try:
        from sap.gui import main as gui_main
    except ImportError:
        print("PySide6 is not installed. Install it (pip install PySide6) or use:")
        print("  SAP-cli.exe scan <sample> --case-dir SAP_CaseWork")
        return 3
    return gui_main()


def _cmd_info(_args) -> int:
    from sap.app import SAPController
    info = SAPController.info()
    print(json.dumps(info, indent=2, sort_keys=True))
    return 0


def _cmd_doctor(_args) -> int:
    from sap.app import SAPController
    report = SAPController.doctor()
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report.get("ok") else 2


def _cmd_scan(args) -> int:
    from sap.app import SAPController, ScanConfig
    config = ScanConfig(analyst=args.analyst, egress_enabled=args.egress,
                        write_reports=not args.no_reports)
    try:
        controller = SAPController(args.case_dir, config)
        card = controller.scan_sample(args.sample)
    except Exception as exc:
        print(f"scan failed: {exc}", file=sys.stderr)
        return 2

    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(card, fh, indent=2, sort_keys=True)
        print(f"card written: {args.out}")

    risk = card["risk"]
    print(f"\n=== SAP TRIAGE CARD ({card['_scan_id']}) ===")
    print(f"sample     : {card['sample']['original_name']} ({card['sample']['size_bytes']} bytes)")
    print(f"sha256     : {card['digests']['sha256']}")
    print(f"risk       : {risk['score']}/100  [{risk['band'].upper()}]")
    print(f"findings   : {len(card['findings'])}")
    for f in card["findings"][:8]:
        print(f"  [{f['severity']:<6}] {f['rule_id']:<12} {f['title']}")
    intel = card.get("intel", {})
    print(f"intel      : hits={len(intel.get('hits', []))} "
          f"highest={intel.get('highest_verdict')} egress={intel.get('egress_used', 0)}")
    if card.get("_reports"):
        for kind, path in card["_reports"].items():
            print(f"report[{kind:<4}]: {path}")
    if args.json:
        print(json.dumps(card, indent=2, sort_keys=True))
    return 0


def _cmd_verify(args) -> int:
    from sap.app import SAPController, ScanConfig
    controller = SAPController(args.case_dir, ScanConfig(analyst=args.analyst))
    report = controller.verify(rehash_path=args.sample)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report.get("ok") else 2


def _cmd_seal(args) -> int:
    from sap.app import SAPController, ScanConfig
    controller = SAPController(args.case_dir, ScanConfig(analyst=args.analyst))
    out = controller.seal(password=args.password)
    print(json.dumps(out, indent=2, sort_keys=True))
    return 0


def _cmd_ioc(args) -> int:
    from sap.app import SAPController, ScanConfig
    controller = SAPController(args.case_dir, ScanConfig(analyst=args.analyst))
    controller.add_ioc(args.sha256, args.verdict, reference=args.reference)
    print(f"ioc added: {args.sha256} -> {args.verdict}")
    return 0


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        return _launch_gui()

    parser = argparse.ArgumentParser(
        prog="sap", description="Static Analysis Pipeline (portable)")
    sub = parser.add_subparsers(dest="cmd")

    sub.add_parser("info", help="pipeline spec + backends")
    sub.add_parser("doctor", help="environment health check")

    p_scan = sub.add_parser("scan", help="run the static pipeline on a sample")
    p_scan.add_argument("sample", help="path to the sample binary")
    p_scan.add_argument("--case-dir", default="SAP_CaseWork")
    p_scan.add_argument("--analyst", default="analyst")
    p_scan.add_argument("--out", help="write the triage card JSON to this path")
    p_scan.add_argument("--json", action="store_true", help="print full card JSON")
    p_scan.add_argument("--no-reports", action="store_true")
    p_scan.add_argument("--egress", action="store_true",
                        help="enable hashed-only opt-in intel egress")

    p_verify = sub.add_parser("verify", help="verify chains + bundle + spec")
    p_verify.add_argument("--case-dir", default="SAP_CaseWork")
    p_verify.add_argument("--analyst", default="analyst")
    p_verify.add_argument("--sample", help="optional: re-hash this sample vs DB")

    p_seal = sub.add_parser("seal", help="sign ledgers and export .sapcase")
    p_seal.add_argument("--case-dir", default="SAP_CaseWork")
    p_seal.add_argument("--analyst", default="analyst")
    p_seal.add_argument("--password", help="AES-256-GCM package password")

    p_ioc = sub.add_parser("ioc", help="local IOC vault management")
    p_ioc_sub = p_ioc.add_subparsers(dest="ioc_cmd")
    p_add = p_ioc_sub.add_parser("add")
    p_add.add_argument("--sha256", required=True)
    p_add.add_argument("--verdict", required=True,
                       choices=["malicious", "suspicious", "benign"])
    p_add.add_argument("--reference", default="")
    p_add.add_argument("--case-dir", default="SAP_CaseWork")
    p_add.add_argument("--analyst", default="analyst")

    sub.add_parser("run-gui", help="launch the portable GUI")

    args = parser.parse_args(argv)
    if args.cmd in (None, "run-gui"):
        return _launch_gui()
    handlers = {
        "info": _cmd_info,
        "doctor": _cmd_doctor,
        "scan": _cmd_scan,
        "verify": _cmd_verify,
        "seal": _cmd_seal,
        "ioc": _cmd_ioc,
    }
    handler = handlers.get(args.cmd)
    if handler is None:
        parser.print_help()
        return 1
    if args.cmd == "ioc" and getattr(args, "ioc_cmd", None) != "add":
        p_ioc.print_help()
        return 1
    return handler(args)


if __name__ == "__main__":
    sys.exit(main())