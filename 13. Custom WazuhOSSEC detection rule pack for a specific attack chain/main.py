"""Project 13 launcher: validate the rule pack, then run post-alert enrichment demo.

Usage:
    py main.py                     # validate pack + enrich demo (default)
    py main.py --skip-enrich       # validate only
    py main.py --alert-file <f>    # enrich a specific phase-final alert
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

if getattr(sys, "frozen", False):
    ROOT = Path(getattr(sys, "_MEIPASS", Path(sys.executable).resolve().parent))
else:
    ROOT = Path(__file__).resolve().parent
APP_DIR = Path(sys.executable).resolve().parent if getattr(sys, "frozen", False) else ROOT
sys.path.insert(0, str(ROOT / "scripts"))
os.chdir(ROOT)

import validate_pack  # noqa: E402
import chain_enrich  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--skip-enrich", action="store_true")
    ap.add_argument("--alert-file", default=str(ROOT / "tests/expected/chain_alert.json"))
    args = ap.parse_args()

    print("=== 1/2 validate rule pack ===")
    vcode = validate_pack.main([])
    if vcode != 0:
        return vcode

    if args.skip_enrich:
        print("\n=== pack validated, enrichment skipped ===")
        return 0

    print("\n=== 2/2 post-alert chain enrichment ===")
    alert_path = Path(args.alert_file)
    if not alert_path.exists():
        print(f"alert file not found: {alert_path}")
        return 2
    alert = json.loads(alert_path.read_text(encoding="utf-8"))
    prior = chain_enrich.evidence_from_alert(alert)
    alert["data"] = {
        "chain_evidence": prior,
        "chain_phases": sorted({p.get("phase", "?") for p in prior}),
    }
    out_dir = APP_DIR if getattr(sys, "frozen", False) else alert_path.parent
    out = out_dir / alert_path.with_suffix(".enriched.json").name
    out.write_text(json.dumps(alert, indent=2), encoding="utf-8")
    phases = alert["data"]["chain_phases"]
    print(f"enriched -> {out.name}")
    print(f"  phases attached: {phases}")
    print("RESULT: phasefinal-confirmed" if len(phases) >= 3 else "RESULT: review-only")
    print("\nPack OK — chain detection demo complete.")
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