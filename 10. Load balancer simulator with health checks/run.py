from __future__ import annotations

import argparse
import sys
import threading
import time
import webbrowser
from pathlib import Path

from aegislb.engine import Simulator
from aegislb.security import SecurityManager

_CLICK_LAUNCHED = False


def _prompt_if_clicked() -> None:
    global _CLICK_LAUNCHED
    if not _CLICK_LAUNCHED:
        return
    try:
        input("\nPress Enter to close this window...")
    except Exception:
        pass


def banner(host: str, port: int, autostart: bool) -> None:
    print("=" * 62)
    print("AegisLB - Load Balancer Simulator with Health Checks (web GUI)")
    print("=" * 62)
    print(f"  Dashboard URL : http://{host}:{port}")
    print(f"  API base      : http://{host}:{port}/api/v1")
    print(f"  Health check  : http://{host}:{port}/healthz")
    if autostart:
        print("  Demo run      : auto-started on launch")
    print("  Stop server   : close this window or press Ctrl+C")
    print("  API keys      : set AEGIS_CONFIG_KEY / AEGIS_OPS_KEY /")
    print("                  AEGIS_AUDITOR_KEY, or use the random ones")
    print("                  (shown redacted on the Security panel)")
    print("=" * 62)
    print()


def open_browser(url: str, delay: float = 1.5) -> None:
    threading.Timer(delay, lambda: webbrowser.open(url)).start()


def serve(args: argparse.Namespace) -> int:
    from aegislb.api import run_server

    sim = Simulator(store_root=args.store_root)
    url = f"http://{args.host}:{args.port}"
    banner(args.host, args.port, autostart=not args.no_autostart)
    if args.browser:
        open_browser(url)
    run_server(sim=sim, host=args.host, port=args.port, autostart=not args.no_autostart)
    return 0


def headless(args: argparse.Namespace) -> int:
    sim = Simulator(store_root=args.out)
    mgr = SecurityManager(emit=lambda etype, payload, sev: sim._emit(etype, payload, sev))
    sim._store.attach_security_manager(mgr)
    manifest = {"seed": args.seed, "rps": args.rps, "speed": args.speed,
                "policy": args.policy, "arrival_model": args.arrival_model}
    res = sim.start(manifest)
    if not res.get("ok"):
        print("failed to start:", res)
        return 1
    end = time.monotonic() + args.seconds
    while time.monotonic() < end and sim.running:
        time.sleep(0.2)
    print("simulated seconds:", round(sim.sim_time, 1))
    print("sessions:", sim.metrics["sessions_total"], "errors:", sim.metrics["errors_total"],
          "rejects:", sim.metrics["rejects_total"])
    for b in sim.backends.values():
        print(f"  {b.name:8s} state={b.state.value:11s} sessions={b.total_sessions:6d} "
              f"probes={b.probes_ok}/{b.probes_fail} ewma={b.ewma_ms:6.1f}ms")
    sim.stop()
    sim.flush_persistent()
    print("preserved ->")
    for f in ("state.md", "memory.md", "security.md"):
        print("  ", Path(args.out) / f)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aegislb",
        description="AegisLB - security-hardened load balancer simulator with health "
                    "checks. Run with no arguments (or double-click run.py) to launch "
                    "the web GUI + API server.")
    sub = parser.add_subparsers(dest="mode")

    sv = sub.add_parser("serve", help="run web GUI + API server (default when no arguments)")
    sv.add_argument("--host", default="127.0.0.1", help="bind address (default: 127.0.0.1)")
    sv.add_argument("--port", type=int, default=8000, help="port to bind (default: 8000)")
    sv.add_argument("--store-root",
                    default=str(Path(__file__).resolve().parent),
                    help="folder for state.md / memory.md / security.md (default: project root)")
    sv.add_argument("--no-browser", dest="browser", action="store_false",
                    default=True, help="do not auto-open the dashboard in a web browser")
    sv.add_argument("--no-autostart", action="store_true",
                    help="do not auto-start a demo run on launch")

    hl = sub.add_parser("headless", help="run a headless scenario and preserve state/memory/security")
    hl.add_argument("--seconds", type=float, default=40.0)
    hl.add_argument("--seed", type=int, default=0xA1B2)
    hl.add_argument("--rps", type=float, default=80.0)
    hl.add_argument("--speed", type=float, default=1.0)
    hl.add_argument("--policy", default="LEAST_CONNECTIONS")
    hl.add_argument("--arrival-model", default="POISSON")
    hl.add_argument("--out", default=str(Path(__file__).resolve().parent))

    return parser


def main(argv=None) -> int:
    global _CLICK_LAUNCHED
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        argv = ["serve"]
        _CLICK_LAUNCHED = True
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.mode == "headless":
        return headless(args)
    if args.mode == "serve":
        return serve(args)
    parser.print_help()
    return 0


if __name__ == "__main__":
    try:
        code = main()
    except KeyboardInterrupt:
        print("\nAegisLB server stopped (Ctrl+C).")
        code = 0
    except Exception as exc:  # noqa: BLE001 - top-level guard keeps the window readable
        print("\n[ERROR] AegisLB did not start:")
        print(f"  {type(exc).__name__}: {exc}")
        print("  Hint: if port 8000 is busy, run:  py run.py serve --port 9000")
        code = 1
    _prompt_if_clicked()
    raise SystemExit(code)