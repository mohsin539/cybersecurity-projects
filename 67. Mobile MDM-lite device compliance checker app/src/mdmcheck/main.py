"""MDM-Lite Compliance Checker entry point.

Runs the local dashboard server and opens the default browser.
"""
from __future__ import annotations

import argparse
import os
import sys
import threading
import webbrowser
from pathlib import Path

from . import __version__
from .dashboard import serve
from .store import StateStore

LOG_FILE: Path | None = None
if getattr(sys, "frozen", False):
    LOG_FILE = Path(sys.executable).with_name("mdm-lite.log")


def _log(msg: str):
    line = f"[mdm-lite] {msg}"
    print(line, flush=True)
    if LOG_FILE:
        try:
            with LOG_FILE.open("a", encoding="utf-8") as fh:
                fh.write(line + "\n")
        except OSError:
            pass


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="mdm-lite-compliance-checker", description="Portable MDM-lite device compliance checker")
    p.add_argument("--port", type=int, default=0, help="TCP port (0 = random)")
    p.add_argument("--host", default="127.0.0.1", help="Bind address (default 127.0.0.1)")
    p.add_argument("--data", default=None, help="Path to the state JSON file")
    p.add_argument("--no-browser", action="store_true", help="Do not auto-open the browser")
    p.add_argument("--seed-demo", action="store_true", help="Seed demo devices if store is empty")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    args = p.parse_args(argv)

    store = StateStore(args.data)
    if args.seed_demo and not store.devices():
        from .demo import demo_batch

        batch = demo_batch()
        for d in batch["devices"]:
            store.add_device(d)
        store.log("info", "demo_seed", f"Seeded {len(batch['devices'])} demo devices.")
        _log("Seeded demo devices.")

    if not store.devices():
        _log("No devices enrolled. Open the dashboard and add a device under 'Devices'.")

    on_shutdown = lambda: os._exit(0)  # noqa: PLW0108
    httpd, url = serve(store, port=args.port, host=args.host, on_shutdown=on_shutdown)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()

    _log(f"v{__version__} running at {url}")
    _log(f"state file -> {store.path}")
    if args.host == "127.0.0.1":
        _log("Bound to loopback only. Data never leaves this machine.")
    _log("Shutdown: press Ctrl+C in the console, or use the Shutdown button in the dashboard.")

    if not args.no_browser:
        try:
            webbrowser.open(url, new=2)
        except Exception as e:  # noqa: BLE001
            _log(f"Browser auto-open failed ({e}); open {url} manually.")

    try:
        while True:
            thread.join(timeout=60)
    except KeyboardInterrupt:
        _log("Shutdown requested.")
        httpd.shutdown()
    return 0


if __name__ == "__main__":
    try:
        rc = main()
    except Exception as e:  # noqa: BLE001
        _log(f"FATAL: {e!r}")
        rc = 1
    sys.exit(rc)