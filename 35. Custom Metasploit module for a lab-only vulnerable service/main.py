"""
VulnLab Sentinel - portable entrypoint.

Launches the loopback web console, opens the default browser, and keeps the
process alive until Ctrl+C. Works identically from source (python main.py)
or from the frozen PyInstaller executable (VulnLabSentinel.exe).
"""
import argparse
import sys
import threading
import time
import webbrowser
from pathlib import Path

from backend.app import serve
from backend.secure_config import SecureConfig
from data.db import Database
from integration.orchestrator import Orchestrator


def portable_root() -> Path:
    """Directory the app writes to: the .exe folder, or the source tree."""
    if getattr(sys, "frozen", False):
        return Path(sys.executable).parent
    return Path(__file__).resolve().parent


def asset_root() -> Path:
    """Read-only bundled assets (web/, modules/): _MEIPASS when frozen."""
    if getattr(sys, "frozen", False):
        return Path(getattr(sys, "_MEIPASS", Path(sys.executable).parent))
    return Path(__file__).resolve().parent


def pick_port(preferred: int) -> int:
    import socket
    for port in [preferred] + list(range(5885, 5920)):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                s.bind(("127.0.0.1", port))
                return port
            except OSError:
                continue
    return preferred


def main():
    ap = argparse.ArgumentParser(
        description="VulnLab Sentinel - lab-only pentest console (portable)")
    ap.add_argument("--port", type=int, default=0,
                    help="override port (default: first free from 5885)")
    ap.add_argument("--no-browser", action="store_true",
                    help="do not auto-open the browser")
    args = ap.parse_args()

    cfg = SecureConfig(portable_root(), asset_root())
    if args.port:
        cfg.port = args.port
    else:
        cfg.port = pick_port(cfg.port)

    banner = r"""
 __   __    _         _     _           ____            _   _
 \ \ / /   | |_   _  | |   | |         / ___|  ___ _ __ | |_(_)_ __   ___
  \ V / _  | | | | | | |   | |    _____\___ \ / _ \ '_ \| __| | '_ \ / _ \
   | | (_) | | |_| | | |___| |___|_____|__) |  __/ | | | |_| | | | |  __/
   |_|\___/|_|\__,_| |_____|_____|    |____/ \___|_| |_|\__|_|_| |_|\___|

        LAB-ONLY portable console  -  v%s
""" % cfg.version

    print(banner)
    db = Database(cfg.data_dir)
    orch = Orchestrator(db, cfg)
    server = serve(cfg, orch)

    threading.Thread(target=server.serve_forever, daemon=True).start()
    url = f"http://{cfg.host}:{cfg.port}/"
    print(f"[*] Console ready at {url}")
    print(f"[*] MSGRPC backend: {orch.transport_kind()}  (real Framework or off-line simulator)")
    print("[*] Press Ctrl+C to stop and purge sessions.")
    if not args.no_browser:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Shutting down VulnLab Sentinel (sessions purged).")
        server.shutdown()


if __name__ == "__main__":
    main()