"""VPN Tunnel Builder — web GUI entry point.

Usage:
    python run.py [--host 127.0.0.1] [--port 8090] [--data-dir data]
                  [--no-auth] [--no-browser]

Serves the console on http://127.0.0.1:8090 by default. Production serving is
done through `waitress` when available (portable, threadsafe) with the Flask
dev server as a fallback.
"""

from __future__ import annotations

import argparse
import os
import sys
import webbrowser

from app import APP_NAME, __version__
from app.web.app import create_app


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="VPN Tunnel Builder (WireGuard) — web console")
    parser.add_argument("--host", default="127.0.0.1", help="bind host (default 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8090, help="bind port (default 8090)")
    parser.add_argument("--data-dir", default="data", help="state/secret/audit directory")
    parser.add_argument("--no-auth", action="store_true",
                        help="DISABLE login. Only for trusted local use — prints a warning.")
    parser.add_argument("--no-browser", action="store_true", help="do not auto-open a browser")
    parser.add_argument("--backend", default=None,
                        help="force backend: auto|local|simulator|dry-run")
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    if args.no_auth:
        print("\n[!] WARNING: running with --no-auth. Do NOT expose this beyond a"
              " trusted localhost session. (NIST AC-3 / OWASP A01)")
        print(f"[i] Bind to {args.host}:{args.port} — the console will have no login.\n")

    if args.backend:
        os.environ.setdefault("VPNTB_BACKEND", args.backend)

    data_dir = os.path.abspath(args.data_dir)
    app = create_app(data_dir=data_dir, no_auth=args.no_auth)

    token_file = os.path.join(data_dir, "initial-auth.txt")
    boot = app.config.get("BOOTSTRAP_TOKEN")
    if boot:
        print("[i] New admin token generated — it is NOT shown again from the UI.")
        print(f"[i] Token saved to: {token_file}")
    elif not args.no_auth and os.path.exists(token_file):
        print(f"[i] Login token available in: {token_file}")

    backend = app.config["SERVICE_CTX"].backend
    print(f"[i] {APP_NAME} v{__version__}")
    print(f"[i] Data directory : {data_dir}")
    print(f"[i] Backend        : {backend.name}"
          + ("  (SIMULATED — no real interfaces will be created)" if backend.is_simulated else ""))
    url = f"http://{args.host}:{args.port}"
    print(f"[i] Console        : {url}")
    print("[i] Press Ctrl+C to stop.\n")

    if not args.no_browser:
        try:
            webbrowser.open(url)
        except Exception:
            pass

    try:
        from waitress import serve  # production-grade, portable
        serve(app, host=args.host, port=args.port,
              threads=8, channel_timeout=60)
    except ImportError:
        app.run(host=args.host, port=args.port, threaded=True,
                debug=False, use_reloader=False)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[.] stopped")
        sys.exit(130)