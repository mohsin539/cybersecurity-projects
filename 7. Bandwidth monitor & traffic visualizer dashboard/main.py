"""Bandwidth Monitor & Traffic Visualizer — entry point.

Usage
-----
    python main.py                       # defaults: 127.0.0.1:8000, 1s interval
    python main.py --host 0.0.0.0        # expose on all interfaces
    python main.py --port 9000           # custom port
    python main.py --interval 0.5        # 500 ms sample cadence
    python main.py --open-browser        # also open the dashboard in a browser

All numeric settings can also be provided via BWMON_* environment variables
(documented in ``config/settings.py``).
"""
from __future__ import annotations

import argparse
import logging
import socket
import sys
from dataclasses import replace
from typing import Optional

try:
    import uvicorn

    from application.monitoring import TelemetryService
    from application.process_stats import ProcessTrafficService
    from config import Settings, load_settings, warn_on_env_problems
    from infrastructure.capture.psutil_process_traffic import PsutilProcessTrafficSource
    from infrastructure.capture.psutil_source import PsutilNetworkSource
    from infrastructure.web.server import build_default_alert_service, create_app
except ImportError as _import_error:
    print(
        "\n  \033[31m✗ Missing dependency: "
        f"{_import_error.name or _import_error}\033[0m"
        "\n    Install the runtime requirements first:\n"
        "\n      pip install -r requirements.txt"
        "\n\n    On Windows you can also just run:\n"
        "\n      run.bat"
        "   (it picks the right interpreter and can set up the venv)\n",
        file=sys.stderr,
    )
    sys.exit(1)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Bandwidth Monitor & Traffic Visualizer Dashboard"
    )
    p.add_argument("--host", default=None, help="Bind address (default 127.0.0.1)")
    p.add_argument("--port", type=int, default=None, help="Bind port (default 8000)")
    p.add_argument(
        "--interval",
        type=float,
        default=None,
        help="Sample interval in seconds (default 1.0)",
    )
    p.add_argument(
        "--log-level",
        default=None,
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        help="Logging verbosity",
    )
    p.add_argument(
        "--no-connections",
        action="store_true",
        help="Disable expensive per-process connection enumeration",
    )
    p.add_argument(
        "--no-processes",
        action="store_true",
        help="Disable per-process bandwidth attribution",
    )
    p.add_argument(
        "--strict-port",
        action="store_true",
        help="Fail instead of falling back when the configured port is busy",
    )
    p.add_argument(
        "--open-browser",
        dest="open_browser",
        action="store_true",
        default=None,
        help="Open the dashboard URL in the default browser once the server is up",
    )
    p.add_argument(
        "--no-open-browser",
        dest="open_browser",
        action="store_false",
        default=None,
        help="Never open a browser, even if BWMON_OPEN_BROWSER is set",
    )
    return p.parse_args(argv)


def _port_available(host: str, port: int) -> bool:
    """True when a TCP listener can bind (host, port) right now."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        # No SO_REUSEADDR here: on Windows it would allow double-binds and
        # make the check unreliable. A plain bind fails for any live listener.
        try:
            sock.bind((host, port))
            return True
        except OSError:
            return False


# How far past the configured port the fallback probe searches.
_NEXT_PORT_SPAN = 25


def _next_free_port(
    host: str, start: int, max_tries: int = _NEXT_PORT_SPAN
) -> Optional[int]:
    """First bindable port >= ``start`` (probing in host:port order)."""
    for candidate in range(start, start + max_tries):
        if _port_available(host, candidate):
            return candidate
    return None


def _pid_on_port(port: int) -> Optional[int]:
    """Best-effort lookup of the pid listening on ``port``.

    Purely cosmetic for the error message; returns None when unavailable
    (e.g. connection enumeration requires elevation).
    """
    try:
        import psutil

        for conn in psutil.net_connections(kind="tcp"):
            if (
                conn.status == psutil.CONN_LISTEN
                and conn.laddr
                and conn.laddr.port == port
                and conn.pid
            ):
                return int(conn.pid)
    except Exception:  # noqa: BLE001 - cosmetic only, never fail startup
        return None
    return None


_DISPLAY_HOST_OVERRIDES = {
    "": "127.0.0.1",  # all interfaces → show loopback for the local browser
    "0.0.0.0": "127.0.0.1",
    "::": "[::1]",
    "[::]": "[::1]",
}


def _display_host(host: str) -> str:
    """Map a bind host to one a local browser can actually open.

    Wildcard bind addresses (``0.0.0.0`` / ``::``) are not browsable; the
    loopback equivalent is shown instead.
    """
    return _DISPLAY_HOST_OVERRIDES.get(host.strip().lower(), host.strip())


def _effective_url(host: str, port: int) -> str:
    """The URL a local browser can open for this server instance."""
    return f"http://{_display_host(host)}:{port}"


def _open_browser(url: str) -> bool:
    """Best-effort browser launch; returns True when a tab was opened."""
    try:
        import webbrowser

        return webbrowser.open(url, new=2)
    except Exception:  # noqa: BLE001 - cosmetic; never fail startup
        return False


def _effective_url_announcement(settings: "Settings") -> str:
    """Multi-line announcement of the URL the dashboard is reachable at.

    Always prints the effective URL (config port, or the fallback port
    picked when the configured one is busy), and calls out loudly when the
    port differs from the built-in default 8000 so the dashboard is never
    hunted for at the wrong address.
    """
    url = _effective_url(settings.host, settings.port)
    lines = [f"  \u001b[32m✓ Dashboard running at {url}\u001b[0m"]
    if settings.port != 8000:
        lines.append(
            f"  \u001b[33m⚠ Note: port {settings.port} differs from the default 8000 "
            f"— use the URL above.\u001b[0m"
        )
    lines.append(f"  API docs: {url}/docs")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)
    settings = load_settings()

    # Merge CLI overrides into the env-based settings.
    replacements: dict = {}
    if args.host is not None:
        replacements["host"] = args.host
    if args.port is not None:
        replacements["port"] = args.port
    if args.interval is not None:
        replacements["refresh_interval"] = args.interval
    if args.log_level is not None:
        replacements["log_level"] = args.log_level
    if args.no_connections:
        replacements["connections_enabled"] = False
    if args.no_processes:
        replacements["processes_enabled"] = False
    if args.strict_port:
        replacements["strict_port"] = True
    if args.open_browser is not None:
        replacements["open_browser"] = args.open_browser

    if replacements:
        settings = replace(settings, **replacements)

    # ---- Logging
    logging.basicConfig(
        level=settings.log_level,
        format="%(asctime)s  %(levelname)-7s  %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    logger = logging.getLogger("bwmon.main")

    # Flag malformed/typo'd BWMON_* entries in .env (they would otherwise
    # be silently skipped or fall back to defaults).
    warn_on_env_problems()

    # ---- Composition root
    source = PsutilNetworkSource()
    store = settings.resolve_store()
    logger.info("History backend: %s", settings.store_backend)
    alert_service = build_default_alert_service(settings)

    telemetry = TelemetryService(
        source=source,
        store=store,
        interval=settings.refresh_interval,
    )
    telemetry.subscribe(alert_service.evaluate)

    process_service: Optional[ProcessTrafficService] = None
    if settings.processes_enabled:
        process_source = PsutilProcessTrafficSource(min_scan_spacing=settings.process_scan_spacing)
        process_service = ProcessTrafficService(process_source)
        telemetry.subscribe(lambda snap: process_service.update(process_source.sample()))
        logger.info("Per-process attribution enabled")

    app = create_app(
        telemetry=telemetry,
        store=store,
        source=source,
        alert_service=alert_service,
        settings=settings,
        process_service=process_service,
    )

    logger.info(
        "Starting %s on %s:%s (interval=%.2fs, history=%d)",
        settings.version,
        settings.host,
        settings.port,
        settings.refresh_interval,
        settings.history_capacity,
    )

    # ---- Port resolution: strict (fail) or friendly fallback to next free port
    if not _port_available(settings.host, settings.port):
        busy_pid = _pid_on_port(settings.port)
        owner = f" (pid {busy_pid})" if busy_pid else ""
        if settings.strict_port:
            logger.error(
                "Port %s on %s is already in use%s", settings.port, settings.host, owner
            )
            print(
                f"\n  \033[31m✗ Port {settings.port} is busy{owner} — cannot start the dashboard.\033[0m"
                f"\n    Another process is listening on {settings.host}:{settings.port}."
                f"\n    Run on a different port:  python main.py --port {settings.port + 1}"
                f"\n    Or free the port first:   netstat -ano | findstr :{settings.port}"
                f"\n    (Auto-fallback is disabled: --strict-port / BWMON_STRICT_PORT)\n",
                file=sys.stderr,
            )
            sys.exit(1)

        fallback = _next_free_port(settings.host, settings.port + 1)
        if fallback is None:
            logger.error("No free port found near %s on %s", settings.port, settings.host)
            print(
                f"\n  \033[31m✗ Port {settings.port} is busy and no free port was found"
                f" within {_NEXT_PORT_SPAN + 1} tries.\033[0m\n",
                file=sys.stderr,
            )
            sys.exit(1)
        logger.warning(
            "Port %s busy%s — falling back to %s (disable with --strict-port)",
            settings.port,
            owner,
            fallback,
        )
        print(
            f"\n  \033[33m⚠ Port {settings.port} is busy{owner} — "
            f"starting on \033[1m{fallback}\033[0m\033[33m instead "
            f"(use --strict-port to fail instead).\033[0m\n",
            file=sys.stderr,
        )
        settings = replace(settings, port=fallback)

    print(
        "\n" + _effective_url_announcement(settings) + "\n",
        file=sys.stderr,
    )

    if settings.open_browser:
        if _open_browser(_effective_url(settings.host, settings.port)):
            logger.info("Dashboard opened in browser: %s", _effective_url(settings.host, settings.port))
        else:
            logger.warning("Could not open a browser automatically — open the URL above manually.")

    try:
        uvicorn.run(
            app,
            host=settings.host,
            port=settings.port,
            log_level=settings.log_level.lower(),
            access_log=False,
        )
    except OSError as exc:
        # Race: something grabbed the port between the check and the bind.
        logger.error("Could not bind %s:%s (%s)", settings.host, settings.port, exc)
        print(
            f"\n  \033[31m✗ Could not bind {settings.host}:{settings.port} ({exc})."
            f"\n    Try another port: python main.py --port {settings.port + 1}\033[0m\n",
            file=sys.stderr,
        )
        sys.exit(1)


if __name__ == "__main__":
    main()