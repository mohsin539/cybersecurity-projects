"""Entrypoint: starts the hardened localhost service and opens the UI.

Portable behaviour:
  * windowed exe (no console) - service auto-opens the default browser
  * console run (python app/main.py) - Ctrl+C stops cleanly
  * idles for IDLE_MINUTES then self-terminates for good hygiene
"""
import os
import sys
import threading
import time
import webbrowser

if __package__ is None:
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from app import APP_NAME, __version__
    from app.server import AppServer
else:
    from . import APP_NAME, __version__
    from .server import AppServer

IDLE_MINUTES = 30


def resource_path(rel):
    """Resolve bundled (PyInstaller) or source-tree assets."""
    base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, rel)


def work_dir_for(web_dir):
    if getattr(sys, "frozen", False):
        base = os.path.dirname(os.path.abspath(sys.executable))
        work = os.path.join(base, "welics_case_data")
    else:
        work = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "workspace")
    os.makedirs(work, exist_ok=True)
    return os.path.abspath(work)


def idle_watchdog(server):
    while True:
        time.sleep(30)
        try:
            if time.time() - server.last_request > IDLE_MINUTES * 60:
                server.audit.append("system", "idle shutdown",
                                    "no traffic for %d min" % IDLE_MINUTES)
                server.safe_shutdown()
                return
        except Exception:
            return


def open_browser_later(url):
    def _run():
        time.sleep(1.2)
        try:
            webbrowser.open(url)
        except Exception:
            pass
    threading.Thread(target=_run, daemon=True).start()


def main():
    import traceback
    err_log = ""
    try:
        web_dir = resource_path(os.path.join("web"))
        work = work_dir_for(web_dir)
        err_log = os.path.join(work, "_startup.log")
        server = AppServer(web_dir=web_dir, work_dir=work)
        url = server.url()
        server.audit.append("system", "start", "%s v%s listening at %s" % (APP_NAME, __version__, url))
        watchdog = threading.Thread(target=idle_watchdog, args=(server,), daemon=True)
        watchdog.start()
        open_browser_later(url)
        print("=" * 72)
        print("  %s v%s" % (APP_NAME, __version__))
        print("  Local dashboard: %s" % url)
        print("  Bind: 127.0.0.1 (loopback only) - session-token protected")
        print("  Press Ctrl+C to stop. Auto-exits after %d min idle." % IDLE_MINUTES)
        print("=" * 72)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            server.audit.append("user", "stop", "interactive stop")
            print("\nStopping...")
        finally:
            server.server_close()
    except Exception:
        tb = traceback.format_exc()
        if err_log:
            try:
                with open(err_log, "w", encoding="utf-8") as fh:
                    fh.write(tb)
            except Exception:
                pass
        print("FATAL:", tb)
        raise
    finally:
        if getattr(sys, "frozen", False):
            os._exit(0)


if __name__ == "__main__":
    main()