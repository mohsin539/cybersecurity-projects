"""Background worker that ticks the orchestration engine every poll interval.

Runs in-process when `ENABLE_EMBEDDED_WORKER=true` (development convenience) or
as a standalone process (`python -m app.worker`) in production containers.

Resilience: the loop catches all exceptions, logs them, and sleeps a few seconds
before retrying.  Each `tick()` is bounded to a small batch so a single bad run
cannot starve the others.
"""
from __future__ import annotations

import logging
import signal
import threading
import time
import datetime as dt

from app.config import settings
from app.db.base import SessionLocal
from app.services import engine

log = logging.getLogger("soarlite.worker")

_stop = threading.Event()
_thread: threading.Thread | None = None


def _run() -> None:
    log.info("worker started: poll_interval=%.1fs", settings.engine_poll_interval_seconds)
    while not _stop.is_set():
        session = SessionLocal()
        try:
            stats = engine.tick(session)
            if stats.get("advanced") or stats.get("completed") or stats.get("failed") or stats.get("awaiting"):
                log.info("tick stats: %s", stats)
        except Exception as exc:
            log.exception("tick error: %s", exc)
            time.sleep(2)
        finally:
            session.close()
        _stop.wait(settings.engine_poll_interval_seconds)
    log.info("worker stopped")


def start_embedded() -> None:
    global _thread
    if _thread is not None:
        return
    _stop.clear()
    _thread = threading.Thread(target=_run, name="soarlite-worker", daemon=True)
    _thread.start()


def stop() -> None:
    _stop.set()
    global _thread
    if _thread:
        _thread.join(timeout=5)
        _thread = None


if __name__ == "__main__":
    from app.core.logging_setup import setup_logging
    from app.db.base import init_db

    setup_logging()
    init_db()

    def handler(signum, frame):
        stop()

    signal.signal(signal.SIGINT, handler)
    signal.signal(signal.SIGTERM, handler)
    _run()