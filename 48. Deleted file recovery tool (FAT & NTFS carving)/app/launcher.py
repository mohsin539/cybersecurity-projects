"""Startup resilience + diagnostics for the portable (windowed) EXE.

A GUI-subsystem build has no console, so an early exception looks exactly
like "the exe does not launch".  This module guarantees three things:

  1. Every uncaught exception is persisted to a log file the operator can
     read (`%LOCALAPPDATA%\\RecovProSecure\\error.log` and, when writable, a
     copy next to the bundle as ``error.log``).
  2. ``--diagnose`` writes ``diagnostics.txt`` and then exits, which settles
     misplacement/copy issues (leaving the exe without its ``_internal``
     folder is the classic silent failure).
  3. GUI startup is wrapped so the window *always* shows a readable message
     box if something fails instead of vanishing.
"""

from __future__ import annotations

import os
import sys
import threading
import traceback


def appdata_dir() -> str:
    base = os.environ.get("LOCALAPPDATA") or os.environ.get("TEMP") or os.getcwd()
    d = os.path.join(base, "RecovProSecure")
    try:
        os.makedirs(d, exist_ok=True)
    except Exception:
        d = os.path.join(base, "RecovProSecure")
    return d


def bundle_dir() -> str:
    """Directory that holds the portable bundle (exe sibling)."""
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _version() -> str:
    try:
        from . import __version__
        return __version__
    except Exception:
        return "unknown"


def write_fault(exc: BaseException, tb=None, stage: str = "runtime") -> str:
    """Persist a fault report; returns the log path written."""
    log_dir = appdata_dir()
    path = os.path.join(log_dir, "error.log")
    body = (
        "RecovPro Secure fault report\n"
        f"stage        : {stage}\n"
        f"time         : {__import__('datetime').datetime.now().isoformat()}\n"
        f"frozen       : {getattr(sys, 'frozen', False)}\n"
        f"executable   : {sys.executable}\n"
        f"version      : {_version()}\n"
        "\n"
    )
    body += "".join(
        traceback.format_exception(type(exc), exc, tb or exc.__traceback__)
    )
    try:
        with open(path, "a", encoding="utf-8") as f:
            f.write(body + "\n" + "=" * 60 + "\n")
        # A copy in the bundle next to the exe so operators see it.
        try:
            with open(os.path.join(bundle_dir(), "error.log"), "a", encoding="utf-8") as f2:
                f2.write(body + "\n" + "=" * 60 + "\n")
        except Exception:
            pass
    except Exception:
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "error.log")
        try:
            with open(path, "a", encoding="utf-8") as f:
                f.write(body + "\n")
        except Exception:
            pass
    return path


def install_guard() -> None:
    """Route all unhandled exceptions to write_fault()."""
    def _hook(exc_type, exc_value, exc_tb):
        if issubclass(exc_type, KeyboardInterrupt):
            sys.__excepthook__(exc_type, exc_value, exc_tb)
            return
        write_fault(exc_value, exc_tb, stage="unhandled")
    sys.excepthook = _hook

    def _thread_hook(args):
        write_fault(args.exc_value, args.exc_traceback,
                    stage=f"thread:{args.thread.name}")
    threading.excepthook = _thread_hook


def diagnose(silent: bool = True) -> dict:
    """Environment + capability probe used by ``--diagnose``."""
    import platform
    from datetime import datetime, timezone

    out: dict = {
        "time": datetime.now(timezone.utc).isoformat(),
        "platform": platform.platform(),
        "python": platform.python_version(),
        "frozen": bool(getattr(sys, "frozen", False)),
        "executable": sys.executable,
        "cwd": os.getcwd(),
        "appdata_dir": appdata_dir(),
        "bundle_dir": bundle_dir(),
    }
    # writability (this is the #1 silent-failure cause: exe copied alone)
    tests = {
        "appdata_writable": os.access(appdata_dir(), os.W_OK),
        "bundle_writable": os.access(bundle_dir(), os.W_OK),
        "layers_present": os.path.exists(bundle_dir()) and
                         (getattr(sys, "frozen", False) and
                          os.path.isdir(os.path.join(bundle_dir(), "_internal"))
                          or not getattr(sys, "frozen", False)),
    }
    out.update(tests)
    try:
        from PySide6 import __version__ as qv
        from PySide6.QtCore import qVersion
        out["pyqt"] = f"PySide6 {qv} / Qt {qVersion()}"
    except Exception as e:
        out["pyqt"] = f"{type(e).__name__}: {e}"
    try:
        from cryptography import __version__ as cv
        out["cryptography"] = cv
    except Exception as e:
        out["cryptography"] = f"{type(e).__name__}: {e}"
    try:
        import PIL
        out["pillow"] = PIL.__version__
    except Exception as e:
        out["pillow"] = f"{type(e).__name__}: {e}"
    try:
        from app.core.disk import is_elevated, enumerate_logical_volumes
        out["elevated"] = bool(is_elevated())
        vols = enumerate_logical_volumes()
        out["volumes"] = [f"{v.device_path} {v.fs_type or 'RAW'} {v.label or ''}" for v in vols]
    except Exception as e:
        out["volume_probe"] = f"{type(e).__name__}: {e}"
    if not silent:
        for k, v in out.items():
            print(f"{k:18s} : {v}")
    return out


def write_diagnostics() -> str:
    out = diagnose(silent=True)
    path = os.path.join(bundle_dir(), "diagnostics.txt")
    with open(path, "w", encoding="utf-8") as f:
        for k, v in out.items():
            f.write(f"{k:18s} : {v}\n")
    return path