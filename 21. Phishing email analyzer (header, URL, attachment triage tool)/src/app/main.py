"""Entry point: bootstrap, secure gate, launch analyst console.

Controls exercised at startup:
  - SC-7 / availability: refuse to run with critically low disk space.
  - A07 / IA-5: no default credentials - the vault gate must succeed.
  - A09 / AU-3: application start/exit audited, tamper-evident chain.
  - SC-28 / A10.1: all persisted state (profile, audit, settings, cases) is
    AES-256-GCM encrypted under a password-unwrapped data key.

Run GUI:        py -3.12 -m src.app.main
Diagnostics:    py -3.12 -m src.app.main --self-test   (headless engine tests)
"""
from __future__ import annotations

import os
import sys
import time
import tkinter as tk


def _data_dir() -> str:
    env = os.environ.get("PEA_DATA_DIR", "").strip()
    if env:
        root = env
    else:
        base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
        root = os.path.join(base, "PhishingEmailAnalyzer")
    os.makedirs(root, exist_ok=True)
    from .sec.validation import check_disk_usage
    check_disk_usage(root)
    return root


def _bootstrap():
    from .sec.identity import IdentityStore, Session
    from .sec.audit import AuditLog
    from .data.settings import SettingsVault
    from .data.store import CaseStore
    from .ui.login import Gate
    from .ui.app_window import AppWindow

    data_dir = _data_dir()
    store = IdentityStore(os.path.join(data_dir, "profile.dat"))

    root = tk.Tk()
    root.withdraw()
    result = Gate(root, store).run()
    root.destroy()
    if result is None:
        return 1
    username, role, data_key, password = result

    session = Session(username, role, bytes(data_key), password)
    audit = AuditLog(os.path.join(data_dir, "audit"), session.data_key)
    settings = SettingsVault(os.path.join(data_dir, "settings.dat"), session.data_key)
    cases = CaseStore(data_dir, session.data_key)
    audit.append("APP_START", username, role, detail="application started")

    app = AppWindow(session, store, audit, settings, cases, data_dir)
    app.mainloop()
    session.wipe()
    return 0


def _self_test():
    """Headless engine/security self-tests (no GUI, no network required)."""
    from .tests_self import run_all
    ok, failures = run_all()
    print(f"SELF-TEST {'PASS' if ok else 'FAIL'}  (failures: {failures})")
    sys.exit(0 if ok else 2)


def main() -> int:
    if "--self-test" in sys.argv:
        return _self_test()
    try:
        return _bootstrap()
    except Exception as exc:  # noqa: BLE001
        try:
            err = os.path.join(_data_dir(), "errors.log")
            with open(err, "a", encoding="utf-8") as fh:
                fh.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] "
                         f"fatal: {type(exc).__name__}: {str(exc)[:500]}\n")
        except Exception:  # noqa: BLE001
            pass
        print(f"Fatal error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())