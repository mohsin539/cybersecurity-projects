"""Web App Fuzzer - entry point (portable GUI app)."""
import os
import sys
import traceback
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

_APP_DIR = Path(sys.executable).resolve().parent if getattr(sys, "frozen", False) else Path(__file__).resolve().parent

if getattr(sys, "frozen", False) and sys.stdout is None:
    sys.stdout = open(os.devnull, "w")
    sys.stderr = sys.stdout


def _startup() -> None:
    from app.gui.app import main
    main()


if __name__ == "__main__":
    try:
        _startup()
    except Exception:  # noqa: BLE001
        log_dir = Path(os.environ.get("WEBAPPFUZZER_LOG_DIR", _APP_DIR))
        try:
            log_dir.mkdir(parents=True, exist_ok=True)
            with open(log_dir / "startup_error.log", "w", encoding="utf-8") as fh:
                fh.write(traceback.format_exc())
        except Exception:
            pass
        try:
            import tkinter.messagebox as mb
            mb.showerror("Web App Fuzzer - startup error", traceback.format_exc())
        except Exception:
            pass
        raise