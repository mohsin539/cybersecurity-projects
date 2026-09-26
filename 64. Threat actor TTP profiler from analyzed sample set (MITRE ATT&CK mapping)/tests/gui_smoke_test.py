"""TTPProfiler :: GUI smoke test (offscreen). Renders pages, grabs screenshots."""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from PySide6.QtWidgets import QApplication  # noqa: E402

from app.security import AuditChain  # noqa: E402
from app.services import Importer, ProfilerEngine  # noqa: E402
from app.store import SecureStore  # noqa: E402
from app.windows import MainWindow  # noqa: E402


def main() -> int:
    app = QApplication([])
    tmp = tempfile.mkdtemp(prefix="ttpp_gui_")
    store = SecureStore(tmp, encrypt_evidence=True)
    audit = AuditChain(store)
    win = MainWindow(store, audit, Path(tmp))

    demo = ROOT / "samples_demo"
    imp = Importer(store, audit, namespace="gui-test")
    res = imp.ingest_directory(demo, "gui-set", "GUI Sample Set")
    assert len(res.samples) == 3

    engine = ProfilerEngine(store, audit)
    profile = engine.build_profile("gui-set", namespace="gui-test")
    assert profile

    win._current_set_id = "gui-set"
    win._current_samples = res.samples
    win._current_profile = profile

    shots = Path(tmp) / "shots"
    shots.mkdir()
    pages = ["Dashboard", "Sample Explorer", "Threat Profile", "Reports", "Audit", "Security"]
    win.show()
    app.processEvents()
    for name in pages:
        win.go(name)
        app.processEvents()
        img = win.pages[name].grab()
        ok = img.save(str(shots / f"{name.replace(' ', '_')}.png"))
        assert ok, f"grab failed for {name}"
        print(f"rendered + saved: {name}")

    win.close()
    store.close()
    print("GUI SMOKE TEST PASSED [OK]")
    print("screenshots:", shots)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())