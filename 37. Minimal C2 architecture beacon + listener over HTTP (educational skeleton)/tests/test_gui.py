"""Verify GUI constructs without mainloop (smoke test)."""
import sys

sys.path.insert(0, ".")

from src.gui import C2Gui

app = C2Gui()
app.update()
app.start_listener()      # starts listener + demo beacon thread
for _ in range(8):
    app.update()
    app.after(200)
    try:
        app.tk.dooneevent(app.tk.ALL_EVENTS)  # pump event queue a bit
    except Exception:
        pass
beacons = app.listener.registry.snapshot() if app.listener else []
print("GUI constructed OK; beacons seen:", len(beacons))
app._on_close()
print("GUI closed cleanly")