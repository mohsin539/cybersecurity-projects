import os

os.environ["QT_QPA_PLATFORM"] = "offscreen"

from PySide6.QtCore import QTimer
from PySide6.QtWidgets import QApplication

from arp_scanner.gui.main_window import MainWindow
from arp_scanner.security import guard

guard.acknowledge_consent()
app = QApplication([])
win = MainWindow()
win._refresh_interfaces(autodetect=True) if hasattr(win, "_refresh_interfaces") else None
win.show()
assert win.iface_combo.count() >= 1, "interface combo populated"
assert win.table.columnCount() == 5, "table has 5 columns"

exit_code = []


def _finish():
    win.close()
    app.quit()
    exit_code.append("ok")


QTimer.singleShot(1200, _finish)
legacy = app.exec()
print(f"GUI smoke OK, exec={legacy}, combos={win.iface_combo.count()}")
print(f"celebrity local: {win.local_label.text()}")