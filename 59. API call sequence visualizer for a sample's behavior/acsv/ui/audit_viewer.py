"""Audit viewer page (architecture §8: append-only hash-chained log,
integrity self-check, export)."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtWidgets import (
    QFileDialog, QHBoxLayout, QLabel, QMessageBox, QPushButton, QTableWidget,
    QTableWidgetItem, QVBoxLayout, QWidget,
)

from .widgets import section_title


class AuditPage(QWidget):
    def __init__(self, win) -> None:
        super().__init__()
        self.win = win
        self._build()

    def _build(self) -> None:
        lay = QVBoxLayout(self)
        lay.setContentsMargins(26, 22, 26, 22)
        lay.setSpacing(12)

        title = QLabel("Audit Log (append-only · HMAC-chain)")
        title.setObjectName("PageTitle")
        lay.addWidget(title)

        head = QHBoxLayout()
        verify = QPushButton("✓  Verify chain integrity")
        verify.setObjectName("Primary")
        verify.clicked.connect(self._verify)
        export = QPushButton("⬇  Export audit bundle (jsonl + manifest)")
        export.clicked.connect(self._export)
        rotate = QPushButton("↻ Rotate secrets")
        rotate.clicked.connect(self._rotate)
        self.status = QLabel("Status: unknown")
        self.status.setObjectName("kpi_label")
        for w in (verify, export, rotate):
            head.addWidget(w)
        head.addStretch(1)
        head.addWidget(self.status)
        lay.addLayout(head)

        lay.addWidget(section_title("Entries (newest first)"))
        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(["Seq", "Time", "Actor", "Action", "Payload", "Entry hash"])
        self.table.setAlternatingRowColors(True)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        lay.addWidget(self.table, stretch=1)

    def on_shown(self) -> None:
        self.table.setRowCount(0)
        for e in self.win.services.audit.iter_entries():
            r = self.table.rowCount()
            self.table.insertRow(r)
            self.table.setItem(r, 0, QTableWidgetItem(str(e["seq"])))
            self.table.setItem(r, 1, QTableWidgetItem(e.get("ts_dt", "")))
            self.table.setItem(r, 2, QTableWidgetItem(e["actor"]))
            self.table.setItem(r, 3, QTableWidgetItem(e["action"]))
            import json
            self.table.setItem(r, 4, QTableWidgetItem(json.dumps(e["payload"])[:80]))
            self.table.setItem(r, 5, QTableWidgetItem(e["entry_hash"][:20] + "…"))
        self.table.resizeColumnsToContents()
        self.status.setText(f"Status: {self.win.services.audit.count()} entries")

    # ---------------------------------------------------------------- actions
    def _verify(self) -> None:
        try:
            ok, failures = self.win.services.audit.verify_chain()
        except Exception as exc:  # noqa: BLE001
            QMessageBox.critical(self, "Verify failed", str(exc))
            return
        self.win.services.audit.record("INTEGRITY_CHECK", {
            "ok": ok, "failures": len(failures),
        })
        if ok:
            QMessageBox.information(self, "Audit integrity",
                                    "Chain verified — no tampering detected.")
        else:
            QMessageBox.critical(self, "Audit integrity",
                                 f"Tampering detected:\n" + "\n".join(
                                     str(f) for f in failures[:20]))

    def _export(self) -> None:
        dest, _ = QFileDialog.getExistingDirectory(self, "Export audit bundle to")
        if not dest:
            return
        manifest = self.win.services.audit.export(Path(dest))
        self.win.services.audit.record("AUDIT_EXPORT", {
            "dir": dest, "lines": manifest["lines"], "sha256": manifest["sha256"],
        })
        QMessageBox.information(self, "Export", f"Exported {manifest['lines']} entries\n"
                                                f"SHA-256: {manifest['sha256']}")

    def _rotate(self) -> None:
        self.win.services.dapi.rotate_secrets()
        self.win.services.audit.record("AUDIT_ROTATE_KEYS", {"by": "user"})
        QMessageBox.information(self, "Secrets rotated",
                                "HMAC master key rotated (new entry chained from new key).\n"
                                "Historical chain verification now requires the old key.")