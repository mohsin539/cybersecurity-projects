"""Vault & Audit page — integrity, tamper-evidence and encrypted export."""

from __future__ import annotations

from PySide6.QtCore import Qt, QAbstractTableModel, QModelIndex, Signal
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QTableView, QHeaderView,
    QTabWidget, QLabel, QFileDialog, QMessageBox, QInputDialog, QAbstractItemView,
)

from .theme import PALETTE


class VaultModel(QAbstractTableModel):
    cols = [("name", "File"), ("sha256", "SHA-256"), ("size", "Size"),
            ("kind", "Kind"), ("stored", "Stored At")]

    def __init__(self, parent=None):
        super().__init__(parent)
        self.rows = []

    def set_rows(self, rows):
        self.beginResetModel()
        self.rows = rows
        self.endResetModel()

    def rowCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self.rows)

    def columnCount(self, parent=QModelIndex()):
        return len(self.cols)

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if role == Qt.DisplayRole and orientation == Qt.Horizontal:
            return self.cols[section][1]
        return None

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid():
            return None
        r = self.rows[index.row()]
        key = self.cols[index.column()][0]
        if role == Qt.DisplayRole:
            v = r.get(key, "")
            if key == "sha256":
                return str(v)[:16] + "…"
            return str(v)
        if role == Qt.ToolTipRole:
            return r.get("sha256", "")
        if role == Qt.ForegroundRole:
            return QColor(PALETTE["text"])
        return None


class AuditModel(QAbstractTableModel):
    cols = [("ts", "Timestamp"), ("event", "Event"), ("result", "Result"),
            ("source", "Source"), ("detail", "Details"), ("self", "Hash (trunc)")]

    def __init__(self, parent=None):
        super().__init__(parent)
        self.rows = []

    def set_rows(self, rows):
        self.beginResetModel()
        self.rows = rows
        self.endResetModel()

    def rowCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self.rows)

    def columnCount(self, parent=QModelIndex()):
        return len(self.cols)

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if role == Qt.DisplayRole and orientation == Qt.Horizontal:
            return self.cols[section][1]
        return None

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid():
            return None
        r = self.rows[index.row()]
        key = self.cols[index.column()][0]
        if role == Qt.DisplayRole:
            v = r.get(key, "")
            if key == "self":
                return str(v)[:12] + "…" if v else ""
            if key == "detail" and isinstance(v, dict):
                items = []
                for kk in ("name", "sha", "size", "error", "target"):
                    if kk in v:
                        items.append(f"{kk}={v[kk]}")
                return ", ".join(items)
            return str(v)
        if role == Qt.ForegroundRole:
            if key == "result" and r.get("result") == "error":
                return QColor("#f87171")
            return QColor(PALETTE["text"])
        if role == Qt.BackgroundRole and key == "result":
            if r.get("result") == "error":
                return QColor("#3d1d1d")
        return None


class SecurityPage(QWidget):
    def __init__(self, vault, audit, parent=None):
        super().__init__(parent)
        self.vault = vault
        self.audit = audit
        self._vault_items = []
        root = QVBoxLayout(self)
        root.setContentsMargins(18, 18, 18, 18)
        root.setSpacing(12)

        head = QLabel("Vault & Audit — integrity, tamper-evidence, at-rest encryption")
        head.setStyleSheet("font-size:16px; font-weight:600; color:#fff;")
        root.addWidget(head)

        self.tabs = QTabWidget()
        root.addWidget(self.tabs, 1)

        # ---- vault tab
        vtab = QWidget()
        vl = QVBoxLayout(vtab)
        bar = QHBoxLayout()
        self.vault_info = QLabel("No vault loaded")
        self.vault_info.setStyleSheet("color:#93a4c4;")
        self.btn_export_vault = QPushButton("Export Encrypted Bundle (AES-256-GCM)")
        self.btn_restore = QPushButton("Restore Bundle…")
        self.btn_verify_vault = QPushButton("Verify Integrity")
        bar.addWidget(self.vault_info, 1)
        bar.addWidget(self.btn_verify_vault)
        bar.addWidget(self.btn_export_vault)
        bar.addWidget(self.btn_restore)
        vl.addLayout(bar)
        self.vault_table = QTableView()
        self.vault_model = VaultModel(self)
        self.vault_table.setModel(self.vault_model)
        self.vault_table.setAlternatingRowColors(True)
        self.vault_table.verticalHeader().setVisible(False)
        self.vault_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        hh = self.vault_table.horizontalHeader()
        hh.setSectionResizeMode(0, QHeaderView.Stretch)
        hh.setSectionResizeMode(1, QHeaderView.Stretch)
        vl.addWidget(self.vault_table, 1)
        self.tabs.addTab(vtab, "Recovery Vault")

        # ---- audit tab
        atab = QWidget()
        al = QVBoxLayout(atab)
        abar = QHBoxLayout()
        self.audit_info = QLabel("Tamper-evident hash-chained audit log")
        self.audit_info.setStyleSheet("color:#93a4c4;")
        self.btn_verify_chain = QPushButton("Verify Audit Chain")
        self.btn_open_log = QPushButton("Refresh Log")
        abar.addWidget(self.audit_info, 1)
        abar.addWidget(self.btn_open_log)
        abar.addWidget(self.btn_verify_chain)
        al.addLayout(abar)
        self.audit_table = QTableView()
        self.audit_model = AuditModel(self)
        self.audit_table.setModel(self.audit_model)
        self.audit_table.setAlternatingRowColors(True)
        self.audit_table.verticalHeader().setVisible(False)
        ah = self.audit_table.horizontalHeader()
        ah.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        ah.setSectionResizeMode(4, QHeaderView.Stretch)
        al.addWidget(self.audit_table, 1)
        self.tabs.addTab(atab, "Audit Log")

        self.btn_verify_vault.clicked.connect(self._verify_vault)
        self.btn_export_vault.clicked.connect(self._export_vault)
        self.btn_restore.clicked.connect(self._restore_vault)
        self.btn_verify_chain.clicked.connect(self._verify_chain)
        self.btn_open_log.clicked.connect(self._refresh_all)
        self.refresh_vault()

    # ------------------------------------------------------------------
    def set_vault(self, vault):
        self.vault = vault
        self.refresh_vault()

    def refresh_vault(self):
        if not self.vault:
            self.vault_model.set_rows([])
            self.vault_info.setText("No vault loaded — run a recovery first.")
            return
        self._vault_items = self.vault.list_items()
        self.vault_model.set_rows(self._vault_items)
        self.vault_info.setText(
            f"Vault: {self.vault.root}  ·  {len(self._vault_items)} artifacts, SHA-256 manifest")

    def _refresh_audit(self):
        entries = self.audit.read_entries(500)
        self.audit_model.set_rows(entries)

    def _refresh_all(self):
        self.refresh_vault()
        self._refresh_audit()

    def _verify_vault(self):
        if not self.vault:
            return
        ok, total = self.vault.verify_all()
        self.audit.log("vault_integrity_check", result="ok" if ok == total else "error",
                       detail={"verified": ok, "total": total})
        QMessageBox.information(
            self, "Vault Integrity",
            f"{ok} of {total} artifacts passed SHA-256 verification."
            + ("" if ok == total else "\nSome artifacts failed verification — do not rely on them."))

    def _export_vault(self):
        if not self.vault:
            QMessageBox.information(self, "Vault", "No vault to export.")
            return
        path, _ = QFileDialog.getSaveFileName(self, "Export encrypted vault bundle",
                                             "recovery-vault.recpro", "RecovPro bundle (*.recpro)")
        if not path:
            return
        pwd, ok = QInputDialog.getText(self, "Encrypt bundle",
                                       "Set a strong passphrase (confirmed remember: none stored):",
                                       echo=QInputDialog.Password)
        if not ok or not pwd:
            return
        try:
            self.vault.export_encrypted(path, pwd)
            self.audit.log("vault_export_encrypted", detail={"path": path.split("\\")[-1]})
            QMessageBox.information(self, "Exported",
                                    "Encrypted AES-256-GCM bundle written.\n"
                                    "The passphrase is not stored anywhere by design.")
        except Exception as e:
            self.audit.log("vault_export_failed", result="error", detail={"error": str(e)[:150]})
            QMessageBox.critical(self, "Export failed", str(e))

    def _restore_vault(self):
        path, _ = QFileDialog.getOpenFileName(self, "Open encrypted vault bundle",
                                             "", "RecovPro bundle (*.recpro)")
        if not path:
            return
        pwd, ok = QInputDialog.getText(self, "Restore bundle",
                                       "Passphrase:", echo=QInputDialog.Password)
        if not ok:
            return
        outdir = QFileDialog.getExistingDirectory(self, "Restore into folder")
        if not outdir:
            return
        try:
            n = self.vault.restore_encrypted(path, pwd, outdir)
            self.audit.log("vault_restore", detail={"files": n})
            self.refresh_vault()
            QMessageBox.information(self, "Restored", f"{n} artifacts restored to vault.")
        except Exception as e:
            QMessageBox.critical(self, "Restore failed",
                                 "Wrong passphrase or corrupted bundle.\n" + str(e))

    def _verify_chain(self):
        ok, n = self.audit.verify_chain()
        self.audit.log("audit_chain_check", result="ok" if ok else "error",
                       detail={"entries": n})
        if ok:
            QMessageBox.information(self, "Audit Chain",
                                    f"Hash chain verified — {n} entries.",
                                    )
        else:
            QMessageBox.critical(self, "Audit Chain",
                                 "Chain integrity check FAILED — log may be tampered with.")