"""Portable GUI — SAP triage console (PySide6).

Default UX of the portable `SAP.exe`: open a sample, run the pipeline, and
inspect the triage card across Strings / PE / Intel / Findings tabs with a
colored risk gauge. All pipeline work happens on a worker thread; the UI only
talks to the controller, never to the filesystem directly (ASVS V4.1).

Requires PySide6 (bundled in the portable build; `sap.gui` import fails
gracefully without it so `sap scan` still works headless).
"""
from __future__ import annotations

import sys
import threading
import traceback
from pathlib import Path

from sap import APP_TITLE, __version__
from sap.app import SAPController, ScanConfig
from sap.security.policy import PolicyViolation

BAND_COLORS = {
    "benign": "#27ae60",
    "low": "#f1c40f",
    "suspicious": "#e67e22",
    "high": "#c0392b",
}


class ScanWorker(object):
    """Runs one scan with progress callbacks (no Qt QThread dependency: the
    controller is detached from the UI via plain callbacks + a timer poll)."""

    def __init__(self, controller: SAPController, sample: str,
                 on_done, on_error, on_log, cancel_event: threading.Event):
        self.controller = controller
        self.sample = sample
        self.on_done = on_done
        self.on_error = on_error
        self.on_log = on_log
        self.cancel_event = cancel_event
        self.thread: threading.Thread | None = None

    def start(self) -> None:
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def _run(self) -> None:
        try:
            self.on_log("sealing sample (sha256/sha1/md5/blake2b) ...")
            card = self.controller.scan_sample(self.sample, self.cancel_event)
            self.on_log(f"scan complete: risk {card['risk']['score']}/100 "
                        f"[{card['risk']['band']}]")
            self.on_done(card)
        except PolicyViolation as exc:
            self.on_error(f"policy violation (fail closed): {exc}")
        except Exception as exc:
            self.on_error(f"scan error: {type(exc).__name__}: {exc}")
            if "SAP_DEBUG" in __import__("os").environ:
                traceback.print_exc()


def _run_gui() -> int:
    import os

    from PySide6.QtCore import Qt, QTimer
    from PySide6.QtGui import QAction, QFont
    from PySide6.QtWidgets import (
        QApplication, QCheckBox, QFileDialog, QHBoxLayout, QLabel, QLineEdit,
        QMainWindow, QMessageBox, QPlainTextEdit, QProgressBar, QPushButton,
        QSplitter, QTableWidget, QTableWidgetItem, QTabWidget, QVBoxLayout,
        QWidget,
    )

    class MainWindow(QMainWindow):
        def __init__(self):
            super().__init__()
            self.setWindowTitle(f"{APP_TITLE} {__version__} — triage console")
            self.resize(1180, 760)
            self._worker = None
            self._cancel = threading.Event()
            self._build_ui()

        # ------------------------------------------------------------- UI ---
        def _build_ui(self):
            tb = self.addToolBar("main")
            tb.setMovable(False)
            self.act_open = QAction("Open Sample", self)
            self.act_run = QAction("Run Scan", self)
            self.act_verify = QAction("Verify Case", self)
            self.act_seal = QAction("Seal & Export", self)
            self.act_ioc = QAction("IOC Manager", self)
            self.act_open.triggered.connect(self._open_sample)
            self.act_run.triggered.connect(self._run_scan)
            self.act_verify.triggered.connect(self._verify)
            self.act_seal.triggered.connect(self._seal)
            self.act_ioc.triggered.connect(self._add_ioc_dialog)
            for a in (self.act_open, self.act_run, self.act_verify,
                      self.act_seal, self.act_ioc):
                tb.addAction(a)
            self.act_run.setEnabled(False)

            form = QWidget()
            lay = QVBoxLayout(form)
            lay.addWidget(QLabel("<b>Sample</b>"))
            row = QHBoxLayout()
            self.ed_sample = QLineEdit()
            self.ed_sample.setPlaceholderText("select a suspicious binary ...")
            btn = QPushButton("Browse")
            btn.clicked.connect(self._open_sample)
            row.addWidget(self.ed_sample, 1)
            row.addWidget(btn)
            lay.addLayout(row)

            row2 = QHBoxLayout()
            lay2 = QVBoxLayout()
            lay2.addWidget(QLabel("Analyst"))
            self.ed_analyst = QLineEdit("analyst")
            lay2.addWidget(self.ed_analyst)
            row2.addLayout(lay2, 1)
            lay3 = QVBoxLayout()
            lay3.addWidget(QLabel("Case directory"))
            self.ed_case = QLineEdit("SAP_CaseWork")
            lay3.addWidget(self.ed_case)
            row2.addLayout(lay3, 1)
            lay.addLayout(row2)
            self.chk_egress = QCheckBox(
                "Enable hashed-only intel egress (allowlisted, capped)")
            self.chk_egress.setToolTip(
                "Only sha256 digests are sent; raw sample bytes NEVER leave the host.")
            lay.addWidget(self.chk_egress)
            lay.addStretch(1)

            left = QWidget()
            llay = QVBoxLayout(left)
            llay.addWidget(form)
            self.digest_box = QPlainTextEdit()
            self.digest_box.setReadOnly(True)
            self.digest_box.setMaximumHeight(120)
            monofont = QFont("Consolas")
            self.digest_box.setFont(monofont)
            llay.addWidget(self.digest_box)

            self.gauge = QProgressBar()
            self.gauge.setRange(0, 100)
            self.gauge.setFormat("%v / 100")
            self.gauge.setTextVisible(True)
            self.gauge.setMaximumHeight(26)
            self.gauge.setStyleSheet(
                "QProgressBar{border:1px solid #ccc;border-radius:8px;"
                "background:#f4f6f8;text-align:center}")
            llay.addWidget(self.gauge)
            self.lbl_band = QLabel("ready")
            self.lbl_band.setWordWrap(True)
            llay.addWidget(self.lbl_band)

            self.tabs = QTabWidget()
            self.tab_summ = QWidget()
            self.tab_str = QWidget()
            self.tab_pe = QWidget()
            self.tab_intel = QWidget()
            self.tab_find = QWidget()
            self._build_summary_tab()
            self._build_strings_tab()
            self._build_pe_tab()
            self._build_intel_tab()
            self._build_findings_tab()
            self.tabs.addTab(self.tab_summ, "Triage")
            self.tabs.addTab(self.tab_str, "Strings")
            self.tabs.addTab(self.tab_pe, "PE Structure")
            self.tabs.addTab(self.tab_intel, "Threat Intel")
            self.tabs.addTab(self.tab_find, "Findings")

            self.log_text = QPlainTextEdit()
            self.log_text.setReadOnly(True)
            self.log_text.setMaximumHeight(170)
            self.log_text.setPlaceholderText("audit / scan log")

            right = QWidget()
            rlay = QVBoxLayout(right)
            rlay.addWidget(self.tabs, 1)
            rlay.addWidget(QLabel("<b>Log</b>"))
            rlay.addWidget(self.log_text)

            split = QSplitter()
            split.addWidget(left)
            split.addWidget(right)
            split.setSizes([360, 760])
            self.setCentralWidget(split)
            self.statusBar().showMessage("idle")

        def _table(self, parent: QWidget, headers: list[str]):
            table = QTableWidget(0, len(headers))
            table.setHorizontalHeaderLabels(headers)
            table.verticalHeader().setVisible(False)
            table.setEditTriggers(QTableWidget.NoEditTriggers)

            def fill(rows: list[tuple]) -> None:
                table.setRowCount(len(rows))
                for r, row in enumerate(rows):
                    for c, value in enumerate(row):
                        item = QTableWidgetItem(str(value))
                        if c == 0:
                            item.setFont(QFont("Consolas"))
                        table.setItem(r, c, item)
                table.resizeColumnsToContents()
            table.setProperty("_fill", fill)
            lay = QVBoxLayout(parent)
            lay.addWidget(table)
            return table, fill

        def _build_summary_tab(self):
            self.tbl_controls, self.fill_controls = self._table(
                self.tab_summ, ["Control", "Framework"])

        def _build_strings_tab(self):
            self.lbl_str = QLabel("no strings run yet")
            self.lbl_str.setWordWrap(True)
            self.tbl_art, self.fill_art = self._table(
                self.tab_str, ["kind", "value", "offset", "entropy"])
            lay = self.tab_str.layout() or QVBoxLayout(self.tab_str)
            lay.insertWidget(0, self.lbl_str)

        def _build_pe_tab(self):
            self.lbl_pe = QLabel("no PE run yet")
            self.lbl_pe.setWordWrap(True)
            self.tbl_sec, self.fill_sec = self._table(
                self.tab_pe, ["name", "entropy", "raw_size", "virtual_size", "writable", "anomaly"])
            lay = self.tab_pe.layout() or QVBoxLayout(self.tab_pe)
            lay.insertWidget(0, self.lbl_pe)

        def _build_intel_tab(self):
            self.lbl_intel = QLabel("no intel run yet")
            self.lbl_intel.setWordWrap(True)
            self.tbl_hits, self.fill_hits = self._table(
                self.tab_intel, ["source", "verdict", "detections", "total", "reference"])
            lay = self.tab_intel.layout() or QVBoxLayout(self.tab_intel)
            lay.insertWidget(0, self.lbl_intel)

        def _build_findings_tab(self):
            self.tbl_find, self.fill_find = self._table(
                self.tab_find, ["severity", "rule_id", "title", "category", "controls"])
            self.lbl_find = QLabel("")
            lay = self.tab_find.layout() or QVBoxLayout(self.tab_find)
            lay.insertWidget(0, self.lbl_find)

        # ----------------------------------------------------------- actions ---
        def _open_sample(self):
            path, _ = QFileDialog.getOpenFileName(
                self, "Open suspicious binary", "",
                "Binaries (*.exe *.dll *.sys *.scr *.bin);;All files (*.*)")
            if path:
                self.ed_sample.setText(path)
                self.act_run.setEnabled(True)
                self._log(f"sample selected: {path}")
                self._show_digest_preview(path)

        def _show_digest_preview(self, path):
            try:
                from sap.engines.hashing import compute_all
                d = compute_all(path)
                self.digest_box.setPlainText(
                    f"md5     {d['md5']}\nsha1     {d['sha1']}\n"
                    f"sha256  {d['sha256']}\nblake2b {d['blake2b']}")
            except Exception as exc:
                self.digest_box.setPlainText(f"digest error: {exc}")

        def _run_scan(self):
            if self._worker is not None and self._worker.thread and \
                    self._worker.thread.is_alive():
                return
            sample = self.ed_sample.text().strip()
            case_dir = self.ed_case.text().strip() or "SAP_CaseWork"
            analyst = self.ed_analyst.text().strip() or "analyst"
            if not sample or not Path(sample).is_file():
                QMessageBox.warning(self, "No sample", "Choose an existing sample file.")
                return
            self._cancel.clear()
            try:
                config = ScanConfig(analyst=analyst,
                                    egress_enabled=self.chk_egress.isChecked())
                controller = SAPController(case_dir, config)
            except Exception as exc:
                self._log(f"controller init failed: {exc}")
                return
            self.act_run.setEnabled(False)
            self.statusBar().showMessage("scanning ...")
            self._log(f"scanning {Path(sample).name} (case={case_dir})")
            self._worker = ScanWorker(
                controller, sample, on_done=self._card_ready,
                on_error=self._scan_error, on_log=self._log,
                cancel_event=self._cancel)
            self._worker.start()

        def _card_ready(self, card):
            self.act_run.setEnabled(True)
            self.statusBar().showMessage("done")
            risk = card["risk"]
            self.gauge.setValue(int(risk["score"]))
            color = BAND_COLORS.get(risk["band"], "#7f8c8d")
            self.gauge.setStyleSheet(
                "QProgressBar{border:1px solid #ccc;border-radius:8px;"
                f"background:#f4f6f8;text-align:center}}"
                f"QProgressBar::chunk{{background:{color};border-radius:8px}}")
            self.lbl_band.setText(
                f"RISK {risk['score']}/100 — {risk['band'].upper()}\n"
                f"top: {'; '.join(risk['top_signals'][:3])}\n"
                f"controls: {', '.join(risk['controls'][:6])}")
            self._populate(card)

        def _populate(self, card):
            dig = card.get("digests", {})
            self.digest_box.setPlainText(
                f"md5     {dig.get('md5','')}\nsha1     {dig.get('sha1','')}\n"
                f"sha256  {dig.get('sha256','')}\nblake2b {dig.get('blake2b','')}")

            st = card.get("strings_summary", {})
            self.lbl_str.setText(
                f"ascii={st.get('ascii_count')} utf16={st.get('utf16_count')} "
                f"high_entropy={st.get('high_entropy_count')} "
                f"suspicious_apis={st.get('suspicious_apis')}")
            self.fill_art([(a.get('kind'), a.get('value'), a.get('offset'),
                            a.get('entropy'))
                           for a in st.get("artifacts", [])[:200]])

            pe = card.get("pe_summary", {})
            self.lbl_pe.setText(
                f"backend={pe.get('backend')} machine={pe.get('machine')} "
                f"{pe.get('bitness')} ep=0x{pe.get('entry_point',''):x} "
                f"image_base={pe.get('image_base')} checksum_ok={pe.get('checksum_ok')} "
                f"overlay={pe.get('overlay_size')}B\n"
                + ("\n".join(f"ANOMALY: {a}" for a in pe.get('anomalies', []))))
            self.fill_sec([
                (s.get('name'), s.get('entropy'), s.get('raw_size'),
                 s.get('virtual_size'), s.get('writable'),
                 "writable" if s.get('writable') and s.get('name') not in (".text",) else "")
                for s in pe.get("sections", [])])

            i = card.get("intel", {})
            hits = i.get("hits", [])
            self.lbl_intel.setText(
                f"hits={len(hits)} highest={i.get('highest_verdict')} "
                f"egress_used={i.get('egress_used')} cached={i.get('cached')}")
            self.fill_hits([
                (h.get('source'), h.get('verdict'), h.get('detections'),
                 h.get('total'), h.get('reference'))
                for h in hits])

            findings = card.get("findings", [])
            self.lbl_find.setText(
                f"{len(findings)} findings — mapped controls: "
                f"{', '.join(card.get('risk', {}).get('controls', [])[:10])}")
            self.fill_find([
                (f.get('severity'), f.get('rule_id'), f.get('title'),
                 f.get('category'), " | ".join(f.get('controls', [])))
                for f in findings])

            self.fill_controls([
                (c, "ISO/NIST/OWASP") for c in card.get("risk", {}).get("controls", [])])

        def _scan_error(self, message):
            self.act_run.setEnabled(True)
            self.statusBar().showMessage("scan failed")
            self._log(f"ERROR: {message}")
            QMessageBox.critical(self, "Scan failed", message)

        def _verify(self):
            case_dir = self.ed_case.text().strip() or "SAP_CaseWork"
            try:
                from sap.app import SAPController, ScanConfig
                ctl = SAPController(case_dir, ScanConfig(analyst=self.ed_analyst.text() or "analyst"))
                report = ctl.verify()
            except Exception as exc:
                self._log(f"VERIFY ERROR: {exc}")
                return
            self._log(f"verify: audit.ok={report['audit']['ok']} "
                      f"custody.ok={report['custody']['ok']} "
                      f"bundle.ok={report['bundle']['ok']} "
                      f"spec.ok={report['spec']['ok']} self_ok={report['self_integrity']['ok']}")
            QMessageBox.information(self, "Verify",
                                    "OK ✓" if report.get("ok") else "FAILED ✗ — see log")

        def _seal(self):
            case_dir = self.ed_case.text().strip() or "SAP_CaseWork"
            try:
                from sap.app import SAPController, ScanConfig
                ctl = SAPController(case_dir, ScanConfig(analyst=self.ed_analyst.text() or "analyst"))
                out = ctl.seal()
            except Exception as exc:
                self._log(f"SEAL ERROR: {exc}")
                return
            self._log(f"sealed (both chains) -> {out['package']}")
            QMessageBox.information(self, "Sealed", f"package written to:\n{out['package']}")

        def _add_ioc_dialog(self):
            from PySide6.QtWidgets import QDialog, QDialogButtonBox, QComboBox
            dialog = QDialog(self)
            dialog.setWindowTitle("Add local IOC")
            lay = QVBoxLayout(dialog)
            lay.addWidget(QLabel("sha256"))
            ed_sha = QLineEdit()
            lay.addWidget(ed_sha)
            lay.addWidget(QLabel("verdict"))
            combo = QComboBox()
            combo.addItems(["malicious", "suspicious", "benign"])
            lay.addWidget(combo)
            lay.addWidget(QLabel("reference"))
            ed_ref = QLineEdit()
            lay.addWidget(ed_ref)
            buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
            buttons.accepted.connect(dialog.accept)
            buttons.rejected.connect(dialog.reject)
            lay.addWidget(buttons)
            if dialog.exec() != QDialog.Accepted:
                return
            case_dir = self.ed_case.text().strip() or "SAP_CaseWork"
            try:
                from sap.app import SAPController, ScanConfig
                ctl = SAPController(case_dir, ScanConfig(analyst=self.ed_analyst.text() or "analyst"))
                ctl.add_ioc(ed_sha.text().strip(), combo.currentText(), ed_ref.text().strip())
            except Exception as exc:
                self._log(f"IOC ERROR: {exc}")
                return
            self._log(f"ioc added: {ed_sha.text()} -> {combo.currentText()}")

        def _log(self, message: str):
            self.log_text.appendPlainText(message)

    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    return app.exec()


def main() -> int:
    try:
        return _run_gui()
    except ImportError:
        print("PySide6 is not installed — use the headless CLI: sap scan <sample>")
        return 3
    except Exception as exc:
        print(f"GUI failed to start: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 4


if __name__ == "__main__":
    sys.exit(main())