from __future__ import annotations

import html
import json
from datetime import datetime, timezone
from pathlib import Path

from PySide6.QtCore import QDate, QThread, Qt, Slot
from PySide6.QtGui import QAction, QKeySequence
from PySide6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QComboBox,
    QDateEdit,
    QDockWidget,
    QFileDialog,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QSplitter,
    QTableView,
    QTextBrowser,
    QVBoxLayout,
    QWidget,
)

from .. import __version__
from ..config import AppSettings, ScanOptions
from ..correlation import Correlator
from ..export import export_csv, export_html, export_json
from ..models import Severity, TimelineEvent
from ..security.audit import AuditLogger, verify_audit_chain
from ..security.integrity import build_manifest, verify_manifest, write_manifest
from ..storage import CaseStore
from .models import TimelineTableModel
from .theme import SEVERITY_COLORS
from .worker import ScanWorker


class MainWindow(QMainWindow):
    def __init__(self, settings: AppSettings | None = None, case_path: str | None = None):
        super().__init__()
        self.settings = settings or AppSettings()
        self.setWindowTitle(f"TimelineBuilder {__version__} - Unified DFIR Timeline")
        self.resize(1500, 920)

        self.sources: list[dict] = []
        self._thread: QThread | None = None
        self._worker: ScanWorker | None = None

        self.case_path = Path(case_path) if case_path else self._default_case_path()
        self.audit_path = Path(self.settings.audit_dir) / f"{self.case_path.stem}.audit.jsonl"
        self.audit = AuditLogger(self.audit_path, actor="analyst", case_id=self.case_path.stem)
        self.store = CaseStore(self.case_path, case_id=self.case_path.stem)
        self.store.audit = self.audit
        self.audit.log("case.open", target=str(self.case_path))

        self.model = TimelineTableModel([])
        self._build_ui()
        self._refresh_summary()
        self._verify_chain()

    def _default_case_path(self) -> Path:
        case_dir = Path(self.settings.case_dir)
        case_dir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        return case_dir / f"case-{stamp}.tbcase"

    def _build_ui(self) -> None:
        toolbar = self.addToolBar("Main")
        toolbar.setMovable(False)

        self.act_add_folder = QAction("Add Folder", self)
        self.act_add_folder.triggered.connect(self._add_folder)
        self.act_add_log = QAction("Add Log File", self)
        self.act_add_log.triggered.connect(self._add_log)
        self.act_remove = QAction("Remove", self)
        self.act_remove.triggered.connect(self._remove_source)
        self.act_scan = QAction("Scan", self)
        self.act_scan.setShortcut(QKeySequence("F5"))
        self.act_scan.triggered.connect(self._start_scan)
        self.act_stop = QAction("Stop", self)
        self.act_stop.setEnabled(False)
        self.act_stop.triggered.connect(self._stop_scan)
        self.act_export_csv = QAction("CSV", self)
        self.act_export_csv.triggered.connect(lambda: self._export("csv"))
        self.act_export_json = QAction("JSON", self)
        self.act_export_json.triggered.connect(lambda: self._export("json"))
        self.act_export_html = QAction("HTML Report", self)
        self.act_export_html.triggered.connect(lambda: self._export("html"))
        self.act_manifest = QAction("Evidence Manifest", self)
        self.act_manifest.triggered.connect(self._write_manifest)
        self.act_verify_audit = QAction("Verify Audit", self)
        self.act_verify_audit.triggered.connect(self._verify_chain)
        self.act_about = QAction("About", self)
        self.act_about.triggered.connect(self._about)

        for action in (
            self.act_add_folder,
            self.act_add_log,
            self.act_remove,
            self.act_scan,
            self.act_stop,
        ):
            toolbar.addAction(action)
        toolbar.addSeparator()
        toolbar.addAction(self.act_export_csv)
        toolbar.addAction(self.act_export_json)
        toolbar.addAction(self.act_export_html)
        toolbar.addSeparator()
        toolbar.addAction(self.act_manifest)
        toolbar.addAction(self.act_verify_audit)
        toolbar.addAction(self.act_about)

        container = QWidget()
        container.setObjectName("Root")
        layout = QVBoxLayout(container)
        layout.setContentsMargins(10, 8, 10, 10)

        header = QHBoxLayout()
        title = QLabel("Timeline Builder")
        title.setObjectName("Title")
        subtitle = QLabel("filesystem + log artifacts  ->  unified, integrity-verified timeline")
        subtitle.setObjectName("Sub")
        header.addWidget(title)
        header.addWidget(subtitle)
        header.addStretch(1)
        self.lbl_case = QLabel(f"Case: {self.case_path.name}")
        self.lbl_case.setObjectName("Sub")
        header.addWidget(self.lbl_case)
        layout.addLayout(header)

        splitter = QSplitter(Qt.Vertical)
        self.table = QTableView()
        self.table.setModel(self.model)
        self.table.setSortingEnabled(True)
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self.table.setColumnWidth(0, 150)
        self.table.setColumnWidth(2, 90)
        self.table.setColumnWidth(3, 100)
        self.table.selectionModel().selectionChanged.connect(self._on_selection)
        splitter.addWidget(self.table)

        self.details = QTextBrowser()
        self.details.setOpenExternalLinks(False)
        splitter.addWidget(self.details)
        splitter.setSizes([620, 260])
        layout.addWidget(splitter, 1)

        self.setCentralWidget(container)
        self._build_sources_dock()
        self._build_filters_dock()
        self._build_summary_dock()

        status = self.statusBar()
        self.progress = QProgressBar()
        self.progress.setMaximumWidth(320)
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        self.chain_label = QLabel("Audit chain: checking...")
        self.chain_label.setObjectName("ChainOk")
        status.addPermanentWidget(self.chain_label)
        status.addPermanentWidget(self.progress)
        status.showMessage("Ready")

    def _build_sources_dock(self) -> None:
        dock = QDockWidget("Evidence Sources", self)
        dock.setObjectName("SourcesDock")
        widget = QWidget()
        layout = QVBoxLayout(widget)
        self.source_list = QListWidget()
        self.source_list.setSelectionMode(QAbstractItemView.SingleSelection)
        layout.addWidget(self.source_list)
        row = QHBoxLayout()
        add_folder = QPushButton("Add Folder")
        add_folder.setObjectName("Ghost")
        add_folder.clicked.connect(self._add_folder)
        add_log = QPushButton("Add Log")
        add_log.setObjectName("Ghost")
        add_log.clicked.connect(self._add_log)
        remove = QPushButton("Remove")
        remove.setObjectName("Ghost")
        remove.clicked.connect(self._remove_source)
        row.addWidget(add_folder)
        row.addWidget(add_log)
        row.addWidget(remove)
        layout.addLayout(row)
        dock.setWidget(widget)
        dock.setMinimumWidth(320)
        self.addDockWidget(Qt.LeftDockWidgetArea, dock)

    def _build_filters_dock(self) -> None:
        dock = QDockWidget("Filters", self)
        dock.setObjectName("FiltersDock")
        widget = QWidget()
        layout = QVBoxLayout(widget)

        box = QGroupBox("Search & Facets")
        box_layout = QVBoxLayout(box)
        self.search = QLineEdit()
        self.search.setPlaceholderText("Search description, path, host, user...")
        self.search.returnPressed.connect(self._apply_filters)
        box_layout.addWidget(self.search)

        self.sev_filter = QComboBox()
        self.sev_filter.addItem("All severities", "")
        for severity in ("critical", "high", "medium", "low", "info"):
            self.sev_filter.addItem(severity.title(), severity)
        box_layout.addWidget(self.sev_filter)

        self.src_filter = QComboBox()
        self.src_filter.addItem("All sources", "")
        self.src_filter.addItem("Filesystem", "filesystem")
        self.src_filter.addItem("Log", "log")
        box_layout.addWidget(self.src_filter)

        self.host_filter = QComboBox()
        self.host_filter.addItem("All hosts", "")
        box_layout.addWidget(self.host_filter)

        self.range_enabled = QCheckBox("Limit time window")
        box_layout.addWidget(self.range_enabled)
        dates = QHBoxLayout()
        self.date_from = QDateEdit(QDate.currentDate().addYears(-1))
        self.date_to = QDateEdit(QDate.currentDate().addDays(1))
        for edit in (self.date_from, self.date_to):
            edit.setCalendarPopup(True)
        dates.addWidget(QLabel("From"))
        dates.addWidget(self.date_from)
        dates.addWidget(QLabel("To"))
        dates.addWidget(self.date_to)
        box_layout.addLayout(dates)

        buttons = QHBoxLayout()
        apply_btn = QPushButton("Apply")
        apply_btn.clicked.connect(self._apply_filters)
        clear_btn = QPushButton("Reset")
        clear_btn.setObjectName("Ghost")
        clear_btn.clicked.connect(self._reset_filters)
        buttons.addWidget(apply_btn)
        buttons.addWidget(clear_btn)
        box_layout.addLayout(buttons)
        layout.addWidget(box)

        self.chk_hashes = QCheckBox("Compute SHA-256 for files")
        self.chk_hashes.setChecked(self.settings.scan.compute_hashes)
        layout.addWidget(self.chk_hashes)
        self.chk_created = QCheckBox("Collect creation times (B)")
        self.chk_created.setChecked(True)
        layout.addWidget(self.chk_created)
        self.chk_accessed = QCheckBox("Collect access times (A)")
        self.chk_accessed.setChecked(True)
        layout.addWidget(self.chk_accessed)
        layout.addStretch(1)

        dock.setWidget(widget)
        self.addDockWidget(Qt.LeftDockWidgetArea, dock)

    def _build_summary_dock(self) -> None:
        dock = QDockWidget("Summary", self)
        dock.setObjectName("SummaryDock")
        self.summary = QTextBrowser()
        dock.setWidget(self.summary)
        dock.setMinimumWidth(340)
        self.addDockWidget(Qt.RightDockWidgetArea, dock)

    def _add_folder(self) -> None:
        path = QFileDialog.getExistingDirectory(self, "Select folder to analyze")
        if path:
            self._add_source(path, "filesystem")

    def _add_log(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Select log artifact",
            "",
            "Logs (*.log *.txt *.json *.jsonl *.ndjson *.csv *.tsv *.evtx *.evt);;All files (*.*)",
        )
        if path:
            self._add_source(path, "log")

    def _add_source(self, path: str, kind: str) -> None:
        self.sources.append({"path": path, "kind": kind})
        item = QListWidgetItem(f"[{kind}]  {path}")
        self.source_list.addItem(item)
        self.statusBar().showMessage(f"Added {kind} source: {path}", 4000)
        self.audit.log("source.add", target=path, kind=kind)

    def _remove_source(self) -> None:
        row = self.source_list.currentRow()
        if row < 0:
            return
        removed = self.sources.pop(row)
        self.source_list.takeItem(row)
        self.audit.log("source.remove", target=removed["path"])

    def _scan_options(self) -> ScanOptions:
        options = ScanOptions()
        options.compute_hashes = self.chk_hashes.isChecked()
        options.collect_created = self.chk_created.isChecked()
        options.collect_accessed = self.chk_accessed.isChecked()
        return options

    def _start_scan(self) -> None:
        if not self.sources:
            QMessageBox.information(self, "No sources", "Add at least one folder or log artifact first.")
            return
        if self._thread is not None:
            return
        self.audit.log("scan.start", targets=json.dumps(self.sources))
        self.act_scan.setEnabled(False)
        self.act_stop.setEnabled(True)
        self.progress.setRange(0, 0)
        self.statusBar().showMessage("Scanning...")

        self._thread = QThread(self)
        self._worker = ScanWorker(self.sources, self._scan_options(), self.store, correlator=Correlator())
        self._worker.moveToThread(self._thread)
        self._thread.started.connect(self._worker.run)
        self._worker.progress.connect(self._on_progress)
        self._worker.message.connect(lambda m: self.statusBar().showMessage(m))
        self._worker.finished.connect(self._on_scan_finished)
        self._worker.failed.connect(self._on_scan_failed)
        self._worker.finished.connect(self._thread.quit)
        self._worker.failed.connect(self._thread.quit)
        self._thread.finished.connect(self._cleanup_thread)
        self._thread.start()

    def _stop_scan(self) -> None:
        if self._worker is not None:
            self._worker.cancel()
            self.statusBar().showMessage("Cancellation requested...")

    @Slot(int, int, str)
    def _on_progress(self, current: int, total: int, message: str) -> None:
        if total and total > 0:
            self.progress.setRange(0, total)
            self.progress.setValue(current)
        else:
            self.progress.setRange(0, 0)
        if message:
            self.statusBar().showMessage(message)

    @Slot(dict)
    def _on_scan_finished(self, summary: dict) -> None:
        self.progress.setRange(0, 100)
        self.progress.setValue(100)
        self.statusBar().showMessage(
            f"Scan complete: {summary.get('total', 0):,} events, {summary.get('error_count', 0)} errors", 8000
        )
        self.audit.log("scan.complete", **{k: v for k, v in summary.items() if k != "errors"})
        self._populate_facets()
        self._apply_filters()
        self._refresh_summary()
        self._verify_chain()

    @Slot(str)
    def _on_scan_failed(self, trace: str) -> None:
        self.audit.log("scan.failed", outcome="failure", error=trace.splitlines()[-1] if trace else "")
        QMessageBox.critical(self, "Scan failed", trace)
        self.statusBar().showMessage("Scan failed")

    def _cleanup_thread(self) -> None:
        if self._thread is not None:
            self._thread.deleteLater()
        self._thread = None
        self._worker = None
        self.act_scan.setEnabled(True)
        self.act_stop.setEnabled(False)

    def _populate_facets(self) -> None:
        current = self.host_filter.currentData()
        self.host_filter.blockSignals(True)
        self.host_filter.clear()
        self.host_filter.addItem("All hosts", "")
        for host in self.store.distinct("host"):
            self.host_filter.addItem(host, host)
        index = self.host_filter.findData(current)
        if index >= 0:
            self.host_filter.setCurrentIndex(index)
        self.host_filter.blockSignals(False)

    def _filter_kwargs(self) -> dict:
        kwargs: dict = {"text": self.search.text().strip()}
        severity = self.sev_filter.currentData()
        if severity:
            kwargs["severities"] = [severity]
        source = self.src_filter.currentData()
        if source:
            kwargs["source_types"] = [source]
        host = self.host_filter.currentData()
        if host:
            kwargs["hosts"] = [host]
        if self.range_enabled.isChecked():
            kwargs["start"] = datetime(
                self.date_from.date().year(), self.date_from.date().month(), self.date_from.date().day(), tzinfo=timezone.utc
            ).isoformat()
            kwargs["end"] = datetime(
                self.date_to.date().year(), self.date_to.date().month(), self.date_to.date().day(), 23, 59, 59, tzinfo=timezone.utc
            ).isoformat()
        return kwargs

    def _apply_filters(self) -> None:
        kwargs = self._filter_kwargs()
        events = self.store.query(limit=100000, **kwargs)
        self.model.set_events(events)
        self.statusBar().showMessage(f"{len(events):,} events shown")
        self.audit.log("filter.apply", count=len(events), filters=json.dumps({k: v for k, v in kwargs.items() if v}))

    def _reset_filters(self) -> None:
        self.search.clear()
        self.sev_filter.setCurrentIndex(0)
        self.src_filter.setCurrentIndex(0)
        if self.host_filter.count():
            self.host_filter.setCurrentIndex(0)
        self.range_enabled.setChecked(False)
        self._apply_filters()

    def _on_selection(self, *_args) -> None:
        rows = self.table.selectionModel().selectedRows()
        if not rows:
            return
        event = self.model.event_at(rows[0].row())
        if event is not None:
            self.details.setHtml(self._event_html(event))

    def _event_html(self, event: TimelineEvent) -> str:
        color = SEVERITY_COLORS.get(event.severity.value, "#60a5fa")
        rows = [
            ("Event ID", event.event_id),
            ("Timestamp (UTC)", event.normalized_timestamp().isoformat()),
            ("Time kind", event.time_kind.value),
            ("Severity", event.severity.value),
            ("Source type", event.source_type.value),
            ("Host", event.host or "-"),
            ("User", event.user or "-"),
            ("Path", event.source_path),
            ("Size", str(event.size) if event.size is not None else "-"),
            ("SHA-256", event.sha256 or "not computed"),
            ("Tags", ", ".join(event.tags) or "-"),
        ]
        table = "".join(
            f"<tr><td style='color:#8ea0cc;padding:3px 12px 3px 0'>{html.escape(k)}</td>"
            f"<td style='padding:3px 0'>{html.escape(str(v))}</td></tr>"
            for k, v in rows
        )
        raw = html.escape(json.dumps(event.raw, indent=2, default=str))[:6000]
        return (
            f"<div style='color:#e6ecff;font-family:Segoe UI'>"
            f"<h3 style='margin:0 0 4px'>"
            f"<span style='background:{color};color:#05070f;border-radius:999px;padding:2px 10px;font-size:12px'>"
            f"{html.escape(event.severity.value.upper())}</span> "
            f"{html.escape(event.description[:300])}</h3>"
            f"<table style='font-size:13px'>{table}</table>"
            f"<h4 style='color:#22d3ee;margin-bottom:2px'>Raw</h4>"
            f"<pre style='background:#0b1226;border:1px solid #22305c;border-radius:8px;padding:10px;white-space:pre-wrap'>{raw}</pre>"
            f"</div>"
        )

    def _refresh_summary(self) -> None:
        stats = self.store.stats()
        by_sev = stats["by_severity"]
        bars = ""
        total = max(1, stats["total"])
        for severity in ("critical", "high", "medium", "low", "info"):
            count = by_sev.get(severity, 0)
            pct = round(100 * count / total, 1)
            color = SEVERITY_COLORS[severity]
            bars += (
                f"<div style='margin:6px 0'><span style='color:#8ea0cc;font-size:12px'>{severity.title()} "
                f"({count:,})</span>"
                f"<div style='background:#1a2440;border-radius:6px;height:10px;margin-top:3px'>"
                f"<div style='width:{pct}%;background:{color};height:10px;border-radius:6px'></div></div></div>"
            )
        span = stats["span"]
        hosts = "".join(
            f"<li>{html.escape(str(k))} <span style='color:#8ea0cc'>({v:,})</span></li>" for k, v in stats["by_host"].items()
        )
        self.summary.setHtml(
            f"<div style='font-family:Segoe UI;color:#e6ecff'>"
            f"<h2 style='margin:0;color:#22d3ee'>{stats['total']:,} events</h2>"
            f"<p style='color:#8ea0cc;margin:4px 0'>{html.escape(str(span['start'] or '-'))}<br>to {html.escape(str(span['end'] or '-'))}</p>"
            f"<h4 style='margin-bottom:2px'>Severity</h4>{bars}"
            f"<h4 style='margin-bottom:2px'>Top hosts</h4><ul style='margin-top:2px;padding-left:18px'>{hosts or '<li>-</li>'}</ul>"
            f"<h4 style='margin-bottom:2px'>Sources registered</h4>"
            f"<p style='color:#8ea0cc'>{len(self.store.sources())} source(s)</p>"
            f"</div>"
        )

    def _verify_chain(self) -> None:
        ok, message = verify_audit_chain(self.audit_path)
        self.chain_label.setText(("Audit chain: " + ("INTACT" if ok else "BROKEN")) + f" ({message})")
        self.chain_label.setObjectName("ChainOk" if ok else "ChainBad")
        self.chain_label.style().unpolish(self.chain_label)
        self.chain_label.style().polish(self.chain_label)

    def _export(self, kind: str) -> None:
        events = self.store.query(limit=1_000_000, order="ASC")
        if not events:
            QMessageBox.information(self, "Nothing to export", "The timeline is empty.")
            return
        filters = ";;".join([f"{kind.upper()} (*.{kind})", "All files (*.*)"])
        default = f"timeline-{datetime.now().strftime('%Y%m%d-%H%M%S')}.{kind}"
        path, _ = QFileDialog.getSaveFileName(self, "Export timeline", default, filters)
        if not path:
            return
        ok, message = self.audit.verify()
        chain = "INTACT" if ok else "BROKEN"
        try:
            if kind == "csv":
                export_csv(events, path)
            elif kind == "json":
                export_json(events, path, metadata={"case_id": self.case_path.stem, "chain": chain})
            else:
                export_html(events, path, case_id=self.case_path.stem, chain_status=chain, version=__version__)
        except Exception as exc:
            QMessageBox.critical(self, "Export failed", str(exc))
            self.audit.log("export.failed", outcome="failure", kind=kind, error=str(exc))
            return
        digest = self._sha256(path)
        self.audit.log("export.complete", target=path, kind=kind, events=len(events), sha256=digest)
        self.statusBar().showMessage(f"Exported {len(events):,} events to {path}", 8000)

    @staticmethod
    def _sha256(path: str) -> str:
        from ..security.hashing import sha256_file

        try:
            return sha256_file(path)
        except OSError:
            return ""

    def _write_manifest(self) -> None:
        if not self.sources:
            QMessageBox.information(self, "No sources", "Add sources before writing an evidence manifest.")
            return
        default = f"manifest-{datetime.now().strftime('%Y%m%d-%H%M%S')}.json"
        path, _ = QFileDialog.getSaveFileName(self, "Save evidence manifest", default, "JSON (*.json)")
        if not path:
            return
        manifest = build_manifest([s["path"] for s in self.sources], case_id=self.case_path.stem)
        write_manifest(path, manifest)
        self.audit.log("manifest.write", target=path, artifacts=len(manifest["artifacts"]))
        self.statusBar().showMessage(f"Manifest written to {path}", 8000)

    def _about(self) -> None:
        QMessageBox.about(
            self,
            "About TimelineBuilder",
            f"<b>TimelineBuilder {__version__}</b><br>"
            "Portable DFIR timeline builder for filesystem and log artifacts.<br><br>"
            "Controls: ISO/IEC 27001:2022, NIST SP 800-53, NIST SP 800-61, OWASP Top 10.<br>"
            "Read-only collection, SHA-256 integrity, tamper-evident audit chain.<br><br>"
            f"Case: {html.escape(str(self.case_path))}<br>Audit: {html.escape(str(self.audit_path))}",
        )

    def closeEvent(self, event) -> None:
        if self._worker is not None:
            self._worker.cancel()
        if self._thread is not None:
            self._thread.quit()
            self._thread.wait(3000)
        try:
            self.audit.log("case.close", target=str(self.case_path))
            self.store.close()
        finally:
            super().closeEvent(event)
