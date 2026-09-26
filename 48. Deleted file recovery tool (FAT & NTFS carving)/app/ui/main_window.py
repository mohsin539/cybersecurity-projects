"""RecovPro Secure — main application window."""

from __future__ import annotations

import os
import sys
import tempfile
from datetime import datetime, timezone
from typing import List, Optional

from PySide6.QtCore import Qt, QThread, QPoint
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel,
    QStackedWidget, QToolButton, QButtonGroup, QScrollArea, QFrame,
    QCheckBox, QComboBox, QLineEdit, QFileDialog, QMessageBox, QProgressBar,
    QListWidget, QListWidgetItem,
)

from .. import __version__, __product__
from ..core.disk import (
    enumerate_logical_volumes, probe_physical_drives, ReadOnlySource,
    SourceInfo, DiskError, human_size, is_elevated,
)
from ..core.engine import RecoveryEngine, RecoveredItem
from ..security.audit import AuditLogger
from ..security.vault import RecoveryVault
from ..utils.reporting import export_csv, export_html, export_json
from .theme import qss, light_qss, PALETTE
from .widgets import (badge, make_label, ScanWorker, RecoverWorker, SourceCard,
                      GradientBanner, StatCard)
from .results import ResultsPage, TONE_HEX
from .security_page import SecurityPage

DEFAULT_VAULT = os.path.join(os.environ.get("USERPROFILE", os.path.expanduser("~")),
                             "Documents", "RecovPro_Vault")

CONFIDENCE_Q = {"high": 0.9, "medium": 0.6, "low": 0.35}


def to_row(item: RecoveredItem) -> dict:
    ext = item.name.rsplit(".", 1)[-1] if "." in item.name else ""
    return {
        "name": item.name, "size": item.size, "fs": item.fs,
        "kind": item.kind, "status": item.status, "method": item.method,
        "confidence": item.confidence, "quality": item.quality(),
        "detail": item.detail or "", "record_id": item.record_id,
        "ext": ext, "recovered_bytes": item.recovered_bytes,
        "created": item.created, "modified": item.modified,
    }


def carve_to_row(c: dict, fs: str) -> dict:
    name = f"carved_{str(c['sha256'])[:12]}.{c['ext']}" if c.get("sha256") else \
        f"carved_{c['start']}.{c['ext']}"
    return {
        "name": name, "size": c["size"], "fs": fs, "kind": "carved",
        "status": "recoverable", "method": "signature",
        "confidence": c["confidence"], "quality": CONFIDENCE_Q.get(c["confidence"], 0.5),
        "detail": f"{c['sig']} anchor={c['anchor']} @0x{c['start']:X}",
        "record_id": f"carve:{c['start']}", "ext": c["ext"],
        "start": c["start"], "region_end": c["region_end"], "sha256": c.get("sha256", ""),
    }


class DashboardPage(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)

        self.banner = GradientBanner(
            "Deleted File Recovery",
            f"{__product__} v{__version__} · Read-only FAT12/16/32 + NTFS metadata recovery "
            "& signature carving · ISO 27001 / NIST / OWASP-aligned")
        root.addWidget(self.banner)

        body = QVBoxLayout()
        body.setContentsMargins(18, 14, 18, 18)
        body.setSpacing(12)

        # ---- stat cards
        stats = QHBoxLayout()
        self.st_cards = [StatCard("", "", "#46465e") for _ in range(4)]
        self.stat_readonly = StatCard("Locked", "READ-ONLY MODE", "#34d399")
        self.stat_sources = StatCard("0", "SOURCES READY", "#22d3ee")
        self.stat_standards = StatCard("3/3", "STANDARDS", "#a78bfa")
        self.stat_last = StatCard("—", "LAST SCAN", "#fbbf24")
        for s in (self.stat_readonly, self.stat_sources, self.stat_standards, self.stat_last):
            stats.addWidget(s)
        body.addLayout(stats)

        # ---- source selection
        src_head = QHBoxLayout()
        src_head.addWidget(make_label("Select a forensic data source", 15, "#ffffff", True))
        src_head.addStretch(1)
        self.btn_refresh = QPushButton("Refresh Volumes")
        self.btn_elevate = QPushButton("Physical Drives (admin)")
        self.btn_open_img = QPushButton("Open Forensic Image…")
        src_head.addWidget(self.btn_open_img)
        src_head.addWidget(self.btn_elevate)
        src_head.addWidget(self.btn_refresh)
        body.addLayout(src_head)

        self.src_scroll = QScrollArea()
        self.src_scroll.setWidgetResizable(True)
        self.src_scroll.setFrameShape(QFrame.NoFrame)
        self.src_box = QWidget()
        self.src_layout = QVBoxLayout(self.src_box)
        self.src_layout.setContentsMargins(0, 0, 0, 0)
        self.src_layout.setSpacing(8)
        self.src_scroll.setWidget(self.src_box)
        self.src_scroll.setFixedHeight(216)
        self.src_scroll.setStyleSheet("QScrollArea{background:transparent;}")
        body.addWidget(self.src_scroll)

        # ---- scan configuration
        cfg = QFrame()
        cfg.setObjectName("Card")
        cv = QVBoxLayout(cfg)
        cv.setContentsMargins(16, 14, 16, 14)
        row = QHBoxLayout()
        row.addWidget(make_label("Scan configuration", 15, "#ffffff", True))
        row.addStretch(1)
        self.scan_mode = QComboBox()
        self.scan_mode.addItem("Quick scan — metadata & deleted records")
        self.scan_mode.addItem("Deep scan — metadata + orphan sweep + carving")
        self.scan_mode.setMaximumWidth(340)
        row.addWidget(self.scan_mode)
        cv.addLayout(row)

        opts = QHBoxLayout()
        self.chk_active = QCheckBox("Include active files")
        self.chk_active.setChecked(False)
        self.chk_deleted = QCheckBox("Deleted files (metadata)")
        self.chk_deleted.setChecked(True)
        self.chk_orphan = QCheckBox("Orphan cluster scan")
        self.chk_orphan.setChecked(True)
        self.chk_verify = QCheckBox("Structural verify")
        self.chk_verify.setChecked(True)
        self.gr_filters = QComboBox()
        self.gr_filters.addItem("All carvable types")
        for g in ("image", "document", "archive", "audio", "video", "executable", "database", "other"):
            self.gr_filters.addItem(f"Group: {g}")
        self.ext_filter = QLineEdit()
        self.ext_filter.setPlaceholderText("Optional ext filter e.g. jpg,pdf")
        self.ext_filter.setMaximumWidth(180)
        opts.addWidget(self.chk_active)
        opts.addWidget(self.chk_deleted)
        opts.addWidget(self.chk_orphan)
        opts.addWidget(self.chk_verify)
        opts.addStretch(1)
        opts.addWidget(make_label("Type filter", 11.5, PALETTE["text_dim"]))
        opts.addWidget(self.gr_filters)
        opts.addWidget(self.ext_filter)
        cv.addLayout(opts)

        act = QHBoxLayout()
        self.selected_lbl = make_label("No source selected yet.", 12, PALETTE["text_dim"])
        self.btn_demo = QPushButton("Run Self-Test Demo (synthetic FAT32)")
        self.btn_start = QPushButton("🔒  Start Secure Scan")
        self.btn_start.setProperty("primary", "true")
        self.btn_start.setEnabled(False)
        act.addWidget(self.selected_lbl, 1)
        act.addWidget(self.btn_demo)
        act.addWidget(self.btn_start)
        cv.addLayout(act)
        body.addWidget(cfg)

        # ---- progress panel
        self.progress_frame = QFrame()
        self.progress_frame.setObjectName("Card")
        pl = QVBoxLayout(self.progress_frame)
        self.progress_lbl = make_label("Idle", 12.5, "#ffffff")
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 1000)
        self.status_line = make_label("", 11.5, PALETTE["text_dim"])
        self.btn_cancel = QPushButton("Cancel")
        bh = QHBoxLayout()
        bh.addWidget(self.progress_lbl, 1)
        bh.addWidget(self.btn_cancel)
        pl.addLayout(bh)
        pl.addWidget(self.progress_bar)
        pl.addWidget(self.status_line)
        self.progress_frame.hide()
        body.addWidget(self.progress_frame)

        body.addStretch(1)
        root.addLayout(body)

        # compliance chips
        comp = QHBoxLayout()
        for t, tone in (("ISO 27001", "green"), ("NIST SP 800-53", "blue"),
                        ("NIST SP 800-88", "violet"), ("OWASP Top 10", "amber"),
                        ("CISA/CDM", "gray")):
            b = badge(t, tone)
            comp.addWidget(b)
        comp.addStretch(1)
        body.addLayout(comp)

    # ------------------------------------------------------------------
    def add_source_card(self, info: SourceInfo, used_ratio: float = 0.5,
                        subtitle: str = "", tone: str = "blue",
                        fs_label: str = ""):
        card = SourceCard(
            title=info.label,
            subtitle=subtitle or f"{info.device_path} · read-only handle",
            fs_tone=TONE_HEX.get(tone, "#60a5fa"),
            fs_label=fs_label or (info.fs_type or "RAW"),
            size_text=human_size(info.size) if info.size else "size unknown",
            used_ratio=used_ratio,
        )
        card.clicked.connect(lambda c=info: self.source_selected(c))
        self.src_layout.addWidget(card)
        return card

    def source_selected(self, info: SourceInfo):
        self.selected_info = info
        self.selected_lbl.setText(f"Selected: {info.label}  ·  read-only")
        self.btn_start.setEnabled(True)


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"{__product__} — Deleted File Recovery  ·  FAT & NTFS Carving")
        self.resize(1280, 820)
        self.setMinimumSize(1080, 720)
        self.setStyleSheet(qss())

        # --- session objects
        self.audit_dir = os.path.join(DEFAULT_VAULT, "_audit")
        os.makedirs(self.audit_dir, exist_ok=True)
        self.audit = AuditLogger(self.audit_dir, app_name=__product__)
        self.vault = RecoveryVault(DEFAULT_VAULT)
        self.engine: Optional[RecoveryEngine] = None
        self.thread: Optional[QThread] = None
        self.worker: Optional[ScanWorker] = None
        self.recover_thread: Optional[QThread] = None

        central = QWidget()
        lay = QHBoxLayout(central)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(0)

        # ---------------- sidebar ----------------
        sb = QWidget()
        sb.setObjectName("Sidebar")
        sb.setFixedWidth(226)
        sv = QVBoxLayout(sb)
        sv.setContentsMargins(16, 22, 16, 18)
        sv.setSpacing(4)
        brand = make_label("◈ " + __product__, 16, "#ffffff", True)
        brand.setObjectName("BrandTitle")
        sub = make_label("FAT · NTFS · CARVING", 10, "#9aa3c7")
        sub.setObjectName("BrandSub")
        sv.addWidget(brand)
        sv.addWidget(sub)
        sv.addSpacing(18)
        self.nav_group = QButtonGroup(self)
        self.nav_group.setExclusive(True)
        self.pages = QStackedWidget()
        self.dashboard = DashboardPage()
        self.results = ResultsPage()
        self.security = SecurityPage(self.vault, self.audit)
        self.pages.addWidget(self.dashboard)   # 0
        self.pages.addWidget(self.results)     # 1
        self.pages.addWidget(self.security)    # 2

        nav_items = [
            ("◆", " Dashboard"),
            ("▤", " Scan Results"),
            ("◈", " Vault & Audit"),
        ]
        for i, (glyph, label) in enumerate(nav_items):
            b = QToolButton()
            b.setText(glyph + label)
            b.setObjectName("NavBtn")
            b.setCheckable(True)
            b.setToolButtonStyle(Qt.ToolButtonTextOnly)
            b.clicked.connect(lambda _=False, idx=i: self.goto(idx))
            self.nav_group.addButton(b, i)
            sv.addWidget(b)
        sv.addStretch(1)
        badge_row = QHBoxLayout()
        for t, tone in (("RO", "green"), ("X", "blue")):
            badge_row.addWidget(badge(t, tone))
        badge_row.addStretch(1)
        ver = make_label(f"v{__version__} · portable", 10, "#6f7a9e")
        sv.addLayout(badge_row)
        sv.addWidget(ver)

        lay.addWidget(sb)
        lay.addWidget(self.pages, 1)
        self.setCentralWidget(central)

        self.nav_group.button(0).setChecked(True)

        # ---------------- wiring ----------------
        self.dashboard.btn_start.clicked.connect(self.start_scan)
        self.dashboard.btn_demo.clicked.connect(self.run_demo)
        self.dashboard.btn_refresh.clicked.connect(self.refresh_volumes)
        self.dashboard.btn_elevate.clicked.connect(self.load_physical)
        self.dashboard.btn_open_img.clicked.connect(self.open_image)
        self.dashboard.btn_cancel.clicked.connect(self.cancel_scan)
        self.results.recover_selected.connect(self.recover_selected)
        self.results.recover_all.connect(self.recover_all)
        self.results.export_requested.connect(self.export_report)
        self.results.verify_vault_requested.connect(self.verify_vault)

        self.refresh_volumes()
        self.audit.log("app_launched", detail={"version": __version__, "elevated": is_elevated()})

    # ==================================================================
    def goto(self, idx: int):
        self.pages.setCurrentIndex(idx)

    # ==================================================================
    # source discovery
    # ==================================================================
    def refresh_volumes(self):
        while self.dashboard.src_layout.count():
            item = self.dashboard.src_layout.takeAt(0)
            w = item.widget()
            if w:
                w.deleteLater()
        self.dashboard.volume_infos = enumerate_logical_volumes()
        for v in self.dashboard.volume_infos:
            ratio = 0.5
            try:
                from ctypes import windll
                pass
            except Exception:
                pass
            tone = {"NTFS": "blue", "FAT": "violet"}.get(v.fs_type.upper(), "gray")
            self.dashboard.add_source_card(
                v, used_ratio=ratio, tone=tone,
                subtitle=f"{v.device_path} · serial {v.serial or '—'}" + " · read-only handle",
                fs_label=(v.fs_type or "RAW").upper())
        self.dashboard.stat_sources.value.setText(f"{len(self.dashboard.volume_infos)}")
        self.dashboard.selected_lbl.setText(f"{len(self.dashboard.volume_infos)} volumes ready — pick one or open an image.")

    def load_physical(self):
        if not is_elevated():
            QMessageBox.information(
                self, "Elevation required",
                "Reading raw physical drives needs an elevated (admin) process.\n"
                "Restart this exe as Administrator, then use 'Physical Drives'.")
            return
        drives = probe_physical_drives()
        acc = [d for d in drives if d["size"] > 0]
        if not acc:
            QMessageBox.warning(self, "Physical drives",
                                "No accessible physical drive enumerated. Use images or volumes instead.")
            return
        from ..core.partition import parse_partitions
        for d in acc:
            with ReadOnlySource(d) as src:
                parts = parse_partitions(src, d.size)
            for p in parts:
                pinfo = SourceInfo(kind="physical", label=f"{d.label} · {p.display}",
                                   device_path=d.device_path, size=p.size_bytes,
                                   bytes_per_sector=512, fs_type=("NTFS" if p.is_ntfs() else "FAT32" if p.is_fat() else "?"),
                                   readonly=True, disk_number=d.disk_number)
                self.dashboard.add_source_card(
                    pinfo, tone="green", fs_label=(pinfo.fs_type or "RAW").upper(),
                    subtitle=f"offset 0x{p.offset:X} · {d.device_path}")
            self.dashboard.selected_lbl.setText(f"{len(acc)} physical drive(s) parsed.")
        self.audit.log("physical_drive_probe", detail={"ok": len(acc)})

    def open_image(self):
        path, _ = QFileDialog.getOpenFileName(self, "Open forensic image",
                                             "", "Disk images (*.img *.dd *.raw *.bin *.vhd);;All files (*.*)")
        if not path:
            return
        try:
            size = os.path.getsize(path)
        except OSError as e:
            QMessageBox.critical(self, "Image", str(e))
            return
        info = SourceInfo(kind="image", label=os.path.basename(path),
                          device_path=path, size=size, fs_type="", serial="")
        info.info_path = path
        self.dashboard.add_source_card(
            info, tone="violet",
            fs_label="FILE",
            subtitle=f"{path} · read-only · {human_size(size)}")
        self.dashboard.selected_lbl.setText(f"Image selected: {os.path.basename(path)}")
        self.audit.log("image_opened", source=os.path.basename(path))

    # ==================================================================
    # scan lifecycle
    # ==================================================================
    def selected_info(self) -> Optional[SourceInfo]:
        return getattr(self.dashboard, "selected_info", None)

    def start_scan(self):
        info = self.selected_info()
        if not info:
            QMessageBox.information(self, "Scan", "Select a source first.")
            return
        text = self.dashboard.scan_mode.currentText()
        deep = "Deep" in text
        carve = deep or self.dashboard.chk_orphan.isChecked() and deep
        carve = deep  # carving only in deep mode
        ext_filter = self.dashboard.ext_filter.text().strip() or None
        group_filter = None
        if self.dashboard.gr_filters.currentIndex() > 0:
            group_filter = self.dashboard.gr_filters.currentText().split(":")[-1].strip()

        try:
            src = ReadOnlySource(info, getattr(info, "info_path", None))
            engine = RecoveryEngine(src, 0, info.label)
            engine.mount_fs()
        except (DiskError, ValueError) as e:
            QMessageBox.critical(self, "Cannot open source",
                                 f"{type(e).__name__}: {e}\n\n"
                                 "Tip: for physical drives run as Administrator and re-open.")
            return

        self.engine = engine
        self.scan_src = info
        self.thread = QThread(self)
        self.worker = ScanWorker(
            engine,
            want_active=self.dashboard.chk_active.isChecked(),
            want_deleted=self.dashboard.chk_deleted.isChecked(),
            orphan=self.dashboard.chk_orphan.isChecked(),
            carve=carve,
            group_filter=group_filter,
            ext_filter=ext_filter,
        )
        self.worker.moveToThread(self.thread)
        self.thread.started.connect(self.worker.run)
        self.worker.progress.connect(self._scan_progress)
        self.worker.results_ready.connect(self._scan_results)
        self.worker.carved_ready.connect(self._carved_results)
        self.worker.done.connect(self._scan_done)
        self.worker.failed.connect(self._scan_failed)
        self.thread.start()

        self.dashboard.progress_frame.show()
        self.dashboard.btn_start.setEnabled(False)
        self.dashboard.progress_bar.setValue(0)
        self.dashboard.status_line.setText(f"Mounting {engine.fs_type} on {info.label}…")
        self.dashboard.btn_start.setText("● Scanning… (read-only)")
        self.audit.log("scan_started", source=info.label, detail={"mode": text, "fs": engine.fs_type})

    def _scan_progress(self, msg: str, frac: float):
        self.dashboard.progress_lbl.setText(msg if msg else "Working…")
        self.dashboard.progress_bar.setValue(int(frac * 1000))

    def _scan_results(self, items: List):
        self.metadata_items = items
        self.dashboard.status_line.setText(f"Metadata pass complete — {len(items)} entries.")

    def _carved_results(self, carved: List):
        self.carved_items = carved

    def _scan_done(self, stats: dict):
        rows = [to_row(i) for i in self.metadata_items]
        if getattr(self, "carved_items", None):
            rows.extend(carve_to_row(c, stats.get("fs", "")) for c in self.carved_items)
        self.results.set_context(self.engine, rows)
        self.dashboard.progress_bar.setValue(1000)
        self.dashboard.status_line.setText(
            f"Scan complete · {stats.get('deleted', 0)} deleted · "
            f"{stats.get('active', 0)} active · {stats.get('carved', 0)} carved")
        d = self.dashboard
        d.stat_last.value.setText(datetime.now().strftime("%H:%M"))
        if self.thread:
            self.thread.quit()
            self.thread.wait(3000)
            self.thread.deleteLater()
            self.thread = None
        self.dashboard.btn_start.setEnabled(True)
        self.dashboard.btn_start.setText("🔒  Start Secure Scan")
        self.dashboard.progress_frame.hide()
        self.results.refresh_filters()
        self.goto(1)
        self.audit.log("scan_complete", source=getattr(self.scan_src, "label", ""),
                       detail={"deleted": stats.get("deleted", 0),
                               "carved": stats.get("carved", 0),
                               "fs": stats.get("fs", "")})
        for w in stats.get("warnings", []):
            self.dashboard.status_line.setText(w)

    def _scan_failed(self, msg: str):
        QMessageBox.critical(self, "Scan failed", msg)
        self.dashboard.btn_start.setEnabled(True)
        self.dashboard.btn_start.setText("🔒  Start Secure Scan")
        self.dashboard.progress_frame.hide()
        self.audit.log("scan_failed", result="error", detail={"error": str(msg)[:200]})
        if self.thread:
            self.thread.quit()
            self.thread.wait(1000)

    def cancel_scan(self):
        if self.worker:
            self.worker.stop()
        self.dashboard.status_line.setText("Cancelling…")

    # ==================================================================
    # recovery
    # ==================================================================
    def _vault_folder_prompt(self) -> Optional[str]:
        path = self.results.prompt_vault_folder(self.vault.root)
        if not path:
            return None
        self.vault = RecoveryVault(path)
        self.security.set_vault(self.vault)
        return path

    def recover_selected(self):
        rows = self.results.selected_rows()
        if not rows:
            QMessageBox.information(self, "Recovery", "Select at least one row first.")
            return
        self._start_recovery(rows)

    def recover_all(self):
        rows = self.results.all_rows()
        if not rows:
            QMessageBox.information(self, "Recovery", "Nothing to recover.")
            return
        self._start_recovery(rows)

    def _start_recovery(self, rows: List[dict]):
        if not self.engine:
            QMessageBox.warning(self, "Recovery", "Run a scan first.")
            return
        recoverable = [r for r in rows if r.get("status") in ("recoverable", "ok")]
        if not recoverable:
            QMessageBox.information(self, "Recovery",
                                    "None of the selected items are still recoverable "
                                    "(overwritten or zero-length).")
            return
        path = self._vault_folder_prompt()
        if not path:
            return
        items = []
        for r in recoverable:
            it = RecoveredItem(
                name=r["name"], size=int(r.get("size", 0)), fs=r.get("fs", ""),
                kind=r.get("kind", "deleted"), status=r.get("status", "recoverable"),
                method=r.get("method", "metadata"), record_id=r.get("record_id", ""),
                recovered_bytes=int(r.get("recovered_bytes", 0)),
                confidence=r.get("confidence", "high"),
            )
            if r.get("kind") == "carved":
                it._blob = self.engine.src.read(int(r["start"]), int(r["size"]))
            items.append(it)
        self.recover_thread = QThread(self)
        rw = RecoverWorker(self.engine, items, self.vault, self.audit)
        rw.moveToThread(self.recover_thread)
        self.recover_thread.started.connect(rw.run)
        rw.progress.connect(self._recover_progress)
        rw.done.connect(self._recover_done)
        rw.failed.connect(lambda m: QMessageBox.critical(self, "Recovery failed", m))
        self.recover_thread.start()
        self.results.btn_recover_sel.setEnabled(False)
        self.results.btn_recover_all.setEnabled(False)
        QMessageBox.information(self, "Recovery",
                                f"Recovering {len(items)} item(s) into the Vault…\n"
                                "The vault folder is write-protected against path escape.")

    def _recover_progress(self, done: int, total: int, msg: str):
        self.dashboard.status_line.setText(f"Recovery {done}/{total} · {msg}")

    def _recover_done(self, ok: int, total: int):
        if self.recover_thread:
            self.recover_thread.quit()
            self.recover_thread.wait(2000)
            self.recover_thread.deleteLater()
            self.recover_thread = None
        self.results.btn_recover_sel.setEnabled(True)
        self.results.btn_recover_all.setEnabled(True)
        self.security.refresh_vault()
        self.goto(2)
        self.audit.log("recovery_batch_complete", detail={"ok": ok, "attempted": total})
        QMessageBox.information(self, "Recovery complete",
                                f"{ok}/{total} artifacts recovered and recorded in the Vault "
                                "(SHA-256 manifest).")

    # ==================================================================
    # exports & verification
    # ==================================================================
    def export_report(self, kind: str):
        rows = self.results.all_rows()
        if not rows:
            QMessageBox.information(self, "Export", "Nothing exported yet — scan first.")
            return
        if kind == "csv":
            fname = "recovery-report.csv"
        elif kind == "html":
            fname = "recovery-report.html"
        else:
            fname = "recovery-report.json"
        path, _ = QFileDialog.getSaveFileName(self, "Export report", fname)
        if not path:
            return
        if kind == "csv":
            export_csv(path, self.results.all_rows(), [k for k, _ in
                       [("name", 0), ("size", 0), ("fs", 0), ("kind", 0), ("status", 0),
                        ("method", 0), ("confidence", 0), ("quality", 0), ("detail", 0)]])
        elif kind == "html":
            meta = {"columns": ["name", "size", "fs", "kind", "status", "method", "confidence", "quality", "detail"],
                    "generated": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "summary": {"Items": len(rows),
                                "Source": getattr(getattr(self, "scan_src", None), "label", "—")}}
            export_html(path, f"Recovery Report — {__product__}", meta, rows)
        else:
            payload = {"product": __product__, "version": __version__,
                       "generated": datetime.now().isoformat(),
                       "items": rows,
                       "vault": self.vault.list_items()}
            export_json(path, payload)
        self.audit.log("report_exported", detail={"format": kind})
        QMessageBox.information(self, "Exported", f"Report written to:\n{path}")

    def verify_vault(self):
        self.security._verify_vault()

    # ==================================================================
    # demo self-test
    # ==================================================================
    def run_demo(self):
        """Generates a synthetic FAT32 image in %TEMP%, deletes files, and
        runs the full recovery + carving pipeline to prove the engine works
        portably without admin rights."""
        try:
            from ..tests.builders import build_demo_fat32_image
            path = build_demo_fat32_image()
        except Exception as e:
            QMessageBox.critical(self, "Self-Test failed to build image", str(e))
            return
        from ..core.disk import human_size as _hs
        size = os.path.getsize(path)
        info = SourceInfo(kind="image", label="Self-test demo (synthetic FAT32)",
                          device_path=path, size=size, fs_type="FAT32")
        info.info_path = path
        self.dashboard.selected_lbl.setText("Demo image loaded — press Start Secure Scan.")
        self.dashboard.btn_start.setEnabled(True)
        self.dashboard.add_source_card(info, tone="green",
                                       fs_label="FAT32",
                                       subtitle=f"{path} · synthetic demo · {_hs(size)}",
                                       used_ratio=0.4)
        self.dashboard.source_selected(info)
        self.audit.log("demo_self_test_built", detail={"path": os.path.basename(path)})

    def closeEvent(self, e):
        if self.thread:
            self.thread.quit()
            self.thread.wait(2000)
        if self.recover_thread:
            self.recover_thread.quit()
            self.recover_thread.wait(2000)
        if self.engine:
            try:
                self.engine.src.close()
            except Exception:
                pass
        self.audit.log("app_closed")
        super().closeEvent(e)