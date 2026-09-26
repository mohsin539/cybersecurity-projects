"""REkt main window (MVVM-lite: views observe job results, state lives here).

Threading rule: the Qt main thread never runs jobs. AnalysisWorker (QThread)
wraps JobService; recipes and plugin ops run through the same worker pattern.
"""
from __future__ import annotations

import json
import time
from pathlib import Path

from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtGui import QAction, QFont, QKeySequence
from PySide6.QtWidgets import (
    QComboBox, QFileDialog, QHBoxLayout, QHeaderView, QInputDialog, QLabel,
    QLineEdit, QListWidget, QMainWindow, QMessageBox, QPlainTextEdit,
    QPushButton, QSplitter, QTabWidget, QTableWidget, QTableWidgetItem,
    QVBoxLayout, QWidget,
)

from rekt import APP_NAME, __version__
from rekt.application.jobs import JobService
from rekt.application.plugins import LoadedPlugin, discover
from rekt.application.projectfile import ProjectFileError, export_project, import_project
from rekt.application.recipecatalog import CATALOG, get as catalog_get
from rekt.platform.audit import AuditLog
from rekt.platform.config import Config, save_config
from rekt.platform.store import ProjectStore
from rekt.presentation.theme import QSS
from rekt.sandbox.policy import JobKind, Policy, check_consent

HEX_FONT = QFont("Consolas")
HEX_FONT.setStyleHint(QFont.Monospace)


# --------------------------------------------------------------------- worker
class AnalysisWorker(QThread):
    done = Signal(object)   # JobResult.to_dict()
    failed = Signal(str)

    def __init__(self, jobs: JobService, fn_name: str, kwargs: dict) -> None:
        super().__init__()
        self._jobs = jobs
        self._fn_name = fn_name
        self._kwargs = kwargs

    def run(self) -> None:  # executes off the GUI thread
        fn = getattr(self._jobs, self._fn_name, None)
        if fn is None:
            self.failed.emit(f"unknown job {self._fn_name}")
            return
        try:
            self.done.emit(fn(**self._kwargs).to_dict())
        except Exception as e:  # noqa: BLE001 — report, never crash the GUI
            self.failed.emit(f"{type(e).__name__}: {e}")


class PluginOpWorker(QThread):
    """Runs a plugin op with size cap + audit (A08: plugins are the only in-process code)."""

    done = Signal(str)
    failed = Signal(str)

    def __init__(self, plugin: LoadedPlugin, op_name: str, fn, data: bytes,
                 audit: AuditLog) -> None:
        super().__init__()
        self.plugin, self.op_name, self.fn, self.data, self.audit = (
            plugin, op_name, fn, data, audit)

    def run(self) -> None:
        if len(self.data) > 8 * 1024 * 1024:
            self.failed.emit("plugin op input exceeds 8 MiB cap")
            return
        self.audit.append("plugin.op", plugin=self.plugin.name, op=self.op_name,
                          input_sha=ProjectStore.sha256(self.data))
        try:
            out = self.fn(self.data)
        except Exception as e:  # noqa: BLE001
            self.failed.emit(f"{type(e).__name__}: {e}")
            return
        self.done.emit(out.decode("utf-8", "replace") if isinstance(out, bytes)
                       else str(out))


# ------------------------------------------------------------------ main window
class MainWindow(QMainWindow):
    def __init__(self, cfg: Config, store: ProjectStore, audit: AuditLog,
                 jobs: JobService, plugin_dir: Path) -> None:
        super().__init__()
        self.cfg, self.store, self.audit, self.jobs = cfg, store, audit, jobs
        self.current_sha: str | None = None
        self.current_data: bytes = b""
        self.worker: QThread | None = None
        self.session_consents: set[str] = set()
        self.developer_mode = False

        self.setWindowTitle(f"{APP_NAME} {__version__} — RE CTF Solver")
        self.resize(1280, 800)
        self._plugin_dir = plugin_dir
        self._build_ui()
        self._load_plugins(plugin_dir)
        self._refresh_samples()

    # ---------------------------------------------------------------- UI setup
    def _build_ui(self) -> None:
        self._build_menu()
        self._build_toolbar()

        self.banner = QLabel(
            "Authorized CTF / educational use only. Dynamic execution is disabled; "
            "sandbox limits are documented in STATE.md.")
        self.banner.setObjectName("banner")
        self.banner.setWordWrap(True)

        self.sample_list = QListWidget()
        self.sample_list.currentRowChanged.connect(self._on_sample_selected)

        self.tabs = QTabWidget()
        self.tabs.addTab(self._build_summary_tab(), "Summary")
        self.tabs.addTab(self._build_hex_tab(), "Hex")
        self.tabs.addTab(self._build_disasm_tab(), "Disassembly")
        self.tabs.addTab(self._build_decompiler_tab(), "Decompiler")
        self.tabs.addTab(self._build_strings_tab(), "Strings")
        self.tabs.addTab(self._build_findings_tab(), "Findings")
        self.tabs.addTab(self._build_entropy_tab(), "Entropy")
        self.tabs.addTab(self._build_recipe_tab(), "Recipes")
        self.tabs.addTab(self._build_plugin_tab(), "Plugins")
        self.tabs.addTab(self._build_console_tab(), "Console")

        left = QWidget()
        lv = QVBoxLayout(left)
        lv.setContentsMargins(4, 4, 4, 4)
        lv.addWidget(QLabel("Samples"))
        lv.addWidget(self.sample_list)
        left.setMaximumWidth(320)

        split = QSplitter(Qt.Horizontal)
        split.addWidget(left)
        split.addWidget(self.tabs)
        split.setStretchFactor(1, 1)

        central = QWidget()
        cv = QVBoxLayout(central)
        cv.setContentsMargins(6, 6, 6, 6)
        cv.addWidget(self.banner)
        cv.addWidget(split)
        self.setCentralWidget(central)
        self.statusBar().showMessage("Ready — drop a sample via 'Add sample…'")

    def _build_menu(self) -> None:
        m = self.menuBar().addMenu("&File")
        act_add = QAction("Add sample…", self)
        act_add.setShortcut(QKeySequence("Ctrl+O"))
        act_add.triggered.connect(self.add_sample)
        act_verify = QAction("Verify audit log…", self)
        act_verify.triggered.connect(self.verify_audit)
        act_export = QAction("Export project (.rekt)…", self)
        act_export.setShortcut(QKeySequence("Ctrl+E"))
        act_export.triggered.connect(self.export_project)
        act_import = QAction("Import project (.rekt)…", self)
        act_import.setShortcut(QKeySequence("Ctrl+I"))
        act_import.triggered.connect(self.import_project)
        act_quit = QAction("Quit", self)
        act_quit.setShortcut(QKeySequence("Ctrl+Q"))
        act_quit.triggered.connect(self.close)
        for a in (act_add, act_verify, act_export, act_import, act_quit):
            m.addAction(a)

        sm = self.menuBar().addMenu("&Session")
        self.dev_action = QAction("Developer Mode (unsigned plugins)", self)
        self.dev_action.setCheckable(True)
        self.dev_action.triggered.connect(self.toggle_developer_mode)
        sm.addAction(self.dev_action)

    def _build_toolbar(self) -> None:
        tb = self.addToolBar("main")
        tb.setMovable(False)
        b_add = QPushButton("Add sample…")
        b_add.clicked.connect(self.add_sample)
        b_run = QPushButton("Run analysis")
        b_run.setObjectName("primary")
        b_run.clicked.connect(self.run_analysis)
        b_exec = QPushButton("Execute sample (disabled)")
        b_exec.setEnabled(False)
        b_exec.setToolTip("SAMPLE_EXEC ships disabled in v1.0 (ARCHITECTURE.md §11)")
        b_unpack = QPushButton("Unpack (UPX)")
        b_unpack.setToolTip("Static unpack via trusted external UPX on a scratch copy")
        b_unpack.clicked.connect(self.run_unpack)
        for w in (b_add, b_run, b_unpack, b_exec):
            tb.addWidget(w)

    def _build_summary_tab(self) -> QWidget:
        w = QWidget()
        v = QVBoxLayout(w)
        self.summary = QPlainTextEdit()
        self.summary.setReadOnly(True)
        self.summary.setFont(HEX_FONT)
        v.addWidget(self.summary)
        return w

    def _build_hex_tab(self) -> QWidget:
        w = QWidget()
        v = QVBoxLayout(w)
        self.hexview = QPlainTextEdit()
        self.hexview.setReadOnly(True)
        self.hexview.setFont(HEX_FONT)
        self.hexview.setLineWrapMode(QPlainTextEdit.NoWrap)
        v.addWidget(self.hexview)
        return w

    def _build_disasm_tab(self) -> QWidget:
        w = QWidget()
        v = QVBoxLayout(w)
        top = QHBoxLayout()
        top.addWidget(QLabel("Mode:"))
        self.disasm_mode = QComboBox()
        self.disasm_mode.addItems(["recursive", "linear"])
        top.addWidget(self.disasm_mode)
        top.addWidget(QLabel("Arch:"))
        self.disasm_arch = QComboBox()
        for label, arch, bits in (("x86-64", "x86-64", 64), ("i386", "i386", 32),
                                  ("ARM", "ARM", 32), ("AArch64", "AArch64", 64)):
            self.disasm_arch.addItem(label, (arch, bits))
        top.addWidget(self.disasm_arch)
        b = QPushButton("Disassemble (sandboxed)")
        b.setObjectName("primary")
        b.clicked.connect(self.run_disasm)
        top.addWidget(b)
        b2 = QPushButton("Send selected bytes → Recipes")
        b2.clicked.connect(self.send_selection_to_recipes)
        top.addWidget(b2)
        top.addStretch(1)
        v.addLayout(top)
        self.disasm_view = QTableWidget(0, 4)
        self.disasm_view.setHorizontalHeaderLabels(["Address", "Bytes", "Instruction", "Operands"])
        self.disasm_view.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.disasm_view.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        self.disasm_view.setEditTriggers(QTableWidget.NoEditTriggers)
        self.disasm_view.setFont(HEX_FONT)
        v.addWidget(self.disasm_view)
        return w

    def _build_decompiler_tab(self) -> QWidget:
        w = QWidget()
        v = QVBoxLayout(w)
        top = QHBoxLayout()
        top.addWidget(QLabel("Ghidra install root:"))
        self.ghidra_home = QLineEdit()
        self.ghidra_home.setPlaceholderText(
            r"e.g. C:\Tools\ghidra_11.x_PUBLIC  (or set REKT_GHIDRA_HOME)")
        top.addWidget(self.ghidra_home, 1)
        b = QPushButton("Decompile (consent-gated)")
        b.setObjectName("primary")
        b.clicked.connect(self.run_ghidra)
        top.addWidget(b)
        v.addLayout(top)
        self.decomp_note = QLabel(
            "Runs Ghidra headless on a scratch COPY of the sample. Java + a local "
            "Ghidra install required; no downloads (offline-first).")
        self.decomp_note.setWordWrap(True)
        v.addWidget(self.decomp_note)
        self.decomp_view = QPlainTextEdit()
        self.decomp_view.setReadOnly(True)
        self.decomp_view.setFont(HEX_FONT)
        v.addWidget(self.decomp_view, 1)
        return w

    def _build_strings_tab(self) -> QWidget:
        w = QWidget()
        v = QVBoxLayout(w)
        self.strings_view = QTableWidget(0, 3)
        self.strings_view.setHorizontalHeaderLabels(["Offset", "Type", "String"])
        self.strings_view.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.strings_view.setEditTriggers(QTableWidget.NoEditTriggers)
        v.addWidget(self.strings_view)
        return w

    def _build_findings_tab(self) -> QWidget:
        w = QWidget()
        v = QVBoxLayout(w)
        top = QHBoxLayout()
        b_yara = QPushButton("YARA scan (bundled rules)")
        b_yara.setObjectName("primary")
        b_yara.clicked.connect(self.run_yara)
        top.addWidget(b_yara)
        top.addStretch(1)
        v.addLayout(top)
        self.findings_view = QTableWidget(0, 3)
        self.findings_view.setHorizontalHeaderLabels(["Source", "Kind", "Detail"])
        self.findings_view.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.findings_view.setEditTriggers(QTableWidget.NoEditTriggers)
        v.addWidget(self.findings_view)
        return w

    def _build_entropy_tab(self) -> QWidget:
        w = QWidget()
        v = QVBoxLayout(w)
        self.entropy_bar = QPlainTextEdit()
        self.entropy_bar.setReadOnly(True)
        self.entropy_bar.setFont(HEX_FONT)
        self.entropy_bar.setMaximumHeight(160)
        self.entropy_canvas = _EntropyCanvas()
        v.addWidget(QLabel("Entropy per chunk (0–8 bits/byte)"))
        v.addWidget(self.entropy_canvas, 1)
        v.addWidget(self.entropy_bar)
        return w

    def _build_recipe_tab(self) -> QWidget:
        w = QWidget()
        v = QVBoxLayout(w)
        top = QHBoxLayout()
        top.addWidget(QLabel("One-click recipe:"))
        self.recipe_combo = QComboBox()
        for r in CATALOG:
            self.recipe_combo.addItem(r["label"], r["id"])
        top.addWidget(self.recipe_combo, 1)
        b_run1 = QPushButton("Run one-click")
        b_run1.clicked.connect(self.run_one_click)
        top.addWidget(b_run1)
        v.addLayout(top)

        mid = QHBoxLayout()
        mid.addWidget(QLabel("Custom op:"))
        self.custom_op = QComboBox()
        self.custom_op.addItems([
            "b64_decode", "b64_encode", "b32_decode", "b32_encode", "b85_decode",
            "b85_encode", "hex_decode", "hex_encode", "url_decode", "url_encode",
            "rot13", "xor", "sha256"])
        mid.addWidget(self.custom_op)
        mid.addWidget(QLabel("key (for xor):"))
        self.custom_key = QLineEdit()
        self.custom_key.setPlaceholderText("e.g. secret (xor only)")
        mid.addWidget(self.custom_key, 1)
        b_step = QPushButton("Append step")
        b_step.clicked.connect(self.append_step)
        mid.addWidget(b_step)
        v.addLayout(mid)

        self.custom_steps = QPlainTextEdit()
        self.custom_steps.setFont(HEX_FONT)
        self.custom_steps.setMaximumHeight(110)
        self.custom_steps.setPlaceholderText(
            'JSON steps, e.g. [{"op": "hex_decode"}, {"op": "xor", "key": "k3y"}]')
        v.addWidget(QLabel("Custom pipeline (validated at the trust boundary)"))
        v.addWidget(self.custom_steps)
        b_runc = QPushButton("Run custom pipeline")
        b_runc.setObjectName("primary")
        b_runc.clicked.connect(self.run_custom_recipe)
        v.addWidget(b_runc)

        v.addWidget(QLabel("Input (current sample, or paste text):"))
        self.recipe_input = QPlainTextEdit()
        self.recipe_input.setFont(HEX_FONT)
        v.addWidget(self.recipe_input, 1)
        v.addWidget(QLabel("Output:"))
        self.recipe_output = QPlainTextEdit()
        self.recipe_output.setFont(HEX_FONT)
        self.recipe_output.setReadOnly(True)
        v.addWidget(self.recipe_output, 1)
        return w

    def _build_plugin_tab(self) -> QWidget:
        w = QWidget()
        v = QVBoxLayout(w)
        self.plugin_list = QListWidget()
        v.addWidget(QLabel("Loaded plugins (signed allow-list; Developer Mode for unsigned)"))
        v.addWidget(self.plugin_list)
        self.plugin_ops = QComboBox()
        v.addWidget(self.plugin_ops)
        b = QPushButton("Run selected plugin op on current sample")
        b.clicked.connect(self.run_plugin_op)
        v.addWidget(b)
        self.plugin_out = QPlainTextEdit()
        self.plugin_out.setFont(HEX_FONT)
        self.plugin_out.setReadOnly(True)
        v.addWidget(self.plugin_out, 1)
        return w

    def _build_console_tab(self) -> QWidget:
        w = QWidget()
        v = QVBoxLayout(w)
        self.console = QPlainTextEdit()
        self.console.setReadOnly(True)
        self.console.setFont(HEX_FONT)
        v.addWidget(self.console)
        return w

    # ------------------------------------------------------------- helpers
    def log(self, msg: str) -> None:
        self.console.appendPlainText(f"[{time.strftime('%H:%M:%S')}] {msg}")

    def _busy(self, running: bool) -> None:
        self.statusBar().showMessage("Working…" if running else "Ready")

    def _worker_start(self, fn_name: str, **kwargs) -> None:
        if self.worker is not None and self.worker.isRunning():
            QMessageBox.information(self, APP_NAME, "A job is already running.")
            return
        self.worker = AnalysisWorker(self.jobs, fn_name, kwargs)
        self.worker.done.connect(self._on_job_done)
        self.worker.failed.connect(self._on_job_failed)
        self._busy(True)
        self.worker.start()

    # ------------------------------------------------------------- samples
    def add_sample(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Add sample")
        if not path:
            return
        p = Path(path)
        try:
            data = p.read_bytes()
        except OSError as e:
            QMessageBox.critical(self, APP_NAME, f"Cannot read file: {e}")
            return
        if len(data) > self.cfg.max_file_mb * 1024 * 1024:
            QMessageBox.critical(self, APP_NAME,
                                 f"File exceeds {self.cfg.max_file_mb} MiB policy cap.")
            return
        sha = self.store.sha256(data)
        self.store.put_blob(sha, data)
        self.store.add_artifact(sha, note=p.name)
        self.audit.append("sample.added", artifact=sha, size=len(data), name=p.name)
        self.log(f"added sample {p.name} sha256={sha[:16]}…")
        self._refresh_samples(select=sha)

    def _refresh_samples(self, select: str | None = None) -> None:
        self.sample_list.clear()
        rows = self.store.list_artifacts()
        for i, row in enumerate(rows):
            item_text = f"{row['note'] or '(unnamed)'}\n{row['sha256'][:24]}…  {row['size']:,} B"
            self.sample_list.addItem(item_text)
            if select and row["sha256"] == select:
                self.sample_list.setCurrentRow(i)
        if select is None and rows:
            self.sample_list.setCurrentRow(0)

    def _on_sample_selected(self, row: int) -> None:
        rows = self.store.list_artifacts()
        if row < 0 or row >= len(rows):
            return
        sha = rows[row]["sha256"]
        data = self.store.get_artifact(sha)
        if data is None:
            return
        self.current_sha, self.current_data = sha, data
        self._render_hex(data)
        self._render_summary_quick(data)
        self.recipe_input.setPlainText(data.decode("utf-8", "replace")[:200_000])
        self._load_findings(sha)
        self.audit.append("sample.viewed", artifact=sha)

    def _render_hex(self, data: bytes, limit: int = 64 * 1024) -> None:
        lines = []
        for off in range(0, min(len(data), limit), 16):
            chunk = data[off:off + 16]
            hexpart = " ".join(f"{b:02x}" for b in chunk)
            asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            lines.append(f"{off:08x}  {hexpart:<47}  |{asc}|")
        if len(data) > limit:
            lines.append(f"… truncated at {limit:,} bytes (policy cap)")
        self.hexview.setPlainText("\n".join(lines))

    def _render_summary_quick(self, data: bytes) -> None:
        from rekt.core.analyzer import quick_identify

        ident = quick_identify(data)
        self.summary.setPlainText(json.dumps(ident, indent=2))

    def _load_findings(self, sha: str) -> None:
        self.findings_view.setRowCount(0)
        for f in self.store.findings_for(sha):
            r = self.findings_view.rowCount()
            self.findings_view.insertRow(r)
            for c, val in enumerate((f["source"], f["kind"], f["detail"])):
                self.findings_view.setItem(r, c, QTableWidgetItem(val))

    # ------------------------------------------------------------- analysis
    def run_analysis(self) -> None:
        if not self.current_sha:
            QMessageBox.information(self, APP_NAME, "Add a sample first.")
            return
        self.log(f"analysis queued for {self.current_sha[:16]}…")
        self._worker_start("run_analysis", sha=self.current_sha, data=self.current_data)

    def _on_job_done(self, payload: dict) -> None:
        self._busy(False)
        if not payload.get("ok"):
            self.log(f"job failed: {payload.get('detail')}")
            QMessageBox.warning(self, APP_NAME, f"Job failed: {payload.get('detail')}")
            return
        res = payload.get("result") or {}
        if "flags" in res:
            self._render_analysis_result(res)
        elif "log" in res:
            self.recipe_output.setPlainText(
                res.get("result", "") + "\n\n-- steps --\n" +
                "\n".join(str(s) for s in res["log"]))
        elif "rows" in res:
            self._render_disasm(res)
        elif "functions" in res:
            self._render_ghidra(res)
        elif "matches" in res:
            hits = res.get("matches", [])
            self.log(f"yara: {len(hits)} rule(s) matched — see Findings")
            if self.current_sha:
                self._load_findings(self.current_sha)
        elif "unpacked_sha256" in res:
            self.log(f"unpack: {res.get('log', '')[:200]}")
            self._refresh_samples()
        self.log(f"job completed in {payload.get('duration_s')}s")
        if self.current_sha:
            self._load_findings(self.current_sha)

    def _on_job_failed(self, msg: str) -> None:
        self._busy(False)
        self.log(f"worker error: {msg}")
        QMessageBox.critical(self, APP_NAME, msg)

    def _render_analysis_result(self, res: dict) -> None:
        self.summary.setPlainText(json.dumps(
            {k: v for k, v in res.items() if k != "entropy_series"}, indent=2))
        # strings
        from rekt.core.flagfinder import extract_strings

        self.strings_view.setRowCount(0)
        for off, kind, s in extract_strings(self.current_data)[:500]:
            r = self.strings_view.rowCount()
            self.strings_view.insertRow(r)
            self.strings_view.setItem(r, 0, QTableWidgetItem(f"0x{off:x}"))
            self.strings_view.setItem(r, 1, QTableWidgetItem(kind))
            self.strings_view.setItem(r, 2, QTableWidgetItem(s[:200]))
        # entropy
        series = res.get("entropy_series", [])
        self.entropy_canvas.set_series(series)
        self.entropy_bar.setPlainText(
            " ".join(f"{v:.2f}" for v in series[:256]))

    # ------------------------------------------------------------- disasm
    def run_disasm(self) -> None:
        if not self.current_sha:
            QMessageBox.information(self, APP_NAME, "Add a sample first.")
            return
        arch, bits = self.disasm_arch.currentData()
        self._worker_start("run_disasm", sha=self.current_sha, data=self.current_data,
                           arch=arch, bits=bits, mode=self.disasm_mode.currentText())

    def _render_disasm(self, res: dict) -> None:
        rows = res.get("rows", [])
        self.disasm_view.setRowCount(0)
        for r in rows[:2000]:
            row = self.disasm_view.rowCount()
            self.disasm_view.insertRow(row)
            self.disasm_view.setItem(row, 0, QTableWidgetItem(f"0x{r['addr']:x}"))
            self.disasm_view.setItem(row, 1, QTableWidgetItem(r["bytes"]))
            self.disasm_view.setItem(row, 2, QTableWidgetItem(r["mnemonic"]))
            self.disasm_view.setItem(row, 3, QTableWidgetItem(r["op_str"]))
        entry = res.get("entry_rva")
        self.log(f"disasm: {res.get('count', 0)} instructions"
                 + (f", entry rva 0x{entry:x}" if entry else ""))

    def send_selection_to_recipes(self) -> None:
        sel = self.disasm_view.selectedItems()
        if not sel:
            sel = self.hexview.textCursor().selectedText() 
            if sel:
                self.recipe_input.setPlainText(sel.replace("\u2029", "\n"))
                self.tabs.setCurrentIndex(self.tabs.indexOf(self.recipe_input.parentWidget()))
            return
        row = sel[0].row()
        item = self.disasm_view.item(row, 1)
        if item:
            self.recipe_input.setPlainText(item.text())
            self.tabs.setCurrentIndex(self.tabs.indexOf(
                self.recipe_input.parentWidget()))
            self.log("selection sent to Recipes (hex bytes)")

    # ------------------------------------------------------------- ghidra
    def run_ghidra(self) -> None:
        if not self.current_sha:
            QMessageBox.information(self, APP_NAME, "Add a sample first.")
            return
        home = self.ghidra_home.text().strip()
        confirm = QMessageBox.question(
            self, "Ghidra analysis",
            "Run Ghidra headless on a scratch COPY of this sample?\n"
            "This launches a local JVM (analyzeHeadless) and is audited.",
            QMessageBox.Yes | QMessageBox.No)
        if confirm != QMessageBox.Yes:
            return
        self.session_consents.add("GHIDRA")
        self._worker_start("run_ghidra", sha=self.current_sha, data=self.current_data,
                           ghidra_home=home, session_consents=set(self.session_consents))

    def _render_ghidra(self, res: dict) -> None:
        self.decomp_view.setPlainText(res.get("text", ""))
        funcs = res.get("functions", [])
        self.log(f"ghidra: {len(funcs)} functions decompiled")

    # ------------------------------------------------------------- recipes
    def run_one_click(self) -> None:
        rid = self.recipe_combo.currentData()
        recipe = catalog_get(rid)
        if not recipe or not self.current_data:
            QMessageBox.information(self, APP_NAME, "Add a sample first.")
            return
        data = self.recipe_input.toPlainText().encode("utf-8", "replace")
        self._worker_start("run_recipe", data=data, steps=recipe["steps"],
                           label=recipe["id"])

    def append_step(self) -> None:
        import json as _json

        op = self.custom_op.currentText()
        steps = []
        try:
            steps = _json.loads(self.custom_steps.toPlainText() or "[]")
        except _json.JSONDecodeError:
            pass
        step = {"op": op}
        if op == "xor":
            step["key"] = self.custom_key.text()
        steps.append(step)
        self.custom_steps.setPlainText(_json.dumps(steps))

    def run_custom_recipe(self) -> None:
        import json as _json

        try:
            steps = _json.loads(self.custom_steps.toPlainText() or "[]")
        except _json.JSONDecodeError as e:
            QMessageBox.warning(self, APP_NAME, f"Invalid pipeline JSON: {e}")
            return
        data = self.recipe_input.toPlainText().encode("utf-8", "replace")
        self._worker_start("run_recipe", data=data, steps=steps, label="custom")

    # ------------------------------------------------------------- plugins
    def _load_plugins(self, plugin_dir: Path) -> None:
        self.plugin_list.clear()
        self.plugin_ops.clear()
        loaded, rejected = discover(plugin_dir, self.developer_mode, self.audit)
        self._plugin_ops_map: dict[str, tuple[LoadedPlugin, object]] = {}
        for lp in loaded:
            self.plugin_list.addItem(
                f"✔ {lp.name} v{lp.version} {'(signed)' if lp.signed else '(UNSIGNED)'}")
            for op_name, fn in (lp.instance.operations() or {}).items():
                self._plugin_ops_map[f"{lp.name}:{op_name}"] = (lp, fn)
                self.plugin_ops.addItem(f"{lp.name}:{op_name}")
        for r in rejected:
            self.plugin_list.addItem(f"✖ {r}")
        if not loaded and not rejected:
            self.plugin_list.addItem("(no plugins found)")

    def toggle_developer_mode(self, checked: bool) -> None:
        if checked:
            ok = QMessageBox.warning(
                self, "Developer Mode",
                "Unsigned plugin code will run IN-PROCESS with your user rights.\n"
                "Enable Developer Mode for this session?",
                QMessageBox.Yes | QMessageBox.No)
            if ok != QMessageBox.Yes:
                self.dev_action.setChecked(False)
                return
        self.developer_mode = checked
        self.audit.append("session.dev_mode", enabled=checked)
        self._load_plugins(self._plugin_dir_for_refresh())

    def _plugin_dir_for_refresh(self) -> Path:
        # re-derive from the path captured at startup
        return self._plugin_dir  # set in __init__ below

    def run_plugin_op(self) -> None:
        key = self.plugin_ops.currentText()
        entry = getattr(self, "_plugin_ops_map", {}).get(key)
        if not entry or not self.current_data:
            return
        lp, fn = entry
        if not self.developer_mode and not lp.signed:
            QMessageBox.warning(self, APP_NAME, "Unsigned plugin ops require Developer Mode.")
            return
        self._plugin_worker = PluginOpWorker(lp, key.split(":", 1)[1], fn,
                                             self.current_data, self.audit)
        self._plugin_worker.done.connect(lambda s: self.plugin_out.setPlainText(s))
        self._plugin_worker.failed.connect(lambda m: QMessageBox.critical(self, APP_NAME, m))
        self._plugin_worker.start()

    # ------------------------------------------------------------- yara / unpack
    def run_yara(self) -> None:
        if not self.current_sha:
            QMessageBox.information(self, APP_NAME, "Add a sample first.")
            return
        self._worker_start("run_yara", sha=self.current_sha, data=self.current_data)

    def run_unpack(self) -> None:
        if not self.current_sha:
            QMessageBox.information(self, APP_NAME, "Add a sample first.")
            return
        confirm = QMessageBox.question(
            self, "Unpack (UPX)",
            "Run trusted external UPX (-d) on a scratch COPY of this sample?\n"
            "The unpacked binary is added as a new sample and audited.",
            QMessageBox.Yes | QMessageBox.No)
        if confirm != QMessageBox.Yes:
            return
        self._worker_start("run_unpack", sha=self.current_sha, data=self.current_data,
                           tool="upx")

    # ------------------------------------------------------------- project file
    def export_project(self) -> None:
        path, _ = QFileDialog.getSaveFileName(self, "Export project",
                                              "project.rekt", "REkt projects (*.rekt)")
        if not path:
            return
        passphrase, ok = QInputDialog.getText(
            self, "Encrypt project (optional)",
            "Passphrase (leave empty to export unencrypted):",
            QLineEdit.Password)
        if not ok:
            return
        try:
            stats = export_project(self.store, Path(path), passphrase or None)
        except (ProjectFileError, OSError) as e:
            QMessageBox.critical(self, APP_NAME, f"Export failed: {e}")
            return
        self.audit.append("project.exported", path=str(path), **{
            k: stats[k] for k in ("artifacts", "findings", "encrypted")})
        self.log(f"exported {stats['artifacts']} artifact(s), "
                 f"{stats['findings']} finding(s) -> {path}")
        QMessageBox.information(self, APP_NAME,
                                f"Exported {stats['artifacts']} artifact(s), "
                                f"{stats['findings']} finding(s).")

    def import_project(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Import project", "",
                                              "REkt projects (*.rekt)")
        if not path:
            return
        passphrase, ok = QInputDialog.getText(
            self, "Project passphrase", "Passphrase (empty for unencrypted):",
            QLineEdit.Password)
        if not ok:
            return
        try:
            stats = import_project(Path(path), self.store, passphrase or None)
        except ProjectFileError as e:
            QMessageBox.critical(self, APP_NAME, f"Import failed: {e}")
            return
        self.audit.append("project.imported", path=str(path),
                          imported=stats["imported"], findings=stats["findings"],
                          warnings=len(stats["warnings"]))
        self.log(f"imported {stats['imported']} artifact(s), "
                 f"{stats['findings']} new finding(s), "
                 f"{len(stats['warnings'])} warning(s)")
        self._refresh_samples()
        QMessageBox.information(self, APP_NAME,
                                f"Imported {stats['imported']} artifact(s). "
                                f"{len(stats['warnings'])} warning(s).")

    # ------------------------------------------------------------- audit
    def verify_audit(self) -> None:
        ok, msg = self.audit.verify()
        self.log(f"audit verify: {'OK' if ok else 'TAMPERED'} ({msg})")
        QMessageBox.information(self, APP_NAME,
                                f"Audit log {'is intact' if ok else 'TAMPERED'}: {msg}")

    # ------------------------------------------------------------- consent
    def request_sample_exec(self) -> bool:
        """Per-session consent gate for EXEC-class actions (ARCHITECTURE.md §3.6)."""
        reason = check_consent(
            Policy(kind=JobKind.SAMPLE_EXEC, allow_exec=True),
            self.developer_mode, self.session_consents)
        if reason:
            QMessageBox.warning(self, APP_NAME, reason)
            return False
        self.session_consents.add(JobKind.SAMPLE_EXEC.value)
        self.audit.append("consent.sample_exec", granted=True)
        return True

    def closeEvent(self, event) -> None:  # noqa: N802 — Qt naming
        self.audit.append("session.end")
        super().closeEvent(event)


class _EntropyCanvas(QWidget):
    """Minimal entropy bar chart (no third-party chart deps)."""

    def __init__(self) -> None:
        super().__init__()
        self._series: list[float] = []
        self.setMinimumHeight(120)

    def set_series(self, series: list[float]) -> None:
        self._series = series[:512]
        self.update()

    def paintEvent(self, event) -> None:  # noqa: N802 — Qt naming
        from PySide6.QtGui import QPainter, QColor

        p = QPainter(self)
        p.fillRect(self.rect(), QColor("#101218"))
        if not self._series:
            p.end()
            return
        w = self.width() / max(1, len(self._series))
        for i, v in enumerate(self._series):
            h = (v / 8.0) * self.height()
            color = QColor("#3fa66a") if v < 6.5 else QColor("#d4a24c") \
                if v < 7.3 else QColor("#e06c6c")
            p.fillRect(int(i * w), self.height() - int(h), max(1, int(w)) - 1,
                       int(h), color)
        p.setPen(QColor("#7a7f8a"))
        p.drawText(8, 16, f"{len(self._series)} chunks")
        p.end()
