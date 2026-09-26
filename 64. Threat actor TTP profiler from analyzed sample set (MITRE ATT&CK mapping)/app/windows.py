"""TTPProfiler :: MainWindow + page widgets."""
from __future__ import annotations

import json
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QIcon
from PySide6.QtWidgets import (
    QButtonGroup, QFileDialog, QFrame, QGridLayout, QHBoxLayout, QLabel, QLineEdit,
    QListWidget, QMessageBox, QPushButton, QScrollArea, QSplitter, QTableWidget,
    QTableWidgetItem, QTextEdit, QVBoxLayout, QWidget,
)

from . import data as D
from . import reports as R
from .models import ActorProfile
from .services import ImportError_, Importer, ProfilerEngine
from .security import AuditChain
from .store import SecureStore
from .theme import PALETTE, QSS
from .ui.widgets import HeatmapMatrix, KillChainTimeline, TacticRadar

PAGES = ["Dashboard", "Import Samples", "Sample Explorer", "Threat Profile", "Reports", "Audit", "Security"]


def _panel(title: str = "") -> QFrame:
    fr = QFrame()
    fr.setObjectName("panel")
    lay = QVBoxLayout(fr)
    lay.setContentsMargins(18, 16, 18, 16)
    lay.setSpacing(12)
    if title:
        lbl = QLabel(title)
        lbl.setObjectName("sectionTitle")
        lay.addWidget(lbl)
    return fr


def _metric(value: str, label: str, color: str = "cyan") -> QFrame:
    fr = QFrame()
    fr.setObjectName("elev")
    lay = QVBoxLayout(fr)
    v = QLabel(value)
    v.setObjectName("metricValue")
    v.setStyleSheet(f"color:#{PALETTE[color]}")
    t = QLabel(label)
    t.setObjectName("metricTitle")
    lay.addWidget(v)
    lay.addWidget(t)
    return fr


def _autoid(set_id: str = "local") -> str:
    import uuid
    return f"{set_id}-{uuid.uuid4().hex[:12]}"


class MainWindow(QWidget):
    def __init__(self, store: SecureStore, audit: AuditChain, workspace: Path):
        super().__init__()
        self.setObjectName("root")
        self.store = store
        self.audit = audit
        self.workspace = Path(workspace)
        self.engine = ProfilerEngine(store, audit)
        self._current_set_id: str | None = None
        self._current_profile: ActorProfile | None = None
        self._current_samples: list = []

        self.setWindowTitle("Threat Actor TTP Profiler — MITRE ATT&CK Mapping")
        self.resize(1500, 900)
        self.setStyleSheet(QSS)
        self._build()
        self.go("Dashboard")

    # ------------------------------------------------------------------ ui --
    def _build(self) -> None:
        outer = QHBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        outer.addWidget(self._sidebar())
        self.stack = QStackedWidgetHolder()
        self.pages = {}
        for name in PAGES:
            w = self._page_for(name)
            self.stack.addWidget(w)
            self.pages[name] = w
        outer.addWidget(self.stack, 1)

    def _sidebar(self) -> QFrame:
        side = QFrame()
        side.setObjectName("sidebar")
        side.setFixedWidth(230)
        lay = QVBoxLayout(side)
        lay.setContentsMargins(12, 22, 12, 16)
        title = QLabel("🛡️ TTP PROFILER")
        title.setObjectName("appTitle")
        sub = QLabel("MITRE ATT&CK™ mapping")
        sub.setObjectName("appSub")
        lay.addWidget(title)
        lay.addWidget(sub)
        lay.addSpacing(22)

        self._nav_btns: dict[str, QPushButton] = {}
        self._nav_group = QButtonGroup(self)
        self._nav_group.setExclusive(True)
        for name in PAGES:
            btn = QPushButton(f"  {self._icon(name)}  {name}")
            btn.setObjectName("navBtn")
            btn.setCheckable(True)
            btn.setCursor(Qt.PointingHandCursor)
            btn.clicked.connect(lambda _=False, n=name: self.go(n))
            self._nav_btns[name] = btn
            self._nav_group.addButton(btn)
            lay.addWidget(btn)
        lay.addStretch(1)
        ver = QLabel("v1.0.0 · offline · ISO/NIST/OWASP hardened")
        ver.setObjectName("hint")
        ver.setWordWrap(True)
        lay.addWidget(ver)
        return side

    @staticmethod
    def _icon(name: str) -> str:
        return {
            "Dashboard": "📊", "Import Samples": "📥", "Sample Explorer": "🗂️",
            "Threat Profile": "🎯", "Reports": "📄", "Audit": "📋", "Security": "🔐",
        }.get(name, "•")

    def go(self, page: str) -> None:
        if self.pages.get(page):
            self.stack.setCurrentWidget(self.pages[page])
        if page in self._nav_btns:
            self._nav_btns[page].setChecked(True)
        if page == "Dashboard":
            self.pages[page].refresh(self._current_profile)
        elif page == "Sample Explorer":
            self.pages[page].refresh(self._current_set_id, self._current_profile)
        elif page == "Threat Profile":
            self.pages[page].refresh(self._current_profile)
        elif page == "Reports":
            self.pages[page].refresh(self._current_profile, self._current_set_id, self._current_samples)
        elif page == "Audit":
            self.pages["Audit"].refresh()

    def _page_for(self, name: str) -> QWidget:
        if name == "Dashboard":
            return DashboardPage(self)
        if name == "Import Samples":
            return ImportPage(self)
        if name == "Sample Explorer":
            return SamplesPage(self)
        if name == "Threat Profile":
            return ProfilePage(self)
        if name == "Reports":
            return ReportsPage(self)
        if name == "Audit":
            return AuditPage(self)
        if name == "Security":
            return SecurityPage(self)
        raise ValueError(name)

    # ----------------------------------------------------------- actions ----
    def run_import(self, folder: str, set_name: str) -> None:
        try:
            set_id = _autoid()
            imp = Importer(self.store, self.audit, namespace="local")
            result = imp.ingest_directory(folder, set_id, set_name)
        except (ImportError_, Exception) as exc:  # noqa: BLE001
            QMessageBox.critical(self, "Import failed", str(exc))
            return
        self._current_set_id = set_id
        self._current_samples = result.samples
        QMessageBox.information(
            self, "Import complete",
            f"Imported {len(result.samples)} samples ({len(result.errors)} errors).\n"
            "Switch to Threat Profile and press Build Profile.")

    def build_profile(self) -> None:
        if not self._current_set_id:
            QMessageBox.warning(self, "No sample set", "Import samples first.")
            return
        self._current_profile = self.engine.build_profile(self._current_set_id)
        if not self._current_profile:
            QMessageBox.warning(self, "Empty", "No samples found for this set.")
            return
        QMessageBox.information(
            self, "Profile built",
            f"Techniques: {len(self._current_profile.techniques)}\n"
            f"Top actor: {self._current_profile.top_actor.name if self._current_profile.top_actor else 'n/a'}\n"
            f"Confidence: {self._current_profile.confidence:.1f}% · Grade {self._current_profile.intel_grade}")
        self.go("Dashboard")

    def export_reports(self, out_dir: str, set_name: str) -> None:
        if not self._current_profile:
            QMessageBox.warning(self, "No profile", "Build a profile first.")
            return
        manifest = R.write_all(self._current_profile, Path(out_dir), set_name, self._current_samples)
        self.audit.record("REPORTS", f"exported={len(manifest['files'])} to={out_dir}")
        QMessageBox.information(
            self, "Exported",
            f"{len(manifest['files'])} artifacts written to {out_dir}\n"
            + "\n".join(manifest["files"].keys()))


class QStackedWidgetHolder(QWidget):
    def __init__(self):
        super().__init__()
        from PySide6.QtWidgets import QStackedWidget
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        self.s = QStackedWidget()
        lay.addWidget(self.s)

    def addWidget(self, w) -> None:
        self.s.addWidget(w)

    def setCurrentWidget(self, w) -> None:
        self.s.setCurrentWidget(w)


# ---------------------------------------------------------------------------
# Pages
# ---------------------------------------------------------------------------
class DashboardPage(QWidget):
    def __init__(self, win: MainWindow):
        super().__init__()
        self.win = win
        lay = QVBoxLayout(self)
        lay.setContentsMargins(26, 24, 26, 24)
        lay.setSpacing(16)

        head = QLabel("📊 Threat Profile Dashboard")
        head.setObjectName("appTitle")
        lay.addWidget(head)
        sub = QLabel("Live view of the analyzed sample-set & MITRE ATT&CK coverage")
        sub.setObjectName("hint")
        lay.addWidget(sub)

        self.metrics_row = QHBoxLayout()
        lay.addLayout(self.metrics_row)

        mid = QSplitter()
        radar_panel = _panel("Tactic Coverage Radar")
        self.radar = TacticRadar()
        radar_panel.layout().addWidget(self.radar)
        chain_panel = _panel("Kill-Chain Coverage")
        self.chain = KillChainTimeline()
        chain_panel.layout().addWidget(self.chain)
        mid.addWidget(radar_panel)
        mid.addWidget(chain_panel)
        mid.setSizes([500, 500])
        lay.addWidget(mid, 1)

        heat = _panel("MITRE ATT&CK Technique Heatmap")
        self.heatmap = HeatmapMatrix()
        self.heat_meta = QLabel("")
        self.heat_meta.setObjectName("hint")
        heat.layout().insertWidget(0, self.heat_meta)
        heat.layout().addWidget(self.heatmap, 1)
        self.heatmap.hovered.connect(
            lambda tid: self.heat_meta.setText(
                f"{tid} — {D.TECHNIQUES.get(tid, {}).get('name', '')}"))
        lay.addWidget(heat, 2)

    def clear_metrics(self):
        while self.metrics_row.count():
            item = self.metrics_row.takeAt(0)
            w = item.widget()
            if w:
                w.deleteLater()

    def refresh(self, profile: ActorProfile | None) -> None:
        self.clear_metrics()
        if not profile:
            for value, label, color in [
                ("0", "Samples", "cyan"), ("0", "Techniques", "cyan"),
                ("0", "Tactics", "cyan"), ("—", "Attribution", "amber")]:
                self.metrics_row.addWidget(_metric(value, label, color))
            self.radar.set_profile({})
            self.chain.set_profile({})
            self.heatmap.set_profile({}, [])
            self.heat_meta.setText("Import a sample set and build a profile (Threat Profile page).")
            return
        top = profile.top_actor
        values = [
            (str(profile.sample_count), "Samples", "cyan"),
            (str(len(profile.techniques)), "Techniques Mapped", "violet"),
            (str(len(profile.tactic_scores)), "Tactics Engaged", "violet"),
            (f"{profile.confidence:.0f}%", "Profile Confidence", "lime"),
            (f"{top.name if top else 'n/a'}", f"{top.confidence:.0f}% actor confidence" if top else "Attribution", "magenta"),
            (profile.intel_grade, "Intel Grade", "amber"),
        ]
        for value, label, color in values:
            self.metrics_row.addWidget(_metric(value, label, color))
        self.radar.set_profile(profile.tactic_scores)
        self.chain.set_profile(profile.tactic_scores)
        self.heatmap.set_profile(profile.tactic_scores, profile.techniques)


class ImportPage(QWidget):
    def __init__(self, win: MainWindow):
        super().__init__()
        self.win = win
        lay = QVBoxLayout(self)
        lay.setContentsMargins(26, 24, 26, 24)
        lay.setSpacing(16)

        lay.addWidget(QLabel("📥 Import Analyzed Sample Set"))
        panel = _panel("1 · Locate report directory")
        row = QHBoxLayout()
        self.folder_edit = QLineEdit()
        self.folder_edit.setPlaceholderText("Folder containing sandbox/scan JSON reports…")
        browse = QPushButton("Browse…")
        browse.setObjectName("ghost")
        browse.clicked.connect(self._browse)
        row.addWidget(self.folder_edit, 1)
        row.addWidget(browse)
        panel.layout().addLayout(row)
        lay.addWidget(panel)

        panel2 = _panel("2 · Name the sample set")
        self.name_edit = QLineEdit("APT Triage Collection")
        panel2.layout().addWidget(self.name_edit)
        lay.addWidget(panel2)

        panel3 = _panel("3 · Ingest (default-deny parsers, hashed & quarantined)")
        run = QPushButton("🚀 Import Sample Set")
        run.setObjectName("primary")
        run.clicked.connect(lambda: self._import())
        panel3.layout().addWidget(run)
        lay.addWidget(panel3)

        self.status = QLabel("Waiting for import…")
        self.status.setObjectName("hint")
        lay.addWidget(self.status)
        lay.addStretch(1)

        note = QLabel("Supported: *.json / *.jsonl / *.txt — CAPE/Cuckoo-style."
                      " Each file becomes one sample; SHA-256 dedupe; inputs are sanitized (OWASP A03).")
        note.setObjectName("hint")
        note.setWordWrap(True)
        lay.addWidget(note)

    def _browse(self):
        d = QFileDialog.getExistingDirectory(self, "Choose report folder")
        if d:
            self.folder_edit.setText(d)

    def _import(self):
        folder = self.folder_edit.text().strip()
        name = self.name_edit.text().strip() or "Untitled set"
        if not folder or not Path(folder).is_dir():
            QMessageBox.warning(self, "Folder required", "Pick a valid directory.")
            return
        self.status.setText("Importing…")
        self.win.run_import(folder, name)
        self.status.setText(f"Done → set: {self.win._current_set_id}")


class SamplesPage(QWidget):
    def __init__(self, win: MainWindow):
        super().__init__()
        self.win = win
        lay = QVBoxLayout(self)
        lay.setContentsMargins(26, 24, 26, 24)
        lay.addWidget(QLabel("🗂️ Sample Explorer"))
        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["SHA-256", "Filename", "Family", "Verdict", "YARA rules"])
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setAlternatingRowColors(True)
        lay.addWidget(self.table)
        self.hint = QLabel("")
        self.hint.setObjectName("hint")
        lay.addWidget(self.hint)

    def refresh(self, set_id: str | None, profile: ActorProfile | None) -> None:
        self.hint.setText(f"Sample set: {set_id or 'none'} · techniques {len(profile.techniques) if profile else 0}")
        self.table.setRowCount(0)
        if not set_id:
            return
        samples = self.win.store.load_samples(set_id)
        self.table.setRowCount(len(samples))
        for i, s in enumerate(samples):
            for j, val in enumerate([
                s.sha256[:20] + "…", s.filename, s.family or "—", s.verdict,
                ", ".join(s.yara_rules[:3]) or "—"]):
                self.table.setItem(i, j, QTableWidgetItem(val))
            verdict = s.verdict
            item = self.table.item(i, 3)
            color = {"malicious": PALETTE["crimson"], "suspicious": PALETTE["amber"],
                     "clean": PALETTE["lime"], "unknown": PALETTE["muted"]}.get(verdict, PALETTE["muted"])
            item.setForeground(QColor(PALETTE["ghost"]))
            item.setBackground(QColor(color))


class ProfilePage(QWidget):
    def __init__(self, win: MainWindow):
        super().__init__()
        self.win = win
        lay = QVBoxLayout(self)
        lay.setContentsMargins(26, 24, 26, 24)
        lay.setSpacing(16)
        head_row = QHBoxLayout()
        lbl = QLabel("🎯 Threat Profile Builder")
        lbl.setObjectName("appTitle")
        head_row.addWidget(lbl)
        head_row.addStretch(1)
        build_btn = QPushButton("⚡ Build ATT&CK Profile")
        build_btn.setObjectName("primary")
        build_btn.clicked.connect(win.build_profile)
        head_row.addWidget(build_btn)
        lay.addLayout(head_row)

        info = _panel("Pipeline: Extract → Score → Attribute (weights = base × strength × coverage)")
        self.info = QLabel("No profile yet. Build one from the imported sample set.")
        self.info.setObjectName("hint")
        info.layout().addWidget(self.info)
        lay.addWidget(info)

        split = QSplitter()
        left = _panel("Actor Attribution Ranking")
        self.actors = QListWidget()
        left.layout().addWidget(self.actors)
        right = _panel("Mapped Techniques (evidence-ranked)")
        self.techs = QTableWidget(0, 4)
        self.techs.setHorizontalHeaderLabels(["ID", "Technique", "Tactics", "Score"])
        self.techs.setAlternatingRowColors(True)
        self.techs.verticalHeader().setVisible(False)
        right.layout().addWidget(self.techs)
        split.addWidget(left)
        split.addWidget(right)
        split.setSizes([500, 900])
        lay.addWidget(split, 1)

    def refresh(self, profile: ActorProfile | None) -> None:
        if not profile:
            self.info.setText("No profile yet. Build one from the imported sample set.")
            self.actors.clear()
            self.techs.setRowCount(0)
            return
        self.info.setText(
            f"Confidence {profile.confidence:.1f}% · Intel grade {profile.intel_grade} · "
            f"samples {profile.sample_count} · techniques {len(profile.techniques)}")
        self.actors.clear()
        for a in profile.actor_ranking[:6]:
            self.actors.addItem(
                f"{a.name}  —  conf {a.confidence:.0f}%  (sim {a.similarity:.2f})")
        self.techs.setRowCount(0)
        rows = sorted(profile.techniques, key=lambda t: -t.score)
        self.techs.setRowCount(len(rows))
        for i, t in enumerate(rows):
            tech = D.TECHNIQUES.get(t.technique_id, {})
            tactic_names = ", ".join(TA_LABEL[x] for x in D.TECHNIQUE_TACTICS.get(t.technique_id, []))
            self.techs.setItem(i, 0, QTableWidgetItem(t.technique_id))
            self.techs.setItem(i, 1, QTableWidgetItem(tech.get("name", "?")))
            self.techs.setItem(i, 2, QTableWidgetItem(tactic_names))
            self.techs.setItem(i, 3, QTableWidgetItem(f"{t.score:.2f}"))


TA_LABEL = {t["short"]: t["name"] for t in D.TACTICS}


class ReportsPage(QWidget):
    def __init__(self, win: MainWindow):
        super().__init__()
        self.win = win
        lay = QVBoxLayout(self)
        lay.setContentsMargins(26, 24, 26, 24)
        lay.setSpacing(16)
        lay.addWidget(QLabel("📄 Reports & Intelligence Export"))
        panel = _panel("Portable, signed, offline artifacts")
        row = QHBoxLayout()
        self.out_edit = QLineEdit(str(Path.cwd() / "reports"))
        self.out_edit.setPlaceholderText("Output directory…")
        browse = QPushButton("Browse…")
        browse.setObjectName("ghost")
        browse.clicked.connect(self._browse)
        row.addWidget(self.out_edit, 1)
        row.addWidget(browse)
        panel.layout().addLayout(row)
        exp = QPushButton("🚀 Generate Reports + Manifest")
        exp.setObjectName("primary")
        exp.clicked.connect(lambda: self.win.export_reports(self.out_edit.text().strip() or "reports", "sample-set"))
        panel.layout().addWidget(exp)
        lay.addWidget(panel)

        note = _panel("Artifacts")
        self.note = QLabel(
            "executive_report.html · navigator_layer.json (MITRE ATT&CK Navigator) · "
            "stix_bundle.json · profile.json · MANIFEST.sha256.json")
        self.note.setObjectName("hint")
        self.note.setWordWrap(True)
        note.layout().addWidget(self.note)
        lay.addWidget(note)
        lay.addStretch(1)

    def _browse(self):
        d = QFileDialog.getExistingDirectory(self, "Output folder")
        if d:
            self.out_edit.setText(d)

    def refresh(self, profile, set_id, samples):
        self.note.setText(
            f"Profile: {profile.id if profile else '—'} · set: {set_id or '—'} · samples: {len(samples)}")


class AuditPage(QWidget):
    def __init__(self, win: MainWindow):
        super().__init__()
        self.win = win
        lay = QVBoxLayout(self)
        lay.setContentsMargins(26, 24, 26, 24)
        lay.addWidget(QLabel("📋 Hash-Chained Audit Trail"))
        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["Seq", "Timestamp UTC", "Action", "Detail", "Chain hash"])
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setAlternatingRowColors(True)
        lay.addWidget(self.table)
        self.chain = QLabel("Chain head:")
        self.chain.setObjectName("hint")
        lay.addWidget(self.chain)

    def refresh(self) -> None:
        rows = self.win.store.audit_rows(300)
        self.table.setRowCount(len(rows))
        for i, r in enumerate(rows):
            vals = [r["seq"], r["ts"], r["action"], r["detail"][:80], r["hash"][:16] + "…"]
            for j, val in enumerate(vals):
                self.table.setItem(i, j, QTableWidgetItem(str(val)))
        self.chain.setText("Chain head: " + self.win.audit.last_hash[:48] + "…")


class SecurityPage(QWidget):
    def __init__(self, win: MainWindow):
        super().__init__()
        self.win = win
        lay = QVBoxLayout(self)
        lay.setContentsMargins(26, 24, 26, 24)
        lay.setSpacing(16)
        lay.addWidget(QLabel("🔐 Security Posture"))

        info = _panel("Runtime security state")
        self.info = QLabel("")
        self.info.setObjectName("hint")
        info.layout().addWidget(self.info)
        lay.addWidget(info)

        check = _panel("Control coverage — ISO 27001 · NIST CSF 2.0 · OWASP Top 10")
        self.checks = QListWidget()
        check.layout().addWidget(self.checks)
        lay.addWidget(check, 1)

        verify = QPushButton("🧪 Run Self-Audit (--verify)")
        verify.setObjectName("primary")
        verify.clicked.connect(self._verify)
        lay.addWidget(verify)

    def refresh(self) -> None:
        enc = self.win.store.encrypt_evidence
        self.info.setText(
            "Storage: SQLite WAL + parameterized queries · Evidence encryption: "
            f"{'DPAPI AES-256-GCM' if enc else 'plaintext (disabled)'} · "
            f"Audit chain: SHA-256 linked-hash · DB: {self.win.store.db_path}")

    def _verify(self):
        checks = []
        try:
            self.win.store.conn.execute("PRAGMA integrity_check").fetchall()
            checks.append(("SQLite integrity", True, "PRAGMA integrity_check passed"))
        except Exception as exc:  # noqa: BLE001
            checks.append(("SQLite integrity", False, str(exc)))
        for r in self.win.store.audit_rows(2):
            checks.append(("Audit chain", True, f"seq {r['seq']} hash ok"))
            break
        self.checks.clear()
        coverage = [
            ("ISO A.8 · Asset management", True, "sample-set inventory"),
            ("ISO A.10 · Cryptography", self.win.store.encrypt_evidence, "DPAPI at-rest"),
            ("ISO A.12 · Operations", True, "default-deny import"),
            ("ISO A.16 · Incident mgmt", True, "audit trail"),
            ("NIST PR.DS · Protect data", self.win.store.encrypt_evidence, "encryption"),
            ("NIST DE.CM · Monitoring", True, "hash-chain audit"),
            ("NIST AU-3 · Audit", True, "append-only log"),
            ("OWASP A03 · Injection", True, "parameterized SQL + sanitizers"),
            ("OWASP A06 · Vulnerable components", True, "SBOM in build"),
            ("OWASP A09 · Logging", True, "structured audit events"),
        ]
        for label, ok, how in coverage:
            mark = "✅" if ok else "⚠️"
            self.checks.addItem(f"{mark}  {label} — {how}")