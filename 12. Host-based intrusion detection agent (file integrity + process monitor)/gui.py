"""HIDS Agent — graphical console.

A tkinter desktop application for the Project-12 host-based intrusion
detection agent (file integrity monitoring + process monitoring):

  Dashboard   - live status cards + latest findings feed
  File Integrity - baseline table for all scoped files
  Processes   - live process snapshot with suspect highlighting
  Findings    - full alert history with severity filtering/export
  Settings    - agent configuration, baseline build, data management

The monitoring engine runs in a background worker thread; results are
posted to the UI via a queue polled on the tkinter main loop.
"""
from __future__ import annotations

import json
import os
import queue
import sys
import threading
import time
import traceback
from collections import deque
from datetime import datetime
from pathlib import Path

import tkinter as tk
from tkinter import filedialog, messagebox, ttk

PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))
os.chdir(PROJECT_ROOT)

import hids.alert as alert              # noqa: E402
from hids.baseline import BaselineDB    # noqa: E402
from hids.fim import FimEngine, load_scopes  # noqa: E402
from hids.process import ProcMonitor    # noqa: E402

SEVERITY_COLORS = {
    "high": "#c62828",
    "medium": "#ef6c00",
    "low": "#2e7d32",
}

# --------------------------------------------------------------------------
# Shared state (thread-safe via lock)
# --------------------------------------------------------------------------

class AppState:
    """Snapshot of agent state, shared between worker thread and GUI."""

    def __init__(self) -> None:
        self.lock = threading.RLock()
        self.findings: deque = deque(maxlen=3000)
        self.last_procs: list = []
        self.running = False
        self.cycle = 0
        self.last_scan_ts: float | None = None
        self.last_fim_findings = 0
        self.last_proc_findings = 0
        self.last_message = "idle"
        self.fim_total = 0
        self.fim_critical = 0

    def bump_counts(self) -> None:
        counts = {"high": 0, "medium": 0, "low": 0}
        with self.lock:
            for f in self.findings:
                counts[f.get("severity", "low")] = counts.get(f.get("severity", "low"), 0) + 1
        self._sev_counts = counts

    @property
    def severity_counts(self) -> dict:
        counts = {"high": 0, "medium": 0, "low": 0}
        with self.lock:
            for f in self.findings:
                sev = f.get("severity", "low")
                counts[sev] = counts.get(sev, 0) + 1
        return counts

    def summary(self) -> dict:
        with self.lock:
            return {
                "procs": len(self.last_procs),
                "cycle": self.cycle,
                "running": self.running,
                "last_scan_ts": self.last_scan_ts,
                "last_fim": self.last_fim_findings,
                "last_proc": self.last_proc_findings,
                "message": self.last_message,
                "fim_total": self.fim_total,
            }


class FindingsHook:
    """Alert hook that feeds the live GUI findings view."""

    def __init__(self, state: AppState) -> None:
        self.state = state

    def __call__(self, finding: dict) -> None:
        with self.state.lock:
            self.state.findings.appendleft(finding)

    def close(self) -> None:  # hook interface compat
        pass


# --------------------------------------------------------------------------
# Monitoring worker thread
# --------------------------------------------------------------------------

class WorkerConfig:
    def __init__(self) -> None:
        self.interval = 5.0
        self.enable_proc = True
        self.enable_fim = True
        self.scopes_path = "scopes.json"
        self.rules_path = "rules.json"
        self.state_dir = "data"
        self.known_hashes: set[str] = set()


class ScanWorker(threading.Thread):
    """Continuously runs FIM + process scans on a configurable cadence."""

    def __init__(self, state: AppState, cfg: WorkerConfig, reply: queue.Queue) -> None:
        super().__init__(daemon=True, name="hids-scan-worker")
        self.state = state
        self.cfg = cfg
        self.reply = reply
        self._stop_evt = threading.Event()
        self._wake_evt = threading.Event()
        self._scan_now = False
        self.db: BaselineDB | None = None
        self.fim: FimEngine | None = None
        self.proc: ProcMonitor | None = None

    # -- control ----------------------------------------------------------
    def request_scan(self) -> None:
        self._scan_now = True
        self._wake_evt.set()

    def shutdown(self) -> None:
        self._stop_evt.set()
        self._wake_evt.set()

    # -- internals --------------------------------------------------------
    def _post(self, msg: dict) -> None:
        self.reply.put(msg)

    def _load(self) -> None:
        self.db = BaselineDB(Path(self.cfg.state_dir) / "baseline.db")
        scopes = load_scopes(Path(self.cfg.scopes_path))
        self.fim = FimEngine(self.db, scopes, baseline=False)
        self.cfg.known_hashes = set()
        rp = Path(self.cfg.rules_path)
        if rp.exists():
            try:
                rd = json.loads(rp.read_text(encoding="utf-8"))
                self.cfg.known_hashes = set(rd.get("known_binary_hashes", []))
            except (json.JSONDecodeError, OSError):
                pass
        self.proc = ProcMonitor(self.cfg.known_hashes, alert.emit)

    def _has_baseline(self) -> bool:
        try:
            return bool(self.db and self.db.all())
        except Exception:
            return False

    def run(self) -> None:
        try:
            self._load()
            with self.state.lock:
                self.state.running = True
            self._post({"kind": "ready"})
            first_proc = True
            while not self._stop_evt.is_set():
                n_fim = n_proc = 0
                try:
                    n_fim = self.fim.snapshot() if self.cfg.enable_fim else 0
                    if self.cfg.enable_proc and self.proc:
                        n_proc = self.proc.scan(warmup=first_proc)
                        first_proc = False
                except Exception as exc:  # noqa: BLE001
                    traceback.print_exc()
                    self._post({"kind": "error", "text": str(exc)})

                procs = list(self.proc.procs) if self.proc else []
                with self.state.lock:
                    self.state.last_procs = procs
                    self.state.cycle += 1
                    self.state.last_scan_ts = time.time()
                    self.state.last_fim_findings = n_fim
                    self.state.last_proc_findings = n_proc
                    try:
                        rows = self.db.all() if self.db else []
                    except Exception:
                        rows = []
                    self.state.fim_total = len(rows)
                    self.state.fim_critical = sum(
                        1 for r in rows if r.get("mode") == "critical"
                    ) if rows else 0
                    self.state.running = not self._stop_evt.is_set()

                self._post({
                    "kind": "cycle",
                    "n_fim": n_fim,
                    "n_proc": n_proc,
                    "procs": len(procs),
                    "fim_total": len(rows),
                })

                if self._scan_now:
                    self._scan_now = False
                    continue
                self._wake_evt.wait(self.cfg.interval)
                self._wake_evt.clear()
        except Exception:  # noqa: BLE001
            traceback.print_exc()
            with self.state.lock:
                self.state.running = False
            self._post({"kind": "fatal", "text": traceback.format_exc()})

    # -- baseline ---------------------------------------------------------
    def build_baseline(self) -> bool:
        """One-shot rebuild of the FIM baseline. Runs on caller thread."""
        try:
            Path(self.cfg.state_dir).mkdir(parents=True, exist_ok=True)
            scopes = load_scopes(Path(self.cfg.scopes_path))
            db = BaselineDB(Path(self.cfg.state_dir) / "baseline.db")
            eng = FimEngine(db, scopes, baseline=True)
            n = eng.snapshot()
            db.close()
            self._post({"kind": "baseline_done", "files": n})
            return True
        except Exception as exc:  # noqa: BLE001
            traceback.print_exc()
            self._post({"kind": "error", "text": f"baseline failed: {exc}"})
            return False


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

def fmt_ts(epoch: float | None) -> str:
    if not epoch:
        return "—"
    return datetime.fromtimestamp(epoch).strftime("%H:%M:%S")


def fmt_size_mb(kb: int) -> str:
    return f"{kb / 1024.0:.1f} MB" if kb else ""


def short_hash(h: str, n: int = 12) -> str:
    return h[:n] if h else ""


def fit(s: str, n: int) -> str:
    s = s or ""
    return s if len(s) <= n else s[: n - 1] + "…"


# --------------------------------------------------------------------------
# GUI application
# --------------------------------------------------------------------------

class HidsApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("HIDS Agent — File Integrity + Process Monitor")
        self.geometry("1280x820")
        self.minsize(1120, 720)

        self.state_dir = Path("data")
        self.scopes_path = Path("scopes.json")
        self.rules_path = Path("rules.json")

        self.state = AppState()
        self.cfg = WorkerConfig()
        self.cfg.scopes_path = str(self.scopes_path)
        self.cfg.rules_path = str(self.rules_path)
        self.cfg.state_dir = str(self.state_dir)

        self.reply: queue.Queue = queue.Queue()
        self.worker: ScanWorker | None = None
        self._frame_counter = 0
        self._suspect_pids: set[int] = set()

        self._configure_style()
        self._build_menu()
        self._build_ui()

        alert.register_hook(FindingsHook(self.state))
        alert.register_hook(alert.JsonlHook(self.state_dir / "findings.jsonl"))
        alert.register_hook(alert.SyslogHook(self.state_dir / "syslog.out"))

        self._refresh_all_state()
        self.after(200, self._tick)
        self._maybe_offer_baseline()
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    # ------------------------------------------------------------------ UI
    def _configure_style(self) -> None:
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("TFrame", background="#0f1420")
        style.configure("TLabel", background="#0f1420", foreground="#dbe2ee")
        style.configure("Card.TFrame", background="#16202f",
                        borderwidth=1, relief="solid")
        style.configure("CardTitle.TLabel", background="#16202f",
                        foreground="#8fa3bf", font=("Segoe UI", 9, "bold"))
        style.configure("CardValue.TLabel", background="#16202f",
                        foreground="#ffffff", font=("Segoe UI", 22, "bold"))
        style.configure("CardSub.TLabel", background="#16202f",
                        foreground="#7b8aa3", font=("Segoe UI", 9))
        style.configure("Accent.TButton", font=("Segoe UI", 9, "bold"))
        style.configure("Toolbar.TFrame", background="#0f1420")
        style.configure("Section.TLabel", background="#0f1420",
                        foreground="#e8eef8", font=("Segoe UI", 11, "bold"))
        style.configure("Status.TLabel", background="#0d1119",
                        foreground="#8fa3bf", font=("Segoe UI", 9))
        style.configure("Treeview", background="#141c2b", fieldbackground="#141c2b",
                        foreground="#dbe2ee", rowheight=24, borderwidth=0)
        style.configure("Treeview.Heading", background="#1d2839",
                        foreground="#c3d0e4", font=("Segoe UI", 9, "bold"),
                        relief="flat", padding=(4, 4))
        style.map("Treeview", background=[("selected", "#2a4a7f")],
                  foreground=[("selected", "#ffffff")])

    def _build_menu(self) -> None:
        menubar = tk.Menu(self, tearoff=0)
        fmenu = tk.Menu(menubar, tearoff=0)
        fmenu.add_command(label="Start monitoring", command=self._start_monitoring)
        fmenu.add_command(label="Run scan now", command=self._request_scan)
        fmenu.add_separator()
        fmenu.add_command(label="Exit", command=self._on_close)
        menubar.add_cascade(label="Agent", menu=fmenu)

        amenu = tk.Menu(menubar, tearoff=0)
        amenu.add_command(label="Build baseline", command=self._build_baseline_action)
        amenu.add_command(label="Refresh file state", command=self._refresh_fim_table)
        amenu.add_command(label="Capture process snapshot", command=self._request_scan)
        menubar.add_cascade(label="Actions", menu=amenu)

        hmenu = tk.Menu(menubar, tearoff=0)
        hmenu.add_command(label="About", command=self._show_about)
        menubar.add_cascade(label="Help", menu=hmenu)
        self.config(menu=menubar)

    def _mk_card(self, parent, title: str) -> tuple[ttk.Frame, ttk.Label, ttk.Label]:
        card = ttk.Frame(parent, style="Card.TFrame", padding=14)
        ttl = ttk.Label(card, text=title, style="CardTitle.TLabel")
        val = ttk.Label(card, text="—", style="CardValue.TLabel")
        sub = ttk.Label(card, text="", style="CardSub.TLabel")
        ttl.pack(anchor="w")
        val.pack(anchor="w", pady=(2, 0))
        sub.pack(anchor="w")
        return card, val, sub

    def _build_ui(self) -> None:
        self.nb = ttk.Notebook(self)
        self.nb.pack(fill="both", expand=True, padx=8, pady=(8, 0))

        self.tab_dash = ttk.Frame(self.nb)
        self.tab_fim = ttk.Frame(self.nb)
        self.tab_proc = ttk.Frame(self.nb)
        self.tab_find = ttk.Frame(self.nb)
        self.tab_set = ttk.Frame(self.nb)
        self.nb.add(self.tab_dash, text="  Dashboard  ")
        self.nb.add(self.tab_fim, text="  File Integrity  ")
        self.nb.add(self.tab_proc, text="  Processes  ")
        self.nb.add(self.tab_find, text="  Findings  ")
        self.nb.add(self.tab_set, text="  Settings  ")

        self._build_dashboard()
        self._build_fim_tab()
        self._build_proc_tab()
        self._build_findings_tab()
        self._build_settings_tab()

        self.statusbar = tk.Frame(self, bg="#0d1119", height=26)
        self.statusbar.pack(fill="x", side="bottom")
        self.lbl_status = tk.Label(self.statusbar, text="Agent idle",
                                   bg="#0d1119", fg="#8fa3bf", anchor="w",
                                   font=("Consolas", 9))
        self.lbl_status.pack(side="left", padx=10, pady=3)
        self.lbl_clock = tk.Label(self.statusbar, text="", bg="#0d1119",
                                  fg="#6b7a94", font=("Consolas", 9))
        self.lbl_clock.pack(side="right", padx=10, pady=3)

    # ---- Dashboard -----------------------------------------------------
    def _build_dashboard(self) -> None:
        root = self.tab_dash
        cards = ttk.Frame(root)
        cards.pack(fill="x", padx=10, pady=(10, 6))

        self.card_status, self.card_status_v, self.card_status_s = self._mk_card(cards, "Status")
        self.card_files, self.card_files_v, self.card_files_s = self._mk_card(cards, "Files Monitored")
        self.card_find, self.card_find_v, self.card_find_s = self._mk_card(cards, "Findings")
        self.card_proc, self.card_proc_v, self.card_proc_s = self._mk_card(cards, "Processes")
        self.card_scan, self.card_scan_v, self.card_scan_s = self._mk_card(cards, "Last Scan")
        for c in (self.card_status, self.card_files, self.card_find,
                  self.card_proc, self.card_scan):
            c.pack(side="left", expand=True, fill="both", padx=5)

        # Control + feed
        body = ttk.Frame(root)
        body.pack(fill="both", expand=True, padx=10, pady=6)

        ctl = ttk.Frame(body, padding=12)
        ctl.pack(side="left", fill="y")
        ttk.Label(ctl, text="Monitoring Controls",
                  style="Section.TLabel").pack(anchor="w")
        self.btn_start = ttk.Button(ctl, text="▶ Start Monitoring", style="Accent.TButton",
                                    command=self._start_monitoring)
        self.btn_start.pack(fill="x", pady=4)
        self.btn_scan = ttk.Button(ctl, text="⟳ Run Scan Now", command=self._request_scan)
        self.btn_scan.pack(fill="x", pady=4)
        self.btn_baseline = ttk.Button(ctl, text="◆ Build Baseline",
                                       command=self._build_baseline_action)
        self.btn_baseline.pack(fill="x", pady=4)
        ttk.Separator(ctl, orient="horizontal").pack(fill="x", pady=10)

        ttk.Label(ctl, text="Last cycle", style="CardTitle.TLabel").pack(anchor="w")
        self.lbl_last_fim = ttk.Label(ctl, text="FIM findings: —", style="CardSub.TLabel")
        self.lbl_last_fim.pack(anchor="w")
        self.lbl_last_proc = ttk.Label(ctl, text="Proc findings: —", style="CardSub.TLabel")
        self.lbl_last_proc.pack(anchor="w")
        self.lbl_cycles = ttk.Label(ctl, text="Scan cycles: 0", style="CardSub.TLabel")
        self.lbl_cycles.pack(anchor="w")

        ttk.Separator(ctl, orient="horizontal").pack(fill="x", pady=10)
        ttk.Label(ctl, text="System", style="CardTitle.TLabel").pack(anchor="w")
        self.lbl_sysinfo = ttk.Label(ctl, text=self._sysinfo(), style="CardSub.TLabel",
                                     justify="left", wraplength=250)
        self.lbl_sysinfo.pack(anchor="w")

        feed = ttk.Frame(body, padding=12)
        feed.pack(side="left", fill="both", expand=True)
        feed_hdr = ttk.Frame(feed)
        feed_hdr.pack(fill="x")
        ttk.Label(feed_hdr, text="Live Findings Feed", style="Section.TLabel").pack(side="left")
        self.btn_go_findings = ttk.Button(feed_hdr, text="Open Findings →",
                                          command=lambda: self.nb.select(self.tab_find))
        self.btn_go_findings.pack(side="right")
        cols = ("ts", "sev", "type", "target")
        self.feed_tree = ttk.Treeview(feed, columns=cols, show="headings", height=12)
        for c, w, anchor in (("ts", 90, "w"), ("sev", 60, "center"),
                             ("type", 110, "w"), ("target", 420, "w")):
            self.feed_tree.heading(c, text=("Time" if c == "ts" else c.title()))
            self.feed_tree.column(c, width=w, anchor=anchor, stretch=(c == "target"))
        vsb = ttk.Scrollbar(feed, orient="vertical", command=self.feed_tree.yview)
        self.feed_tree.configure(yscrollcommand=vsb.set)
        self.feed_tree.pack(side="left", fill="both", expand=True, pady=(6, 0))
        vsb.pack(side="right", fill="y", pady=(6, 0))
        for sev, color in SEVERITY_COLORS.items():
            self.feed_tree.tag_configure(sev, foreground=color)
            self.feed_tree.tag_configure(sev + "_bg", background="#1a2433", foreground=color)

    def _sysinfo(self) -> str:
        import platform
        lines = [
            f"Python   {platform.python_version()}",
            f"Platform {platform.system()} {platform.release()}",
            f"State    {self.state_dir}",
            f"Scopes   {self.scopes_path}",
            f"Sensors  FIM + Proc",
        ]
        return "\n".join(lines)

    # ---- File Integrity tab --------------------------------------------
    def _build_fim_tab(self) -> None:
        root = self.tab_fim
        bar = ttk.Frame(root)
        bar.pack(fill="x", padx=10, pady=(10, 4))
        self.btn_fim_refresh = ttk.Button(bar, text="↻ Refresh from DB",
                                          command=self._refresh_fim_table)
        self.btn_fim_refresh.pack(side="left")
        self.var_fim_search = tk.StringVar()
        e = ttk.Entry(bar, textvariable=self.var_fim_search, width=40)
        e.pack(side="left", padx=8)
        e.bind("<KeyRelease>", lambda _e: self._refresh_fim_table(preserve=True))
        ttk.Label(bar, text="Filter (path / hash)").pack(side="left")
        self.lbl_fim_count = ttk.Label(bar, text="", style="CardSub.TLabel")
        self.lbl_fim_count.pack(side="right")

        cols = ("path", "mode", "size", "mtime", "hash", "snap")
        self.fim_tree = ttk.Treeview(root, columns=cols, show="headings")
        heads = {"path": "Path", "mode": "Mode", "size": "Size (B)",
                 "mtime": "Modified", "hash": "SHA-256", "snap": "Snap"}
        widths = {"path": 520, "mode": 70, "size": 90, "mtime": 140,
                  "hash": 130, "snap": 60}
        for c in cols:
            self.fim_tree.heading(c, text=heads[c])
            self.fim_tree.column(c, width=widths[c], anchor="w",
                                 stretch=(c in ("path", "hash")))
        vsb = ttk.Scrollbar(root, orient="vertical", command=self.fim_tree.yview)
        hsb = ttk.Scrollbar(root, orient="horizontal", command=self.fim_tree.xview)
        self.fim_tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        self.fim_tree.pack(side="left", fill="both", expand=True, padx=(10, 0), pady=(0, 10))
        vsb.pack(side="right", fill="y", pady=(0, 10))
        hsb.pack(side="bottom", fill="x", padx=10)
        self.fim_tree.tag_configure("critical", foreground="#ffb74d")

    # ---- Processes tab ---------------------------------------------------
    def _build_proc_tab(self) -> None:
        root = self.tab_proc
        bar = ttk.Frame(root)
        bar.pack(fill="x", padx=10, pady=(10, 4))
        self.btn_proc_refresh = ttk.Button(bar, text="↻ Refresh snapshot",
                                           command=self._request_scan)
        self.btn_proc_refresh.pack(side="left")
        self.var_proc_search = tk.StringVar()
        e = ttk.Entry(bar, textvariable=self.var_proc_search, width=30)
        e.pack(side="left", padx=8)
        e.bind("<KeyRelease>", lambda _e: self._refresh_proc_table(preserve=True))
        ttk.Label(bar, text="Filter").pack(side="left")
        self.var_proc_suspects = tk.BooleanVar(value=False)
        ttk.Checkbutton(bar, text="Suspects only", variable=self.var_proc_suspects,
                        command=lambda: self._refresh_proc_table(preserve=True)).pack(side="left", padx=8)
        self.lbl_proc_count = ttk.Label(bar, text="", style="CardSub.TLabel")
        self.lbl_proc_count.pack(side="right")

        cols = ("pid", "ppid", "name", "exe", "rss", "cmd")
        self.proc_tree = ttk.Treeview(root, columns=cols, show="headings")
        heads = {"pid": "PID", "ppid": "PPID", "name": "Name", "exe": "Executable",
                 "rss": "Memory", "cmd": "Command Line"}
        widths = {"pid": 70, "ppid": 70, "name": 170, "exe": 300,
                  "rss": 90, "cmd": 420}
        for c in cols:
            self.proc_tree.heading(c, text=heads[c])
            self.proc_tree.column(c, width=widths[c], anchor="w", stretch=(c in ("exe", "cmd")))
        vsb = ttk.Scrollbar(root, orient="vertical", command=self.proc_tree.yview)
        hsb = ttk.Scrollbar(root, orient="horizontal", command=self.proc_tree.xview)
        self.proc_tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        self.proc_tree.pack(side="left", fill="both", expand=True, padx=(10, 0), pady=(0, 10))
        vsb.pack(side="right", fill="y", pady=(0, 10))
        hsb.pack(side="bottom", fill="x", padx=10)
        self.proc_tree.tag_configure("suspect", foreground="#ff8a80")
        self.proc_tree.tag_configure("new", foreground="#80cbc4")

    # ---- Findings tab -----------------------------------------------------
    def _build_findings_tab(self) -> None:
        root = self.tab_find
        bar = ttk.Frame(root)
        bar.pack(fill="x", padx=10, pady=(10, 4))
        ttk.Label(bar, text="Severity").pack(side="left")
        self.var_find_filter = tk.StringVar(value="All")
        cb = ttk.Combobox(bar, textvariable=self.var_find_filter, width=10,
                          values=["All", "High", "Medium", "Low"], state="readonly")
        cb.pack(side="left", padx=6)
        cb.bind("<<ComboboxSelected>>", lambda _e: self._refresh_findings_table())
        self.btn_find_export = ttk.Button(bar, text="⬇ Export Log", command=self._export_findings)
        self.btn_find_export.pack(side="left", padx=6)
        self.btn_find_clear = ttk.Button(bar, text="Clear View", command=self._clear_findings)
        self.btn_find_clear.pack(side="left")
        self.lbl_find_count = ttk.Label(bar, text="", style="CardSub.TLabel")
        self.lbl_find_count.pack(side="right")

        cols = ("ts", "sev", "type", "target", "detail")
        self.find_tree = ttk.Treeview(root, columns=cols, show="headings")
        heads = {"ts": "Time", "sev": "Severity", "type": "Type",
                 "target": "Target", "detail": "Evidence"}
        widths = {"ts": 110, "sev": 80, "type": 110, "target": 380, "detail": 420}
        for c in cols:
            self.find_tree.heading(c, text=heads[c])
            self.find_tree.column(c, width=widths[c], anchor="w", stretch=(c in ("target", "detail")))
        vsb = ttk.Scrollbar(root, orient="vertical", command=self.find_tree.yview)
        hsb = ttk.Scrollbar(root, orient="horizontal", command=self.find_tree.xview)
        self.find_tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        self.find_tree.pack(side="left", fill="both", expand=True, padx=(10, 0), pady=(0, 10))
        vsb.pack(side="right", fill="y", pady=(0, 10))
        hsb.pack(side="bottom", fill="x", padx=10)
        for sev, color in SEVERITY_COLORS.items():
            self.find_tree.tag_configure(sev, foreground=color)

    # ---- Settings tab -------------------------------------------------------
    def _build_settings_tab(self) -> None:
        root = self.tab_set

        left = ttk.Frame(root, padding=14)
        left.pack(side="left", fill="y", padx=10, pady=10)
        ttk.Label(left, text="Agent Configuration", style="Section.TLabel").pack(anchor="w", pady=(0, 8))

        row = ttk.Frame(left)
        row.pack(fill="x", pady=3)
        ttk.Label(row, text="Scan interval (s)", width=20).pack(side="left")
        self.var_interval = tk.StringVar(value="5")
        ttk.Spinbox(row, from_=1, to=600, textvariable=self.var_interval,
                    width=8).pack(side="left")

        row = ttk.Frame(left)
        row.pack(fill="x", pady=3)
        ttk.Label(row, text="Scopes file", width=20).pack(side="left")
        self.var_scopes = tk.StringVar(value=str(self.scopes_path))
        e = ttk.Entry(row, textvariable=self.var_scopes)
        e.pack(side="left", fill="x", expand=True, padx=(0, 4))
        ttk.Button(row, text="…", width=3, command=self._browse_scopes).pack(side="left")

        row = ttk.Frame(left)
        row.pack(fill="x", pady=3)
        ttk.Label(row, text="Rules file", width=20).pack(side="left")
        self.var_rules = tk.StringVar(value=str(self.rules_path))
        e = ttk.Entry(row, textvariable=self.var_rules)
        e.pack(side="left", fill="x", expand=True, padx=(0, 4))
        ttk.Button(row, text="…", width=3, command=self._browse_rules).pack(side="left")

        self.var_enable_fim = tk.BooleanVar(value=True)
        self.var_enable_proc = tk.BooleanVar(value=True)
        ttk.Checkbutton(left, text="Enable file integrity monitoring",
                        variable=self.var_enable_fim).pack(anchor="w", pady=3)
        ttk.Checkbutton(left, text="Enable process monitoring",
                        variable=self.var_enable_proc).pack(anchor="w", pady=3)

        ttk.Button(left, text="Apply Configuration", style="Accent.TButton",
                   command=self._apply_config).pack(fill="x", pady=(12, 4))

        ttk.Separator(left, orient="horizontal").pack(fill="x", pady=10)

        ttk.Label(left, text="Baseline", style="CardTitle.TLabel").pack(anchor="w")
        ttk.Label(left,
                  text="Build/rebuild the integrity baseline of all scoped\n"
                       "files. Run on first deploy and after legitimate\n"
                       "upgrades. No findings are raised in baseline mode.",
                  style="CardSub.TLabel", justify="left").pack(anchor="w", pady=4)
        ttk.Button(left, text="◆ Build / Rebuild Baseline",
                   command=self._build_baseline_action).pack(fill="x", pady=4)
        ttk.Button(left, text="Open Data Folder",
                   command=self._open_data_folder).pack(fill="x", pady=4)

        right = ttk.Frame(root, padding=14)
        right.pack(side="left", fill="both", expand=True, padx=(0, 10), pady=10)
        ttk.Label(right, text="Agent State & Output", style="Section.TLabel").pack(anchor="w", pady=(0, 8))
        self.state_tree = ttk.Treeview(right, columns=("k", "v"), show="headings", height=14)
        self.state_tree.heading("k", text="Key")
        self.state_tree.heading("v", text="Value")
        self.state_tree.column("k", width=200, anchor="w")
        self.state_tree.column("v", width=560, anchor="w")
        self.state_tree.pack(fill="both", expand=True)

        self._logs_text = tk.Text(right, height=10, bg="#0d1119", fg="#a7b8cf",
                                  insertbackground="white", font=("Consolas", 9))
        self._logs_text.pack(fill="both", expand=True, pady=(10, 0))

    # ------------------------------------------------------------------ actions
    def _start_monitoring(self) -> None:
        if self.worker and self.worker.is_alive():
            return
        self._apply_config()
        self.worker = ScanWorker(self.state, self.cfg, self.reply)
        self.worker.start()
        self.lbl_status.config(text="Starting agent…")
        self._post_log("Monitoring thread started")

    def _request_scan(self) -> None:
        if not (self.worker and self.worker.is_alive()):
            self._start_monitoring()
            return
        self.worker.request_scan()
        self._post_log("Scan requested")

    def _build_baseline_action(self) -> None:
        if self.worker and self.worker.is_alive():
            messagebox.showinfo(
                "HIDS Agent",
                "Stop monitoring before rebuilding the baseline,\n"
                "or baseline files will be re-flagged as changes.",
                parent=self)
            return
        if not messagebox.askyesno(
                "Build Baseline",
                "This replaces the integrity baseline with the current\n"
                "state of all scoped files. Continue?", parent=self):
            return
        self.lbl_status.config(text="Building baseline…")
        self._post_log("Building baseline (async)…")
        t = threading.Thread(target=self._baseline_async, daemon=True)
        t.start()

    def _baseline_async(self) -> None:
        cfg = WorkerConfig()
        cfg.scopes_path = self.var_scopes.get() or str(self.scopes_path)
        cfg.rules_path = self.var_rules.get() or str(self.rules_path)
        cfg.state_dir = str(self.state_dir)
        w = ScanWorker(self.state, cfg, self.reply)
        w.build_baseline()
        self.after(0, self._baseline_done_ui)

    def _baseline_done_ui(self) -> None:
        self.lbl_status.config(text="Baseline built")
        self._refresh_all_state()

    # ------------------------------------------------------------------ data refresh
    def _refresh_all_state(self) -> None:
        self._refresh_fim_table()
        self._refresh_proc_table()
        self._refresh_findings_table()
        self._refresh_state_tree()
        self._update_cards()

    def _refresh_fim_table(self, preserve: bool = False) -> None:
        try:
            db = BaselineDB(self.state_dir / "baseline.db")
            rows = db.all()
            db.close()
        except Exception:
            rows = []
        q = (self.var_fim_search.get() if hasattr(self, "var_fim_search") else "").strip().lower()
        self.fim_tree.delete(*self.fim_tree.get_children())
        count = 0
        for r in rows:
            path = r.get("path", "")
            h = r.get("hash", "")
            if q and q not in path.lower() and q not in h.lower():
                continue
            count += 1
            mode = r.get("mode", "")
            self.fim_tree.insert("", "end", values=(
                fit(path, 60), mode, r.get("size", 0),
                datetime.fromtimestamp(float(r.get("mtime", 0) or 0)).strftime("%Y-%m-%d %H:%M:%S")
                if r.get("mtime") else "—",
                short_hash(h), r.get("snapshot_id", 0),
            ), tags=(mode,))
        self.lbl_fim_count.config(text=f"{count} / {len(rows)} files")
        with self.state.lock:
            self.state.fim_total = len(rows)

    def _refresh_proc_table(self, preserve: bool = False) -> None:
        with self.state.lock:
            procs = list(self.state.last_procs)
        q = (self.var_proc_search.get() if hasattr(self, "var_proc_search") else "").strip().lower()
        suspects_only = self.var_proc_suspects.get() if hasattr(self, "var_proc_suspects") else False
        self.proc_tree.delete(*self.proc_tree.get_children())
        count = 0
        for p in procs:
            is_suspect = p.pid in self._suspect_pids
            if suspects_only and not is_suspect:
                continue
            if q and q not in p.name.lower() and q not in (p.exe or "").lower() \
                    and q not in (p.cmdline or "").lower():
                continue
            count += 1
            self.proc_tree.insert("", "end", values=(
                p.pid, p.ppid, fit(p.name, 24), fit(p.exe, 40),
                fmt_size_mb(p.rss_kb), fit(p.cmdline, 90),
            ), tags=("suspect",) if is_suspect else ())
        self.lbl_proc_count.config(text=f"{count} processes")

    def _refresh_findings_table(self) -> None:
        with self.state.lock:
            findings = list(self.state.findings)
        filt = self.var_find_filter.get() if hasattr(self, "var_find_filter") else "All"
        self.find_tree.delete(*self.find_tree.get_children())
        count = 0
        for f in findings:
            sev = f.get("severity", "low")
            if filt != "All" and sev.lower() != filt.lower():
                continue
            count += 1
            if f.get("type") in ("proc_new",):
                target = str(f.get("pid", ""))
                detail = f.get("cmdline") or f.get("exe") or ""
            else:
                target = fit(f.get("path", ""), 46)
                detail = ""
                if f.get("type") == "file_changed":
                    detail = f"hash {short_hash(f.get('old_hash', ''))} → {short_hash(f.get('new_hash', ''))}"
                elif f.get("type") == "file_new":
                    detail = short_hash((f.get("sig") or {}).get("hash", ""))
                elif f.get("type") == "file_deleted":
                    detail = "removed from scope"
                if f.get("reason"):
                    detail = (detail + " | " if detail else "") + f.get("reason", "")
            self.find_tree.insert("", "end", values=(
                f.get("ts", "—"), sev.title(), f.get("type", "—"), target, detail,
            ), tags=(sev,))
        self.lbl_find_count.config(text=f"{count} findings")
        self._update_feed()

    def _update_feed(self) -> None:
        if not hasattr(self, "feed_tree"):
            return
        with self.state.lock:
            items = list(self.state.findings)[:20]
        self.feed_tree.delete(*self.feed_tree.get_children())
        for f in items:
            sev = f.get("severity", "low")
            target = f.get("path") or f.get("pid") or ""
            self.feed_tree.insert("", "end", values=(
                (f.get("ts") or "")[11:19] if f.get("ts") else "—",
                sev.title(), f.get("type", "—"), fit(str(target), 48),
            ), tags=(sev,))

    def _refresh_state_tree(self) -> None:
        self.state_tree.delete(*self.state_tree.get_children())
        s = self.state.summary()
        rows = [
            ("agent", os.path.basename(sys.argv[0])),
            ("state dir", str(self.state_dir)),
            ("findings log", str(self.state_dir / "findings.jsonl")),
            ("syslog out", str(self.state_dir / "syslog.out")),
            ("monitored files", s["fim_total"]),
            ("last scan", fmt_ts(s["last_scan_ts"])),
            ("scan cycles", s["cycle"]),
            ("running", str(s["running"])),
            ("last FIM findings", s["last_fim"]),
            ("last proc findings", s["last_proc"]),
            ("processes tracked", s["procs"]),
            ("rules hashes", len(self.cfg.known_hashes)),
        ]
        for k, v in rows:
            self.state_tree.insert("", "end", values=(k, v))

    def _update_cards(self) -> None:
        s = self.state.summary()
        counts = self.state.severity_counts
        live = s["running"]
        self.card_status_v.config(text="MONITORING" if live else "IDLE",
                                  foreground="#69f0ae" if live else "#b0bec5")
        self.card_status_s.config(text="worker thread " + ("active" if live else "stopped"))
        self.card_files_v.config(text=str(s["fim_total"]))
        self.card_files_s.config(text="baseline records")
        self.card_find_v.config(text=str(sum(counts.values())))
        self.card_find_s.config(text=f"high {counts['high']} · med {counts['medium']} · low {counts['low']}")
        self.card_proc_v.config(text=str(s["procs"]))
        self.card_proc_s.config(text="processes in snapshot")
        self.card_scan_v.config(text=fmt_ts(s["last_scan_ts"]))
        self.card_scan_s.config(text=f"cycle {s['cycle']}")

        self.lbl_last_fim.config(text=f"FIM findings: {s['last_fim']}")
        self.lbl_last_proc.config(text=f"Proc findings: {s['last_proc']}")
        self.lbl_cycles.config(text=f"Scan cycles: {s['cycle']}")

    def _refresh_suspect_pids(self) -> None:
        with self.state.lock:
            self._suspect_pids = {
                int(f["pid"]) for f in self.state.findings
                if f.get("type") == "proc_new" and str(f.get("pid", "")).isdigit()
            }

    # ------------------------------------------------------------------ settings actions
    def _browse_scopes(self) -> None:
        p = filedialog.askopenfilename(parent=self, title="Scopes file",
                                       initialdir=str(PROJECT_ROOT),
                                       filetypes=[("JSON", "*.json")])
        if p:
            self.var_scopes.set(p)

    def _browse_rules(self) -> None:
        p = filedialog.askopenfilename(parent=self, title="Rules file",
                                       initialdir=str(PROJECT_ROOT),
                                       filetypes=[("JSON", "*.json")])
        if p:
            self.var_rules.set(p)

    def _apply_config(self) -> None:
        try:
            interval = float(self.var_interval.get())
            interval = max(1.0, min(600.0, interval))
        except ValueError:
            interval = self.cfg.interval
        self.cfg.interval = interval
        self.cfg.enable_fim = self.var_enable_fim.get()
        self.cfg.enable_proc = self.var_enable_proc.get()
        self.cfg.scopes_path = self.var_scopes.get() or str(self.scopes_path)
        self.cfg.rules_path = self.var_rules.get() or str(self.rules_path)
        self._post_log(f"Config applied: interval={interval}s "
                       f"fim={self.cfg.enable_fim} proc={self.cfg.enable_proc}")

    def _export_findings(self) -> None:
        path = filedialog.asksaveasfilename(parent=self, defaultextension=".jsonl",
                                            initialfile="findings-export.jsonl",
                                            filetypes=[("JSON Lines", "*.jsonl"),
                                                       ("All files", "*.*")])
        if not path:
            return
        with self.state.lock:
            items = list(self.state.findings)
        with open(path, "w", encoding="utf-8") as fh:
            for f in reversed(items):
                fh.write(json.dumps(f) + "\n")
        self._post_log(f"Exported {len(items)} findings → {path}")
        self.lbl_status.config(text=f"Exported {len(items)} findings")

    def _clear_findings(self) -> None:
        with self.state.lock:
            self.state.findings.clear()
        self._refresh_findings_table()
        self._update_cards()
        self._post_log("Findings view cleared (log files untouched)")

    def _open_data_folder(self) -> None:
        try:
            os.startfile(str(self.state_dir.resolve()))  # type: ignore[attr-defined]
        except OSError as exc:
            self._post_log(f"open data folder failed: {exc}")

    def _show_about(self) -> None:
        messagebox.showinfo(
            "HIDS Agent",
            "Host-based intrusion detection agent\n"
            "File Integrity Monitoring + Process Monitoring\n\n"
            "Detects file tampering (hashes, size, mtime, deletions)\n"
            "and suspicious process launches (cmdline patterns,\n"
            "unknown binary hashes).", parent=self)

    # ------------------------------------------------------------------ loop
    def _maybe_offer_baseline(self) -> None:
        try:
            db = BaselineDB(self.state_dir / "baseline.db")
            has = bool(db.all())
            db.close()
        except Exception:
            has = False
        if not has:
            self.after(600, lambda: messagebox.showinfo(
                "First run",
                "No baseline exists yet. Build the integrity baseline\n"
                "from the Dashboard or Settings, then start monitoring.",
                parent=self))

    def _tick(self) -> None:
        self.lbl_clock.config(text=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        processed = 0
        try:
            while processed < 50:
                msg = self.reply.get_nowait()
                processed += 1
                self._handle_reply(msg)
        except queue.Empty:
            pass
        self._loop_heartbeat()
        self.after(200, self._tick)

    def _loop_heartbeat(self) -> None:
        self._frame_counter += 1
        if self._frame_counter % 5 == 0:
            self._refresh_suspect_pids()
            if self.nb.index(self.nb.select()) in (0, 3):  # dashboard / findings
                self._update_cards()
            self._refresh_findings_table()
            self._refresh_proc_table(preserve=True)
            if self.nb.index(self.nb.select()) == 4:
                self._refresh_state_tree()
            if self.worker:
                self.lbl_status.config(text=self.state.last_message or "running")

    def _handle_reply(self, msg: dict) -> None:
        kind = msg.get("kind")
        if kind == "cycle":
            n = None
            self._post_log(f"cycle done: fim_findings={msg.get('n_fim')} "
                           f"proc_findings={msg.get('n_proc')} procs={msg.get('procs')}")
            self._update_cards()
            self._refresh_fim_table(preserve=True)
            self._refresh_proc_table(preserve=True)
            self._refresh_findings_table()
        elif kind == "ready":
            self.lbl_status.config(text="Monitoring active")
        elif kind == "baseline_done":
            with self.state.lock:
                self.state.last_message = f"baseline built ({msg.get('files')} files)"
            self.lbl_status.config(text=f"Baseline built: {msg.get('files')} files")
            self._refresh_all_state()
        elif kind == "error":
            self.lbl_status.config(text=f"⚠ {msg.get('text', '')}")
            self._post_log(f"error: {msg.get('text', '')}")
        elif kind == "fatal":
            self.lbl_status.config(text="Worker crashed")
            self._post_log(msg.get("text", "worker crash"))
            messagebox.showerror("HIDS Agent", msg.get("text", "worker crashed"), parent=self)

    # ------------------------------------------------------------------ utils
    def _post_log(self, text: str) -> None:
        try:
            line = f"[{datetime.now().strftime('%H:%M:%S')}] {text}\n"
            self._logs_text.insert("end", line)
            self._logs_text.see("end")
        except tk.TclError:
            pass

    def _on_close(self) -> None:
        if self.worker:
            self.worker.shutdown()
            self.worker.join(timeout=2.0)
        try:
            for hook in list(alert._hooks):
                if hasattr(hook, "close"):
                    hook.close()
        except Exception:
            pass
        self.destroy()


def main() -> int:
    app = HidsApp()
    app.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())