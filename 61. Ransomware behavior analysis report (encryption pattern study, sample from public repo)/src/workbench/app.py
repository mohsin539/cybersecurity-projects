from __future__ import annotations

import json
import os
import queue
import shutil
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from typing import Any, Optional

from . import __app_name__, __version__
from .core.intake import human_size, ingest, read_quarantined, sha256_file
from .core.ledger import Ledger
from .core.models import Sample
from .core.patternengine import build_fingerprint
from .core.report import save_report
from .core.staticanalyzer import static_analyze
from .core.workspace import Workspace, default_workspace_root, now_iso

BG = "#1e1f26"
PANEL = "#26272e"
ROW = "#2f3140"
FG = "#e6e6e6"
MUTED = "#9aa0b4"
ACCENT = "#4f8cff"
OK = "#3fb950"
WARN = "#e3b341"
BAD = "#f85149"

BIG_FILE_LIMIT = 128 * 1024 * 1024  # 128 MiB safety cap (memory footprint)
ACTOR = "analyst"


def config_path() -> str:
    base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
    return os.path.join(base, "RansomLens", "app_cfg.json")


def load_cfg() -> dict:
    try:
        with open(config_path(), "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def save_cfg(cfg: dict) -> None:
    try:
        os.makedirs(os.path.dirname(config_path()), exist_ok=True)
        with open(config_path(), "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2, ensure_ascii=True)
    except Exception:
        pass


class RansomLensApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title(f"{__app_name__} - Ransomware Behavior Analysis Workbench v{__version__}")
        self.geometry("1280x820")
        self.minsize(1040, 700)
        self.configure(bg=BG)
        self._ui_queue: "queue.Queue[tuple[str, Any]]" = queue.Queue()
        self.cfg: dict = load_cfg()
        self.root_path: str = self.cfg.get("workspace") or default_workspace_root()
        self.workspace: Optional[Workspace] = None
        self.ledger: Optional[Ledger] = None
        self.pending: list[dict[str, Any]] = []
        self.evidence_path: Optional[str] = self.cfg.get("evidence") or None
        self._build_styles()
        self._build_ui()
        self._init_workspace(self.root_path)
        self.after(200, self._poll_queue)

    # ------------------------------------------------------------------ setup
    def _build_styles(self) -> None:
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure(".", background=BG, foreground=FG, fieldbackground=PANEL,
                        bordercolor=PANEL, lightcolor=PANEL, darkcolor=PANEL)
        style.configure("TFrame", background=BG)
        style.configure("Panel.TFrame", background=PANEL)
        style.configure("TLabel", background=BG, foreground=FG, font=("Segoe UI", 10))
        style.configure("Muted.TLabel", background=BG, foreground=MUTED, font=("Segoe UI", 9))
        style.configure("H1.TLabel", background=BG, foreground=FG, font=("Segoe UI", 15, "bold"))
        style.configure("H2.TLabel", background=BG, foreground=ACCENT, font=("Segoe UI", 11, "bold"))
        style.configure("Stat.TLabel", background=PANEL, foreground=FG,
                        font=("Consolas", 16, "bold"), padding=14, anchor="center")
        style.configure("TNotebook", background=BG, borderwidth=0)
        style.configure("TNotebook.Tab", background=PANEL, foreground=FG,
                        padding=(14, 7), font=("Segoe UI", 10))
        style.map("TNotebook.Tab", background=[("selected", ACCENT)],
                  foreground=[("selected", "#ffffff")])
        style.configure("Treeview", background=ROW, fieldbackground=ROW, foreground=FG,
                        rowheight=24, borderwidth=0)
        style.configure("Treeview.Heading", background=PANEL, foreground=FG,
                        font=("Segoe UI", 9, "bold"))
        style.map("Treeview", background=[("selected", "#3a4b6b")])
        style.configure("TEntry", foreground=FG, insertcolor=FG)

    def _button(self, parent, text, cmd, accent: bool = False, **kw):
        return tk.Button(
            parent, text=text, command=cmd, relief="flat", cursor="hand2",
            bg=ACCENT if accent else ROW, fg="#ffffff" if accent else FG,
            activebackground="#6b9dff" if accent else "#3a3d4d",
            activeforeground="#ffffff" if accent else FG,
            font=("Segoe UI", 9, "bold"), padx=12, pady=5, bd=0, **kw
        )

    def _build_ui(self) -> None:
        # header
        head = tk.Frame(self, bg=BG)
        head.pack(fill="x", padx=18, pady=(14, 6))
        tk.Label(head, text=__app_name__, bg=BG, fg=FG,
                 font=("Segoe UI", 20, "bold")).pack(side="left")
        tk.Label(head, text="  non-executing forensic workbench",
                 bg=BG, fg=MUTED, font=("Segoe UI", 10)).pack(side="left", pady=(6, 0))
        self.status_var = tk.StringVar(value="Starting...")
        tk.Label(head, textvariable=self.status_var, bg=BG, fg=MUTED,
                 font=("Consolas", 9)).pack(side="right")

        # tab notebook
        self.nb = ttk.Notebook(self)
        self.nb.pack(fill="both", expand=True, padx=18, pady=(4, 10))
        self._tab_dashboard = ttk.Frame(self.nb)
        self._tab_intake = ttk.Frame(self.nb)
        self._tab_reports = ttk.Frame(self.nb)
        self._tab_ledger = ttk.Frame(self.nb)
        self._tab_settings = ttk.Frame(self.nb)
        for t, label in ((self._tab_dashboard, "Dashboard"),
                         (self._tab_intake, "Intake && Analyze"),
                         (self._tab_reports, "Reports"),
                         (self._tab_ledger, "Audit Ledger"),
                         (self._tab_settings, "Settings && Security")):
            self.nb.add(t, text=label)

        self._build_dashboard()
        self._build_intake()
        self._build_reports()
        self._build_ledger()
        self._build_settings()

    # ---------------------------------------------------------------- tab UI
    def _build_dashboard(self) -> None:
        tab = self._tab_dashboard
        ttk.Label(tab, text="Operational snapshot", style="H1.TLabel").pack(
            anchor="w", padx=14, pady=(14, 6))

        cards = tk.Frame(tab, bg=BG)
        cards.pack(fill="x", padx=14, pady=4)
        self.stat_vars: dict[str, tk.StringVar] = {}
        for key, title in (("samples", "Samples in vault"), ("analyses", "Analyses run"),
                           ("high_risk", "High-risk findings"), ("reports", "Reports issued")):
            card = tk.Frame(cards, bg=PANEL, highlightthickness=0)
            card.pack(side="left", padx=(0, 12), fill="x", expand=True)
            v = tk.StringVar(value="0")
            self.stat_vars[key] = v
            tk.Label(card, text=title, bg=PANEL, fg=MUTED,
                     font=("Segoe UI", 9)).pack(pady=(10, 0))
            tk.Label(card, textvariable=v, bg=PANEL, fg=FG,
                     font=("Consolas", 20, "bold")).pack(pady=(2, 12))

        tk.Label(tab, text="How to use this workbench", bg=BG, fg=ACCENT,
                 font=("Segoe UI", 11, "bold")).pack(anchor="w", padx=14, pady=(18, 4))
        guide = (
            "1. Go to Intake && Analyze and add files (or a folder) - each is hashed (SHA-256) and "
            "quarantined into the vault, deduplicated by hash.\n"
            "2. Optional: pick an *evidence original* (a known-plaintext twin) to strengthen the "
            "overwrite-strategy inference.\n"
            "3. Run Scout (static pass) then Analyze (full encryption-pattern fingerprint + report).\n"
            "4. Read results in Reports; every analysis writes a signed-chain entry to Audit Ledger.\n"
            "5. Files are NEVER executed - analysis is read-only entropy / structural / string evidence.\n"
            "6. This build is the portable workbench slice of architecture.md (Sections 6.1-6.7, 7, 15);\n"
            "   the live detonation sandbox (Section 7, Zone 0) is deliberately out of scope for this build."
        )
        box = tk.Text(tab, bg=PANEL, fg=FG, relief="flat", height=10, wrap="word",
                      font=("Consolas", 10), padx=14, pady=12, insertbackground=FG)
        box.insert("1.0", guide)
        box.configure(state="disabled")
        box.pack(fill="both", expand=True, padx=14, pady=(2, 14))

    def _build_intake(self) -> None:
        tab = self._tab_intake
        bar = tk.Frame(tab, bg=BG)
        bar.pack(fill="x", padx=12, pady=(12, 6))
        self._button(bar, "+ Add Files", self.on_add_files, accent=True).pack(side="left", padx=4)
        self._button(bar, "+ Add Folder", self.on_add_folder).pack(side="left", padx=4)
        self._button(bar, "Scout (static pass)", self.on_scout).pack(side="left", padx=4)
        self._button(bar, "Analyze Selected", self.on_analyze, accent=True).pack(side="left", padx=4)
        self._button(bar, "Clear Queue", self.on_clear_queue).pack(side="left", padx=4)

        ev = tk.Frame(tab, bg=BG)
        ev.pack(fill="x", padx=12, pady=(0, 6))
        tk.Label(ev, text="Evidence original (optional):", bg=BG, fg=MUTED,
                 font=("Segoe UI", 9)).pack(side="left")
        self.evidence_var = tk.StringVar(value=self.evidence_path or "(none)")
        tk.Label(ev, textvariable=self.evidence_var, bg=BG, fg=FG,
                 font=("Consolas", 9)).pack(side="left", padx=8)
        self._button(ev, "Choose", self.on_choose_evidence).pack(side="left")
        self._button(ev, "Clear", self.on_clear_evidence).pack(side="left", padx=4)

        # pending queue
        ttk.Label(tab, text="Quarantine queue (pending analysis)", style="H2.TLabel").pack(
            anchor="w", padx=12, pady=(8, 2))
        cols = ("name", "sha", "size", "magic")
        self.pending_tree = ttk.Treeview(tab, columns=cols, show="headings", height=7)
        for c, w, t in (("name", 340, "File"), ("sha", 460, "SHA-256"),
                        ("size", 110, "Size"), ("magic", 200, "Magic")):
            self.pending_tree.heading(c, text=t)
            self.pending_tree.column(c, width=w, stretch=(c == "sha"))
        self.pending_tree.pack(fill="x", padx=12, pady=4)

        ttk.Label(tab, text="Analysis results (this session)", style="H2.TLabel").pack(
            anchor="w", padx=12, pady=(12, 2))
        cols2 = ("pattern", "conf", "risk", "entropy", "note", "sample")
        self.result_tree = ttk.Treeview(tab, columns=cols2, show="headings")
        for c, w, t in (("pattern", 240, "Encryption pattern"),
                        ("conf", 80, "Confidence"), ("risk", 70, "Risk"),
                        ("entropy", 90, "Entropy"), ("note", 380, "Summary"),
                        ("sample", 140, "SHA (short)")):
            self.result_tree.heading(c, text=t)
            self.result_tree.column(c, width=w, stretch=(c == "note"))
        self.result_tree.pack(fill="both", expand=True, padx=12, pady=(4, 12))
        self.result_tree.bind("<Double-1>", self.on_open_last_report)

    def _build_reports(self) -> None:
        tab = self._tab_reports
        bar = tk.Frame(tab, bg=BG)
        bar.pack(fill="x", padx=12, pady=(12, 6))
        self._button(bar, "Refresh", self.refresh_reports).pack(side="left", padx=4)
        self._button(bar, "Open selected", self.on_open_report, accent=True).pack(side="left", padx=4)
        self._button(bar, "Export copy...", self.on_export_report).pack(side="left", padx=4)

        self.report_list = tk.Listbox(tab, bg=ROW, fg=FG, relief="flat",
                                      selectbackground=ACCENT, font=("Consolas", 10),
                                      highlightthickness=0, activestyle="none")
        self.report_list.pack(fill="both", expand=True, padx=12, pady=(4, 6))
        self.report_list.bind("<Double-1>", lambda e: self.on_open_report())

        self.report_view = tk.Text(tab, bg=PANEL, fg=FG, relief="flat", wrap="none",
                                   font=("Consolas", 10), padx=12, pady=10,
                                   insertbackground=FG, state="disabled", height=14)
        self.report_view.pack(fill="both", expand=False, padx=12, pady=(0, 12))

    def _build_ledger(self) -> None:
        tab = self._tab_ledger
        bar = tk.Frame(tab, bg=BG)
        bar.pack(fill="x", padx=12, pady=(12, 6))
        self._button(bar, "Refresh", self.refresh_ledger).pack(side="left", padx=4)
        self._button(bar, "Verify hash-chain integrity", self.on_verify_ledger,
                     accent=True).pack(side="left", padx=4)
        self.ledger_state = tk.Label(bar, text="", bg=BG, fg=MUTED, font=("Consolas", 9))
        self.ledger_state.pack(side="right", padx=8)

        cols = ("seq", "ts", "actor", "action", "detail", "hash")
        self.ledger_tree = ttk.Treeview(tab, columns=cols, show="headings")
        for c, w, t in (("seq", 50, "#"), ("ts", 170, "Timestamp (UTC)"),
                        ("actor", 90, "Actor"), ("action", 140, "Action"),
                        ("detail", 560, "Detail"), ("hash", 150, "Hash (short)")):
            self.ledger_tree.heading(c, text=t)
            self.ledger_tree.column(c, width=w, stretch=(c == "detail"))
        self.ledger_tree.pack(fill="both", expand=True, padx=12, pady=(4, 12))

    def _build_settings(self) -> None:
        tab = self._tab_settings
        ttk.Label(tab, text="Workspace & security posture", style="H1.TLabel").pack(
            anchor="w", padx=14, pady=(14, 6))

        f = tk.Frame(tab, bg=PANEL)
        f.pack(fill="x", padx=14, pady=6)
        tk.Label(f, text="Workspace root (vault, reports, ledger, DB):", bg=PANEL, fg=MUTED,
                 font=("Segoe UI", 9)).grid(row=0, column=0, sticky="w", padx=12, pady=(12, 4))
        self.ws_entry = tk.Entry(f, bg=ROW, fg=FG, insertbackground=FG, relief="flat",
                                 font=("Consolas", 10))
        self.ws_entry.grid(row=1, column=0, sticky="we", padx=12, pady=(0, 12))
        self.ws_entry.insert(0, self.root_path)
        f.columnconfigure(0, weight=1)
        btns = tk.Frame(f, bg=PANEL)
        btns.grid(row=1, column=1, sticky="e", padx=12, pady=(0, 12))
        self._button(btns, "Apply workspace", self.on_apply_workspace, accent=True).pack(side="left", padx=4)
        self._button(btns, "Open folder", self.on_open_workspace).pack(side="left", padx=4)

        posture = (
            "Security controls implemented in this build (see security.md for the full mapping):\n"
            "  - Non-executing pipeline: samples are parsed as inert bytes (no loadlibrary / spawn / subprocess).\n"
            "  - SHA-256 hash-first intake with dedupe and quarantined vault copies (read-only access).\n"
            "  - Tamper-evident hash-chained audit ledger (ISO A.8.15 / A.8.2), verification built in.\n"
            "  - No network egress: the workbench makes zero outbound connections (offline analysis).\n"
            "  - Report schema pinned (sba.pattern.v1) + environment fingerprint for reproducibility.\n"
            "  - No plaintext secrets stored; workspace path + last evidence path only (config in LOCALAPPDATA).\n"
            "  - Memory-safety posture: file size cap for analysis (128 MiB), no dynamic code eval.\n"
            "  - All controls map to OWASP Top 10 / ISO 27001 / NIST CSF per security.md.\n\n"
            f"App version : {__version__}\n"
            f"Config file : {config_path()}\n"
            "Ledger format: JSONL, prev-hash chained, SHA-256 over canonical payload"
        )
        box = tk.Text(tab, bg=PANEL, fg=FG, relief="flat", wrap="word",
                      font=("Consolas", 10), padx=14, pady=12, insertbackground=FG)
        box.insert("1.0", posture)
        box.configure(state="disabled")
        box.pack(fill="both", expand=True, padx=14, pady=(6, 14))

    # ------------------------------------------------------------- workspace
    def _init_workspace(self, root_path: str) -> None:
        try:
            self.workspace = Workspace(root_path)
            self.ledger = Ledger(self.workspace.ledger_path)
            self.root_path = root_path
            self.status_var.set(f"workspace: {root_path}")
            self.refresh_dashboard()
            self.refresh_reports()
            self.refresh_ledger()
        except Exception as e:
            messagebox.showerror("Workspace error", f"Could not open workspace:\n{e}")
            self.status_var.set("workspace error")

    def on_apply_workspace(self) -> None:
        path = self.ws_entry.get().strip()
        if not path:
            return
        self.cfg["workspace"] = path
        save_cfg(self.cfg)
        self._init_workspace(path)

    def on_open_workspace(self) -> None:
        if self.workspace and os.path.isdir(self.workspace.root):
            os.startfile(self.workspace.root)

    # ------------------------------------------------------------- dashboard
    def refresh_dashboard(self) -> None:
        if not self.workspace:
            return
        try:
            st = self.workspace.stats()
        except Exception:
            return
        for k, v in self.stat_vars.items():
            v.set(str(st.get(k, 0)))

    # ----------------------------------------------------------------- queue
    def _poll_queue(self) -> None:
        try:
            while True:
                kind, payload = self._ui_queue.get_nowait()
                if kind == "status":
                    self.status_var.set(str(payload))
                elif kind == "dash":
                    self.refresh_dashboard()
                elif kind == "results":
                    self._insert_result(payload)
                elif kind == "reports":
                    self.refresh_reports()
                elif kind == "ledger":
                    self.refresh_ledger()
                elif kind == "error":
                    messagebox.showerror("Analysis error", str(payload))
        except queue.Empty:
            pass
        self.after(200, self._poll_queue)

    def _insert_result(self, r: dict) -> None:
        self.result_tree.insert("", 0, values=(
            r["pattern"], f"{r['confidence']:.2f}",
            "HIGH" if r["risk_flag"] else "low", f"{r['entropy']:.3f}",
            r["summary"], r["sha"][:16]))

    # ---------------------------------------------------------------- intake
    def on_add_files(self) -> None:
        paths = filedialog.askopenfilenames(title="Select files for quarantine analysis")
        if paths:
            self._quarantine(list(paths))

    def on_add_folder(self) -> None:
        folder = filedialog.askdirectory(title="Select folder of evidence files")
        if not folder:
            return
        paths = []
        for name in sorted(os.listdir(folder)):
            p = os.path.join(folder, name)
            if os.path.isfile(p):
                paths.append(p)
        if not paths:
            messagebox.showinfo("Add folder", "No files found in that folder.")
            return
        self._quarantine(paths)

    def _quarantine(self, paths: list[str]) -> None:
        if not self.workspace:
            return
        added = skipped = failed = 0
        for p in paths:
            try:
                if os.path.getsize(p) > BIG_FILE_LIMIT and \
                        not messagebox.askyesno("Large file",
                                                f"{os.path.basename(p)} is over 128 MiB.\n"
                                                "Analyze anyway? (memory pressure risk)"):
                    skipped += 1
                    continue
                sample, new = ingest(p, self.workspace.vault)
                sid, _ = self.workspace.upsert_sample(sample)
                self.pending.append({"sample": sample, "path": p, "id": sid})
                iid = f"row{len(self.pending) - 1}"
                self.pending_tree.insert("", "end", iid=iid, values=(
                    sample.original_name, sample.sha256, human_size(sample.size), sample.magic_hint))
                if new:
                    self.ledger.append(ACTOR, "sample.intake",
                                       f"{sample.original_name} | sha={sample.sha256[:16]}...", now_iso())
                    added += 1
                else:
                    self.ledger.append(ACTOR, "sample.dedup",
                                       f"{sample.original_name} | already in vault (sha={sample.sha256[:16]}...)",
                                       now_iso())
                    skipped += 1
            except Exception as e:
                failed += 1
                print(f"[intake-fail] {p}: {e}")
        self.status_var.set(f"intake: {added} added, {skipped} skipped, {failed} failed")
        self._queue(("ledger", None))
        self._queue(("dash", None))

    def on_clear_queue(self) -> None:
        for iid in self.pending_tree.get_children():
            self.pending_tree.delete(iid)
        self.pending.clear()
        self.status_var.set("queue cleared")

    def on_choose_evidence(self) -> None:
        p = filedialog.askopenfilename(title="Select evidence original (known-plaintext twin)")
        if p:
            self.evidence_path = p
            self.evidence_var.set(p)
            self.cfg["evidence"] = p
            save_cfg(self.cfg)

    def on_clear_evidence(self) -> None:
        self.evidence_path = None
        self.evidence_var.set("(none)")
        self.cfg.pop("evidence", None)
        save_cfg(self.cfg)

    # ------------------------------------------------------------ analysis
    def on_scout(self) -> None:
        if not self.workspace:
            return
        selected = self.pending_tree.selection()
        rows = selected if selected else self.pending_tree.get_children()
        if not rows:
            messagebox.showinfo("Scout", "Add files to the queue first.")
            return
        lines = []
        for iid in rows:
            idx = int(iid.replace("row", "")) if iid.startswith("row") else None
            if idx is None:
                continue
            sample = self.pending[idx]["sample"]
            data = read_quarantined(sample)
            st = static_analyze(data, sample.original_name)
            lines.append(f"{sample.original_name}\n  sha256   {sample.sha256}\n"
                         f"  entropy  {st.entropy:.4f} | high-entropy blocks "
                         f"{st.block_high_entropy_ratio:.4f}\n"
                         f"  pe       {st.pe_info.get('is_pe')}\n"
                         f"  crypto   {', '.join(st.crypto_imports) or '-'}\n"
                         f"  indicators {', '.join(st.ransom_indicators) or '-'}\n")
        win = tk.Toplevel(self)
        win.title("Static scout pass")
        win.configure(bg=BG)
        win.geometry("760x520")
        t = tk.Text(win, bg=PANEL, fg=FG, relief="flat", font=("Consolas", 10),
                    padx=14, pady=12, insertbackground=FG)
        t.insert("1.0", "\n".join(lines))
        t.configure(state="disabled")
        t.pack(fill="both", expand=True, padx=12, pady=12)
        self.ledger.append(ACTOR, "static.scout",
                           f"{len(rows)} sample(s) static-scouted", now_iso())
        self._queue(("ledger", None))

    def on_analyze(self) -> None:
        if not self.workspace:
            return
        selected = self.pending_tree.selection()
        rows = list(selected) if selected else list(self.pending_tree.get_children())
        if not rows:
            messagebox.showinfo("Analyze", "Add files to the queue first.")
            return
        jobs = []
        for iid in rows:
            if iid.startswith("row"):
                idx = int(iid.replace("row", ""))
                jobs.append(self.pending[idx])
        if not jobs:
            messagebox.showinfo("Analyze", "No valid queue rows selected.")
            return
        threading.Thread(target=self._run_jobs, args=(jobs, self.evidence_path),
                         daemon=True).start()

    def _run_jobs(self, jobs: list[dict], evidence: Optional[str]) -> None:
        total = len(jobs)
        for i, job in enumerate(jobs, 1):
            sample: Sample = job["sample"]
            try:
                self._queue(("status", f"analyzing {i}/{total}: {sample.original_name}"))
                st = static_analyze(read_quarantined(sample), sample.original_name)
                fp = build_fingerprint(sample, st, evidence)
                md_path, js_path, _ = save_report(self.workspace.reports, sample, st, fp)
                self.workspace.add_analysis(
                    job["id"], st.entropy, st.block_high_entropy_ratio,
                    fp["pattern"]["class"], fp["risk_flag"], fp["confidence_overall"],
                    json.dumps(fp, ensure_ascii=True), md_path, js_path)
                self.ledger.append(ACTOR, "analysis.run",
                                   f"sha={sample.sha256[:16]}... pattern={fp['pattern']['class']} "
                                   f"conf={fp['confidence_overall']}", now_iso())
                self.ledger.append(ACTOR, "report.issue",
                                   f"report={os.path.basename(md_path)}", now_iso())
                self._queue(("results", {
                    "pattern": fp["pattern"]["class"],
                    "confidence": fp["confidence_overall"],
                    "risk_flag": fp["risk_flag"],
                    "entropy": st.entropy,
                    "summary": fp["summary"],
                    "sha": sample.sha256,
                }))
            except Exception as e:  # noqa: BLE001
                self._queue(("error", f"{sample.original_name}: {e}"))
        self._queue(("status", f"analysis complete ({total} sample(s))"))
        self._queue(("dash", None))
        self._queue(("reports", None))
        self._queue(("ledger", None))

    def _queue(self, item) -> None:
        self._ui_queue.put(item)

    def on_open_last_report(self, _event=None) -> None:
        if self.workspace:
            md, _ = self.workspace.list_reports()
            if md:
                self.nb.select(self._tab_reports)
                self.refresh_reports()

    # --------------------------------------------------------------- reports
    def refresh_reports(self) -> None:
        if not self.workspace:
            return
        md, _ = self.workspace.list_reports()
        self.report_list.delete(0, "end")
        for p in md:
            self.report_list.insert("end", os.path.basename(p))
        if md:
            self.report_list.selection_set(0)
            self._show_report(md[0])

    def _show_report(self, path: str) -> None:
        self.report_view.configure(state="normal")
        self.report_view.delete("1.0", "end")
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                self.report_view.insert("1.0", f.read())
        except OSError as e:
            self.report_view.insert("1.0", f"could not read report: {e}")
        self.report_view.configure(state="disabled")

    def _selected_report_path(self) -> Optional[str]:
        sel = self.report_list.curselection()
        if not sel or not self.workspace:
            return None
        name = self.report_list.get(sel[0])
        return os.path.join(self.workspace.reports, name)

    def on_open_report(self) -> None:
        p = self._selected_report_path()
        if p:
            os.startfile(p)

    def on_export_report(self) -> None:
        p = self._selected_report_path()
        if not p:
            messagebox.showinfo("Export", "Select a report first.")
            return
        dest = filedialog.asksaveasfilename(title="Export report copy",
                                            defaultextension=".md",
                                            initialfile=os.path.basename(p))
        if dest:
            shutil.copy2(p, dest)
            self.ledger.append(ACTOR, "report.export",
                               f"{os.path.basename(p)} -> {dest}", now_iso())
            self._queue(("ledger", None))
            messagebox.showinfo("Export", "Report copy saved.")

    # ---------------------------------------------------------------- ledger
    def refresh_ledger(self) -> None:
        if not self.ledger:
            return
        for iid in self.ledger_tree.get_children():
            self.ledger_tree.delete(iid)
        for e in reversed(list(self.ledger.entries())):
            self.ledger_tree.insert("", "end", values=(
                e.seq, e.ts, e.actor, e.action, e.detail, (e.hash or "")[:16]))
        self.ledger_state.config(text=f"{self.ledger.count()} entries")

    def on_verify_ledger(self) -> None:
        if not self.ledger:
            return
        ok, bad = self.ledger.verify()
        if ok:
            self.ledger_state.config(text=f"chain OK ({self.ledger.count()} entries)")
            self.ledger_state.config(fg=OK)
            messagebox.showinfo(
                "Ledger verification", "Hash chain verified: no tampering detected.")
        else:
            self.ledger_state.config(text=f"CHAIN BROKEN at entry {bad}", fg=BAD)
            messagebox.showwarning("Ledger verification",
                                   f"Hash chain broken at entry #{bad} - possible tampering.")


def run() -> None:
    app = RansomLensApp()
    app.mainloop()