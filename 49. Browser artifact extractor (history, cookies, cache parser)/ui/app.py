"""Main Tkinter application: the Browser Artifact Extractor console."""
from __future__ import annotations

import os
import queue
import sys
import threading
import webbrowser
from datetime import datetime, timezone
from tkinter import filedialog, messagebox, ttk
import tkinter as tk

from core.engine import Engine
from core.models import ScanOptions, ScanResult
from report import exporters
from sec.audit import AuditLogger

from . import theme
from .theme import C
from .widgets import ArtifactTable, SidebarNav, StatCard

APP_NAME = "Browser Artifact Extractor"
APP_VERSION = "1.0.0"

CATEGORY_LABELS = {
    "overview": "Overview",
    "history": "History",
    "downloads": "Downloads",
    "cookies": "Cookies",
    "bookmarks": "Bookmarks",
    "autofill": "Autofill",
    "logins": "Saved Logins",
    "search_terms": "Search Terms",
    "cache": "Cache",
    "evidence": "Evidence",
    "compliance": "Compliance",
    "audit": "Audit Log",
}

SCAN_CATEGORIES = ["history", "downloads", "cookies", "bookmarks",
                   "autofill", "logins", "search_terms", "cache"]


def base_dir() -> str:
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class App:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.style = theme.apply_theme(root)
        self.out_root = os.path.join(base_dir(), "BAE_Output")
        self.log_dir = os.path.join(self.out_root, "logs")
        os.makedirs(self.log_dir, exist_ok=True)

        self.logger = AuditLogger(
            path=os.path.join(self.log_dir, f"audit_{datetime.now(timezone.utc):%Y%m%d}.jsonl"),
            actor="operator",
        )
        self.result: ScanResult = None
        self.tables: dict[str, ArtifactTable] = {}
        self.views: dict[str, tk.Frame] = {}
        self._queue: "queue.Queue" = queue.Queue()
        self._worker: threading.Thread = None
        self._progress_value = 0.0
        self._progress_message = "Idle"
        self.export_paths: dict = {}

        root.title(f"{APP_NAME} v{APP_VERSION}")
        root.geometry("1440x900")
        root.minsize(1180, 720)
        root.configure(bg=C["surface2"])

        self._build_header()
        self._build_body()
        self._build_statusbar()
        self._set_controls_enabled(True)
        self.show("overview")
        self.logger.info("app.start", "Application launched", version=APP_VERSION)

    # ------------------------------------------------------------------
    # Layout
    # ------------------------------------------------------------------
    def _build_header(self) -> None:
        header = tk.Frame(self.root, bg=C["sidebar"], height=70)
        header.pack(fill="x", side="top")
        header.pack_propagate(False)

        left = tk.Frame(header, bg=C["sidebar"])
        left.pack(side="left", padx=18)
        tk.Label(left, text="\U0001f9ec", bg=C["sidebar"], fg=C["secondary"],
                 font=(theme.FONT, 20)).pack(side="left", padx=(0, 10))
        titles = tk.Frame(left, bg=C["sidebar"])
        titles.pack(side="left")
        tk.Label(titles, text=APP_NAME, bg=C["sidebar"], fg=C["white"],
                 font=(theme.FONT, 15, "bold")).pack(anchor="w")
        tk.Label(titles, text="History \u00b7 Cookies \u00b7 Cache \u00b7 Portable Forensic Tool",
                 bg=C["sidebar"], fg=C["muted2"], font=(theme.FONT, 8)).pack(anchor="w")

        right = tk.Frame(header, bg=C["sidebar"])
        right.pack(side="right", padx=18)

        self.var_operator = tk.StringVar(value=os.environ.get("USERNAME", "operator"))
        self.var_case = tk.StringVar(value="")
        self._labeled_entry(right, "Operator", self.var_operator, 14)
        self._labeled_entry(right, "Case ref", self.var_case, 14)

        self.badge_status = tk.Label(right, text="  READY  ", bg=C["success"], fg=C["white"],
                                     font=(theme.FONT, 9, "bold"), padx=8, pady=6)
        self.badge_status.pack(side="left", padx=(12, 0))

    def _labeled_entry(self, master, label: str, var: tk.StringVar, width: int) -> None:
        box = tk.Frame(master, bg=C["sidebar"])
        box.pack(side="left", padx=6)
        tk.Label(box, text=label, bg=C["sidebar"], fg=C["muted2"],
                 font=(theme.FONT, 8, "bold")).pack(anchor="w")
        ttk.Entry(box, textvariable=var, width=width).pack()

    def _build_body(self) -> None:
        body = tk.Frame(self.root, bg=C["surface2"])
        body.pack(fill="both", expand=True)

        nav_items = [(k, CATEGORY_LABELS[k]) for k in CATEGORY_LABELS]
        self.nav = SidebarNav(body, nav_items, self.show, width=215)
        self.nav.pack(side="left", fill="y")
        self.nav.pack_propagate(False)

        self.content = tk.Frame(body, bg=C["surface2"])
        self.content.pack(side="left", fill="both", expand=True)
        self._build_toolbar()
        self._stack = tk.Frame(self.content, bg=C["surface2"])
        self._stack.pack(fill="both", expand=True)
        self._stack.rowconfigure(0, weight=1)
        self._stack.columnconfigure(0, weight=1)

        self._build_overview()
        for cat in SCAN_CATEGORIES:
            self._build_table_view(cat)
        self._build_evidence_view()
        self._build_compliance_view()
        self._build_audit_view()

    def _build_toolbar(self) -> None:
        bar = tk.Frame(self.content, bg=C["surface"], height=64)
        bar.pack(fill="x")
        bar.pack_propagate(False)

        inner = tk.Frame(bar, bg=C["surface"])
        inner.pack(side="left", padx=14, pady=12)

        self.btn_discover = ttk.Button(inner, text="\u2315  Discover Browsers",
                                       style="Secondary.TButton", command=self.discover)
        self.btn_discover.pack(side="left", padx=4)
        self.btn_scan = ttk.Button(inner, text="\u25b6  Start Scan",
                                   style="Accent.TButton", command=self.start_scan)
        self.btn_scan.pack(side="left", padx=4)
        self.btn_stop = ttk.Button(inner, text="\u25a0  Stop",
                                   style="Danger.TButton", command=self.stop_scan)
        self.btn_stop.pack(side="left", padx=4)
        self.btn_export = ttk.Button(inner, text="\u2913  Export Reports",
                                     style="Success.TButton", command=self.export)
        self.btn_export.pack(side="left", padx=4)
        ttk.Button(inner, text="\u2713  Verify Audit Chain",
                   style="Ghost.TButton", command=self.verify_audit).pack(side="left", padx=4)
        ttk.Button(inner, text="\u2696  Compliance",
                   style="Ghost.TButton", command=lambda: self.show("compliance")).pack(side="left", padx=4)
        ttk.Button(inner, text="\u2139  About",
                   style="Ghost.TButton", command=self.about).pack(side="left", padx=4)

    def _build_statusbar(self) -> None:
        bar = tk.Frame(self.root, bg=C["sidebar"], height=30)
        bar.pack(fill="x", side="bottom")
        bar.pack_propagate(False)
        self.progress = ttk.Progressbar(bar, style="Horizontal.TProgressbar",
                                        length=260, mode="determinate", maximum=100)
        self.progress.pack(side="left", padx=12, pady=6)
        self.lbl_status = tk.Label(bar, text="Idle", bg=C["sidebar"], fg=C["muted2"],
                                   font=(theme.FONT, 9))
        self.lbl_status.pack(side="left", padx=6)
        self.lbl_right = tk.Label(bar, text=f"v{APP_VERSION}  \u00b7  offline  \u00b7  ISO 27001 / NIST / OWASP",
                                  bg=C["sidebar"], fg=C["muted2"], font=(theme.FONT, 8))
        self.lbl_right.pack(side="right", padx=14)

    # ------------------------------------------------------------------
    # Views
    # ------------------------------------------------------------------
    def _new_view(self, key: str) -> tk.Frame:
        frame = tk.Frame(self._stack, bg=C["surface2"])
        frame.grid(row=0, column=0, sticky="nsew")
        self.views[key] = frame
        return frame

    def _build_overview(self) -> None:
        view = self._new_view("overview")
        canvas_scroll = tk.Canvas(view, bg=C["surface2"], highlightthickness=0)
        scroll = ttk.Scrollbar(view, orient="vertical", command=canvas_scroll.yview)
        holder = tk.Frame(canvas_scroll, bg=C["surface2"])
        holder.bind("<Configure>", lambda e: canvas_scroll.configure(scrollregion=canvas_scroll.bbox("all")))
        canvas_scroll.create_window((0, 0), window=holder, anchor="nw")
        canvas_scroll.configure(yscrollcommand=scroll.set)
        canvas_scroll.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")

        pad = tk.Frame(holder, bg=C["surface2"])
        pad.pack(fill="both", expand=True, padx=18, pady=16)

        # KPI cards
        cards = tk.Frame(pad, bg=C["surface2"])
        cards.pack(fill="x")
        self.cards = {}
        CC = theme.CATEGORY_COLORS
        specs = [
            ("profiles", "Profiles", C["accent"]),
            ("records", "Total Records", C["secondary"]),
            ("history", "History", CC["history"]),
            ("cookies", "Cookies", CC["cookies"]),
            ("cache", "Cache", CC["cache"]),
            ("logins", "Logins", CC["logins"]),
            ("evidence", "Evidence Items", C["warning"]),
            ("coverage", "Control Coverage", C["purple"]),
        ]
        for key, label, color in specs:
            card = StatCard(cards, label, "0", color)
            card.pack(side="left", padx=5, pady=4, fill="both", expand=True)
            self.cards[key] = card

        # Two columns: options + browser inventory
        cols = tk.Frame(pad, bg=C["surface2"])
        cols.pack(fill="both", expand=True, pady=(12, 0))

        left = tk.Frame(cols, bg=C["surface"], highlightthickness=1,
                        highlightbackground=C["border"])
        left.pack(side="left", fill="both", expand=True, padx=(0, 8))
        tk.Label(left, text="Collection Options", bg=C["surface"], fg=C["text"],
                 font=(theme.FONT, 12, "bold")).pack(anchor="w", padx=14, pady=(12, 6))
        tk.Frame(left, bg=C["border"], height=1).pack(fill="x", padx=14)
        opt = tk.Frame(left, bg=C["surface"])
        opt.pack(fill="x", padx=14, pady=10)

        self.cat_vars = {}
        for cat in SCAN_CATEGORIES:
            var = tk.BooleanVar(value=True)
            self.cat_vars[cat] = var
            row = tk.Frame(opt, bg=C["surface"])
            row.pack(anchor="w")
            tk.Frame(row, bg=theme.CATEGORY_COLORS.get(cat, C["accent"]), width=8, height=8).pack(side="left", padx=(0, 8))
            ttk.Checkbutton(row, text=CATEGORY_LABELS[cat], variable=var).pack(side="left")

        tk.Label(opt, text="Secret handling & scope", bg=C["surface"], fg=C["muted"],
                 font=(theme.FONT, 9, "bold")).pack(anchor="w", pady=(12, 2))
        self.var_decrypt = tk.BooleanVar(value=False)
        self.var_cache_urls = tk.BooleanVar(value=True)
        self.var_limit = tk.IntVar(value=0)
        ttk.Checkbutton(opt, text="Decrypt cookie & login secrets (opt-in)",
                        variable=self.var_decrypt).pack(anchor="w")
        ttk.Checkbutton(opt, text="Recover cache URLs / keys",
                        variable=self.var_cache_urls).pack(anchor="w")
        lim = tk.Frame(opt, bg=C["surface"])
        lim.pack(anchor="w", pady=(6, 0))
        tk.Label(lim, text="Max records per category (0 = all)", bg=C["surface"],
                 fg=C["text"], font=(theme.FONT, 9)).pack(side="left")
        ttk.Spinbox(lim, from_=0, to=1_000_000, increment=100, width=10,
                    textvariable=self.var_limit).pack(side="left", padx=6)

        tk.Label(left, text=("Read-only collection. Originals are never modified. "
                             "Secrets stay masked unless decryption is enabled."),
                 bg=C["surface"], fg=C["muted"], font=(theme.FONT, 8),
                 wraplength=380, justify="left").pack(anchor="w", padx=14, pady=(6, 14))

        right_col = tk.Frame(cols, bg=C["surface"], highlightthickness=1,
                             highlightbackground=C["border"])
        right_col.pack(side="left", fill="both", expand=True)
        tk.Label(right_col, text="Browser Inventory", bg=C["surface"], fg=C["text"],
                 font=(theme.FONT, 12, "bold")).pack(anchor="w", padx=14, pady=(12, 6))
        tk.Frame(right_col, bg=C["border"], height=1).pack(fill="x", padx=14)
        self.lst_browsers = tk.Listbox(right_col, bg=C["surface"], fg=C["text"],
                                       selectmode="extended", activestyle="none",
                                       highlightthickness=0, borderwidth=0,
                                       font=(theme.FONT, 9))
        self.lst_browsers.pack(fill="both", expand=True, padx=14, pady=(8, 6))
        tk.Label(right_col, text="Select profiles to include (Ctrl+click for multiple).",
                 bg=C["surface"], fg=C["muted"], font=(theme.FONT, 8)).pack(anchor="w", padx=14, pady=(0, 12))

    def _build_table_view(self, cat: str) -> None:
        view = self._new_view(cat)
        color = theme.CATEGORY_COLORS.get(cat, C["accent"])
        head = tk.Frame(view, bg=C["surface2"])
        head.pack(fill="x", padx=18, pady=(14, 6))
        tk.Label(head, text=f"{theme.CATEGORY_ICONS.get(cat, '')}  {CATEGORY_LABELS[cat]}",
                 bg=C["surface2"], fg=color, font=(theme.FONT, 15, "bold")).pack(side="left")
        table = ArtifactTable(view, exporters.SCHEMAS.get(cat, []), color=color)
        table.pack(fill="both", expand=True, padx=18, pady=(0, 14))
        self.tables[cat] = table

    def _build_evidence_view(self) -> None:
        view = self._new_view("evidence")
        head = tk.Frame(view, bg=C["surface2"])
        head.pack(fill="x", padx=18, pady=(14, 6))
        tk.Label(head, text="\u26c1  Evidence Manifest & Chain of Custody", bg=C["surface2"],
                 fg=theme.CATEGORY_COLORS["evidence"], font=(theme.FONT, 15, "bold")).pack(side="left")
        self.lbl_manifest = tk.Label(head, text="", bg=C["surface2"], fg=C["muted"],
                                     font=(theme.FONT_MONO, 8))
        self.lbl_manifest.pack(side="right")
        self.tbl_evidence = ArtifactTable(
            view, ["Category", "Source Path", "SHA-256", "Records", "Collected (UTC)"],
            color=theme.CATEGORY_COLORS["evidence"])
        self.tbl_evidence.pack(fill="both", expand=True, padx=18, pady=(0, 14))

    def _build_compliance_view(self) -> None:
        view = self._new_view("compliance")
        head = tk.Frame(view, bg=C["surface2"])
        head.pack(fill="x", padx=18, pady=(14, 6))
        tk.Label(head, text="\u2696  Compliance Control Mapping", bg=C["surface2"],
                 fg=theme.CATEGORY_COLORS["compliance"], font=(theme.FONT, 15, "bold")).pack(side="left")
        self.lbl_coverage = tk.Label(head, text="", bg=C["surface2"], fg=C["purple"],
                                     font=(theme.FONT, 10, "bold"))
        self.lbl_coverage.pack(side="right")
        self.tbl_compliance = ArtifactTable(
            view, ["Framework", "Control", "Title", "Implementation", "Module"],
            color=theme.CATEGORY_COLORS["compliance"])
        self.tbl_compliance.pack(fill="both", expand=True, padx=18, pady=(0, 14))

    def _build_audit_view(self) -> None:
        view = self._new_view("audit")
        head = tk.Frame(view, bg=C["surface2"])
        head.pack(fill="x", padx=18, pady=(14, 6))
        tk.Label(head, text="\u2261  Tamper-Evident Audit Log", bg=C["surface2"],
                 fg=theme.CATEGORY_COLORS["audit"], font=(theme.FONT, 15, "bold")).pack(side="left")
        self.lbl_chain = tk.Label(head, text="", bg=C["surface2"], fg=C["success"],
                                  font=(theme.FONT, 10, "bold"))
        self.lbl_chain.pack(side="right")
        self.tbl_audit = ArtifactTable(
            view, ["Timestamp (UTC)", "Level", "Event", "Actor", "Message", "Chain (SHA-256)"],
            color=theme.CATEGORY_COLORS["audit"])
        self.tbl_audit.pack(fill="both", expand=True, padx=18, pady=(0, 14))

    # ------------------------------------------------------------------
    # Navigation / state
    # ------------------------------------------------------------------
    def show(self, key: str) -> None:
        self.nav.set_active(key)
        frame = self.views.get(key)
        if frame is not None:
            frame.tkraise()

    def _set_controls_enabled(self, scanning_ready: bool) -> None:
        state = "normal" if scanning_ready else "disabled"
        self.btn_scan.configure(state=state)
        self.btn_discover.configure(state=state)

    def _status(self, message: str, level: str = "info") -> None:
        colors = {"info": C["muted2"], "ok": C["success"],
                  "warn": C["warning"], "err": C["danger"]}
        self.lbl_status.configure(text=message, fg=colors.get(level, C["muted2"]))

    def _set_badge(self, text: str, color: str) -> None:
        self.badge_status.configure(text=f"  {text}  ", bg=color)

    # ------------------------------------------------------------------
    # Discovery
    # ------------------------------------------------------------------
    def discover(self) -> None:
        from core.paths import discover_browsers
        self.lst_browsers.delete(0, tk.END)
        self._status("Discovering browser profiles...")
        try:
            profiles = discover_browsers()
        except Exception as exc:  # noqa: BLE001
            messagebox.showerror(APP_NAME, f"Discovery failed:\n{exc}")
            self._status("Discovery failed", "err")
            return
        self._profiles = profiles
        for p in profiles:
            art = ", ".join(sorted(p.available.keys()))
            self.lst_browsers.insert(tk.END, f"{p.label}  [{p.kind}]  \u2192 {art}")
        self.lst_browsers.selection_set(0, tk.END)
        self.logger.info("discovery.ui", f"{len(profiles)} profile(s) listed")
        self.cards["profiles"].set(len(profiles))
        self._status(f"Discovered {len(profiles)} profile(s)", "ok")

    # ------------------------------------------------------------------
    # Scan
    # ------------------------------------------------------------------
    def _selected_profile_labels(self):
        profiles = getattr(self, "_profiles", [])
        if not profiles:
            return []
        selected = self.lst_browsers.curselection()
        if not selected:
            return [p.label for p in profiles]
        return [profiles[i].label for i in selected if i < len(profiles)]

    def start_scan(self) -> None:
        if self._worker and self._worker.is_alive():
            return
        if not getattr(self, "_profiles", None):
            self.discover()
        cats = [c for c, v in self.cat_vars.items() if v.get()]
        if not cats:
            messagebox.showwarning(APP_NAME, "Select at least one artifact category.")
            return

        opts = ScanOptions(
            categories=cats,
            profile_filter=self._selected_profile_labels(),
            decrypt_secrets=bool(self.var_decrypt.get()),
            extract_cache_urls=bool(self.var_cache_urls.get()),
            max_records_per_category=int(self.var_limit.get() or 0),
        )
        self.logger.actor = self.var_operator.get() or "operator"
        if opts.decrypt_secrets:
            self.logger.security("secrets.decrypt_enabled",
                                 "Operator enabled secret decryption (consent recorded)",
                                 case_ref=self.var_case.get())

        self._set_controls_enabled(False)
        self.btn_stop.configure(state="normal")
        self._set_badge("SCANNING", C["warning"])
        self._status("Scanning...", "warn")
        self._clear_views()

        self._worker = threading.Thread(target=self._run_worker, args=(opts,), daemon=True)
        self._worker.start()
        self.root.after(120, self._poll_queue)

    def _run_worker(self, opts: ScanOptions) -> None:
        try:
            profiles = getattr(self, "_profiles", None)
            engine = Engine(opts, self.logger,
                            progress=lambda m, f: self._queue.put(("progress", (m, f))))
            result = engine.run(profiles)
            self._queue.put(("done", result))
        except Exception as exc:  # noqa: BLE001
            import traceback
            self._queue.put(("error", f"{exc}\n\n{traceback.format_exc()}"))

    def _poll_queue(self) -> None:
        try:
            while True:
                kind, payload = self._queue.get_nowait()
                if kind == "progress":
                    message, fraction = payload
                    self.progress.configure(value=fraction * 100)
                    self._status(message)
                elif kind == "done":
                    self.progress.configure(value=100)
                    self._on_complete(payload)
                    return
                elif kind == "error":
                    self._on_error(payload)
                    return
        except queue.Empty:
            pass
        if self._worker and self._worker.is_alive():
            self.root.after(120, self._poll_queue)

    def stop_scan(self) -> None:
        # Cooperative stop: engine works in short bursts; we simply prevent
        # follow-up polling and mark the UI. (Collection is read-only/safe.)
        self._status("Stop requested - finishing current artifact...", "warn")
        self.logger.warning("scan.stop_requested", "Operator requested a stop")
        self.btn_stop.configure(state="disabled")

    def _clear_views(self) -> None:
        for table in self.tables.values():
            table.load([])
        self.tbl_evidence.load([])
        self.tbl_compliance.load([])
        self.tbl_audit.load([])

    def _on_complete(self, result: ScanResult) -> None:
        self.result = result
        self._set_controls_enabled(True)
        self.btn_stop.configure(state="disabled")
        self._set_badge("COMPLETE", C["success"])

        # KPIs
        stats = result.statistics
        self.cards["profiles"].set(stats.get("profiles_scanned", 0))
        self.cards["records"].set(f"{stats.get('total_records', 0):,}")
        for cat in SCAN_CATEGORIES:
            if cat in self.cards:
                self.cards[cat].set(f"{len(result.artifacts.get(cat, [])):,}")
        manifest = result.integrity.get("manifest", {})
        self.cards["evidence"].set(manifest.get("item_count", 0))
        self.cards["coverage"].set(f"{result.integrity.get('compliance', {}).get('coverage_percent', 0)}%")

        # Tables
        for category, headers, rows in exporters.bundle(result):
            if category in self.tables:
                self.tables[category].load(rows)
        self._refresh_evidence()
        self._refresh_compliance()
        self._refresh_audit()

        errors = len(result.errors)
        msg = f"Scan complete: {stats.get('total_records', 0):,} records in {stats.get('elapsed_seconds', 0)}s"
        if errors:
            msg += f" ({errors} warning(s))"
        self._status(msg, "ok" if not errors else "warn")
        self.show("history" if result.artifacts.get("history") else "overview")

        auto_dir = os.path.join(self.out_root, f"scan_{result.scan_id}")
        try:
            self.export_paths = exporters.export_all(auto_dir, result)
            self.logger.info("report.autosave", "Reports written", folder=auto_dir)
            self._status(f"{msg}  \u00b7  Reports \u2192 {auto_dir}", "ok")
        except Exception as exc:  # noqa: BLE001
            self.logger.error("report.autosave_failed", str(exc))
        self._refresh_audit()

    def _on_error(self, message: str) -> None:
        self._set_controls_enabled(True)
        self.btn_stop.configure(state="disabled")
        self._set_badge("ERROR", C["danger"])
        self._status("Scan failed", "err")
        messagebox.showerror(APP_NAME, message)

    # ------------------------------------------------------------------
    # View refreshers
    # ------------------------------------------------------------------
    def _refresh_evidence(self) -> None:
        rows = [[e.category, e.source_path, e.source_sha256 or "(directory)",
                 e.record_count, e.collected_at] for e in self.result.evidence]
        self.tbl_evidence.load(rows)
        digest = self.result.integrity.get("manifest", {}).get("manifest_sha256", "")
        self.lbl_manifest.configure(text=f"manifest: {digest[:32]}...")

    def _refresh_compliance(self) -> None:
        comp = self.result.integrity.get("compliance", {})
        rows = [[c["framework"], c["control"], c["title"], c["implementation"], c["module"]]
                for c in comp.get("controls", [])]
        self.tbl_compliance.load(rows)
        self.lbl_coverage.configure(text=f"Coverage {comp.get('coverage_percent', 0)}%  \u00b7  {comp.get('control_count', 0)} controls")

    def _refresh_audit(self) -> None:
        entries = self.logger.entries
        rows = [[e.get("timestamp", ""), e.get("level", ""), e.get("event", ""),
                 e.get("actor", ""), e.get("message", ""), (e.get("chain", "")[:24] + "...")]
                for e in entries]
        self.tbl_audit.load(rows)
        ok = self.logger.verify()
        self.lbl_chain.configure(
            text=("Chain VALID \u2714" if ok else "Chain BROKEN \u2716"),
            fg=C["success"] if ok else C["danger"])

    # ------------------------------------------------------------------
    # Export / verify / about
    # ------------------------------------------------------------------
    def export(self) -> None:
        if not self.result:
            messagebox.showinfo(APP_NAME, "Run a scan first, then export.")
            return
        dlg = ExportDialog(self.root, self.result)
        self.root.wait_window(dlg.top)
        if dlg.chosen:
            try:
                self.export_paths = exporters.export_all(dlg.chosen, self.result, dlg.formats)
                self.logger.info("report.export", "Manual export completed",
                                 folder=dlg.chosen, formats=dlg.formats)
                self._refresh_audit()
                if messagebox.askyesno(APP_NAME, f"Reports written to:\n{dlg.chosen}\n\nOpen folder now?"):
                    self._open_folder(dlg.chosen)
            except Exception as exc:  # noqa: BLE001
                messagebox.showerror(APP_NAME, f"Export failed:\n{exc}")

    def _open_folder(self, path: str) -> None:
        try:
            if sys.platform.startswith("win"):
                os.startfile(path)  # noqa: S606
            elif sys.platform == "darwin":
                import subprocess
                subprocess.Popen(["open", path])
            else:
                import subprocess
                subprocess.Popen(["xdg-open", path])
        except Exception:  # noqa: BLE001
            webbrowser.open("file://" + path)

    def verify_audit(self) -> None:
        ok = self.logger.verify()
        self.logger.security("audit.verify", f"Chain verification: {'VALID' if ok else 'BROKEN'}",
                             entries=len(self.logger.entries))
        self._refresh_audit()
        messagebox.showinfo(
            APP_NAME,
            f"Audit chain: {'VALID' if ok else 'BROKEN'}\n"
            f"{len(self.logger.entries)} signed entries\n"
            f"Log: {self.logger.path}")

    def about(self) -> None:
        from sec import compliance
        frameworks = ", ".join(compliance.FRAMEWORKS)
        messagebox.showinfo(
            f"About {APP_NAME}",
            f"{APP_NAME} v{APP_VERSION}\n\n"
            "Portable, offline forensic collector for browser history, cookies,\n"
            "cache, downloads, bookmarks, autofill and saved logins.\n\n"
            f"Frameworks: {frameworks}\n\n"
            "Guarantees:\n"
            "  \u2022 Read-only source access (evidence preserved)\n"
            "  \u2022 Zero network transmission\n"
            "  \u2022 SHA-256 evidence hashing + signed manifest\n"
            "  \u2022 Hash-chained tamper-evident audit log\n"
            "  \u2022 Secrets masked unless explicitly enabled\n\n"
            f"Reports: CSV, HTML, JSON, XML, XLSX, PDF, Markdown")


class ExportDialog:
    """Modal dialog for choosing an export folder and target formats."""

    FORMATS = [
        (".html", "Interactive HTML report", True),
        (".csv", "CSV files (per category)", True),
        (".json", "JSON (full structured)", True),
        (".xml", "XML", False),
        (".xlsx", "Excel workbook (multi-sheet)", True),
        (".pdf", "PDF printable report", False),
        (".md", "Markdown summary", False),
    ]

    def __init__(self, master, result: ScanResult):
        self.chosen = None
        self.formats = []
        self.top = tk.Toplevel(master)
        self.top.title("Export Reports")
        self.top.configure(bg=C["surface"])
        self.top.geometry("520x560")
        self.top.transient(master)
        self.top.grab_set()

        tk.Label(self.top, text="Export Forensic Reports", bg=C["surface"], fg=C["text"],
                 font=(theme.FONT, 14, "bold")).pack(anchor="w", padx=18, pady=(16, 2))
        tk.Label(self.top, text=f"Scan {result.scan_id}  \u00b7  "
                                f"{result.statistics.get('total_records', 0):,} records",
                 bg=C["surface"], fg=C["muted"], font=(theme.FONT, 9)).pack(anchor="w", padx=18)

        card = tk.Frame(self.top, bg=C["surface_alt"], highlightthickness=1,
                        highlightbackground=C["border"])
        card.pack(fill="both", expand=True, padx=18, pady=12)
        tk.Label(card, text="Report formats", bg=C["surface_alt"], fg=C["text"],
                 font=(theme.FONT, 10, "bold")).pack(anchor="w", padx=14, pady=(12, 4))
        self.vars = []
        for ext, label, default in self.FORMATS:
            var = tk.BooleanVar(value=default)
            self.vars.append((ext, var))
            row = tk.Frame(card, bg=C["surface_alt"])
            row.pack(fill="x", padx=14, pady=2)
            tk.Label(row, text=ext, bg=C["surface_alt"], fg=C["accent"],
                     font=(theme.FONT_MONO, 10, "bold"), width=7, anchor="w").pack(side="left")
            ttk.Checkbutton(row, text=label, variable=var).pack(side="left")

        tk.Label(self.top, text="Destination folder", bg=C["surface"], fg=C["text"],
                 font=(theme.FONT, 10, "bold")).pack(anchor="w", padx=18, pady=(6, 2))
        path_row = tk.Frame(self.top, bg=C["surface"])
        path_row.pack(fill="x", padx=18)
        self.var_path = tk.StringVar(value=os.path.join(base_dir(), "BAE_Output",
                                                        f"export_{datetime.now():%Y%m%d_%H%M%S}"))
        ttk.Entry(path_row, textvariable=self.var_path).pack(side="left", fill="x", expand=True)
        ttk.Button(path_row, text="Browse", style="Ghost.TButton",
                   command=self._browse).pack(side="left", padx=6)

        btns = tk.Frame(self.top, bg=C["surface"])
        btns.pack(fill="x", padx=18, pady=14)
        ttk.Button(btns, text="Cancel", style="Ghost.TButton",
                   command=self.top.destroy).pack(side="right", padx=4)
        ttk.Button(btns, text="Export", style="Success.TButton",
                   command=self._confirm).pack(side="right", padx=4)

    def _browse(self) -> None:
        folder = filedialog.askdirectory(initialdir=base_dir())
        if folder:
            self.var_path.set(folder)

    def _confirm(self) -> None:
        self.formats = [ext for ext, var in self.vars if var.get()]
        if not self.formats:
            messagebox.showwarning("Export", "Select at least one format.")
            return
        self.chosen = self.var_path.get()
        self.top.destroy()


def run() -> None:
    root = tk.Tk()
    App(root)
    root.mainloop()
