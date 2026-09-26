"""GUI desktop edition of the Traffic Obfuscation Techniques Demo.

Dark-themed Tkinter application over the existing analysis engine:
  * Run analysis on the synthetic dataset (animated pipeline preview)
  * Browse Flow Verdicts, Findings and Framework Coverage
  * One-click exports to .XLSX / .CSV / .HTML / .JSON
  * Opens bundled architecture dashboard (index.html)

Run for development :  python src/gui.py
Run self-test        :  python src/gui.py --selftest
"""

from __future__ import annotations

import os
import sys
import webbrowser
from datetime import datetime, timezone
from pathlib import Path
from tkinter import ttk, filedialog, messagebox

import tkinter as tk

# ---------------------------------------------------------------------------
# palette
# ---------------------------------------------------------------------------
BG = "#0b0e1f"
PANEL = "#131a33"
PANE = "#182045"
LINE = "#273055"
ACCENT = "#8b5cf6"
ACCENT2 = "#a78bfa"
CYAN = "#22d3ee"
TEAL = "#2dd4bf"
ROSE = "#fb7185"
GOLD = "#fbbf24"
LIME = "#a3e635"
GREEN = "#059669"
ORANGE = "#e17055"
RED = "#ef4444"
INK = "#eef1ff"
MUTED = "#8491bd"
FONT = "Segoe UI"

SEV_COLORS = {
    "critical": "#ef4444", "high": "#e17055", "medium": "#f59e0b",
    "low": "#38bdf8", "info": "#64748b",
}
VERDICT_COLORS = {"fronted": "#ef4444", "suspicious": "#e17055", "benign": "#059669"}


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _bundle_path() -> Path:
    """Read-only resources (bundled index.html, icon) - _MEIPASS when frozen."""
    if getattr(sys, "frozen", False):
        return Path(sys._MEIPASS)
    return Path(__file__).resolve().parent.parent


def _runtime_dir() -> Path:
    """Writable base next to the portable exe; project root in dev."""
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent.parent


def _report_dir(base: Path) -> Path:
    """Reports land next to the portable exe, or under output/ in dev."""
    if getattr(sys, "frozen", False):
        base = base / "Reports"
    target = base / f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    target.mkdir(parents=True, exist_ok=True)
    return target


# ---------------------------------------------------------------------------
# analysis + export logic (window-free so selftest can run headless)
# ---------------------------------------------------------------------------
def run_analysis():
    from src.detection.engine import evaluate_all
    from src.generator import build_dataset
    from src.reporting.bundle import ReportBundle
    from src.frameworks import build_catalog, summary_stats

    records = build_dataset()
    verdicts = list(evaluate_all(records).values())
    findings = [f for v in verdicts for f in v.findings]
    bundle = ReportBundle.build(records, verdicts, findings, _now())
    bundle.meta["catalog"] = [
        {"fw": c.framework.value, "ref": c.ref, "title": c.title,
         "category": c.category, "status": c.status}
        for c in build_catalog()
    ]
    return bundle


def export_all(bundle, out_dir: Path) -> dict:
    from src.reporting import export_csv, export_html, export_json, export_xlsx

    produced = {}
    produced["xlsx"] = export_xlsx(bundle, out_dir / "traffic_obfuscation_report.xlsx")
    produced["csv"] = export_csv(bundle, out_dir)
    produced["html"] = export_html(bundle, out_dir / "traffic_obfuscation_report.html")
    produced["json"] = export_json(bundle, out_dir / "traffic_obfuscation_report.json")
    return produced


# ---------------------------------------------------------------------------
# widgets helpers
# ---------------------------------------------------------------------------
def _chip(parent, text: str, bg: str, fg: str = "#ffffff"):
    w = tk.Label(parent, text=text, bg=bg, fg=fg, font=(FONT, 9, "bold"),
                 padx=10, pady=3)
    return w


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Traffic Obfuscation Techniques Demo - GUI Desktop Edition")
        self.geometry("1240x800")
        self.minsize(1020, 680)
        self.configure(bg=BG)
        try:
            self.tk.call("tk", "wm", "attributes", ".", "-darkmode", "1")
        except tk.TclError:
            pass
        try:
            self.iconbitmap(str(_bundle_path() / "assets" / "app.ico"))
        except Exception:
            pass

        self.bundle = None
        self.produced = None
        self.sim_step = 0

        self._setup_style()
        self._build_header()
        self._build_notebook()
        self._build_export_bar()
        self._build_statusbar()
        self._set_status("Ready - press Run Analysis.")

    # -------------------------------------------------- style
    def _setup_style(self):
        st = ttk.Style(self)
        st.theme_use("clam")
        st.configure(".",
                     background=BG, foreground=INK, bordercolor=LINE,
                     lightcolor=LINE, darkcolor=LINE, font=(FONT, 10))
        st.configure("TFrame", background=BG)
        st.configure("Panel.TFrame", background=PANEL)
        st.configure("TLabel", background=BG, foreground=INK, font=(FONT, 10))
        st.configure("Panel.TLabel", background=PANEL, foreground=INK, font=(FONT, 10))
        st.configure("Muted.TLabel", background=PANEL, foreground=MUTED, font=(FONT, 9))

        st.configure("Accent.TButton", background=ACCENT, foreground="#ffffff",
                     font=(FONT, 10, "bold"), padding=(16, 8), borderwidth=0,
                     focuscolor=ACCENT2)
        st.map("Accent.TButton",
               background=[("active", ACCENT2), ("pressed", "#5b3fcf")],
               focuscolor=[("focus", ACCENT2)])
        st.configure("Ghost.TButton", background=PANE, foreground=INK,
                     font=(FONT, 9), padding=(12, 7), borderwidth=1,
                     relief="flat", bordercolor="#2c3763")
        st.map("Ghost.TButton",
               background=[("active", "#24305e"), ("pressed", "#1c274f")],
               bordercolor=[("active", "#3b4780")])

        st.configure("TNotebook", background=BG, borderwidth=0, tabmargins=(8, 6, 8, 0))
        st.configure("TNotebook.Tab", background="#1c2547", foreground=MUTED,
                     padding=(18, 8), font=(FONT, 10), borderwidth=0)
        st.map("TNotebook.Tab",
               background=[("selected", PANEL)],
               foreground=[("selected", INK)])
        st.configure("TProgressbar", background=ACCENT, troughcolor=PANE,
                     borderwidth=0, lightcolor=ACCENT, darkcolor=ACCENT)

        st.configure("Treeview", background=PANEL, fieldbackground=PANEL,
                     foreground=INK, rowheight=30, borderwidth=0,
                     font=(FONT, 10))
        st.configure("Treeview.Heading", background="#1c2547", foreground=INK,
                     font=(FONT, 9, "bold"), borderwidth=0, padding=(6, 6))
        st.map("Treeview", background=[("selected", ACCENT)],
               foreground=[("selected", "#ffffff")])
        st.map("Treeview.Heading", background=[("active", "#24305e")])

    # -------------------------------------------------- header
    def _build_header(self):
        bar = tk.Frame(self, bg=PANEL, padx=20, pady=14, highlightthickness=1,
                       highlightbackground=LINE)
        bar.pack(fill="x")

        top = tk.Frame(bar, bg=PANEL)
        top.pack(fill="x")
        title = tk.Label(top, text="Traffic Obfuscation Techniques Demo",
                         bg=PANEL, fg=INK, font=(FONT, 17, "bold"))
        title.pack(side="left")
        sub = tk.Label(top, text="Domain Fronting Concepts  |  Detection-Focused  |  Desktop Edition",
                       bg=PANEL, fg=MUTED, font=(FONT, 10))
        sub.pack(side="bottom", anchor="w", pady=(2, 0))
        right = tk.Frame(top, bg=PANEL)
        right.pack(side="right")
        for txt, bg in (("OWASP Top 10", "#7c3aed"), ("NIST CSF 2.0", "#0891b2"),
                        ("ISO 27001:2022", "#4d7c0f"), ("SV v1.0", "#1e293b")):
            _chip(right, txt, bg).pack(side="left", padx=3)

        mid = tk.Frame(bar, bg=PANEL)
        mid.pack(fill="x", pady=(12, 0))
        self.btn_run = ttk.Button(mid, text="Run Analysis", style="Accent.TButton",
                                  command=self._on_run)
        self.btn_run.pack(side="left")
        self.progress = ttk.Progressbar(mid, length=340, mode="determinate")
        self.progress.pack(side="left", padx=16, fill="x", expand=True)

    # -------------------------------------------------- notebook
    def _build_notebook(self):
        self.nb = ttk.Notebook(self)
        self.nb.pack(fill="both", expand=True, padx=12, pady=12)
        self.tab_overview = ttk.Frame(self.nb)
        self.tab_verdicts = ttk.Frame(self.nb)
        self.tab_findings = ttk.Frame(self.nb)
        self.tab_frameworks = ttk.Frame(self.nb)
        self.nb.add(self.tab_overview, text="Overview")
        self.nb.add(self.tab_verdicts, text="Flow Verdicts")
        self.nb.add(self.tab_findings, text="Findings")
        self.nb.add(self.tab_frameworks, text="Framework Coverage")

        self._build_overview()
        self._build_verdicts()
        self._build_findings()
        self._build_frameworks()

    def _stat_card(self, parent, title, value, sub, accent):
        box = tk.Frame(parent, bg=PANE, highlightthickness=1,
                       highlightbackground=LINE)
        box.configure(padx=16, pady=12)
        tk.Label(box, text=title.upper(), bg=PANE, fg=MUTED,
                 font=(FONT, 9, "bold")).pack(anchor="w")
        tk.Label(box, text=str(value), bg=PANE, fg=accent,
                 font=(FONT, 26, "bold")).pack(anchor="w", pady=(2, 0))
        tk.Label(box, text=sub, bg=PANE, fg=MUTED, font=(FONT, 9)).pack(anchor="w")
        box.pack_propagate(False)
        return box

    def _build_overview(self):
        page = self.tab_overview
        stats = tk.Frame(page, bg=BG)
        stats.pack(fill="x", pady=(14, 6), padx=8)
        stats.grid_columnconfigure((0, 1, 2, 3), weight=1, uniform="s")
        self.cards = {}
        specs = [
            ("flows", "Flows", 0, "analysed TLS sessions", ACCENT),
            ("fronted", "Fronted", 0, "verdict = fronted", RED),
            ("suspicious", "Suspicious", 0, "verdict = suspicious", ORANGE),
            ("findings", "Findings", 0, "high/critical raised", GOLD),
        ]
        for key, title, _v, sub, accent in specs:
            card = self._stat_card(stats, title, "0", sub, accent)
            card.grid(row=0, column=len(self.cards), sticky="nsew", padx=4)
            self.cards[key] = card

        canvas_wrap = tk.Frame(page, bg=PANEL, highlightthickness=1,
                               highlightbackground=LINE, padx=0, pady=0)
        canvas_wrap.pack(fill="both", expand=True, padx=8, pady=(10, 8))
        panel = _FlowCanvas(canvas_wrap, bg=PANEL, highlightthickness=0, height=180)
        panel.pack(fill="both", expand=True)
        tip = tk.Label(page, text=(
            "Pipeline preview: ClientHello telemetry -> CDN anycast edge -> hidden origin, "
            "with the detection lane scoring SNI/Host divergence in real time."),
            bg=BG, fg=MUTED, font=(FONT, 9)).pack(pady=(0, 10))

    def _tree(self, parent, columns, heights=14):
        box = ttk.Frame(parent)
        box.pack(fill="both", expand=True, padx=8, pady=(10, 4))
        tree = ttk.Treeview(box, columns=columns, show="headings", height=heights)
        vsb = ttk.Scrollbar(box, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=vsb.set)
        tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")
        for c in columns:
            tree.heading(c, text=c.replace("_", " ").title())
        tree.tag_configure("fronted", background="#32130f", foreground="#ffc2b3")
        tree.tag_configure("suspicious", background="#2a1a08", foreground="#ffe0b3")
        tree.tag_configure("benign", background="#0d2a1e", foreground="#a7f3d0")
        for sev, color in SEV_COLORS.items():
            tree.tag_configure(sev, foreground=color)
        return tree

    def _build_verdicts(self):
        cols = ("record", "scenario", "sni", "host", "dest_ip", "cdn", "score", "verdict")
        self.verdict_tree = self._tree(self.tab_verdicts, cols)
        widths = {"record": 90, "scenario": 110, "sni": 190, "host": 190,
                  "dest_ip": 130, "cdn": 90, "score": 60, "verdict": 90}
        for c, w in widths.items():
            self.verdict_tree.column(c, width=w, anchor="w",
                                     stretch=(c in ("sni", "host")))

    def _build_findings(self):
        cols = ("find", "severity", "title", "evidence", "controls")
        self.finding_tree = self._tree(self.tab_findings, cols)
        widths = {"find": 110, "severity": 90, "title": 300, "evidence": 420,
                  "controls": 160}
        for c, w in widths.items():
            self.finding_tree.column(c, width=w, anchor="w",
                                     stretch=(c in ("title", "evidence")))

    def _build_frameworks(self):
        cols = ("framework", "ref", "control", "status")
        self.fw_tree = self._tree(self.tab_frameworks, cols)
        for c, w in {"framework": 170, "ref": 70, "control": 460, "status": 90}.items():
            self.fw_tree.column(c, width=w, anchor="w")
        self.fw_hint = tk.Label(self.tab_frameworks, bg=BG, fg=MUTED, font=(FONT, 9),
                                text="Controls adopted = actively enforced by the demo; "
                                     "review = to be addressed by the organisation.")
        self.fw_hint.pack(pady=(4, 10))

    # -------------------------------------------------- export bar
    def _build_export_bar(self):
        bar = tk.Frame(self, bg=PANEL, padx=16, pady=12, highlightthickness=1,
                       highlightbackground=LINE)
        bar.pack(fill="x", side="bottom", pady=(0, 34))
        lbl = tk.Label(bar, text="Export:", bg=PANEL, fg=MUTED,
                       font=(FONT, 10, "bold"))
        lbl.pack(side="left")
        self.btn_xlsx = ttk.Button(bar, text=".XLSX", style="Ghost.TButton",
                                   command=lambda: self._on_export("xlsx"))
        self.btn_xlsx.pack(side="left", padx=4)
        for fmt, txt in (("csv", ".CSV"), ("html", ".HTML"), ("json", ".JSON")):
            b = ttk.Button(bar, text=txt, style="Ghost.TButton",
                           command=lambda f=fmt: self._on_export(f))
            b.pack(side="left", padx=4)
            setattr(self, f"btn_{fmt}", b)
        for b in (self.btn_xlsx, self.btn_csv, self.btn_html, self.btn_json):
            b.state(["disabled"])

        tk.Frame(bar, bg=PANEL, width=24).pack(side="left")
        ttk.Button(bar, text="Open Report Folder", style="Ghost.TButton",
                   command=self._on_open_folder).pack(side="left", padx=4)
        ttk.Button(bar, text="Open HTML Report", style="Ghost.TButton",
                   command=self._on_open_report).pack(side="left", padx=4)
        ttk.Button(bar, text="Architecture", style="Ghost.TButton",
                   command=self._on_open_architecture).pack(side="right", padx=4)

    def _build_statusbar(self):
        self.status = tk.Label(self, text="", bg=BG, fg=MUTED, font=(FONT, 9),
                               anchor="w", padx=18, pady=4)
        self.status.pack(fill="x", side="bottom")

    # -------------------------------------------------- behaviours
    def _set_status(self, text: str, color=MUTED):
        self.status.configure(text=text, fg=color)

    def _on_run(self):
        if self.bundle is None:
            self.progress["value"] = 0
            self.btn_run.state(["disabled"])
            steps = ["Generating synthetic TLS sessions...",
                     "Unpacking ClientHello features...",
                     "Running SNI / Host + JA4 + CDN heuristics...",
                     "Scoring flows 0-100...",
                     "Mapping to OWASP / NIST / ISO controls..."]
            self._simulate(steps, 0)
        else:
            self._finalise_analysis()

    def _simulate(self, steps: list, i: int):
        if i < len(steps):
            self._set_status(steps[i], ACCENT2)
            self.progress["value"] = (i + 1) * (100 // len(steps))
            self.after(140, lambda: self._simulate(steps, i + 1))
        else:
            self.progress["value"] = 100
            self._finalise_analysis()

    def _finalise_analysis(self):
        import traceback
        try:
            self.bundle = run_analysis()
        except Exception:
            self._set_status("Analysis failed - see log.", RED)
            messagebox.showerror("Analysis failed", traceback.format_exc())
            self.btn_run.state(["!disabled"])
            return
        self._populate()
        self.progress["value"] = 100
        self.btn_run.state(["!disabled"])
        self._set_status("Analysis complete - browse results or export reports.", LIME)

    def _populate(self):
        b = self.bundle
        verdicts = list(b.verdicts)
        findings = b.findings
        fronted = [v for v in verdicts if v.label.value == "fronted"]
        susp = [v for v in verdicts if v.label.value == "suspicious"]
        high = [f for f in findings if f.severity.value in ("high", "critical")]

        self.cards["flows"].winfo_children()[1].configure(text=len(verdicts))
        self.cards["fronted"].winfo_children()[1].configure(text=len(fronted))
        self.cards["suspicious"].winfo_children()[1].configure(text=len(susp))
        self.cards["findings"].winfo_children()[1].configure(text=len(high))

        self.verdict_tree.delete(*self.verdict_tree.get_children())
        for v in verdicts:
            self.verdict_tree.insert("", "end", values=(
                v.record_id, v.scenario, v.sni, v.host_header, v.dest_ip,
                v.cdn_owner or "-", f"{v.score}", v.label.value),
                tags=(v.label.value,))

        self.finding_tree.delete(*self.finding_tree.get_children())
        for f in findings:
            self.finding_tree.insert("", "end", values=(
                f.finding_id, f.severity.value, f.title, f.evidence,
                ", ".join(f.refs)), tags=(f.severity.value,))

        self.fw_tree.delete(*self.fw_tree.get_children())
        from src.frameworks import build_catalog
        for c in build_catalog():
            color = {"adopt": "green", "monitoring": "cyan"}
            self.fw_tree.insert("", "end", values=(
                c.framework.value, c.ref, c.title, c.status))
        for b_ in (self.btn_xlsx, self.btn_csv, self.btn_html, self.btn_json):
            b_.state(["!disabled"])

    def _on_export(self, fmt: str):
        if self.bundle is None:
            return
        from src.reporting import export_csv, export_html, export_json, export_xlsx
        out = _report_dir(_runtime_dir())
        try:
            if fmt == "xlsx":
                export_xlsx(self.bundle, out / "traffic_obfuscation_report.xlsx")
            elif fmt == "csv":
                export_csv(self.bundle, out)
            elif fmt == "html":
                export_html(self.bundle, out / "traffic_obfuscation_report.html")
            elif fmt == "json":
                export_json(self.bundle, out / "traffic_obfuscation_report.json")
            self.produced = (fmt, out)
            self._set_status(f"Exported {fmt.upper()} -> {out}", LIME)
        except Exception as exc:
            self._set_status(f"Export {fmt} failed: {exc}", RED)
            messagebox.showerror("Export failed", str(exc))

    def _on_open_folder(self):
        base = _runtime_dir()
        target = base / "Reports" if base == _runtime_dir() and getattr(sys, "frozen", False) else base / "output"
        if self.produced:
            target = self.produced[1]
        target.mkdir(parents=True, exist_ok=True)
        os.startfile(str(target))

    def _on_open_report(self):
        base = _runtime_dir()
        if self.produced and (self.produced[0] == "html"):
            webbrowser.open((self.produced[1] / "traffic_obfuscation_report.html").as_uri())
        elif self.bundle is not None:
            from src.reporting import export_html
            out = _report_dir(base)
            export_html(self.bundle, out / "traffic_obfuscation_report.html")
            webbrowser.open((out / "traffic_obfuscation_report.html").as_uri())

    def _on_open_architecture(self):
        arch = _bundle_path() / "index.html"
        if arch.exists():
            webbrowser.open(arch.as_uri())


# ---------------------------------------------------------------------------
# animated pipeline preview canvas
# ---------------------------------------------------------------------------
class _FlowCanvas(tk.Canvas):
    def __init__(self, parent, **kw):
        kw.setdefault("height", 180)
        super().__init__(parent, **kw)
        self.nodes = []
        self.dots = []
        self._offset = 0
        self._build()

    def _box(self, x, y, w, h, fill, title, sub, title_color="#ffffff"):
        self.create_rectangle(x, y, x + w, y + h, fill=fill, outline="#2c3763",
                              width=1)
        self.create_text(x + w / 2, y + h / 2 - 8, text=title, fill=title_color,
                         font=(FONT, 11, "bold"))
        self.create_text(x + w / 2, y + h / 2 + 10, text=sub, fill="#c9d4ee",
                         font=(FONT, 8))
        return (x + w, y + h / 2)

    def _build(self):
        y = 28
        h = 64
        right1 = self._box(30, y, 210, h, "#7c3aed", "Client / Generator",
                           "synthetic TLS ClientHello")
        right2 = self._box(300, y, 230, h, "#db2777", "Fronting Concepts",
                           "SNI / Host / :authority")
        right3 = self._box(590, y, 240, h, "#0891b2", "CDN Anycast Edge",
                           "shared front - TLS terminates")
        right4 = self._box(890, y, 250, h, "#ca8a04", "Hidden Origin",
                           "allow-listed backend")
        edges = [(right1, right2), (right2, right3), (right3, right4)]
        colors = ["#a855f7", "#fb7185", "#22d3ee", "#fbbf24"]
        for edge, color in zip(edges, colors):
            (x1, y1), (x2, y2) = edge
            self.create_line(x1, y1, x2, y2, fill=color, width=2,
                             dash=(7, 7), tags="flowline")
            self.dots.append([self.create_oval(-6, -6, 6, 6, fill=color, outline=""),
                              (x1, y1), (x2, y2), 0.0, 0.017])
        det_y = 130
        self.create_line(right3[0], right3[1], right3[0], det_y, fill="#a3e635",
                         width=2, dash=(7, 7))
        det = (right3[0], det_y)
        self._box(480, 118, 320, 52, "#16a34a", "Detection Lane",
                  "SNI mismatch | JA4 | CDN range | TTL scoring")
        self.dots.append([self.create_oval(-6, -6, 6, 6, fill="#a3e635", outline=""),
                          (right3[0], right3[1]), (right3[0], det_y), 0.0, 0.02])
        self._tick()

    def _tick(self):
        for dot, (x1, y1), (x2, y2), t, speed in self.dots:
            t += speed
            if t > 1.0:
                t -= 1.0
            nx = x1 + (x2 - x1) * t
            ny = y1 + (y2 - y1) * t
            self.coords(dot, nx - 5, ny - 5, nx + 5, ny + 5)
        self._offset = (self._offset + 2) % 24
        for item in self.find_withtag("flowline"):
            self.itemconfigure(item, dashoffset=-self._offset)
        self.after(30, self._tick)


# ---------------------------------------------------------------------------
# selftest (headless verification for the packaged exe)
# ---------------------------------------------------------------------------
def _selftest() -> int:
    bundle = run_analysis()
    marker_target = _runtime_dir() if getattr(sys, "frozen", False) else Path.cwd()
    marker = marker_target / "gui_selftest_ok.txt"
    marker.write_text(
        "SELFTEST PASS\n"
        f"flows={len(bundle.verdicts)}\n"
        f"findings={len(bundle.findings)}\n"
        f"fronted={sum(1 for v in bundle.verdicts if v.label.value == 'fronted')}\n",
        encoding="utf-8")
    return 0


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if "--selftest" in argv:
        return _selftest()
    app = App()
    app.mainloop()
    return 0


if __name__ == "__main__":
    sys.exit(main())