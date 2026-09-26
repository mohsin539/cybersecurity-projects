"""Web App Fuzzer - desktop GUI (Tkinter, portable, no install)."""
from __future__ import annotations

import json
import queue
import sys
import threading
import time
import tkinter as tk
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from tkinter import ttk, filedialog, messagebox

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.core.engine import Engine, ScanConfig
from app.core.framemap import MODULES, SEVERITY_WEIGHT
from app.core.models import Finding
from app.core.reporter import export_html, export_json


def base_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent.parent.parent


APP = "Web App Fuzzer"
DATA_DIR = base_dir() / "data"
AUDIT_DIR = DATA_DIR / "audit"
REPORTS_DIR = DATA_DIR / "reports"
CONFIG_FILE = DATA_DIR / "fuzzer_config.json"

COLS = ("sev", "module", "title", "owasp", "cwe", "url", "param", "conf")


class App(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title(APP)
        self.geometry("1080x700")
        self.minsize(940, 620)
        self._log_q: "queue.Queue[str]" = queue.Queue()
        self._finding_q: "queue.Queue[Finding]" = queue.Queue()
        self._progress_q: "queue.Queue[tuple[int, int]]" = queue.Queue()
        self._findings: list[Finding] = []
        self._engine: Engine | None = None
        self._worker: threading.Thread | None = None
        self._start = 0.0

        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        self._build_menu()
        self._notebook = ttk.Notebook(self)
        self._notebook.pack(fill="both", expand=True)

        self.tab_target = self._build_target_tab()
        self.tab_payloads = self._build_payloads_tab()
        self.tab_scan = self._build_scan_tab()
        self.tab_findings = self._build_findings_tab()
        self.tab_report = self._build_report_tab()

        self._load_config()
        self.after(250, self._drain_queues)

    # ------------------------------------------------------------------ tabs
    def _build_target_tab(self) -> ttk.Frame:
        f = ttk.Frame(self._notebook, padding=14)
        self._notebook.add(f, text="  Target & Scope  ")

        row = 0
        ttk.Label(f, text="Target URL (https://...)").grid(row=row, column=0, sticky="w", pady=4)
        self.v_url = tk.StringVar()
        ttk.Entry(f, textvariable=self.v_url, width=70).grid(row=row, column=1, columnspan=3, sticky="we", pady=4)
        row += 1

        ttk.Label(f, text="Auth cookie").grid(row=row, column=0, sticky="w", pady=4)
        self.v_cookie = tk.StringVar()
        ttk.Entry(f, textvariable=self.v_cookie, width=70, show="*").grid(row=row, column=1, columnspan=3, sticky="we", pady=4)
        row += 1

        ttk.Label(f, text="Auth header (Name: value)").grid(row=row, column=0, sticky="w", pady=4)
        self.v_authhdr = tk.StringVar()
        ttk.Entry(f, textvariable=self.v_authhdr, width=70, show="*").grid(row=row, column=1, columnspan=3, sticky="we", pady=4)
        row += 1

        ttk.Label(f, text="Extra headers (one per line)").grid(row=row, column=0, sticky="nw", pady=4)
        self.v_extrahdrs = tk.Text(f, width=52, height=4)
        self.v_extrahdrs.grid(row=row, column=1, columnspan=3, sticky="we", pady=4)
        row += 1

        ttk.Label(f, text="Max pages to crawl").grid(row=row, column=0, sticky="w", pady=4)
        self.v_pages = tk.StringVar(value="10")
        ttk.Spinbox(f, from_=1, to=200, textvariable=self.v_pages, width=8).grid(row=row, column=1, sticky="w", pady=4)
        ttk.Label(f, text="Max fuzz requests").grid(row=row, column=2, sticky="e", pady=4)
        self.v_maxreq = tk.StringVar(value="500")
        ttk.Spinbox(f, from_=10, to=100000, textvariable=self.v_maxreq, width=10).grid(row=row, column=3, sticky="w", pady=4)
        row += 1

        ttk.Label(f, text="Concurrency (threads)").grid(row=row, column=0, sticky="w", pady=4)
        self.v_conc = tk.StringVar(value="4")
        ttk.Spinbox(f, from_=1, to=16, textvariable=self.v_conc, width=8).grid(row=row, column=1, sticky="w", pady=4)
        ttk.Label(f, text="Politeness delay (ms)").grid(row=row, column=2, sticky="e", pady=4)
        self.v_delay = tk.StringVar(value="100")
        ttk.Spinbox(f, from_=0, to=5000, increment=25, textvariable=self.v_delay, width=10).grid(row=row, column=3, sticky="w", pady=4)
        row += 1

        ttk.Label(f, text="HTTP timeout (s)").grid(row=row, column=0, sticky="w", pady=4)
        self.v_timeout = tk.StringVar(value="15")
        ttk.Spinbox(f, from_=1, to=120, textvariable=self.v_timeout, width=8).grid(row=row, column=1, sticky="w", pady=4)
        ttk.Label(f, text="Proxy (http://host:port)").grid(row=row, column=2, sticky="e", pady=4)
        self.v_proxy = tk.StringVar()
        ttk.Entry(f, textvariable=self.v_proxy, width=28).grid(row=row, column=3, sticky="w", pady=4)
        row += 1

        self.v_verify = tk.BooleanVar(value=True)
        ttk.Checkbutton(f, text="Verify TLS certificates", variable=self.v_verify).grid(row=row, column=0, sticky="w", pady=4)
        ttk.Label(f, text="Seed").grid(row=row, column=2, sticky="e", pady=4)
        self.v_seed = tk.StringVar(value="20260919")
        ttk.Entry(f, textvariable=self.v_seed, width=14).grid(row=row, column=3, sticky="w", pady=4)
        row += 1

        ttk.Label(f, text="Authorization note (owner / ticket / scope)").grid(row=row, column=0, sticky="nw", pady=4)
        self.v_notes = tk.Text(f, width=52, height=3)
        self.v_notes.grid(row=row, column=1, columnspan=3, sticky="we", pady=4)
        row += 1

        ttk.Label(
            f,
            text="Only scan systems you are authorized to test. This tool generates attack traffic.",
            foreground="#9a0000",
        ).grid(row=row, column=0, columnspan=4, sticky="w", pady=8)

        f.columnconfigure(1, weight=1)
        f.columnconfigure(3, weight=1)
        return f

    def _build_payloads_tab(self) -> ttk.Frame:
        f = ttk.Frame(self._notebook, padding=14)
        self._notebook.add(f, text="  Modules / Payloads  ")

        top = ttk.Frame(f)
        top.pack(fill="x")
        ttk.Label(top, text="Select fuzzing modules (mapped to OWASP Top 10:2025)").pack(side="left", pady=6)
        ttk.Button(top, text="Select all", command=self._select_all).pack(side="right", padx=4)
        ttk.Button(top, text="Clear", command=self._clear_all).pack(side="right", padx=4)

        wrap = ttk.Frame(f)
        wrap.pack(fill="both", expand=True)
        self._module_vars: dict[str, tk.BooleanVar] = {}
        for i, (key, meta) in enumerate(MODULES.items()):
            var = tk.BooleanVar(value=True)
            self._module_vars[key] = var
            cb = ttk.Checkbutton(wrap, text=f"{key.upper():8s} {str(meta['title'])}", variable=var)
            cb.grid(row=i // 2, column=i % 2 * 3, sticky="w", padx=6, pady=3)
            ttk.Label(wrap, text=f"→ {str(meta['owasp'])}", foreground="#555").grid(row=i // 2, column=i % 2 * 3 + 1, sticky="w", padx=2)
        f.columnconfigure(1, weight=1)
        f.columnconfigure(4, weight=1)
        return f

    def _build_scan_tab(self) -> ttk.Frame:
        f = ttk.Frame(self._notebook, padding=14)
        self._notebook.add(f, text="  Run Scan  ")

        controls = ttk.Frame(f)
        controls.pack(fill="x")
        self.btn_start = ttk.Button(controls, text="Start scan", command=self._start_scan)
        self.btn_start.pack(side="left", padx=2)
        self.btn_stop = ttk.Button(controls, text="Stop", state="disabled", command=self._stop_scan)
        self.btn_stop.pack(side="left", padx=2)
        self.v_progress = tk.DoubleVar(value=0.0)
        self.pbar = ttk.Progressbar(controls, variable=self.v_progress, maximum=100, length=360)
        self.pbar.pack(side="left", padx=10)
        self.lbl_progress = ttk.Label(controls, text="idle")
        self.lbl_progress.pack(side="left")

        ttk.Label(f, text="Live log (immutable audit trail written to data/audit/)").pack(anchor="w", pady=(12, 2))
        self.txt_log = tk.Text(f, height=22, state="disabled", wrap="word")
        self.txt_log.pack(fill="both", expand=True)
        sb = ttk.Scrollbar(self.txt_log, command=self.txt_log.yview)
        self.txt_log.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        return f

    def _build_findings_tab(self) -> ttk.Frame:
        f = ttk.Frame(self._notebook, padding=8)
        self._notebook.add(f, text="  Findings  ")

        self.tree = ttk.Treeview(f, columns=COLS, show="headings", height=12)
        heads = {
            "sev": ("Severity", 90),
            "module": ("Module", 90),
            "title": ("Title", 200),
            "owasp": ("OWASP 2025", 130),
            "cwe": ("CWE", 80),
            "url": ("URL", 320),
            "param": ("Parameter", 110),
            "conf": ("Conf", 60),
        }
        for c, (label, w) in heads.items():
            self.tree.heading(c, text=label)
            self.tree.column(c, width=w, stretch=(c in ("title", "url")))
        ys = ttk.Scrollbar(f, command=self.tree.yview)
        self.tree.configure(yscrollcommand=ys.set)
        self.tree.pack(side="left", fill="both", expand=True)
        ys.pack(side="right", fill="y")
        self.tree.bind("<<TreeviewSelect>>", self._on_select_finding)

        self.detail = tk.Text(f, height=12, state="disabled", wrap="word")
        self.detail.pack(side="bottom", fill="x")
        return f

    def _build_report_tab(self) -> ttk.Frame:
        f = ttk.Frame(self._notebook, padding=14)
        self._notebook.add(f, text="  Report & Export  ")

        ttk.Label(f, text="Export evidence-ready reports (traceability: OWASP / NIST / ISO)").pack(anchor="w", pady=4)
        row = ttk.Frame(f)
        row.pack(fill="x", pady=6)
        ttk.Button(row, text="Export HTML report…", command=lambda: self._export("html")).pack(side="left", padx=4)
        ttk.Button(row, text="Export JSON report…", command=lambda: self._export("json")).pack(side="left", padx=4)
        ttk.Button(row, text="Save scan config", command=self._save_config).pack(side="left", padx=4)

        self.txt_summary = tk.Text(f, height=12, state="disabled", wrap="word")
        self.txt_summary.pack(fill="both", expand=True, pady=8)
        self._write_summary("No scan has been run yet in this session.")
        return f

    # ------------------------------------------------------------------ menu
    def _build_menu(self) -> None:
        menubar = tk.Menu(self)
        mfile = tk.Menu(menubar, tearoff=0)
        mfile.add_command(label="Save config", command=self._save_config)
        mfile.add_command(label="Load config", command=self._load_config_interactive)
        mfile.add_separator()
        mfile.add_command(label="Exit", command=self.destroy)
        menubar.add_cascade(label="File", menu=mfile)
        mhelp = tk.Menu(menubar, tearoff=0)
        mhelp.add_command(label="About", command=self._about)
        menubar.add_cascade(label="Help", menu=mhelp)
        self.config(menu=menubar)

    # ------------------------------------------------------------------ logic
    def _config_values(self) -> dict:
        try:
            return {
                "url": self.v_url.get().strip(),
                "auth_cookie": self.v_cookie.get().strip(),
                "auth_header": self.v_authhdr.get().strip(),
                "extra_headers": self.v_extrahdrs.get("1.0", "end").strip(),
                "max_pages": max(1, min(200, int(self.v_pages.get()))),
                "max_requests": max(10, min(100000, int(self.v_maxreq.get()))),
                "concurrency": max(1, min(16, int(self.v_conc.get()))),
                "delay_ms": max(0, min(5000, int(self.v_delay.get()))),
                "timeout": max(1, min(120, int(self.v_timeout.get()))),
                "verify_tls": bool(self.v_verify.get()),
                "proxy": self.v_proxy.get().strip(),
                "seed": int(self.v_seed.get()),
                "notes": self.v_notes.get("1.0", "end").strip(),
                "modules": [k for k, v in self._module_vars.items() if v.get()],
            }
        except ValueError:
            messagebox.showerror("Invalid value", "Check numeric fields (pages, requests, concurrency, delay, timeout, seed).")
            return {}

    def _start_scan(self) -> None:
        if not self.v_url.get().strip():
            messagebox.showwarning("No target", "Enter a target URL to scan.")
            return
        if self._engine is not None:
            return

        cfg = ScanConfig(**self._config_values())
        if not cfg.modules:
            messagebox.showwarning("No modules", "Select at least one fuzzing module.")
            return
        if not cfg.url.startswith(("http://", "https://")):
            messagebox.showwarning("Bad URL", "URL must start with http:// or https://.")

        AUDIT_DIR.mkdir(parents=True, exist_ok=True)
        REPORTS_DIR.mkdir(parents=True, exist_ok=True)

        self._findings = []
        for item in self.tree.get_children():
            self.tree.delete(item)
        self._detail_clear()
        self._write_summary(f"Scan started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\nTarget: {cfg.url}\nModules: {', '.join(cfg.modules)}\nAudit: {AUDIT_DIR / 'audit.jsonl'}\n")

        self._engine = Engine(
            cfg,
            on_log=self._log_q.put,
            on_finding=self._finding_q.put,
            on_progress=self._progress_q.put,
            audit_dir=str(AUDIT_DIR),
        )
        self._start = time.time()
        self.btn_start.config(state="disabled")
        self.btn_stop.config(state="normal")
        self.v_progress.set(0.0)
        self.lbl_progress.config(text="starting…")
        self._log_q.put("[ui] scan started")

        self._worker = threading.Thread(target=self._run_engine, daemon=True)
        self._worker.start()

    def _run_engine(self) -> None:
        try:
            self._engine.run()
        except Exception as exc:  # noqa: BLE001
            self._log_q.put(f"[ui] ERROR: {type(exc).__name__}: {exc}")
        finally:
            self.after(0, self._scan_finished)

    def _stop_scan(self) -> None:
        if self._engine:
            self._engine.stop()
            self._log_q.put("[ui] stop requested")

    def _scan_finished(self) -> None:
        self.btn_start.config(state="normal")
        self.btn_stop.config(state="disabled")
        self.lbl_progress.config(text="done")
        dur = time.time() - self._start
        self._write_summary(
            f"Scan finished in {dur:.1f}s — {self._engine.requests if self._engine else 0} requests, {len(self._findings)} findings.\n"
            + "Export a report from the 'Report & Export' tab."
        )
        self._log_q.put(f"[ui] finished: {len(self._findings)} findings, {dur:.1f}s")
        self._engine = None

    def _drain_queues(self) -> None:
        while True:
            try:
                line = self._log_q.get_nowait()
                self._log(line)
            except queue.Empty:
                break
        while True:
            try:
                done, total = self._progress_q.get_nowait()
                pct = (done / total * 100.0) if total else 0.0
                self.v_progress.set(pct)
                self.lbl_progress.config(text=f"{done}/{total}")
            except queue.Empty:
                break
        while True:
            try:
                finding = self._finding_q.get_nowait()
                self._findings.append(finding)
                self._tree_insert(finding)
            except queue.Empty:
                break
        self.after(250, self._drain_queues)

    def _log(self, line: str) -> None:
        self.txt_log.config(state="normal")
        self.txt_log.insert("end", line.rstrip() + "\n")
        self.txt_log.see("end")
        self.txt_log.config(state="disabled")

    def _tree_insert(self, f: Finding) -> None:
        self.tree.insert(
            "",
            "end",
            iid=f.id,
            values=(f.severity, f.module, f.title, f.owasp, ",".join(f.cwes), f.url, f.param, f"{f.confidence:.2f}"),
        )

    def _on_select_finding(self, _e) -> None:
        sel = self.tree.selection()
        if not sel:
            return
        fid = sel[0]
        for f in self._findings:
            if f.id == fid:
                self._show_detail(f)
                break

    def _show_detail(self, f: Finding) -> None:
        ev = "\n".join(f"  {k}: {v}" for k, v in f.evidence.items())
        text = (
            f"{f.id} — {f.title} [{f.severity}] conf={f.confidence:.2f}\n"
            f"URL: {f.url}\nParameter: {f.param} | Payload: {f.payload_id}\n"
            f"OWASP 2025: {f.owasp}  CWE: {','.join(f.cwes)}\n"
            f"NIST SP 800-53: {','.join(f.nist_controls)} | NIST SSDF: {','.join(f.ssdf_tasks)} | ISO 27001:2022: {','.join(f.iso_controls)}\n"
            f"Evidence:\n{ev}\n"
            f"Remediation:\n  {f.remediation}"
        )
        self.detail.config(state="normal")
        self.detail.delete("1.0", "end")
        self.detail.insert("1.0", text)
        self.detail.config(state="disabled")

    def _detail_clear(self) -> None:
        self.detail.config(state="normal")
        self.detail.delete("1.0", "end")
        self.detail.config(state="disabled")

    def _write_summary(self, text: str) -> None:
        self.txt_summary.config(state="normal")
        self.txt_summary.delete("1.0", "end")
        self.txt_summary.insert("1.0", text)
        self.txt_summary.config(state="disabled")

    def _export(self, kind: str) -> None:
        if not self._findings:
            messagebox.showwarning("Nothing to export", "Run a scan and produce findings first.")
            return
        cfg = self._config_values() or {}
        meta = {
            "tool": APP,
            "generated": datetime.utcnow().isoformat(),
            "target": cfg.get("url", ""),
            "modules": ",".join(cfg.get("modules", [])),
            "requests": self._engine.requests if self._engine else len(self._findings),
            "findings": len(self._findings),
            "authorization_note": cfg.get("notes", ""),
        }
        ext = "html" if kind == "html" else "json"
        default = REPORTS_DIR / f"report-{datetime.now().strftime('%Y%m%d-%H%M%S')}.{ext}"
        path = filedialog.asksaveasfilename(defaultextension=f".{ext}", initialfile=default.name, initialdir=str(REPORTS_DIR), filetypes=[(ext.upper(), f"*.{ext}")])
        if not path:
            return
        if kind == "html":
            export_html(self._findings, meta, path)
        else:
            export_json(self._findings, meta, path)
        messagebox.showinfo("Export", f"Report saved:\n{path}")

    def _select_all(self) -> None:
        for v in self._module_vars.values():
            v.set(True)

    def _clear_all(self) -> None:
        for v in self._module_vars.values():
            v.set(False)

    # ------------------------------------------------------------------ config io
    def _save_config(self) -> None:
        cfg = self._config_values()
        if not cfg:
            return
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        with open(CONFIG_FILE, "w", encoding="utf-8") as fh:
            json.dump(cfg, fh, indent=2)
        self._log_q.put(f"[ui] config saved: {CONFIG_FILE}")

    def _load_config(self, silent: bool = True) -> None:
        if not CONFIG_FILE.exists():
            return
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as fh:
                cfg = json.load(fh)
            self._apply_config(cfg)
            if not silent:
                self._log_q.put(f"[ui] config loaded: {CONFIG_FILE}")
        except Exception as exc:  # noqa: BLE001
            if not silent:
                messagebox.showerror("Load config", str(exc))

    def _load_config_interactive(self) -> None:
        path = filedialog.askopenfilename(initialdir=str(DATA_DIR), filetypes=[("JSON", "*.json")])
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8") as fh:
                cfg = json.load(fh)
            self._apply_config(cfg)
            self._log_q.put(f"[ui] config loaded: {path}")
        except Exception as exc:  # noqa: BLE001
            messagebox.showerror("Load config", str(exc))

    def _apply_config(self, cfg: dict) -> None:
        def txt(widget: tk.Text, key: str) -> None:
            v = cfg.get(key, "")
            if v:
                widget.delete("1.0", "end")
                widget.insert("1.0", str(v))

        maps = {
            "url": self.v_url, "auth_cookie": self.v_cookie, "auth_header": self.v_authhdr,
            "proxy": self.v_proxy, "seed": self.v_seed, "pages": self.v_pages,
            "maxreq": self.v_maxreq, "conc": self.v_conc, "delay": self.v_delay,
            "timeout": self.v_timeout,
        }
        for cfg_key, var in maps.items():
            if cfg_key in cfg:
                var.set(str(cfg[cfg_key]))
        txt(self.v_extrahdrs, "extra_headers")
        txt(self.v_notes, "notes")
        if "verify_tls" in cfg:
            self.v_verify.set(bool(cfg["verify_tls"]))
        mods = set(cfg.get("modules", []))
        for key, var in self._module_vars.items():
            var.set(key in mods if mods else True)

    def _about(self) -> None:
        messagebox.showinfo(
            "About",
            f"{APP} v1.0\n\nA portabl dynamic web-application fuzzer for input-validation testing.\n"
            "Maps findings to OWASP Top 10:2025, NIST SP 800-53/800-218, ISO/IEC 27001:2022 Annex A.\n\n"
            "Use only against systems you are authorized to test.",
        )


def main() -> None:
    app = App()
    app.mainloop()


if __name__ == "__main__":
    main()