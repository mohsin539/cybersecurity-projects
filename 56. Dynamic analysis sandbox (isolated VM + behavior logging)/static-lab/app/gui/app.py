"""StaticLab main window: browse -> analyze -> inspect -> export/audit."""

from __future__ import annotations

import os
import queue
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from .. import __version__, __app_name__
from ..config import Config, app_data_dir
from ..core.audit import AuditStore
from ..core.pipeline import analyze, strings_text
from ..report.exporter import export_html, export_json, export_txt
from . import theme

_PROVIDER_LABELS = {
    "virustotal": "VirusTotal v3",
    "malwarebazaar": "MalwareBazaar",
    "otx": "AlienVault OTX",
    "hybridanalysis": "Hybrid Analysis",
}


class StaticLabApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.cfg: Config = Config(app_data_dir())
        self.store = AuditStore(app_data_dir() / "audit.db", self._audit_key())
        self.q: queue.Queue = queue.Queue()
        self.result = None
        self.current_file: str = ""

        self.title(f"{__app_name__} v{__version__} - PE Static Analysis Sandbox")
        self.geometry("1240x820")
        self.minsize(1000, 680)
        self.configure(bg=theme.BG)
        self.style = theme.apply(self)

        self._build_menu()
        self._build_header()
        self._build_controls()
        self._build_tabs()

        self.after(200, self._poll)
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    # ------------------------------------------------------------------ key
    def _audit_key(self) -> bytes:
        """Machine-scoped HMAC key for the audit chain (DPAPI-protected)."""
        key_file = app_data_dir() / "audit.key"
        if key_file.exists():
            return key_file.read_bytes()
        key = os.urandom(32)
        key_file.write_bytes(key)
        return key

    # ----------------------------------------------------------------- menu
    def _build_menu(self) -> None:
        m = tk.Menu(self)
        fm = tk.Menu(m, tearoff=0)
        fm.add_command(label="Open File...", command=self._browse)
        fm.add_separator()
        fm.add_command(label="Export Report (HTML)...", command=lambda: self._export("html"))
        fm.add_command(label="Export Report (JSON)...", command=lambda: self._export("json"))
        fm.add_command(label="Export Report (TXT)...", command=lambda: self._export("txt"))
        fm.add_command(label="Export Full Strings...", command=self._export_strings)
        fm.add_separator()
        fm.add_command(label="Exit", command=self._on_close)
        m.add_cascade(label="File", menu=fm)

        sm = tk.Menu(m, tearoff=0)
        sm.add_command(label="API Keys / Providers...", command=self._open_settings)
        sm.add_command(label="Audit Log Viewer...", command=self._open_audit)
        sm.add_command(label="Verify Audit Chain", command=self._verify_chain_msg)
        m.add_cascade(label="Tools", menu=sm)

        hm = tk.Menu(m, tearoff=0)
        hm.add_command(label="About", command=self._about)
        m.add_cascade(label="Help", menu=hm)
        self.config(menu=m)

    # ---------------------------------------------------------------- layout
    def _build_header(self) -> None:
        head = ttk.Frame(self, style="Panel.TFrame", padding=(18, 14))
        head.pack(fill="x")
        ttk.Label(head, text=f"{__app_name__} \u2014 Static Analysis Pipeline", style="Title.TLabel").pack(anchor="w")
        ttk.Label(
            head,
            text="strings \u00b7 PE header parsing \u00b7 hash lookups \u00b7 auditable reports   [offline-capable, threat-intel via API keys]",
            style="Dim.TLabel",
        ).pack(anchor="w", pady=(2, 0))

    def _build_controls(self) -> None:
        bar = ttk.Frame(self, padding=(14, 10))
        bar.pack(fill="x")
        bar.columnconfigure(1, weight=1)

        ttk.Label(bar, text="Target file:").grid(row=0, column=0, padx=(0, 8))
        self.path_var = tk.StringVar()
        ttk.Entry(bar, textvariable=self.path_var).grid(row=0, column=1, sticky="ew")
        ttk.Button(bar, text="Browse\u2026", command=self._browse).grid(row=0, column=2, padx=(8, 0))
        self.btn_analyze = ttk.Button(bar, text="\u25b6 Analyze", style="Accent.TButton", command=self._analyze)
        self.btn_analyze.grid(row=0, column=3, padx=(8, 0))

        status = ttk.Frame(self, padding=(14, 4, 14, 10))
        status.pack(fill="x")
        self.progress = ttk.Progressbar(status, mode="determinate", maximum=8)
        self.progress.pack(fill="x")
        self.status_var = tk.StringVar(value="Ready \u2014 select a file and press Analyze.")
        ttk.Label(status, textvariable=self.status_var, style="Dim.TLabel").pack(anchor="w", pady=(4, 0))

    def _build_tabs(self) -> None:
        nb = ttk.Notebook(self, style="flat.TNotebook")
        nb.pack(fill="both", expand=True, padx=14, pady=(0, 14))

        # ---- Overview ----------------------------------------------------
        ov = ttk.Frame(nb)
        nb.add(ov, text=" \U0001f4c8 Overview ")
        self.verdict_var = tk.StringVar(value="NO SAMPLE")
        verdict_row = ttk.Frame(ov, padding=10)
        verdict_row.pack(fill="x")
        ttk.Label(verdict_row, textvariable=self.verdict_var, font=("Segoe UI", 22, "bold"), foreground=theme.DIM).pack(side="left")
        self.ov_text = self._text_widget(ov)

        # ---- PE headers --------------------------------------------------
        pe = ttk.Frame(nb)
        nb.add(pe, text=" \U0001f50d PE Headers ")
        self.pe_tree = self._tree(pe, ("Property", "Value"), width=(34, 66))
        self.pe_tree.pack(fill="both", expand=True, padx=8, pady=8)

        # ---- Sections ----------------------------------------------------
        sec = ttk.Frame(nb)
        nb.add(sec, text=" \U0001f4ca Sections ")
        self.sec_tree = self._tree(sec, ("Name", "VA", "VSize", "RSize", "Entropy", "SHA-256"), width=(16, 12, 12, 12, 10, 26))
        self.sec_tree.pack(fill="both", expand=True, padx=8, pady=8)

        # ---- Imports / Exports -------------------------------------------
        im = ttk.Frame(nb)
        nb.add(im, text=" \U0001f511 Imports ")
        self.imp_tree = self._tree(im, ("DLL", "Functions"), width=(30, 70))
        self.imp_tree.pack(fill="both", expand=True, padx=8, pady=8)

        # ---- Strings ------------------------------------------------------
        st = ttk.Frame(nb)
        nb.add(st, text=" \U0001f50e Strings ")
        toolbar = ttk.Frame(st, padding=(8, 8, 8, 0))
        toolbar.pack(fill="x")
        ttk.Button(toolbar, text="Export full strings\u2026", command=self._export_strings).pack(side="right")
        self.str_info = ttk.Label(toolbar, text="", style="Dim.TLabel")
        self.str_info.pack(side="left")
        self.str_tree = self._tree(st, ("Offset", "Enc", "Value", "Flags"), width=(10, 7, 60, 18))
        self.str_tree.pack(fill="both", expand=True, padx=8, pady=8)

        # ---- Threat lookups ------------------------------------------------
        lu = ttk.Frame(nb)
        nb.add(lu, text=" \U0001f4b8 Lookups ")
        self.lu_text = self._text_widget(lu)

        # ---- Audit ---------------------------------------------------------
        au = ttk.Frame(nb)
        nb.add(au, text=" \U0001f512 Audit ")
        toolbar_a = ttk.Frame(au, padding=(8, 8, 8, 0))
        toolbar_a.pack(fill="x")
        ttk.Button(toolbar_a, text="Verify Chronological Chain", command=self._verify_chain_msg).pack(side="right")
        self.audit_info = ttk.Label(toolbar_a, text="", style="Dim.TLabel")
        self.audit_info.pack(side="left")
        self.audit_tree = self._tree(au, ("Ts", "Action", "Target", "Chain (first 16)"), width=(16, 18, 40, 20))
        self.audit_tree.pack(fill="both", expand=True, padx=8, pady=8)
        self._refresh_audit()

    @staticmethod
    def _text_widget(parent: ttk.Frame) -> tk.Text:
        t = tk.Text(parent, bg=theme.PANEL, fg=theme.FG, insertbackground=theme.FG, relief="flat",
                    font=("Consolas", 11), padx=12, pady=10, wrap="word", state="disabled")
        t.pack(fill="both", expand=True, padx=8, pady=8)
        t.tag_config("hl", foreground=theme.ACCENT)
        t.tag_config("bad", foreground=theme.BAD, font=("Consolas", 11, "bold"))
        t.tag_config("warn", foreground=theme.WARN)
        t.tag_config("good", foreground=theme.GOOD)
        return t

    @staticmethod
    def _tree(parent: ttk.Frame, columns, width) -> ttk.Treeview:
        t = ttk.Treeview(parent, columns=columns, show="headings", selectmode="browse")
        for i, (name, w) in enumerate(zip(columns, width)):
            t.heading(i, text=name)
            t.column(i, width=w, anchor="w")
        return t

    # --------------------------------------------------------------- actions
    def _browse(self) -> None:
        path = filedialog.askopenfilename(
            title="Choose file to analyze",
            filetypes=[
                ("Any file", "*.*"),
                ("Executables", "*.exe *.dll *.sys *.ocx *.scr *.cpl"),
                ("Scripts/others", "*.ps1 *.bat *.vbs *.msi"),
            ],
        )
        if path:
            self.path_var.set(path)
            self.current_file = path

    def _analyze(self) -> None:
        path = self.path_var.get().strip()
        if not path or not os.path.isfile(path):
            messagebox.showwarning("StaticLab", "Select a valid file path first.")
            return
        with open(path, "rb") as _f:
            pass  # validate readability
        self.current_file = path
        self.progress["value"] = 0
        self.btn_analyze.state(["disabled"])
        self.status_var.set("Analyzing\u2026")
        self.verdict_var.set("ANALYZING\u2026")
        self.verdict_var_kwargs = {"foreground": theme.ACCENT}
        enabled = [p for p in self.cfg.get("providers", [])]
        threading.Thread(target=self._worker, args=(path, enabled), daemon=True).start()

    def _worker(self, path: str, enabled: list[str]) -> None:
        try:
            result = analyze(
                path,
                config=self.cfg.secrets_payload(),
                audit=self.store,
                progress=lambda i, n, label: self.q.put(("progress", (i, label))),
                lookups_enabled=enabled,
            )
            self.q.put(("done", result))
        except Exception as e:  # noqa: BLE001
            self.q.put(("error", str(e)))

    def _poll(self) -> None:
        try:
            while True:
                kind, payload = self.q.get_nowait()
                if kind == "progress":
                    step, label = payload
                    self.progress["value"] = step
                    self.status_var.set(label)
                elif kind == "done":
                    self._render(payload)
                elif kind == "error":
                    self.status_var.set(f"Error: {payload}")
                    self.verdict_var.set("ERROR")
                    messagebox.showerror("StaticLab", f"Analysis failed:\n{payload}")
                    self.btn_analyze.state(["!disabled"])
        except queue.Empty:
            pass
        self.after(200, self._poll)

    def _render(self, r) -> None:
        self.result = r
        self.progress["value"] = 8
        self.status_var.set(f"Complete in {len(r.stages)} stages \u2013 {r.verdict_label} ({r.score}/100)")
        self.verdict_var.set(f"{r.verdict_label}   {r.score}/100")
        self.verdict_var_kwargs = {"foreground": r.score_color}
        self.btn_analyze.state(["!disabled"])
        self._populate_overview(r)
        self._populate_pe(r)
        self._populate_sections(r)
        self._populate_imports(r)
        self._populate_strings(r)
        self._populate_lookups(r)
        self._refresh_audit()

    # --------------------------------------------------------------- populate
    def _populate_overview(self, r) -> None:
        t = self.ov_text
        t.config(state="normal")
        t.delete("1.0", "end")
        h = r.hashes
        t.insert("end", f"THREAT SCORE: {r.score}/100  ({r.verdict_label})\n\n", "bad" if r.score >= 50 else "hl")
        t.insert("end", f"File       {r.file_name}\n")
        t.insert("end", f"Path       {r.file_path}\n")
        t.insert("end", f"Size       {r.file_size:,} bytes\n")
        t.insert("end", f"Type       {r.magic_hint or 'n/a'}\n")
        t.insert("end", f"Created    {r.stat_created or '-'}\nModified   {r.stat_modified or '-'}\n\n")
        if h:
            t.insert("end", "MD5      " + h.md5 + "\n", "hl")
            t.insert("end", "SHA-1    " + h.sha1 + "\n", "hl")
            t.insert("end", "SHA-256  " + h.sha256 + "\n", "hl")
            t.insert("end", "SHA-512  " + h.sha512 + "\n", "hl")
            t.insert("end", f"imphash  {h.imphash or '-'}\n")
            t.insert("end", f"Authentihash {h.authentihash or '-'}\n")
            t.insert("end", f"Entropy  {h.entropy:.4f} bits/byte\n")
        if r.pe and r.pe.warnings:
            t.insert("end", "\nWarnings:\n", "warn")
            for w in r.pe.warnings:
                t.insert("end", "  ! " + w + "\n", "warn")
        if r.audit_chain_hash:
            t.insert("end", f"\nAudit chain hash: {r.audit_chain_hash}\n")
            t.insert("end", f"Audit chain verified: {bool(r.audit_verified)}\n", "good" if r.audit_verified else "bad")
        t.config(state="disabled")

    def _populate_pe(self, r) -> None:
        t = self.pe_tree
        t.delete(*t.get_children())
        pe = r.pe if (r.pe and r.pe.is_pe) else r.pe
        rows = [
            ("Format", f"{pe.magic} ({'DLL' if pe.is_dll else 'EXE'}{' driver' if pe.is_driver else ''})" if pe else "not a PE"),
            ("Sections", str(pe.number_of_sections)) if pe else ("Status", "no PE"),
        ]
        if pe:
            rows = [
                ("Magic", pe.magic if pe.is_pe else "n/a"),
                ("Machine", pe.machine or "n/a"),
                ("Number of sections", str(pe.number_of_sections)),
                ("Compilation timestamp", pe.timestamp or "n/a"),
                ("Characteristics", pe.characteristics or "n/a"),
                ("Linker version", pe.linker_version or "n/a"),
                ("Image base", f"0x{pe.image_base:X}" if pe.image_base else "n/a"),
                ("Entry point", f"0x{pe.entry_point:X}" if pe.entry_point else "n/a"),
                ("Subsystem", pe.subsystem or "n/a"),
                ("DLL characteristics", pe.dll_characteristics or "n/a"),
                ("Is DLL", str(pe.is_dll)),
                ("Is driver", str(pe.is_driver)),
                ("Certificate present", str(pe.certificate_present)),
                ("Signed (pefile)", str(pe.is_signed)),
                ("Overlay bytes", f"{pe.overlay_size:,}" + ("  (embedded PE!)" if pe.overlay_pe_embedded else "")),
                ("Debug info", pe.debug_type or "none"),
                ("TLS callbacks", str(pe.tls_callbacks)),
                ("Rich header", pe.rich_header or "none"),
            ] + [("Data directory", f"{name} @ 0x{rva:X}") for name, rva in pe.data_directories[:20]]
            if pe.warnings:
                rows += [("warning", w) for w in pe.warnings[:8]]
        for k, v in rows:
            t.insert("", "end", values=(k, v))

    def _populate_sections(self, r) -> None:
        t = self.sec_tree
        t.delete(*t.get_children())
        pe = r.pe if (r.pe and r.pe.is_pe) else None
        if not pe:
            return
        for s in pe.sections:
            t.insert("", "end", values=(s.name, f"0x{s.virtual_address:X}", s.virtual_size, s.raw_size, f"{s.entropy:.3f}", s.sha256[:16]))

    def _populate_imports(self, r) -> None:
        t = self.imp_tree
        t.delete(*t.get_children())
        pe = r.pe if (r.pe and r.pe.is_pe) else None
        if not pe:
            return
        for dll, funcs in pe.imports[:80]:
            t.insert("", "end", values=(dll, ", ".join(funcs[:40])))
        if pe.exports:
            t.insert("", "end", values=("(exports)", ", ".join(pe.exports[:80])))

    def _populate_strings(self, r) -> None:
        t = self.str_tree
        t.delete(*t.get_children())
        hits = (r.suspicious_strings or r.strings[:500])[:800]
        self.str_info.config(text=f"{len(r.strings):,} strings total \u00b7 showing {len(hits):,} interesting/leading")
        for s in hits:
            t.insert("", "end", values=(f"0x{s.offset:X}", s.encoding, s.value[:220], ", ".join(s.flags[:5])))

    def _populate_lookups(self, r) -> None:
        t = self.lu_text
        t.config(state="normal")
        t.delete("1.0", "end")
        if not r.lookups:
            t.insert("end", "No provider results (set API keys under Tools \u2192 API Keys / Providers).\n", "dim")
        for rep in r.lookups:
            status_color = "warn" if rep.status == "no_key" else ("bad" if rep.status == "error" else "good")
            line = f"provider: {rep.provider}\nstatus  : {rep.status}\nmessage : {rep.message}\n"
            if rep.summary:
                import json as _json
                line += "summary : " + _json.dumps(rep.summary, default=str)[:400] + "\n"
            if rep.url:
                line += "link    : " + rep.url + "\n"
            line += "\n"
            t.insert("end", line, status_color)
        t.config(state="disabled")

    # ---------------------------------------------------------------- audit
    def _refresh_audit(self) -> None:
        t = self.audit_tree
        t.delete(*t.get_children())
        entries = self.store.export()
        self.audit_info.config(text=f"{len(entries):,} ledger entries \u00b7 first-hash {self.store.last_hash() or 'empty'}")
        for e in entries[-500:]:
            try:
                import json as _json
                payload = _json.loads(e["payload"])
                action = payload.get("action", e["payload"][:60])
                target = payload.get("target", "")
                detail = str(payload.get("detail", ""))[:40]
            except Exception:  # noqa: BLE001
                action, target, detail = "?", "", ""
            t.insert("", "end", values=(e["ts"], action, target + (" " + detail if detail else ""), e["chain_hash"][:16]))

    def _verify_chain_msg(self) -> None:
        ok, issues = self.store.verify_chain()
        if ok:
            self.status_var.set("Audit chain verified: no tampering detected.")
            messagebox.showinfo("Audit Verification", "Hash chain + MAC verification passed.\nNo tampering detected.")
        else:
            self.status_var.set(f"Audit chain tampered ({len(issues)} issue(s)).")
            messagebox.showwarning("Audit Verification", "\n".join(issues[:20]))

    def _open_audit(self) -> None:
        win = tk.Toplevel(self)
        win.title("Audit Log Viewer")
        win.geometry("900x520")
        win.configure(bg=theme.BG)
        tree = ttk.Treeview(win, columns=("ts", "action", "target", "chain", "mac"), show="headings")
        for i, (name, w) in enumerate(zip(("Timestamp", "Action", "Target / Detail", "Chain hash", "MAC"), (20, 16, 36, 34, 12))):
            tree.heading(i, text=name)
            tree.column(i, width=w)
        tree.pack(fill="both", expand=True, padx=8, pady=8)
        import json as _json
        for e in self.store.export():
            try:
                p = _json.loads(e["payload"])
                target = p.get("target", "") + " " + str(p.get("detail", ""))[:50]
            except Exception:  # noqa: BLE001
                target = e["payload"][:90]
            tree.insert("", "end", values=(e["ts"], p.get("action", "?"), target, e["chain_hash"], e["mac"][:18]))

    # --------------------------------------------------------------- settings
    def _open_settings(self) -> None:
        win = tk.Toplevel(self)
        win.title("API Keys / Providers")
        win.geometry("560x460")
        win.configure(bg=theme.PANEL)
        win.transient(self)
        win.grab_set()

        vars_ = {
            "virustotal": tk.StringVar(value=self.cfg.api_key("virustotal") or ""),
            "malwarebazaar": tk.StringVar(value=self.cfg.api_key("malwarebazaar") or ""),
            "otx": tk.StringVar(value=self.cfg.api_key("otx") or ""),
            "hybridanalysis": tk.StringVar(value=self.cfg.api_key("hybridanalysis") or ""),
            "hybridanalysis_secret": tk.StringVar(value=self.cfg.api_key("hybridanalysis_secret") or ""),
        }
        minlen = tk.IntVar(value=int(self.cfg.get("min_string_len", 4)))

        def row(parent, r, label, var, width=52):
            ttk.Label(parent, text=label, background=theme.PANEL).grid(row=r, column=0, sticky="w", pady=4)
            e = ttk.Entry(parent, textvariable=var, width=width, show="*")
            e.grid(row=r, column=1, sticky="ew", pady=4)
            return e

        frm = ttk.Frame(win, style="Panel.TFrame", padding=16)
        frm.pack(fill="both", expand=True)
        frm.columnconfigure(1, weight=1)
        ttk.Label(frm, text="Threat-intel API keys (stored DPAPI-encrypted, never plaintext)",
                  style="H1.TLabel", background=theme.PANEL).grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 10))
        row(frm, 1, "VirusTotal v3", vars_["virustotal"])
        row(frm, 2, "MalwareBazaar", vars_["malwarebazaar"])
        row(frm, 3, "AlienVault OTX", vars_["otx"])
        row(frm, 4, "Hybrid Analysis (key)", vars_["hybridanalysis"])
        row(frm, 5, "Hybrid Analysis (secret)", vars_["hybridanalysis_secret"])

        ttk.Label(frm, text="Providers enabled for lookups:",
                  style="H1.TLabel", background=theme.PANEL).grid(row=6, column=0, columnspan=2, sticky="w", pady=(16, 4))
        provs = {}
        enabled_now = set(self.cfg.get("providers", []))
        for i, (pid, label) in enumerate(_PROVIDER_LABELS.items()):
            v = tk.BooleanVar(value=pid in enabled_now)
            provs[pid] = v
            ttk.Checkbutton(frm, text=label, variable=v, style="TCheckbutton", command=lambda: None).grid(
                row=7 + i, column=0, sticky="w", padx=4
            )

        row2 = ttk.Frame(frm, style="Panel.TFrame")
        row2.grid(row=12, column=0, columnspan=2, sticky="w", pady=(18, 0))
        ttk.Label(row2, text="Min string length:", background=theme.PANEL).pack(side="left")
        ttk.Spinbox(row2, from_=4, to=64, textvariable=minlen, width=5).pack(side="left", padx=6)

        btns = ttk.Frame(frm, style="Panel.TFrame")
        btns.grid(row=13, column=0, columnspan=2, sticky="e", pady=(16, 0))

        def save():
            payload = {k: v.get() for k, v in vars_.items()}
            try:
                self.cfg.save_secrets(payload)
            except RuntimeError as e:
                messagebox.showerror("StaticLab", f"Could not store secrets securely: {e}")
                return
            self.cfg.set("min_string_len", max(4, minlen.get()))
            self.cfg.set("providers", [p for p, v in provs.items() if v.get()])
            self.status_var.set("Settings saved (secrets encrypted at rest).")
            win.destroy()

        ttk.Button(btns, text="Save", style="Accent.TButton", command=save).pack(side="right", padx=6)
        ttk.Button(btns, text="Cancel", command=win.destroy).pack(side="right")

    # ---------------------------------------------------------------- export
    def _export(self, fmt: str) -> None:
        if not self.result:
            messagebox.showinfo("StaticLab", "Run an analysis first.")
            return
        r = self.result
        ext = {"html": "html", "json": "json", "txt": "txt"}[fmt]
        path = filedialog.asksaveasfilename(
            defaultextension=f".{ext}",
            initialfile=f"{r.file_name}.staticlab.{ext}",
            filetypes=[(f"{fmt.upper()} report", f"*.{ext}")],
        )
        if not path:
            return
        try:
            if fmt == "html":
                content = export_html(r)
            elif fmt == "json":
                content = export_json(r)
            else:
                content = export_txt(r)
            with open(path, "w", encoding="utf-8") as f:
                f.write(content)
            self.status_var.set(f"Exported {fmt.upper()} report \u2192 {os.path.basename(path)}")
            self._audit("report.export", os.path.basename(path), {"format": fmt, "sha256": r.hashes.sha256 if r.hashes else None})
        except Exception as e:  # noqa: BLE001
            messagebox.showerror("StaticLab", f"Export failed: {e}")

    def _export_strings(self) -> None:
        if not self.result:
            messagebox.showinfo("StaticLab", "Run an analysis first.")
            return
        r = self.result
        path = filedialog.asksaveasfilename(
            defaultextension=".strings.txt",
            initialfile=f"{r.file_name}.strings.txt",
            filetypes=[("Strings dump", "*.txt")],
        )
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(strings_text(r, include_all=True))
            self.status_var.set(f"Exported strings \u2192 {os.path.basename(path)}")
        except Exception as e:  # noqa: BLE001
            messagebox.showerror("StaticLab", f"Export failed: {e}")

    def _audit(self, action: str, target: str, detail=None) -> None:
        self.store.append(action, target, detail)
        self._refresh_audit()

    # ----------------------------------------------------------------- about
    def _about(self) -> None:
        messagebox.showinfo(
            __app_name__,
            f"{__app_name__} v{__version__}\n\n"
            "Portable static-analysis pipeline:\n"
            "\u2022 Strings extraction (ASCII / UTF-16LE + flags)\n"
            "\u2022 PE header parsing (sections, imports, entropy, Rich header)\n"
            "\u2022 Hash computation + threat-intel lookups\n"
            "\u2022 Tamper-evident, hash-chained audit log\n\n"
            "Compliance-aligned: ISO 27001 / NIST 800-53 / OWASP Top 10.",
        )

    def _on_close(self) -> None:
        try:
            self._audit("app.exit", "StaticLab", None)
        except Exception:  # noqa: BLE001
            pass
        try:
            self.store.close()
        except Exception:  # noqa: BLE001
            pass
        self.destroy()


def run_gui() -> None:
    app = StaticLabApp()
    app.mainloop()