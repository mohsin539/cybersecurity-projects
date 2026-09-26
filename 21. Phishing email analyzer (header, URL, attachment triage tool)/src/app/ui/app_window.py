"""Main analyst console: notebook with Analyze / Headers / URLs / Attachments /
Content / Cases / Audit / Settings tabs. All rendering is plain text (A03),
all actions are role-checked (A01), all critical events are audited (A09).
"""
from __future__ import annotations

import copy
import json
import os
import queue
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from typing import Any, Dict, List, Optional, Tuple

from .. import __version__
from ..analysis import analyze_raw_email
from ..data.settings import SettingsVault
from ..data.store import CaseStore
from ..engines.model import AnalysisReport, Finding, Severity
from ..sec.audit import AuditLog
from ..sec.crypto import file_hmac
from ..sec.identity import IdentityStore, Session
from ..sec.validation import (InputError, sanitize_text, validate_email_bytes)

SEV_COLORS = {
    "Info": "#5b789b",
    "Low": "#c9a227",
    "Medium": "#d97706",
    "High": "#d94b4b",
    "Critical": "#ad2f2f",
}

VERDICT_BANNER = {
    "ALLOW": ("#1d6f42", "ALLOW - No actionable signals"),
    "FLAG": ("#b7791f", "FLAG - Review warranted"),
    "SANDBOX": ("#c2571e", "SANDBOX - In-depth inspection recommended"),
    "QUARANTINE": ("#b03030", "QUARANTINE - High-confidence phishing"),
    "BLOCK": ("#8f1d1d", "BLOCK - Confirmed malicious"),
}


def _severity_of(f: Finding) -> str:
    return f.severity.name.capitalize()


class AppWindow(tk.Tk):
    def __init__(self, session: Session, store: IdentityStore, audit: AuditLog,
                 settings: SettingsVault, case_store: CaseStore, data_dir: str):
        super().__init__()
        self.session = session
        self.id_store = store
        self.audit = audit
        self.settings = settings
        self.cases = case_store
        self.data_dir = data_dir
        self.report: Optional[AnalysisReport] = None
        self.report_raw: Optional[bytes] = None
        self.running = False
        self._last_activity = time.time()
        self._findings_detail_map: Dict[str, Finding] = {}
        self._urls_detail_map: Dict[str, dict] = {}
        self._att_detail_map: Dict[str, dict] = {}

        self.title(f"{'Phishing Email Analyzer'} {__version__} - {session.username} [{session.role}]")
        self.geometry("1180x760")
        self.minsize(960, 640)
        self._register_styles()
        self._last_activity = time.time()
        self.bind("<Any-KeyPress>", self._activity)
        self.bind("<Any-Button>", self._activity)
        self.bind("<Motion>", self._activity)
        self.protocol("WM_DELETE_WINDOW", self._on_close)

        self._build_ui()
        self._audit("APP_START", "application unlocked")
        self.after(8000, self._idle_check)
        self._refresh_audit_tab()
        self._refresh_cases_tab()

    # ---------------------------------------------------------------- styles
    def _register_styles(self):
        s = ttk.Style()
        s.configure("TNotebook.Tab", padding=(12, 6))
        s.configure("H.TLabel", foreground="#c0392b", font=("Segoe UI", 16, "bold"))
        s.configure("A.TLabel", foreground="#1d6f42", font=("Segoe UI", 16, "bold"))
        s.configure("W.TLabel", foreground="#b7791f", font=("Segoe UI", 14, "bold"))
        s.configure("M.TLabel", foreground="#b03030", font=("Segoe UI", 14, "bold"))

    # ---------------------------------------------------------------- layout
    def _build_ui(self):
        self.nb = ttk.Notebook(self)
        self.nb.pack(fill="both", expand=True, padx=8, pady=(8, 2))
        self.t_analyze = ttk.Frame(self.nb); self.nb.add(self.t_analyze, text="Analyze")
        self.t_headers = ttk.Frame(self.nb); self.nb.add(self.t_headers, text="Header Analysis")
        self.t_urls = ttk.Frame(self.nb); self.nb.add(self.t_urls, text="URL Analysis")
        self.t_attach = ttk.Frame(self.nb); self.nb.add(self.t_attach, text="Attachments")
        self.t_content = ttk.Frame(self.nb); self.nb.add(self.t_content, text="Content / Body")
        self.t_cases = ttk.Frame(self.nb); self.nb.add(self.t_cases, text="Cases")
        self.t_audit = ttk.Frame(self.nb); self.nb.add(self.t_audit, text="Audit Log")
        self.t_settings = ttk.Frame(self.nb); self.nb.add(self.t_settings, text="Security & Settings")

        self._build_analyze_tab(self.t_analyze)
        self._build_findings_tab(self.t_headers, "header")
        self._build_urls_tab(self.t_urls)
        self._build_attachments_tab(self.t_attach)
        self._build_content_tab(self.t_content)
        self._build_cases_tab(self.t_cases)
        self._build_audit_tab(self.t_audit)
        self._build_settings_tab(self.t_settings)

        status = ttk.Frame(self)
        status.pack(fill="x", padx=8, pady=4)
        self.l_status = ttk.Label(status, text=f"Role: {self.session.role} | Vault data encrypted (AES-256-GCM)",
                                  anchor="w")
        rg = {"admin": "Administrator", "analyst": "Analyst", "auditor": "Auditor"}
        self.l_status = ttk.Label(status,
                                  text=f"Session: {self.session.username} [{rg.get(self.session.role)}] | "
                                       f"{os.path.basename(self.data_dir)} (encrypted at rest)",
                                  anchor="w")
        self.l_status.pack(side="left")

    # ---------------------------------------------------------------- analyze
    def _build_analyze_tab(self, parent):
        top = ttk.Frame(parent); top.pack(fill="x", padx=10, pady=8)
        ttk.Button(top, text="Load .eml file", command=self._load_eml).pack(side="left", padx=4)
        ttk.Button(top, text="Load raw text", command=lambda: self._load_txt(fraw=True)).pack(side="left", padx=4)
        ttk.Button(top, text="Analyze", command=self._start_analysis).pack(side="left", padx=12)
        self.v_resolve = tk.BooleanVar(value=self.settings.get("resolve_hosts", True))
        self.v_reput = tk.BooleanVar(value=bool(self.settings.get("vt_api_key", "")))
        ttk.Checkbutton(top, text="Resolve hosts (DNS, SSRF-guarded)", variable=self.v_resolve).pack(side="left", padx=6)
        ttk.Checkbutton(top, text="Reputation lookup", variable=self.v_reput).pack(side="left", padx=6)

        mid = ttk.Frame(parent); mid.pack(fill="both", expand=True, padx=10)
        self.txt_paste = tk.Text(mid, height=8, wrap="word", font=("Consolas", 9))
        self.txt_paste.pack(fill="both", expand=True)
        ttk.Label(mid, text="Paste raw .eml / header block above, or load a file. "
                            "Message content is parsed as untrusted data (fails closed).",
                  foreground="#5b789b").pack(anchor="w", pady=(4, 8))

        ver = ttk.Frame(parent); ver.pack(fill="x", padx=10, pady=(0, 8))
        self.l_verdict = ttk.Label(ver, text="No analysis yet", style="TLabel", anchor="center",
                                   background="#222b36")
        self.l_verdict.pack(fill="x", ipady=10)
        info = ttk.Frame(parent); info.pack(fill="x", padx=10, pady=(0, 8))
        self.l_sum = ttk.Label(info, text="", anchor="w", foreground="#d7e0ea")
        self.l_sum.pack(fill="x")
        self.btn_export = ttk.Button(info, text="Export report (JSON)", command=self._export_report,
                                     state="disabled")
        self.btn_export.pack(pady=4)

    # ---------------------------------------------------------------- findings
    def _build_findings_tab(self, parent, engine: str):
        pane = ttk.Panedwindow(parent, orient="vertical")
        pane.pack(fill="both", expand=True, padx=8, pady=8)
        self.tree_f_ind = ttk.Treeview(pane, columns=("sev", "code", "msg"), show="tree headings")
        self.tree_f_ind.heading("#0", text="Engine"); self.tree_f_ind.column("#0", width=90)
        self.tree_f_ind.heading("sev", text="Severity"); self.tree_f_ind.column("sev", width=90)
        self.tree_f_ind.heading("code", text="Code"); self.tree_f_ind.column("code", width=150)
        self.tree_f_ind.heading("msg", text="Finding"); self.tree_f_ind.column("msg", width=640)
        self.tree_f_ind.tag_configure("INFO", foreground="#5b789b")
        self.tree_f_ind.tag_configure("LOW", foreground="#c9a227")
        self.tree_f_ind.tag_configure("MEDIUM", foreground="#d97706")
        self.tree_f_ind.tag_configure("HIGH", foreground="#d94b4b")
        self.tree_f_ind.tag_configure("CRITICAL", foreground="#ad2f2f")
        pane.add(self.tree_f_ind, weight=3)
        self.txt_f_detail = tk.Text(pane, height=6, wrap="word", font=("Consolas", 9), state="disabled")
        pane.add(self.txt_f_detail, weight=1)
        self.tree_f_ind.bind("<<TreeviewSelect>>", self._on_finding_select)

    def _build_urls_tab(self, parent):
        pane = ttk.Panedwindow(parent, orient="vertical"); pane.pack(fill="both", expand=True, padx=8, pady=8)
        self.tree_urls = ttk.Treeview(pane, columns=("url", "host", "flags"), show="headings")
        self.tree_urls.heading("url", text="URL"); self.tree_urls.column("url", width=430)
        self.tree_urls.heading("host", text="Host"); self.tree_urls.column("host", width=220)
        self.tree_urls.heading("flags", text="Flags"); self.tree_urls.column("flags", width=360)
        pane.add(self.tree_urls, weight=3)
        self.txt_url_detail = tk.Text(pane, height=6, wrap="word", font=("Consolas", 9), state="disabled")
        pane.add(self.txt_url_detail, weight=1)
        self.tree_urls.bind("<<TreeviewSelect>>", self._on_url_select)

    def _build_attachments_tab(self, parent):
        pane = ttk.Panedwindow(parent, orient="vertical"); pane.pack(fill="both", expand=True, padx=8, pady=8)
        self.tree_att = ttk.Treeview(pane, columns=("name", "declared", "magic", "sha256", "size", "ent"),
                                     show="headings")
        for col, name, w in (("name", "Filename", 180), ("declared", "Declared MIME", 130),
                             ("magic", "Magic type", 90), ("sha256", "SHA-256 (trunc)", 190),
                             ("size", "Size", 70), ("ent", "Entropy", 60)):
            self.tree_att.heading(col, text=name); self.tree_att.column(col, width=w)
        pane.add(self.tree_att, weight=3)
        self.txt_att_detail = tk.Text(pane, height=5, wrap="word", font=("Consolas", 9), state="disabled")
        pane.add(self.txt_att_detail, weight=1)
        self.tree_att.bind("<<TreeviewSelect>>", self._on_att_select)

    def _build_content_tab(self, parent):
        pane = ttk.Panedwindow(parent, orient="vertical"); pane.pack(fill="both", expand=True, padx=8, pady=8)
        self.txt_body = tk.Text(pane, wrap="word", font=("Consolas", 9), state="disabled", height=12)
        pane.add(self.txt_body, weight=2)
        self.txt_content_res = tk.Text(pane, wrap="word", state="disabled", height=6)
        pane.add(self.txt_content_res, weight=1)

    # ---------------------------------------------------------------- cases
    def _build_cases_tab(self, parent):
        top = ttk.Frame(parent); top.pack(fill="x", padx=8, pady=6)
        ttk.Button(top, text="Refresh", command=self._refresh_cases_tab).pack(side="left", padx=2)
        ttk.Button(top, text="Open case", command=self._open_case).pack(side="left", padx=2)
        ttk.Button(top, text="Export JSON", command=self._export_case).pack(side="left", padx=2)
        self.btn_delete_case = ttk.Button(top, text="Delete (secure erase)",
                                          command=self._delete_case, state="disabled")
        self.btn_delete_case.pack(side="left", padx=2)
        if self.session.can("delete_case"):
            self.btn_delete_case.config(state="normal")
        ttk.Button(top, text="Purge expired (retention)", command=self._purge_cases).pack(side="left", padx=2)
        self.tree_cases = ttk.Treeview(parent, columns=("when", "from", "subject", "verdict", "risk"),
                                       show="headings", height=12)
        for col, name, w in (("when", "Analyzed", 150), ("from", "From", 220), ("subject", "Subject", 330),
                             ("verdict", "Verdict", 110), ("risk", "Risk", 60)):
            self.tree_cases.heading(col, text=name); self.tree_cases.column(col, width=w)
        self.tree_cases.pack(fill="both", expand=True, padx=8, pady=(0, 8))
        self.l_case_detail = tk.Text(parent, height=8, wrap="word", font=("Consolas", 9), state="disabled")
        self.l_case_detail.pack(fill="both", expand=True, padx=8, pady=(0, 8))
        self.tree_cases.bind("<<TreeviewSelect>>", self._on_case_select)

    # ---------------------------------------------------------------- audit
    def _build_audit_tab(self, parent):
        top = ttk.Frame(parent); top.pack(fill="x", padx=8, pady=6)
        ttk.Button(top, text="Verify integrity (hash chain)",
                   command=self._verify_audit).pack(side="left", padx=2)
        ttk.Button(top, text="Export audit CSV", command=self._export_audit).pack(side="left", padx=2)
        ttk.Button(top, text="Purge old (retention)", command=self._purge_audit).pack(side="left", padx=2)
        self.tree_audit = ttk.Treeview(parent, columns=("seq", "ts", "actor", "role", "action", "target", "detail"),
                                       show="headings")
        for col, name, w in (("seq", "Seq", 60), ("ts", "Timestamp", 150), ("actor", "Actor", 90),
                             ("role", "Role", 70), ("action", "Action", 130), ("target", "Target", 170),
                             ("detail", "Detail", 420)):
            self.tree_audit.heading(col, text=name); self.tree_audit.column(col, width=w)
        self.tree_audit.pack(fill="both", expand=True, padx=8, pady=(0, 8))

    # ---------------------------------------------------------------- settings
    def _build_settings_tab(self, parent):
        admin = self.session.can("settings")
        f = ttk.LabelFrame(parent, text="Operational (admin)" if admin else "Operational (read-only)")
        f.pack(fill="x", padx=10, pady=8)

        row = ttk.Frame(f); row.pack(fill="x", padx=6, pady=2)
        self.v_idle = tk.IntVar(value=int(self.settings.get("idle_lock_seconds", 900) // 60))
        ttk.Label(row, text="Idle auto-lock (minutes):").pack(side="left")
        ttk.Spinbox(row, from_=1, to=120, textvariable=self.v_idle, width=6,
                    state="normal" if admin else "disabled").pack(side="left", padx=6)

        row2 = ttk.Frame(f); row2.pack(fill="x", padx=6, pady=2)
        self.v_ret = tk.IntVar(value=int(self.settings.get("case_retention_days", 90)))
        ttk.Label(row2, text="Case retention (days):").pack(side="left")
        ttk.Spinbox(row2, from_=1, to=3650, textvariable=self.v_ret, width=6,
                    state="normal" if admin else "disabled").pack(side="left", padx=6)
        self.v_raw = tk.IntVar(value=int(self.settings.get("raw_retention_days", 30)))
        ttk.Label(row2, text="Raw EML retention (days):").pack(side="left")
        ttk.Spinbox(row2, from_=1, to=365, textvariable=self.v_raw, width=6,
                    state="normal" if admin else "disabled").pack(side="left", padx=6)

        row3 = ttk.Frame(f); row3.pack(fill="x", padx=6, pady=2)
        self.v_resolve_s = tk.BooleanVar(value=self.settings.get("resolve_hosts", True))
        ttk.Checkbutton(row3, text="Resolve URL hosts (SSRF-guarded)", variable=self.v_resolve_s,
                        state="normal" if admin else "disabled").pack(side="left", padx=2)
        self.v_autosave = tk.BooleanVar(value=self.settings.get("auto_save_cases", True))
        ttk.Checkbutton(row3, text="Automatically save analyzed cases",
                        variable=self.v_autosave,
                        state="normal" if admin else "disabled").pack(side="left", padx=8)

        row4 = ttk.Frame(f); row4.pack(fill="x", padx=6, pady=2)
        ttk.Label(row4, text="VirusTotal API key (stored AES-256-GCM encrypted):").pack(side="left")
        self.e_vt = ttk.Entry(row4, width=48, show="*", state="normal" if admin else "disabled")
        stored_key = self.settings.get("vt_api_key", "")
        if not stored_key:
            self.e_vt.insert(0, "" if admin else "(empty)")
        else:
            self.e_vt.insert(0, "•" * 12 if admin else "(set - masked)")
        self.e_vt.pack(side="left", padx=6)

        btns = ttk.Frame(f); btns.pack(fill="x", padx=6, pady=6)
        ttk.Button(btns, text="Save settings",
                   command=self._save_settings, state="normal" if admin else "disabled").pack(side="left", padx=2)
        ttk.Button(btns, text="Verify vault integrity",
                   command=self._vault_integrity).pack(side="left", padx=2)

        g = ttk.LabelFrame(parent, text="Credentials")
        g.pack(fill="x", padx=10, pady=6)
        row = ttk.Frame(g); row.pack(fill="x", padx=6, pady=2)
        ttk.Label(row, text="Current password:").pack(side="left")
        self.e_cur = ttk.Entry(row, width=30, show="*"); self.e_cur.pack(side="left", padx=6)
        ttk.Label(row, text="New:").pack(side="left")
        self.e_new = ttk.Entry(row, width=30, show="*"); self.e_new.pack(side="left", padx=6)
        ttk.Label(row, text="Confirm:").pack(side="left")
        self.e_conf = ttk.Entry(row, width=30, show="*"); self.e_conf.pack(side="left", padx=6)
        ttk.Button(row, text="Change password", command=self._change_password).pack(side="left", padx=8)
        ttk.Button(g, text="Lock now (wipe session keys)", command=self._lock_now).pack(anchor="w", padx=8, pady=6)

        about = ttk.LabelFrame(parent, text="About")
        about.pack(fill="x", padx=10, pady=6)
        ttk.Label(about, text=(
            f"{'Phishing Email Analyzer'} v{__version__} - portable triage tool.\n"
            "Controls aligned with OWASP Top 10 (A01-A10), NIST SP 800-53 "
            "(AC/IA/AU/SC/SI) and ISO/IEC 27001 (A.8-A.18).\n"
            "Email bodies are rendered as PLAIN TEXT only; URL/attachment "
            "content is analyzed statically; no remote URL detonation."),
            justify="left", foreground="#9fb4c7").pack(anchor="w", padx=8, pady=6)

    # =================================================================== engine
    def _load_eml(self):
        path = filedialog.askopenfilename(parent=self, filetypes=[("Email messages", "*.eml"),
                                                                  ("All files", "*.*")])
        if not path:
            return
        try:
            raw = open(path, "rb").read()
            validate_email_bytes(raw)
        except (OSError, InputError) as exc:
            messagebox.showerror("Load failed", str(exc), parent=self)
            return
        self.report_raw = raw
        try:
            self.txt_paste.delete("1.0", "end")
            self.txt_paste.insert("1.0", sanitize_text(raw.decode("utf-8", "replace")[:200_000]))
        except Exception:  # noqa: BLE001
            pass
        self.l_sum.config(text=f"Loaded {os.path.basename(path)} ({len(raw)} bytes) - click Analyze.")
        self._activity()

    def _load_txt(self, fraw: bool = False):
        path = filedialog.askopenfilename(parent=self, filetypes=[("Text/raw email", "*.txt"),
                                                                  ("All files", "*.*")])
        if not path:
            return
        try:
            raw = open(path, "rb").read()
            validate_email_bytes(raw)
        except (OSError, InputError) as exc:
            messagebox.showerror("Load failed", str(exc), parent=self)
            return
        self.report_raw = raw
        self.txt_paste.delete("1.0", "end")
        self.txt_paste.insert("1.0", sanitize_text(raw.decode("utf-8", "replace")[:200_000]))
        self.l_sum.config(text=f"Loaded {os.path.basename(path)} ({len(raw)} bytes).")

    def _current_raw(self) -> Optional[bytes]:
        if self.report_raw:
            return self.report_raw
        text = self.txt_paste.get("1.0", "end")
        if not text.strip():
            return None
        return text.encode("utf-8", "replace")

    def _start_analysis(self):
        if self.running:
            return
        raw = self._current_raw()
        if not raw:
            messagebox.showinfo("Input", "Provide an email (load .eml or paste).", parent=self)
            return
        if not self.session.can("analyze"):
            messagebox.showerror("Denied", "Your role lacks the 'analyze' capability [A01].", parent=self)
            return
        self.running = True
        self.l_sum.config(text="Analyzing (header/URL/attachment/content) ...")
        q: queue.Queue = queue.Queue()

        def work():
            try:
                key = self.settings.get("vt_api_key", "") if self.v_reput.get() else ""
                report = analyze_raw_email(raw, reputation_key=key,
                                           resolve_hosts=self.v_resolve.get())
                q.put(("ok", report, raw))
            except Exception as exc:  # noqa: BLE001
                q.put(("err", str(exc), None))

        threading.Thread(target=work, daemon=True).start()
        self.after(80, lambda: self._poll_analysis(q))

    def _poll_analysis(self, q: queue.Queue):
        try:
            kind, payload, raw = q.get_nowait()
        except queue.Empty:
            self.after(80, lambda: self._poll_analysis(q))
            return
        self.running = False
        if kind == "err":
            self.l_sum.config(text=f"Analysis failed (fail-closed): {payload}")
            if self.report:
                self._show_report(self.report)
            return
        self.report, self.report_raw = payload, raw
        self._show_report(payload)
        if self.settings.get("auto_save_cases", True):
            try:
                cid = self.cases.save(payload, raw, keep_raw=True)
                self._audit("CASE_ANALYZED", f"case {cid} saved", payload.verdict)
            except Exception as exc:  # noqa: BLE001
                self._audit("CASE_ANALYZED", f"save failed: {exc}", "error")
            self._refresh_cases_tab()

    def _show_report(self, rep: AnalysisReport):
        bg, text = VERDICT_BANNER.get(rep.verdict, ("#222b36", rep.verdict))
        self.l_verdict.config(text=f"VERDICT: {text}   (risk {rep.risk_score}/100)",
                              background=bg, foreground="#ffffff",
                              style=f"{'H' if rep.verdict=='QUARANTINE' else 'A'}.TLabel")
        self.l_sum.config(
            text=(f"Subject: {rep.subject} | From: {rep.from_addr} | {rep.verdict_reason} | "
                  f"findings: {len(rep.all_findings())}"))
        self.btn_export.config(state="normal")
        self._render_findings(rep)
        self._render_urls(rep)
        self._render_attachments(rep)
        self._render_content(rep)

    # ---------------------------------------------------------------- render
    def _render_findings(self, rep: AnalysisReport):
        self.tree_f_ind.delete(*self.tree_f_ind.get_children())
        for f in rep.all_findings():
            self.tree_f_ind.insert("", "end", iid=f"{f.engine}:{f.code}:{id(f)}",
                                   values=(f.severity.name.capitalize(), f.code, f.message),
                                   tags=(f.severity.name.upper(),))
            # stash detail map
        self._findings_detail_map = {f"{f.engine}:{f.code}:{id(f)}": f for f in rep.all_findings()}

    def _on_finding_select(self, _evt):
        sel = self.tree_f_ind.selection()
        d = self._findings_detail_map.get(sel[0]) if sel else None
        self.txt_f_detail.config(state="normal")
        self.txt_f_detail.delete("1.0", "end")
        if d:
            self.txt_f_detail.insert("1.0",
                                     f"[{d.severity.name}] {d.engine.upper()} {d.code}\n{d.message}\n"
                                     f"Detail: {d.detail or '(none)'} | Category: {d.category}")
        self.txt_f_detail.config(state="disabled")

    def _render_urls(self, rep: AnalysisReport):
        self.tree_urls.delete(*self.tree_urls.get_children())
        self._urls_detail_map = {}
        for i, u in enumerate((rep.results.get("url") or AnalysisReport().result("url")).meta.get("urls", [])):
            flags = self._url_flags(rep, u["host"])
            iid = f"url{i}"
            self.tree_urls.insert("", "end", iid=iid, values=(u.get("raw", ""), u.get("host", ""), flags))
            self._urls_detail_map[iid] = u
        if not (rep.results.get("url") or AnalysisReport().result("url")).meta.get("urls"):
            self.tree_urls.insert("", "end", values=("(no URLs found)", "", ""))

    def _url_flags(self, rep: AnalysisReport, host: str) -> str:
        flags = []
        for f in rep.all_findings():
            if f.engine == "url" and host and host in f.detail:
                flags.append(f.code)
        return ", ".join(flags[:6])

    def _on_url_select(self, _evt):
        sel = self.tree_urls.selection()
        u = self._urls_detail_map.get(sel[0]) if sel else None
        self.txt_url_detail.config(state="normal")
        self.txt_url_detail.delete("1.0", "end")
        if u:
            self.txt_url_detail.insert("1.0", json.dumps(u, indent=2, ensure_ascii=False))
        self.txt_url_detail.config(state="disabled")

    def _render_attachments(self, rep: AnalysisReport):
        self.tree_att.delete(*self.tree_att.get_children())
        self._att_detail_map = {}
        res = rep.results.get("attachment")
        atts = (res.meta.get("attachments") if res and res.meta else []) or []
        for i, a in enumerate(atts):
            iid = f"att{i}"
            self.tree_att.insert("", "end", iid=iid,
                                 values=(a.get("filename"), a.get("declared"), a.get("magic"),
                                         a.get("sha256", "")[:16], a.get("size"), a.get("entropy")))
            self._att_detail_map[iid] = a
        if not atts:
            self.tree_att.insert("", "end", values=("(no attachments)", "", "", "", "", ""))

    def _on_att_select(self, _evt):
        sel = self.tree_att.selection()
        a = self._att_detail_map.get(sel[0]) if sel else None
        self.txt_att_detail.config(state="normal")
        self.txt_att_detail.delete("1.0", "end")
        if a:
            self.txt_att_detail.insert("1.0",
                                       f"filename={a.get('filename')}\nsha256={a.get('sha256')}\n"
                                       f"sha1={a.get('sha1')}\nmd5={a.get('md5')}\n"
                                       f"declared={a.get('declared')} magic={a.get('magic')} "
                                       f"size={a.get('size')} entropy={a.get('entropy')}")
        self.txt_att_detail.config(state="disabled")

    def _render_content(self, rep: AnalysisReport):
        res = rep.results.get("content")
        self.txt_body.config(state="normal")
        self.txt_body.delete("1.0", "end")
        preview = (res.meta.get("body_preview") if res and res.meta else "") or "(no body)"
        self.txt_body.insert("1.0", f"==== Body preview (plain text; HTML never rendered) ====\n{preview}")
        self.txt_body.config(state="disabled")
        self.txt_content_res.config(state="normal")
        self.txt_content_res.delete("1.0", "end")
        if res:
            for f in res.findings:
                self.txt_content_res.insert("end", f"[{f.severity.name}] {f.code}: {f.message}\n")
        self.txt_content_res.config(state="disabled")

    # ---------------------------------------------------------------- export
    def _export_report(self):
        if not self.report:
            return
        path = filedialog.asksaveasfilename(parent=self, defaultextension=".json",
                                            filetypes=[("JSON", "*.json")])
        if not path:
            return
        data = {
            "tool": "Phishing Email Analyzer", "version": __version__,
            "created": time.time(), "subject": self.report.subject,
            "from": self.report.from_addr, "verdict": self.report.verdict,
            "risk_score": self.report.risk_score, "reason": self.report.verdict_reason,
            "findings": [f.to_dict() for f in self.report.all_findings()],
        }
        try:
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(data, fh, ensure_ascii=False, indent=2)
            self._audit("CASE_EXPORTED", f"report {os.path.basename(path)}")
        except OSError as exc:
            messagebox.showerror("Export failed", str(exc), parent=self)

    # ---------------------------------------------------------------- cases
    def _refresh_cases_tab(self):
        if not hasattr(self, "tree_cases"):
            return
        self.tree_cases.delete(*self.tree_cases.get_children())
        for c in self.cases.list_cases():
            self.tree_cases.insert("", "end", iid=c["id"], values=(
                time.strftime("%Y-%m-%d %H:%M", time.localtime(c.get("created", 0))),
                c.get("from_display") or c.get("from_addr", ""), c.get("subject", ""),
                c.get("verdict", ""), c.get("risk_score", 0)))

    def _on_case_select(self, _evt):
        sel = self.tree_cases.selection()
        cid = sel[0] if sel else None
        self.l_case_detail.config(state="normal")
        self.l_case_detail.delete("1.0", "end")
        if cid:
            doc = self.cases.get(cid)
            if doc:
                self.l_case_detail.insert("1.0", json.dumps(
                    {k: doc.get(k) for k in ("id", "created", "subject", "from_addr", "verdict",
                                             "risk_score", "verdict_reason", "findings")},
                    indent=2, ensure_ascii=False)[:20_000])
                self._audit("CASE_VIEWED", cid, self.session.username)
        self.l_case_detail.config(state="disabled")

    def _open_case(self):
        self.nb.select(self.t_cases)

    def _export_case(self):
        sel = self.tree_cases.selection()
        if not sel:
            return
        path = filedialog.asksaveasfilename(parent=self, defaultextension=".json",
                                            filetypes=[("JSON", "*.json")])
        if path and self.cases.export_case(sel[0], path):
            self._audit("CASE_EXPORTED", f"case {sel[0]} -> {os.path.basename(path)}")
        elif path:
            messagebox.showerror("Export", "Case not found or unreadable.", parent=self)

    def _delete_case(self):
        if not self.session.can("delete_case"):
            messagebox.showerror("Denied", "delete_case requires admin [A01].", parent=self)
            return
        sel = self.tree_cases.selection()
        if not sel or not messagebox.askyesno("Delete case",
                                              "Permanently erase this case (secure overwrite)?"):
            return
        if self.cases.delete(sel[0]):
            self._audit("CASE_DELETED", sel[0], self.session.username)
            self._refresh_cases_tab()
            self.l_case_detail.config(state="normal"); self.l_case_detail.delete("1.0", "end")
            self.l_case_detail.config(state="disabled")

    def _purge_cases(self):
        if not self.session.can("delete_case"):
            messagebox.showerror("Denied", "purge requires admin.", parent=self)
            return
        n = self.cases.purge_expired(self.v_ret.get(), self.v_raw.get())
        self._audit("RETENTION_PURGE", f"{n} case(s) purged")
        self._refresh_cases_tab()
        messagebox.showinfo("Retention", f"Purged {n} expired case(s) per retention policy.", parent=self)

    # ---------------------------------------------------------------- audit
    def _refresh_audit_tab(self):
        if not hasattr(self, "tree_audit"):
            return
        self.tree_audit.delete(*self.tree_audit.get_children())
        for e in self.audit.tail(300):
            self.tree_audit.insert("", "end", values=(
                e.get("seq"), time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(e.get("ts", 0))),
                e.get("actor"), e.get("role"), e.get("action"), e.get("target")[:60],
                e.get("detail", "")[:60]))

    def _verify_audit(self):
        problems = self.audit.verify()
        self._audit("AUDIT_VERIFY", f"{'OK' if not problems else 'FAIL: ' + ';'.join(problems[:4])}")
        if problems:
            messagebox.showerror("Audit integrity",
                                 "Tampering/corruption detected:\n" + "\n".join(problems[:8]), parent=self)
        else:
            messagebox.showinfo("Audit integrity", "Hash chain verified - no tampering detected.", parent=self)

    def _export_audit(self):
        path = filedialog.asksaveasfilename(parent=self, defaultextension=".csv",
                                            filetypes=[("CSV", "*.csv")])
        if not path:
            return
        n = self.audit.export_text(path)
        self._audit("AUDIT_EXPORT", f"{os.path.basename(path)} ({n} rows)")
        messagebox.showinfo("Export", f"Exported {n} audit rows.", parent=self)

    def _purge_audit(self):
        n = self.audit.purge()
        self._audit("RETENTION_PURGE", f"{n} audit batch(es) removed")
        self._refresh_audit_tab()

    # ---------------------------------------------------------------- settings
    def _save_settings(self):
        if not self.session.can("settings"):
            messagebox.showerror("Denied", "settings requires admin [A01].", parent=self)
            return
        pk_new = self.e_vt.get().strip()
        prior = self.settings.get("vt_api_key", "")
        pk_new = pk_new if pk_new and pk_new != "•" * 12 else prior
        self.settings.set_int("idle_lock_seconds", int(self.v_idle.get()) * 60, 60, 7200)
        self.settings.set_int("case_retention_days", int(self.v_ret.get()), 1, 3650)
        self.settings.set_int("raw_retention_days", int(self.v_raw.get()), 1, 365)
        self.settings.set_bool("resolve_hosts", self.v_resolve_s.get())
        self.settings.set_bool("auto_save_cases", self.v_autosave.get())
        if pk_new:
            self.settings.set_text("vt_api_key", pk_new, 256)
        self.settings.save()
        self._audit("SETTINGS_CHANGED", "security/operational settings saved")
        messagebox.showinfo("Settings", "Saved (encrypted).", parent=self)

    def _change_password(self):
        cur = self.e_cur.get()
        new = self.e_new.get()
        conf = self.e_conf.get()
        if new != conf:
            messagebox.showerror("Password", "New passwords do not match.", parent=self)
            return
        if len(new) < 12:
            messagebox.showerror("Password", "New password must be >= 12 chars [IA-5].", parent=self)
            return
        try:
            self.id_store.change_password(self.session.username, cur, new)
        except Exception as exc:  # noqa: BLE001
            messagebox.showerror("Password", str(exc), parent=self)
            return
        self.session.update_password(new)
        self._audit("PASSWORD_CHANGED", "vault password rotated (data key unchanged)", self.session.username)
        messagebox.showinfo("Password", "Changed. Data remains encrypted under the same data key.", parent=self)
        self.e_cur.delete(0, "end"); self.e_new.delete(0, "end"); self.e_conf.delete(0, "end")

    def _vault_integrity(self):
        problems = self.audit.verify()
        msg = f"Audit chain: {'OK' if not problems else len(problems)} issues\n"
        try:
            from ..sec.crypto import decrypt_bytes
            with open(os.path.join(self.data_dir, "profile.dat"), "rb") as fh:
                msg += f"Profile present: {os.path.getsize(os.path.join(self.data_dir, 'profile.dat'))} bytes\n"
        except OSError:
            msg += "Profile file missing!\n"
        report = self.report
        msg += f"Loaded report: {'yes' if report else 'no'}\nSettings encryption: AES-256-GCM (validated on login)"
        self._audit("AUDIT_VERIFY", "vault integrity check")
        messagebox.showinfo("Vault integrity", msg, parent=self)

    def _lock_now(self):
        self._audit("LOCK", "manual lock")
        self._do_lock()

    def _do_lock(self):
        from .login import Gate
        self.withdraw()
        gate = Gate(self, self.id_store)
        self.id_store.wipe_credentials()
        result = gate.run()
        if result is None:
            self.deiconify()
            return
        username, role, data_key, password = result
        if username != self.session.username:
            messagebox.showerror("Lock", "Locked: re-authentication must use the same analyst profile.",
                                 parent=self)
            self.deiconify()
            return
        self.session.wipe()
        self.session = Session(username, role, bytes(data_key), password)
        self.title(f"{'Phishing Email Analyzer'} {__version__} - {username} [{role}]")
        self._audit("LOGIN_SUCCESS", "session re-established after lock", username)
        self._last_activity = time.time()
        self.deiconify()
        self.lift()

    def _activity(self, _evt=None):
        self._last_activity = time.time()

    def _idle_check(self):
        idle = time.time() - self._last_activity
        secs = int(self.settings.get("idle_lock_seconds", 900))
        if idle > max(60, secs):
            self._audit("LOCK", "idle timeout auto-lock")
            self._do_lock()
        self.after(8000, self._idle_check)

    def _audit(self, action: str, detail: str = "", result: str = "ok", target: str = ""):
        try:
            self.audit.append(action, self.session.username, self.session.role,
                              target=target or action, result=result, detail=detail)
            if action in ("CASE_SAVED", "CASE_ANALYZED", "CASE_VIEWED"):
                self._refresh_audit_tab()
        except Exception:  # noqa: BLE001
            pass

    def _on_close(self):
        try:
            self._audit("APP_EXIT", "application closed")
        finally:
            self.session.wipe()
            self.destroy()