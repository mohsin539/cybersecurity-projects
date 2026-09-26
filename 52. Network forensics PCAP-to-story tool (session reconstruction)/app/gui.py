"""gui.py - Desktop console for the PCAP-to-Story Forensics Suite.

Tabs (matching architecture.md SS4.6 presentation tier):
  1. Ingest   - import PCAP/PCAPNG with progress + integrity hashing
  2. Sessions - reconstructed session registry (drill into stories)
  3. Story    - narrative + evidence-anchored timeline replay
  4. Reports  - PDF/HTML/JSON/CSV/MD/STIX/ZIP export pipeline
  5. Audit    - append-only audit bus viewer + tamper verification
  6. About    - security posture & compliance summary
"""

from __future__ import annotations

import json
import os
import queue
import threading
import tkinter as tk
import traceback
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from . import __version__
from .core import audit, pcap_engine, reports, state, story_engine


def _risk_bg(severity: str) -> str:
    return {
        "LOW": "#065f46", "MEDIUM": "#854d0e", "HIGH": "#9a3412", "CRITICAL": "#7f1d1d",
    }.get(severity, "#334155")


class SuiteApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(f"🛰️  PCAP-to-Story Forensics Suite  v{__version__}  (Portable)")
        self.geometry("1280x760")
        self.minsize(1080, 640)
        self.db = state.StateDB()
        self.actor = "analyst"
        self.active_session_id = None
        self._job = queue.Queue()
        self._busy = False

        self._style = ttk.Style(self)
        try:
            self._style.theme_use("clam")
        except Exception:
            pass
        self._palette()
        self._build_ui()
        self.after(120, self._poll_jobs)
        self._refresh_audit()
        audit.AuditBus(self.db, self.actor).log("APP_START", "GUI session started", verdict="ALLOWED")

    # ---------------------------------------------------------------- theming
    def _palette(self):
        s = self._style
        cfg = {
            "bg": "#0f172a", "fg": "#e2e8f0", "fieldbg": "#1e293b", "border": "#334155",
            "selectbg": "#4c1d95", "selectfg": "#e9d5ff", "font": ("Segoe UI", 10),
        }
        self.configure(bg=cfg["bg"])
        s.configure(".", background=cfg["bg"], foreground=cfg["fg"], font=cfg["font"], borderwidth=0)
        s.configure("TNotebook", background=cfg["bg"], borderwidth=0)
        s.configure("TNotebook.Tab", background=cfg["fieldbg"], foreground=cfg["fg"], padding=(16, 8))
        s.map("TNotebook.Tab", background=[("selected", "#4c1d95")], foreground=[("selected", "#ffffff")])
        s.configure("TFrame", background=cfg["bg"])
        s.configure("TLabelframe", background=cfg["bg"], bordercolor=cfg["border"])
        s.configure("TLabelframe.Label", background=cfg["bg"], foreground="#a5b4fc")
        s.configure("TButton", background="#1e40af", foreground="#ffffff", padding=(10, 6))
        s.map("TButton", background=[("active", "#1d4ed8"), ("disabled", "#334155")])
        s.configure("Treeview", background=cfg["fieldbg"], fieldbackground=cfg["fieldbg"], foreground=cfg["fg"], rowheight=26, bordercolor=cfg["border"])
        s.map("Treeview", background=[("selected", cfg["selectbg"])], foreground=[("selected", cfg["selectfg"])])
        s.configure("Treeview.Heading", background="#1e293b", foreground="#c7d2fe", font=("Segoe UI", 10, "bold"))
        s.configure("TProgressbar", troughcolor=cfg["fieldbg"], background="#06b6d4", bordercolor=cfg["border"])
        s.configure("Horizontal.TProgressbar", troughcolor=cfg["fieldbg"], background="#06b6d4")
        s.configure("TEntry", fieldbackground=cfg["fieldbg"], foreground=cfg["fg"], insertcolor=cfg["fg"])
        s.configure("TCombobox", fieldbackground=cfg["fieldbg"], foreground=cfg["fg"])

    # ------------------------------------------------------------------- UI
    def _build_ui(self):
        header = tk.Frame(self, bg="#111827", padx=16, pady=10)
        header.pack(fill="x")
        tk.Label(header, text="🛰️  PCAP-to-Story  ·  Session Reconstruction Suite", font=("Segoe UI", 16, "bold"),
                 bg="#111827", fg="#a5b4fc").pack(side="left")
        tk.Label(header, text="ISO 27001 · NIST CSF 2.0 · OWASP Top 10 · MITRE ATT&CK", font=("Segoe UI", 9),
                 bg="#111827", fg="#64748b").pack(side="right")

        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, padx=6, pady=6)
        self.nb = nb
        nb.add(self._tab_ingest(), text="  📥 Ingest ")
        nb.add(self._tab_sessions(), text="  🧩 Sessions ")
        nb.add(self._tab_story(), text="  🧬 Story ")
        nb.add(self._tab_reports(), text="  📑 Reports ")
        nb.add(self._tab_audit(), text="  🕵️ Audit ")
        nb.add(self._tab_about(), text="  🔐 Security ")

        self.status = tk.Label(self, text="Ready — no capture loaded", anchor="w", padx=12, bg="#111827", fg="#94a3b8")
        self.status.pack(fill="x")

        self.report_callback_exception = self._log_callback_exception

    # ------------------------------------------------------------ error log
    @staticmethod
    def error_log_path() -> str:
        return str(Path(os.environ.get("PCAFLESS_DATA_DIR", Path.home() / ".pcapless")) / "pcapless_error.log")

    def _log_callback_exception(self, exc_type, exc, tb):
        """Route Tk callback errors to a log file instead of the default modal dialog."""
        text = "".join(traceback.format_exception(exc_type, exc, tb))
        try:
            with open(self.error_log_path(), "a", encoding="utf-8") as fo:
                fo.write(text + "\n")
            self.status.config(text=f"Callback error logged → {self.error_log_path()}", fg="#fca5a5")
        except Exception:
            pass

    @staticmethod
    def _log_raw(errors: list):
        log = SuiteApp.error_log_path()
        try:
            with open(log, "a", encoding="utf-8") as fo:
                fo.write("\n".join(errors) + "\n")
        except Exception:
            pass

    # ------------------------------------------------------------ Ingest tab
    def _tab_ingest(self):
        f = ttk.Frame(self.nb, padding=14)
        top = ttk.Frame(f); top.pack(fill="x")
        ttk.Label(top, text="Case ID:").pack(side="left")
        self.case_var = tk.StringVar(value="DEFAULT")
        ttk.Entry(top, textvariable=self.case_var, width=14).pack(side="left", padx=(4, 12))
        ttk.Label(top, text="Analyst:").pack(side="left")
        self.analyst_var = tk.StringVar(value="analyst")
        ttk.Entry(top, textvariable=self.analyst_var, width=14).pack(side="left", padx=(4, 12))
        ttk.Label(top, text="Clearance:").pack(side="left")
        self.clearance_var = tk.StringVar(value="2")
        ttk.Combobox(top, textvariable=self.clearance_var, values=["0", "1", "2"], width=4, state="readonly").pack(side="left", padx=(4, 12))
        ttk.Label(top, text="Output dir:").pack(side="left")
        self.outdir_var = tk.StringVar(value=str(Path.home() / ".pcapless" / "reports"))
        ttk.Entry(top, textvariable=self.outdir_var, width=34).pack(side="left", padx=(4, 4))
        ttk.Button(top, text="…", command=self._pick_outdir, width=3).pack(side="left")

        mid = ttk.Frame(f); mid.pack(fill="x", pady=(14, 6))
        self.file_var = tk.StringVar()
        ttk.Entry(mid, textvariable=self.file_var, state="readonly").pack(side="left", fill="x", expand=True)
        ttk.Button(mid, text="🔍 Choose PCAP / PCAPNG", command=self._choose_file).pack(side="left", padx=6)
        ttk.Button(mid, text="⚡ Reconstruct & Analyse", command=self._start_ingest).pack(side="left")

        self.progress = ttk.Progressbar(f, maximum=100)
        self.progress.pack(fill="x", pady=4)
        self.ingest_status = tk.Label(f, text="", anchor="w", bg="#0f172a", fg="#e2e8f0")
        self.ingest_status.pack(fill="x")

        summary = ttk.Labelframe(f, text="Capture integrity (pre-processing)")
        summary.pack(fill="both", expand=True, pady=(10, 0))
        self.integrity_text = tk.Text(summary, height=12, bg="#0b1220", fg="#a7f3d0", relief="flat",
                                      font=("Consolas", 10), padx=10, pady=6)
        self.integrity_text.pack(fill="both", expand=True, padx=6, pady=6)
        return f

    def _pick_outdir(self):
        d = filedialog.askdirectory(initialdir=self.outdir_var.get())
        if d:
            self.outdir_var.set(d)

    def _choose_file(self):
        p = filedialog.askopenfilename(title="Select network capture", filetypes=[
            ("Capture files", "*.pcap *.pcapng *.cap"), ("All files", "*.*")])
        if p:
            self.file_var.set(p)
            self.status.config(text=f"Selected: {p}")

    def _start_ingest(self):
        path = self.file_var.get()
        if not path or not os.path.isfile(path):
            messagebox.showwarning("Ingest", "Choose a valid capture file first.")
            return
        if self._busy:
            return
        self._busy = True
        self.ingest_status.config(text="Hashing file (SHA-256)…", fg="#c7d2fe")
        self.progress["value"] = 0
        threading.Thread(target=self._ingest_worker, args=(path,), daemon=True).start()

    def _ingest_worker(self, path: str):
        from .core.security import sha256_file as sf
        file_sha = sf(path)
        self._job.put(("sha", file_sha))
        def prog(done, total):
            self._job.put(("prog", done, total))
        try:
            res = pcap_engine.load_capture(path, prog)
        except Exception as ex:
            self._job.put(("err", str(ex)))
            return
        recs = res["sessions"]
        # build stories for each session
        for r in recs:
            story_engine.build_story(r)
        self._job.put(("done", res, recs, path, file_sha))

    # ---------------------------------------------------------- Sessions tab
    def _tab_sessions(self):
        f = ttk.Frame(self.nb, padding=10)
        runner = ttk.Frame(f); runner.pack(fill="x")
        self.sess_filter = tk.StringVar()
        ttk.Label(runner, text="Filter (src/dst/proto/l7):").pack(side="left")
        ttk.Entry(runner, textvariable=self.sess_filter).pack(side="left", fill="x", expand=True, padx=4)
        ttk.Button(runner, text="🔎 Apply", command=self._refresh_sessions).pack(side="left")
        ttk.Button(runner, text="🔄 Refresh", command=self._refresh_sessions).pack(side="left", padx=4)

        cols = ("time", "flow", "proto", "l7", "frames", "bytes", "beacon", "risk")
        tv = ttk.Treeview(f, columns=cols, show="headings")
        widths = {"time": 170, "flow": 300, "proto": 55, "l7": 70, "frames": 70, "bytes": 90, "beacon": 60, "risk": 90}
        lbl = {"time": "Start (UTC)", "flow": "Flow (5-tuple)", "proto": "Proto", "l7": "L7", "frames": "Frames",
               "bytes": "Bytes", "beacon": "Beacon", "risk": "Risk"}
        for idx in cols:
            tv.heading(idx, text=lbl[idx])
            tv.column(idx, width=widths[idx], anchor="center" if idx not in ("flow", "time") else "w")
        vs = ttk.Scrollbar(f, orient="vertical", command=tv.yview)
        tv.configure(yscrollcommand=vs.set)
        tv.pack(side="left", fill="both", expand=True, padx=(0, 6))
        vs.pack(side="right", fill="y")
        tv.bind("<Double-1>", lambda e: self._open_story_from_sessions(tv))
        self.session_tv = tv
        return f

    def _refresh_sessions(self):
        tv = self.session_tv
        tv.delete(*tv.get_children())
        for rec in self.db.session_recs():
            flt = self.sess_filter.get().lower()
            if flt and flt not in (rec["flow_key"] + " " + rec.get("l7", "") + " " + rec.get("proto", "")).lower():
                continue
            story = rec.get("story", {})
            tv.insert("", "end", iid=rec["session_id"], values=(
                rec.get("start_ts", ""), rec["flow_key"], rec.get("proto", ""), rec.get("l7", ""),
                rec.get("frames", 0), rec.get("total_bytes", 0),
                "⚠ C2" if rec.get("beacon") else "—",
                f"{story.get('severity', 'LOW')} {story.get('risk_score', 0)}",
            ))
        self.status.config(text=f"{len(tv.get_children())} sessions listed")

    def _open_story_from_sessions(self, tv):
        sel = tv.selection()
        if sel:
            self.nb.select(2)
            self.show_story(sel[0])

    # ------------------------------------------------------------- Story tab
    def _tab_story(self):
        f = ttk.Frame(self.nb, padding=10)
        left = ttk.Frame(f); left.pack(side="left", fill="both", expand=True)
        right = ttk.Frame(f); right.pack(side="right", fill="both", expand=True)

        meta = ttk.Labelframe(left, text="Flow metadata")
        meta.pack(fill="x")
        self.story_meta = tk.Text(meta, height=6, bg="#0f172a", relief="flat", font=("Segoe UI", 10), padx=10, pady=6)
        self.story_meta.pack(fill="x", padx=6, pady=6)
        self.story_meta.tag_configure("risk", foreground="#ffffff")

        nar = ttk.Labelframe(left, text="Narrative story (evidence-grounded)")
        nar.pack(fill="both", expand=True, pady=(8, 0))
        self.narrative = tk.Text(nar, bg="#0b1220", fg="#e2e8f0", relief="flat", wrap="word", font=("Segoe UI", 11), padx=10, pady=8)
        self.narrative.pack(fill="both", expand=True, padx=6, pady=6)
        self.narrative.tag_configure("head", foreground="#a5b4fc", font=("Segoe UI", 11, "bold"))

        log = ttk.Labelframe(right, text="Evidence-anchored conversation timeline")
        log.pack(fill="both", expand=True)
        cols = ("seq", "dir", "type", "details", "frame", "offset")
        tv = ttk.Treeview(log, columns=cols, show="headings")
        for idx, w, txt in (("seq", 40, "#"), ("dir", 40, "Dir"), ("type", 130, "Type"),
                            ("details", 300, "Details"), ("frame", 60, "Frame"), ("offset", 60, "Offset")):
            tv.heading(idx, text=txt); tv.column(idx, width=w, anchor="w" if idx == "details" else "center")
        tv.pack(fill="both", expand=True, padx=6, pady=6)
        self.timeline = tv
        return f

    def show_story(self, session_id: str):
        rec = self.db.session_rec(session_id)
        if not rec:
            messagebox.showerror("Story", "Session not found.")
            return
        self.active_session_id = session_id
        story = rec.get("story", {})
        self.story_meta.delete("1.0", "end")
        meta = (
            f"Session   {rec['session_id']}\r\n"
            f"Flow      {rec['flow_key']}  (L7={rec.get('l7')}, conf={rec.get('stats', {}).get('l7_confidence', 0)})\r\n"
            f"Frames    {rec.get('frames')}   Bytes {rec.get('total_bytes', 0)} (C2S {rec.get('bytes_c2s', 0)} / S2C {rec.get('bytes_s2c', 0)})\r\n"
            f"Reassembly gaps={rec.get('stats', {}).get('gaps', 0)}  retrans={rec.get('stats', {}).get('retransmits', 0)}  "
            f"beacon_score={rec.get('stats', {}).get('beacon_score', 0)}\r\n"
            f"RISK      {story.get('severity', 'LOW')} (score {story.get('risk_score', 0)})  ·  MITRE {story.get('ttp', '')}"
        )
        self.story_meta.insert("1.0", meta)
        self.story_meta.configure(fg="#a7f3d0")

        self.narrative.delete("1.0", "end")
        self.narrative.insert("end", "NARRATIVE\n", "head")
        for line in story.get("narrative", []):
            self.narrative.insert("end", f"▶ {line}\n\n")
        find = story.get("findings", [])
        if find:
            self.narrative.insert("end", "\nFINDINGS\n", "head")
            for f_ in find:
                self.narrative.insert("end", f"⚠ {f_}\n")

        tv = self.timeline
        tv.delete(*tv.get_children())
        for e in rec.get("events", []):
            tv.insert("", "end", values=(e.get("seq"), e.get("dir"), e.get("type"), str(e.get("details", ""))[:80],
                                         e.get("frame_id"), e.get("payload_offset")))
        self.status.config(text=f"Story loaded: {rec['flow_key']}")
        audit.AuditBus(self.db, self.actor).log("STORY_VIEW", session_id, evidence_hash=json.dumps(
            {"meta": {"frames": rec.get("frames"), "risk": story.get("risk_score")}})[:80])
        return rec

    # ---------------------------------------------------------- Reports tab
    def _tab_reports(self):
        f = ttk.Frame(self.nb, padding=12)
        ttk.Label(f, text="Export active session story into forensic-ready reports", font=("Segoe UI", 12, "bold")).pack(anchor="w")
        info = ttk.Labelframe(f, text="Active session (as loaded in Story tab)")
        info.pack(fill="x", pady=8)
        self.report_target = tk.Text(info, height=3, bg="#0b1220", fg="#c7d2fe", relief="flat", font=("Consolas", 10), padx=8, pady=6)
        self.report_target.pack(fill="x", padx=6, pady=6)

        btns = ttk.Labelframe(f, text="Download formats (architecture.md §9)")
        btns.pack(fill="x", pady=8)
        grid = ttk.Frame(btns); grid.pack(padx=8, pady=8)
        self.fmt_buttons = {}
        fmts = [("pdf", "📕 PDF (PAdES-ready)"), ("html", "🌐 HTML interactive"), ("json", "🧾 JSON verifiable"),
                ("csv", "📊 CSV timeline"), ("md", "📝 Markdown"), ("stix", "🛡️ STIX 2.1"), ("zip", "📦 ZIP bundle")]
        for i, (k, lbl) in enumerate(fmts):
            b = ttk.Button(grid, text=lbl, command=lambda kk=k: self._export(kk))
            b.grid(row=i // 4, column=i % 4, padx=6, pady=6)
            self.fmt_buttons[k] = b
        self.export_status = tk.Label(f, text="", anchor="w", bg="#0f172a", fg="#6ee7b7")
        self.export_status.pack(fill="x")

        hist = ttk.Labelframe(f, text="Generated report history")
        hist.pack(fill="both", expand=True, pady=(8, 0))
        cols = ("ts", "fmt", "filename", "sha", "size", "ver")
        tv = ttk.Treeview(hist, columns=cols, show="headings")
        for idx, w, t in (("ts", 160, "Created (UTC)"), ("fmt", 60, "Format"), ("filename", 320, "File"),
                          ("sha", 80, "SHA-256"), ("size", 80, "Bytes"), ("ver", 50, "Version")):
            tv.heading(idx, text=t); tv.column(idx, width=w, anchor="w" if idx == "filename" else "center")
        tv.pack(fill="both", expand=True, padx=6, pady=6)
        self.report_tv = tv
        return f

    def _refresh_reports(self):
        tv = self.report_tv
        tv.delete(*tv.get_children())
        for r in self.db.reports():
            tv.insert("", "end", values=(r["ts_created"], r["fmt"], r["filename"],
                                         r["file_sha256"][:10], r["size_bytes"], r["report_version"]))

    def _export(self, fmt: str):
        sid = self.active_session_id
        if not sid:
            messagebox.showwarning("Export", "Open a session in the Story tab first.")
            return
        rec = self.db.session_rec(sid)
        if not rec:
            return
        outdir = self.outdir_var.get() or str(Path.home() / ".pcapless" / "reports")
        try:
            res = reports.generate_report(
                rec, fmt, outdir,
                case_id=self.case_var.get() or "DEFAULT", analyst=self.analyst_var.get() or "analyst",
                clearance=int(self.clearance_var.get() or 2), evidence_root=rec["session_id"],
            )
        except Exception as ex:
            messagebox.showerror("Export failed", str(ex))
            return
        self.db.add_report(self.case_var.get() or "DEFAULT", sid, res["fmt"], res["filename"],
                           res["sha256"], res["size"])
        audit.AuditBus(self.db, self.actor).log(
            "REPORT_DOWNLOAD", f"{fmt}://{res['filename']}", evidence_hash=res["sha256"], verdict="ALLOWED")
        self.export_status.config(text=f"✔ Exported {res['filename']}  ·  sha256 {res['sha256'][:16]}…  →  {res['path']}")
        self._refresh_reports()
        self.status.config(text=f"Report {fmt} generated and audit-logged.")

    # ------------------------------------------------------------- Audit tab
    def _tab_audit(self):
        f = ttk.Frame(self.nb, padding=10)
        kpi = ttk.Frame(f); kpi.pack(fill="x")
        self.audit_kpis = {}
        for label in ("Events", "Tamper check", "Allowed", "Blocked"):
            box = tk.Frame(kpi, bg="#1e293b", padx=12, pady=6)
            box.pack(side="left", padx=6)
            tk.Label(box, text=label, bg="#1e293b", fg="#94a3b8", font=("Segoe UI", 9)).pack(anchor="w")
            val = tk.Label(box, text="0", bg="#1e293b", fg="#a5b4fc", font=("Segoe UI", 16, "bold"))
            val.pack(anchor="w")
            self.audit_kpis[label] = val
        btnbar = ttk.Frame(f); btnbar.pack(fill="x", pady=6)
        ttk.Button(btnbar, text="🔎 Verify hash-chain (tamper scan)", command=self._verify_audit).pack(side="left")
        ttk.Button(btnbar, text="💾 Export audit bundle", command=self._export_audit).pack(side="left", padx=8)

        cols = ("ts", "actor", "action", "obj", "evhash")
        tv = ttk.Treeview(f, columns=cols, show="headings")
        for idx, w, t in (("ts", 170, "Timestamp (UTC)"), ("actor", 90, "Actor"), ("action", 180, "Action"),
                          ("obj", 340, "Object"), ("evhash", 90, "Event hash")):
            tv.heading(idx, text=t); tv.column(idx, width=w, anchor="w")
        tv.pack(fill="both", expand=True)
        self.audit_tv = tv
        return f

    def _refresh_audit(self):
        tv = self.audit_tv
        tv.delete(*tv.get_children())
        for r in self.db.audit_all(limit=300):
            tv.insert("", "end", values=(r["ts"], r["actor"], r["action"], r["obj"] or "", r["event_hash"][:10]))
        self.audit_kpis["Events"].config(text=str(self.db.audit_count()))
        ok, bad = self.db.audit_verify()
        self.audit_kpis["Tamper check"].config(text="✅ Intact" if ok else f"⚠ {len(bad)} tampered")
        counts = self.db._conn.execute("SELECT verdict, COUNT(*) n FROM audit GROUP BY verdict").fetchall()
        allowed = blocked = 0
        for row in counts:
            if row["verdict"] == "BLOCKED":
                blocked = row["n"]
            else:
                allowed += row["n"]
        self.audit_kpis["Allowed"].config(text=str(allowed))
        self.audit_kpis["Blocked"].config(text=str(blocked))

    def _verify_audit(self):
        ok, bad = self.db.audit_verify()
        self._refresh_audit()
        if ok:
            messagebox.showinfo("Audit", "Hash-chain verified: no tampering detected. Chain is intact.")
        else:
            messagebox.showwarning("Audit", f"Tampering detected in audit records: IDs {bad[:8]}")
        audit.AuditBus(self.db, self.actor).log("AUDIT_VERIFY", f"chain_ok={ok}")

    def _export_audit(self):
        outdir = self.outdir_var.get() or str(Path.home() / ".pcapless" / "reports")
        os.makedirs(outdir, exist_ok=True)
        import datetime
        path = os.path.join(outdir, f"audit_bundle_{datetime.datetime.now():%Y%m%d_%H%M%S}.json")
        rows = [dict(r) for r in self.db.audit_all(limit=10000)]
        with open(path, "w", encoding="utf-8") as fo:
            json.dump({"events": rows, "verified": self.db.audit_verify()[0]}, fo, indent=2, default=str)
        audit.AuditBus(self.db, self.actor).log("AUDIT_EXPORT", path)
        messagebox.showinfo("Audit", f"Bundle written to\n{path}")

    # ------------------------------------------------------------ About tab
    def _tab_about(self):
        f = ttk.Frame(self.nb, padding=16)
        text = (
            "🔐 SECURITY POSTURE  (PCAFLESS-SUITE PORTABLE)\n\n"
            f"Engine version : {__version__}\n"
            "Execution       : 100% local, offline-capable, portable single-file exe\n"
            "Data at rest    : SQLite (WAL) under ~/.pcapless — master key sealed per install\n"
            "Evidence        : SHA-256 file digest BEFORE processing; chain of custody per frame\n"
            "Audit           : append-only bus, SHA-256 hash-chained, HMAC-signed, tamper-verifiable\n"
            "Encryption      : local data integrity via sealed key (AES-256 scope for cloud profiles)\n\n"
            "FRAMEWORKS MAPPED\n"
            "  ISO 27001:2022  -> A.6.8 A.8.8 A.8.9 A.8.11 A.8.15 A.8.24 A.8.34\n"
            "  NIST CSF 2.0    -> GOVERN/IDENTIFY/PROTECT/DETECT/RESPOND/RECOVER\n"
            "  NIST SP 800-53  -> AC AU CM CP SC SI IR\n"
            "  OWASP Top 10    -> A01 (RBAC gateway) A02 (crypto) A08 (integrity) A09 (audit) A10 (SSRF guard)\n"
            "  MITRE ATT&CK    -> tactic mapping on every reconstructed session\n\n"
            "KEY STORE\n"
            f"  {os.environ.get('PCAFLESS_DATA_DIR', '~/.pcapless')} — .pcapless_master.key (sealed, 32 bytes)\n"
            f"  Database        : ~/.pcapless/pcapless.db\n\n"
            "Kindly keep the data directory with the portable exe for case portability.\n"
            "No external calls are made. Everything runs locally (air-gap safe)."
        )
        box = tk.Text(f, bg="#0f172a", fg="#e2e8f0", wrap="word", relief="flat", font=("Consolas", 10), padx=14, pady=12)
        vs = ttk.Scrollbar(f, orient="vertical", command=box.yview)
        box.configure(yscrollcommand=vs.set)
        box.pack(side="left", fill="both", expand=True)
        vs.pack(side="right", fill="y")
        box.insert("1.0", text)
        for pat in ("🔐 SECURITY POSTURE", "FRAMEWORKS MAPPED", "KEY STORE"):
            start = box.search(pat, "1.0")
            if start:
                end = f"{start.split('.')[0]}.end"
                box.tag_add("h", start, end)
        box.tag_configure("h", foreground="#a5b4fc", font=("Consolas", 10, "bold"))
        return f

    # ------------------------------------------------------------- job pump
    def _poll_jobs(self):
        try:
            try:
                while True:
                    item = self._job.get_nowait()
                    kind = item[0]
                    if kind == "sha":
                        self.ingest_status.config(text=f"File SHA-256 = {item[1]}", fg="#6ee7b7")
                        self.integrity_text.insert("end", f"✔ SHA-256            {item[1]}\n")
                    elif kind == "prog":
                        _, done, total = item
                        pct = int(done / max(1, total) * 100)
                        self.progress["value"] = pct
                        self.ingest_status.config(text=f"Decoding frames… {done}/{total} ({pct}%)", fg="#c7d2fe")
                    elif kind == "err":
                        self._busy = False
                        self.progress["value"] = 0
                        self.ingest_status.config(text=f"✘ Ingest failed: {item[1]}", fg="#fca5a5")
                        messagebox.showerror("Ingest", item[1])
                    elif kind == "done":
                        _, res, recs, path, file_sha = item
                        size = os.path.getsize(path)
                        cap_id = self.db.add_capture(self.case_var.get() or "DEFAULT", os.path.basename(path),
                                                     file_sha, size, res["total_frames"])
                        for r in recs:
                            self.db.add_session(cap_id, r)
                        audit.AuditBus(self.db, self.actor).log(
                            "INGEST", os.path.basename(path), evidence_hash=file_sha, verdict="ALLOWED")
                        self._busy = False
                        self.progress["value"] = 100
                        self.ingest_status.config(
                            text=f"✔ Reconstructed {len(recs)} sessions from {res['total_frames']} frames "
                                 f"({res['decode_errors']} frames skipped).", fg="#6ee7b7")
                        self.integrity_text.insert("end", f"✔ Sessions            {len(recs)}\n"
                                                          f"✔ Frames decoded      {res['total_frames']}\n"
                                                          f"✔ Decode errors       {res['decode_errors']}\n"
                                                          f"✔ Persisted to        {self.db.path}\n")
                        self._refresh_sessions()
            except queue.Empty:
                pass
        except Exception:
            tb = traceback.format_exc()
            self._log_raw([tb])
            self._busy = False
            self.status.config(text="Background job error logged to pcapless_error.log", fg="#fca5a5")
        self.after(120, self._poll_jobs)

    def on_close(self):
        try:
            audit.AuditBus(self.db, self.actor).log("APP_EXIT", "GUI session ended")
        except Exception:
            pass
        self.db.close()
        self.destroy()


def main():
    app = SuiteApp()
    app.protocol("WM_DELETE_WINDOW", app.on_close)
    app.mainloop()


if __name__ == "__main__":
    main()