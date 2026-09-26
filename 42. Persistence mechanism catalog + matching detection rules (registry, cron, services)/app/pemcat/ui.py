import json
import os
import queue
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from . import audit, collect, report, rules
from .__init__ import APP_CODENAME, APP_NAME, APP_VERSION
from .catalog import Storage, canonical_fingerprint, db_path_for, default_data_dir

SEV_TAGS = {"critical": "#9C0006", "high": "#C00000", "medium": "#ED7D31", "low": "#BF8F00"}
ACCENT = "#2E75B6"
DARK = "#1F3864"
TYPE_ORDER = ("registry", "service", "scheduled_task", "cron", "startup", "wmi", "os_internal")


class PemcatApp(tk.Tk):
    def __init__(self, storage):
        super().__init__()
        self.storage = storage
        self.worker_queue = queue.Queue()
        self.generated_files = []
        self.busy = False

        self.title("{0} v{1} - {2}".format(APP_NAME, APP_VERSION, APP_CODENAME))
        self.geometry("1140x720")
        self.minsize(940, 600)

        self._style()
        self._build_toolbar()
        self._build_tabs()
        self._build_statusbar()
        self.after(200, self._poll_worker)
        self.after(150, self.refresh_all)

    def _style(self):
        style = ttk.Style(self)
        try:
            if "clam" in style.theme_names():
                style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("Toolbar.TFrame", background="#EDF1F9")
        style.configure("Scan.TButton", background=ACCENT, foreground="#FFFFFF",
                        font=("Segoe UI", 10, "bold"), padding=(10, 6))
        style.configure("Danger.TButton", background="#C00000", foreground="#FFFFFF",
                        font=("Segoe UI", 10, "bold"), padding=(8, 6))
        style.configure("Status.TLabel", background=DARK, foreground="#FFFFFF",
                        padding=(8, 4), font=("Segoe UI", 9))
        style.configure("Kpi.TFrame", background="#FFFFFF")

    def _build_toolbar(self):
        bar = ttk.Frame(self, style="Toolbar.TFrame", padding=10)
        bar.pack(side="top", fill="x")
        ttk.Label(bar, text="PEM-CAT", font=("Segoe UI", 14, "bold"),
                  foreground=DARK).pack(side="left")
        ttk.Button(bar, text="Scan Persistence", style="Scan.TButton",
                   command=self.scan_now).pack(side="left", padx=(24, 6))
        ttk.Button(bar, text="Run Detection Rules", style="Scan.TButton",
                   command=self.match_now).pack(side="left", padx=6)
        ttk.Button(bar, text="Full Pipeline", style="Scan.TButton",
                   command=self.pipeline_now).pack(side="left", padx=6)
        ttk.Button(bar, text="Export All", style="Danger.TButton",
                   command=self.export_all).pack(side="right")

    def _build_tabs(self):
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=8, pady=(4, 0))
        self.tab_dash = ttk.Frame(self.notebook)
        self.tab_catalog = ttk.Frame(self.notebook)
        self.tab_detect = ttk.Frame(self.notebook)
        self.tab_rules = ttk.Frame(self.notebook)
        self.tab_reports = ttk.Frame(self.notebook)
        self.tab_audit = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_dash, text="Dashboard")
        self.notebook.add(self.tab_catalog, text="Catalog")
        self.notebook.add(self.tab_detect, text="Detections")
        self.notebook.add(self.tab_rules, text="Rules")
        self.notebook.add(self.tab_reports, text="Reports")
        self.notebook.add(self.tab_audit, text="Audit")
        self._build_dashboard()
        self._build_catalog()
        self._build_detections()
        self._build_rules()
        self._build_reports()
        self._build_audit()

    def _build_dashboard(self):
        wrap = ttk.Frame(self.tab_dash)
        wrap.pack(fill="both", expand=True, padx=14, pady=14)
        self.kpi_frame = ttk.Frame(wrap)
        self.kpi_frame.pack(fill="x")
        self.kpi_labels = {}
        for key, label in (
            ("artifacts", "Cataloged artifacts"),
            ("open", "Open detections"),
            ("baselined", "Baselined / trusted"),
            ("rules", "Active rules"),
        ):
            card = ttk.Frame(self.kpi_frame, style="Kpi.TFrame", padding=14)
            card.pack(side="left", expand=True, fill="x", padx=4)
            val = ttk.Label(card, text="0", font=("Segoe UI", 26, "bold"),
                            foreground=ACCENT)
            val.pack()
            ttk.Label(card, text=label, foreground="#5B6281").pack()
            self.kpi_labels[key] = val

        dist = ttk.Frame(wrap)
        dist.pack(fill="both", expand=True, pady=(16, 0))
        ttk.Label(dist, text="Distribution by mechanism",
                  font=("Segoe UI", 12, "bold")).pack(anchor="w")
        self.dist_bars = {}
        self.dist_counts = {}
        for atype in TYPE_ORDER:
            row = ttk.Frame(dist)
            row.pack(fill="x", pady=2)
            ttk.Label(row, text=atype.title(), width=18).pack(side="left")
            bar = ttk.Progressbar(row, maximum=100, length=260)
            bar.pack(side="left", padx=8)
            count = ttk.Label(row, text="0", width=6, anchor="e")
            count.pack(side="left")
            self.dist_bars[atype] = bar
            self.dist_counts[atype] = count

        self.dash_log = tk.Text(dist, height=7, wrap="word", state="disabled",
                                bg="#F7F9FC", fg="#1A1F36", relief="flat")
        self.dash_log.pack(fill="both", expand=True, pady=(12, 0))
        self.dash_log.insert(
            "end", "Dashboard ready. Press 'Scan Persistence' to enumerate this host.\n")

    def _build_catalog(self):
        filters = ttk.Frame(self.tab_catalog, padding=10)
        filters.pack(fill="x")
        ttk.Label(filters, text="Type:").pack(side="left")
        self.cat_type = ttk.Combobox(filters, values=[""] + list(TYPE_ORDER),
                                     state="readonly", width=16)
        self.cat_type.pack(side="left", padx=(4, 12))
        self.cat_type.bind("<<ComboboxSelected>>", lambda e: self.load_catalog())
        ttk.Label(filters, text="Host:").pack(side="left")
        self.cat_host = ttk.Combobox(filters, state="readonly", width=20)
        self.cat_host.pack(side="left", padx=(4, 12))
        self.cat_host.bind("<<ComboboxSelected>>", lambda e: self.load_catalog())
        self.cat_base = tk.BooleanVar(value=False)
        ttk.Checkbutton(filters, text="Show baselined only", variable=self.cat_base,
                        command=self.load_catalog).pack(side="left", padx=6)
        ttk.Button(filters, text="Refresh", command=self.load_catalog).pack(side="left", padx=4)
        ttk.Button(filters, text="Allowlist selected",
                   command=self.allowlist_selected).pack(side="right")

        columns = ("id", "host", "type", "mechanism", "image_path", "seen", "base")
        self.cat_tree = ttk.Treeview(self.tab_catalog, columns=columns, show="headings")
        for col, title, width in (
            ("id", "ID", 60), ("host", "Host", 90), ("type", "Type", 100),
            ("mechanism", "Mechanism", 260), ("image_path", "Image / Command", 320),
            ("seen", "Seen", 60), ("base", "Baselined", 80),
        ):
            self.cat_tree.heading(col, text=title)
            self.cat_tree.column(col, width=width, anchor="w")
        vs = ttk.Scrollbar(self.tab_catalog, orient="vertical", command=self.cat_tree.yview)
        self.cat_tree.configure(yscrollcommand=vs.set)
        vs.pack(side="right", fill="y")
        self.cat_tree.pack(fill="both", expand=True, padx=10, pady=(0, 10))

    def _build_detections(self):
        filters = ttk.Frame(self.tab_detect, padding=10)
        filters.pack(fill="x")
        ttk.Label(filters, text="Status:").pack(side="left")
        self.det_status = ttk.Combobox(filters, values=["", "open", "acked", "fp"],
                                       state="readonly", width=12)
        self.det_status.pack(side="left", padx=(4, 12))
        self.det_status.bind("<<ComboboxSelected>>", lambda e: self.load_detections())
        ttk.Label(filters, text="Severity:").pack(side="left")
        self.det_sev = ttk.Combobox(filters, values=["", "critical", "high", "medium", "low"],
                                    state="readonly", width=10)
        self.det_sev.pack(side="left", padx=(4, 12))
        self.det_sev.bind("<<ComboboxSelected>>", lambda e: self.load_detections())
        ttk.Button(filters, text="Mark Ack",
                   command=lambda: self.set_match_status("acked")).pack(side="right", padx=4)
        ttk.Button(filters, text="Mark FP / Allowlist",
                   command=self.fp_allowlist).pack(side="right", padx=4)

        columns = ("evt", "rule", "rule_name", "tech", "sev", "conf", "score", "status",
                   "host", "mechanism")
        self.det_tree = ttk.Treeview(self.tab_detect, columns=columns, show="headings")
        for col, title, width in (
            ("evt", "Evt", 60), ("rule", "Rule", 110), ("rule_name", "Rule name", 200),
            ("tech", "ATT&CK", 80), ("sev", "Sev", 70), ("conf", "Conf", 60),
            ("score", "Score", 60), ("status", "Status", 80), ("host", "Host", 90),
            ("mechanism", "Mechanism", 260),
        ):
            self.det_tree.heading(col, text=title)
            self.det_tree.column(col, width=width, anchor="w")
        for sev, color in SEV_TAGS.items():
            self.det_tree.tag_configure(sev, background=color, foreground="#FFFFFF")
        vs = ttk.Scrollbar(self.tab_detect, orient="vertical", command=self.det_tree.yview)
        self.det_tree.configure(yscrollcommand=vs.set)
        vs.pack(side="right", fill="y")
        self.det_tree.pack(fill="both", expand=True, padx=10, pady=(0, 10))

    def _build_rules(self):
        bar = ttk.Frame(self.tab_rules, padding=10)
        bar.pack(fill="x")
        ttk.Label(bar, text="Detection rule store (versioned, review-gated)",
                  font=("Segoe UI", 10, "bold"), foreground=DARK).pack(side="left")
        ttk.Button(bar, text="+ Add custom rule", command=self.add_rule).pack(side="right")

        columns = ("id", "name", "tech", "sev", "status", "owner")
        self.rule_tree = ttk.Treeview(self.tab_rules, columns=columns, show="headings")
        for col, title, width in (
            ("id", "Rule ID", 130), ("name", "Name", 300), ("tech", "ATT&CK", 90),
            ("sev", "Severity", 80), ("status", "Status", 80), ("owner", "Owner", 80),
        ):
            self.rule_tree.heading(col, text=title)
            self.rule_tree.column(col, width=width, anchor="w")
        vs = ttk.Scrollbar(self.tab_rules, orient="vertical", command=self.rule_tree.yview)
        self.rule_tree.configure(yscrollcommand=vs.set)
        vs.pack(side="right", fill="y")
        self.rule_tree.pack(fill="both", expand=True, padx=10)
        ttk.Button(self.tab_rules, text="Toggle active/draft for selected",
                   command=self.toggle_rule).pack(anchor="w", padx=10, pady=8)

    def _build_reports(self):
        left = ttk.LabelFrame(self.tab_reports, text="Export / Download", padding=12)
        left.pack(side="left", fill="both", padx=12, pady=12, ipadx=8)
        ttk.Button(left, text="Export .xlsx", style="Scan.TButton",
                   command=lambda: self.export_single("xlsx")).pack(fill="x", pady=4)
        ttk.Button(left, text="Export .csv bundle", style="Scan.TButton",
                   command=lambda: self.export_single("csv")).pack(fill="x", pady=4)
        ttk.Button(left, text="Export .html", style="Scan.TButton",
                   command=lambda: self.export_single("html")).pack(fill="x", pady=4)
        ttk.Button(left, text="Export All Formats", style="Danger.TButton",
                   command=self.export_all).pack(fill="x", pady=4)
        ttk.Button(left, text="Open data folder", command=self.open_data_dir).pack(fill="x", pady=4)
        ttk.Label(left,
                  text="Compliance: OWASP Top 10 / NIST CSF, SP 800-53, SP 800-171 / ISO 27001",
                  foreground="#5B6281", wraplength=220).pack(pady=(12, 0))

        right = ttk.LabelFrame(self.tab_reports, text="Generated files", padding=12)
        right.pack(side="right", fill="both", expand=True, padx=(0, 12), pady=12)
        self.files_list = tk.Listbox(right, height=14, font=("Consolas", 10))
        self.files_list.pack(fill="both", expand=True)
        ttk.Button(right, text="Open selected file",
                   command=self.open_selected_file).pack(pady=(8, 0))

        bot = ttk.LabelFrame(self.tab_reports, text="Security controls snapshot", padding=12)
        bot.pack(side="bottom", fill="x", padx=12, pady=(0, 12))
        lines = (
            "OWASP A01 Broken Access Control: export actions restricted to app actor with audit trail.",
            "OWASP A03 Injection: all HTML report content is HTML-escaped (XSS-safe).",
            "OWASP A08 Integrity: reports carry SHA-256 fingerprints of artifacts.",
            "NIST DE.CM-07 / ISO 8.15: continuous enumeration and rule workflow are audit-logged.",
        )
        tk.Label(bot, text="\n".join(lines), justify="left",
                 font=("Segoe UI", 9), foreground="#33415C").pack(anchor="w")

    def _build_audit(self):
        columns = ("id", "ts", "actor", "action", "object_id", "detail")
        self.audit_tree = ttk.Treeview(self.tab_audit, columns=columns, show="headings")
        for col, title, width in (
            ("id", "ID", 60), ("ts", "Timestamp", 140), ("actor", "Actor", 90),
            ("action", "Action", 150), ("object_id", "Object", 170), ("detail", "Detail", 240),
        ):
            self.audit_tree.heading(col, text=title)
            self.audit_tree.column(col, width=width, anchor="w")
        vs = ttk.Scrollbar(self.tab_audit, orient="vertical", command=self.audit_tree.yview)
        self.audit_tree.configure(yscrollcommand=vs.set)
        vs.pack(side="right", fill="y")
        self.audit_tree.pack(fill="both", expand=True, padx=10, pady=10)

    def _build_statusbar(self):
        self.status = ttk.Label(self, text="Ready", style="Status.TLabel")
        self.status.pack(side="bottom", fill="x")
        self.status_text = "Ready"

    def _log(self, message):
        self.dash_log.configure(state="normal")
        self.dash_log.insert("end", "[{0}] {1}\n".format(
            time.strftime("%H:%M:%S"), message))
        self.dash_log.see("end")
        self.dash_log.configure(state="disabled")

    def _set_busy(self, busy, message=None):
        self.busy = busy
        if message:
            self.set_status(message)
        elif not busy:
            self.refresh_statusbar_text()

    def set_status(self, text):
        self.status_text = text
        self.status.configure(text="{0}   |   Data: {1}".format(text, self.storage.db_path))

    def refresh_statusbar_text(self):
        stats = self.storage.stats()
        open_matches = sum(1 for m in self.storage.list_matches()
                           if m.get("status") == "open")
        self.set_status("Artifacts: {0}  |  Open alerts: {1}".format(
            stats["total"], open_matches))

    def _poll_worker(self):
        try:
            while True:
                event, payload = self.worker_queue.get_nowait()
                self._on_worker_event(event, payload)
        except queue.Empty:
            pass
        self.after(200, self._poll_worker)

    def _on_worker_event(self, event, payload):
        if event == "scan-done":
            stats = payload
            self._log("Scan finished - {0} artifacts cataloged".format(stats["total"]))
        elif event == "match-done":
            summary = payload
            self._log("Matching finished - {0} alerts".format(
                sum(summary["by_severity"].values())))
        elif event == "export-done":
            files = payload
            self.generated_files = files
            self.files_list.delete(0, "end")
            for f in files:
                self.files_list.insert("end", f)
            self._log("Export finished - {0} file(s)".format(len(files)))
            messagebox.showinfo("PEM-CAT", "Export complete.\n{0} file(s) written.".format(len(files)))
        elif event == "error":
            messagebox.showerror("PEM-CAT", "Operation failed:\n{0}".format(payload))
            self._log("ERROR: {0}".format(payload))
        self.refresh_all()
        self._set_busy(False)

    def refresh_all(self):
        self._refresh_statusbar_text_full()
        self._refresh_dashboard()
        self.load_catalog()
        self.load_detections()
        self.load_rules()
        self.load_audit()
        self._refresh_hosts()

    def _refresh_statusbar_text_full(self):
        stats = self.storage.stats()
        open_matches = sum(1 for m in self.storage.list_matches()
                           if m.get("status") == "open")
        self.kpi_labels["artifacts"].configure(text=stats["total"])
        self.kpi_labels["open"].configure(text=open_matches)
        self.kpi_labels["baselined"].configure(text=stats["baselined"])
        rules_active = sum(1 for r in self.storage.rules() if r.get("status") == "active")
        self.kpi_labels["rules"].configure(text=rules_active)
        self.set_status("Artifacts: {0}  |  Open alerts: {1}".format(
            stats["total"], open_matches))

    def _refresh_dashboard(self):
        stats = self.storage.stats()
        by_type = stats.get("by_type", {})
        total = max(stats["total"], 1)
        for atype in TYPE_ORDER:
            count = by_type.get(atype, 0)
            self.dist_bars[atype].configure(value=int(100 * count / total))
            self.dist_counts[atype].configure(text=str(count))

    def _refresh_hosts(self):
        hosts = [""] + self.storage.hosts()
        self.cat_host.configure(values=hosts)

    def load_catalog(self):
        atype = self.cat_type.get() or None
        host = self.cat_host.get() or None
        base = True if self.cat_base.get() else None
        records = self.storage.list_records(artifact_type=atype, host_id=host,
                                            baselined=base)
        self.cat_tree.delete(*self.cat_tree.get_children())
        for rec in records:
            self.cat_tree.insert("", "end", iid=str(rec["artifact_id"]), values=(
                rec["artifact_id"], rec["host_id"], rec["artifact_type"],
                shortened(rec["mechanism"], 60), shortened(rec["image_path"], 58),
                rec["seen_count"], "Yes" if rec["is_baselined"] else "No"))

    def load_detections(self):
        status = self.det_status.get() or None
        sev = self.det_sev.get() or None
        matches = self.storage.list_matches(status=status, severity=sev)
        self.det_tree.delete(*self.det_tree.get_children())
        for m in matches:
            sev_key = str(m["severity"] or "").lower()
            tags = (sev_key,) if sev_key in SEV_TAGS else ()
            self.det_tree.insert("", "end", iid=str(m["evt_id"]), values=(
                m["evt_id"], m["rule_id"], shortened(m["rule_name"], 40),
                m["technique"], m["severity"], m["confidence"], m["score"],
                m["status"], m["host_id"], shortened(m["mechanism"], 48)), tags=tags)

    def load_rules(self):
        self.rule_tree.delete(*self.rule_tree.get_children())
        for r in self.storage.rules():
            self.rule_tree.insert("", "end", iid=r["rule_id"], values=(
                r["rule_id"], r["name"], r["technique"], r["severity"],
                r["status"], r["owner"]))

    def load_audit(self):
        self.audit_tree.delete(*self.audit_tree.get_children())
        for a in self.storage.list_audit():
            self.audit_tree.insert("", "end", values=(
                a["id"], a["ts"], a["actor"], a["action"], a["object_id"], a["detail"]))

    def scan_now(self):
        if self.busy:
            return
        self._set_busy(True, "Scanning persistence mechanisms...")
        audit.log(self.storage, audit.EVENT_SCAN_START, detail="host scan begin")
        threading.Thread(target=self._scan_worker, daemon=True).start()

    def _scan_worker(self):
        try:
            host = collect.host_id()
            self._log("Host: {0}".format(host))
            records, last = collect.enumerate_all()
            total = 0
            for rec in records:
                rec["host_id"] = host
                rec["fingerprint_sha256"] = canonical_fingerprint(rec)
                self.storage.upsert_artifact(rec)
                total += 1
            self.storage.refresh_baselines()
            self.storage.audit(actor, audit.EVENT_SCAN_DONE, last[0],
                               "{0} artifacts, {1} found".format(total, last[1]))
            self.worker_queue.put(("scan-done", self.storage.stats()))
        except Exception as exc:
            self.worker_queue.put(("error", str(exc)))

    def match_now(self):
        if self.busy:
            return
        self._set_busy(True, "Running detection rules...")
        threading.Thread(target=self._match_worker, daemon=True).start()

    def _match_worker(self):
        try:
            matches = rules.run_matching(self.storage)
            summary = rules.summarize(matches)
            self.storage.audit(actor, audit.EVENT_MATCH_RUN, None,
                               "matches={0}".format(sum(summary["by_severity"].values())))
            self.worker_queue.put(("match-done", summary))
        except Exception as exc:
            self.worker_queue.put(("error", str(exc)))

    def pipeline_now(self):
        if self.busy:
            return
        self._set_busy(True, "Running full pipeline (scan + rules)...")
        threading.Thread(target=self._pipeline_worker, daemon=True).start()

    def _pipeline_worker(self):
        try:
            host = collect.host_id()
            records, last = collect.enumerate_all()
            for rec in records:
                rec["host_id"] = host
                rec["fingerprint_sha256"] = canonical_fingerprint(rec)
                self.storage.upsert_artifact(rec)
            self.storage.refresh_baselines()
            matches = rules.run_matching(self.storage)
            summary = rules.summarize(matches)
            self.worker_queue.put(("scan-done", self.storage.stats()))
            self.worker_queue.put(("match-done", summary))
        except Exception as exc:
            self.worker_queue.put(("error", str(exc)))

    def allowlist_selected(self):
        sel = self.cat_tree.selection()
        if not sel:
            return
        for item in sel:
            self.storage.allowlist(item, reason="manual allowlist")
        self.storage.audit(actor, "allowlist-add", item, "artifact allowlisted")
        self.refresh_all()

    def set_match_status(self, status):
        sel = self.det_tree.selection()
        if not sel:
            return
        for item in sel:
            self.storage.update_match_status(int(item), status)
        self.refresh_all()

    def fp_allowlist(self):
        sel = self.det_tree.selection()
        if not sel:
            return
        for item in sel:
            evt_id = int(item)
            matches = self.storage.list_matches(status=None)
            row = next((m for m in matches if m.get("evt_id") == evt_id), None)
            if row and row.get("fingerprint_sha256"):
                self.storage.allowlist(row["fingerprint_sha256"], reason="false-positive")
            self.storage.update_match_status(evt_id, "fp")
        self.refresh_all()

    def toggle_rule(self):
        sel = self.rule_tree.selection()
        if not sel:
            return
        for rule_id in sel:
            row = next((r for r in self.storage.rules() if r.get("rule_id") == rule_id), None)
            if row is None:
                continue
            new_status = "draft" if row.get("status") == "active" else "active"
            self.storage.set_rule_status(rule_id, new_status)
        self.refresh_all()

    def add_rule(self):
        dialog = tk.Toplevel(self)
        dialog.title("Add custom detection rule")
        dialog.geometry("520x480")
        dialog.transient(self)
        fields = (
            ("id", "Rule ID (e.g. PEM-CAT-0100)"),
            ("name", "Rule name"),
            ("technique", "ATT&CK technique (T1xxx.xxx)"),
            ("severity", "Severity (critical/high/medium/low)"),
            ("status", "Status (draft/active)"),
        )
        entries = {}
        for row, (key, label) in enumerate(fields):
            ttk.Label(dialog, text=label).grid(row=row, column=0, sticky="w",
                                               padx=10, pady=6)
            ent = ttk.Entry(dialog, width=52)
            ent.grid(row=row, column=1, padx=10, pady=6)
            entries[key] = ent
        entries["severity"].insert(0, "medium")
        entries["status"].insert(0, "draft")
        ttk.Label(dialog, text="Logic JSON (object, see PEM-CAT-0001 pattern)").grid(
            row=len(fields), column=0, sticky="nw", padx=10, pady=6)
        text = tk.Text(dialog, width=52, height=9, font=("Consolas", 9))
        text.grid(row=len(fields), column=1, padx=10, pady=6)
        text.insert("end", '{"artifact_type": ["registry"], '
                           '"mechanism_contains": ["Run"], '
                           '"image_path_contains": ["temp"], '
                           '"new_only": false}')
        entries["logic"] = text

        def save():
            try:
                logic = json.loads(text.get("1.0", "end-1c"))
            except ValueError as exc:
                messagebox.showerror("PEM-CAT", "Logic JSON invalid: {0}".format(exc))
                return
            rule = {
                "id": entries["id"].get().strip() or "PEM-CAT-USER",
                "name": entries["name"].get().strip() or "Untitled rule",
                "technique": entries["technique"].get().strip(),
                "severity": entries["severity"].get().strip() or "medium",
                "status": entries["status"].get().strip() or "draft",
                "logic": logic,
            }
            self.storage.add_user_rule(rule)
            dialog.destroy()
            self.refresh_all()

        ttk.Button(dialog, text="Save rule", style="Scan.TButton",
                   command=save).grid(row=len(fields) + 1, column=1, pady=10, sticky="e", padx=10)

    def _report_data(self):
        return report.build_report_data(self.storage, APP_VERSION, collect.host_id())

    def export_single(self, fmt):
        if self.busy:
            return
        target = filedialog.askdirectory(title="Choose export folder")
        if not target:
            return
        self._set_busy(True, "Generating {0} report...".format(fmt))
        threading.Thread(target=self._export_worker, args=(fmt, target),
                         daemon=True).start()

    def export_all(self):
        if self.busy:
            return
        target = filedialog.askdirectory(title="Choose export folder")
        if not target:
            return
        self._set_busy(True, "Generating all report formats...")
        threading.Thread(target=self._export_worker, args=("all", target),
                         daemon=True).start()

    def _export_worker(self, fmt, target):
        try:
            data = self._report_data()
            files = []
            if fmt in ("xlsx", "all"):
                path = os.path.join(target, "pemcat_report_{0}.xlsx".format(
                    time.strftime("%Y%m%d_%H%M%S")))
                files.append(report.report_xlsx(path, data))
                audit.log(self.storage, audit.EVENT_REPORT_XLSX, path, "xlsx report")
            if fmt in ("csv", "all"):
                csv_files = report.report_csv(target, data)
                files.extend(csv_files)
                audit.log(self.storage, audit.EVENT_REPORT_CSV, target, "{0} csv files".format(
                    len(csv_files)))
            if fmt in ("html", "all"):
                path = os.path.join(target, "pemcat_report_{0}.html".format(
                    time.strftime("%Y%m%d_%H%M%S")))
                files.append(report.report_html(path, data))
                audit.log(self.storage, audit.EVENT_REPORT_HTML, path, "html report")
            self.worker_queue.put(("export-done", files))
        except Exception as exc:
            self.worker_queue.put(("error", str(exc)))

    def open_data_dir(self):
        try:
            os.startfile(os.path.dirname(self.storage.db_path))
        except AttributeError:
            os.system("xdg-open \"{0}\"".format(os.path.dirname(self.storage.db_path)))

    def open_selected_file(self):
        sel = self.files_list.curselection()
        if not sel:
            return
        path = self.files_list.get(sel[0])
        try:
            os.startfile(path)
        except AttributeError:
            os.system("xdg-open \"{0}\"".format(path))


actor = "analyst"


def shortened(value, length):
    value = str(value or "")
    return value if len(value) <= length else value[: length - 1] + "..."


def main(data_dir=None):
    data_dir = data_dir or default_data_dir()
    provided = os.environ.get("PEMCAT_DATA_DIR")
    if provided:
        data_dir = provided
    storage = Storage(db_path_for(data_dir))
    storage.seed_rules(rules.BUILTIN_RULES)
    app = PemcatApp(storage)
    app.mainloop()


if __name__ == "__main__":
    main()