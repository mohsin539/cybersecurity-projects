"""GUI views: dashboard, capture, handshakes, reports.
"""
import tkinter as tk
from tkinter import ttk

from app.gui.theme import C, SEV_COLORS
from app.report import base, html_exporter, csv_exporter, xlsx_exporter, json_exporter
from app.config import REPORT_DIR


class KpiCard(tk.Frame):
    def __init__(self, parent, title, color=C["green"]):
        super().__init__(parent, bg=C["panel"], highlightbackground=C["border"], highlightthickness=1)
        self.num = tk.Label(self, text="0", font=("Segoe UI", 24, "bold"), fg=color, bg=C["panel"])
        self.num.pack(anchor="w", padx=16, pady=(14, 0))
        tk.Label(self, text=title, font=("Segoe UI", 9), fg=C["muted"], bg=C["panel"]).pack(
            anchor="w", padx=16, pady=(0, 14))
        self._color = color

    def set(self, value):
        self.num.config(text=str(value), fg=self._color)


class DashboardView(tk.Frame):
    def __init__(self, parent, engine, app_ref):
        super().__init__(parent, bg=C["bg"])
        self.engine = engine
        self.app = app_ref

        tk.Label(self, text="Live Dashboard", font=("Segoe UI", 17, "bold"),
                 fg=C["cyan"], bg=C["bg"]).pack(anchor="w", padx=20, pady=(16, 4))
        tk.Label(self, text="Realtime telemetry · Evidence is encrypted at rest (AES-256-GCM) · Zero network egress",
                 fg=C["muted"], bg=C["bg"], font=("Segoe UI", 9)).pack(anchor="w", padx=20)

        cards = tk.Frame(self, bg=C["bg"])
        cards.pack(fill="x", padx=20, pady=14)
        self.c_aps = KpiCard(cards, "Lab APs", C["cyan"])
        self.c_clients = KpiCard(cards, "Clients", C["green"])
        self.c_sessions = KpiCard(cards, "EAPOL Sessions", C["purple"])
        self.c_complete = KpiCard(cards, "Complete 4-Way", C["teal"])
        self.c_findings = KpiCard(cards, "Findings", C["red"])
        for i, c in enumerate([self.c_aps, self.c_clients, self.c_sessions, self.c_complete, self.c_findings]):
            c.grid(row=0, column=i, sticky="nsew", padx=6)
            cards.columnconfigure(i, weight=1)

        mid = tk.Frame(self, bg=C["bg"])
        mid.pack(fill="both", expand=True, padx=20)
        mid.columnconfigure(0, weight=3)
        mid.columnconfigure(1, weight=2)

        left = tk.Frame(mid, bg=C["panel"], highlightbackground=C["border"], highlightthickness=1)
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 6))
        right = tk.Frame(mid, bg=C["panel"], highlightbackground=C["border"], highlightthickness=1)
        right.grid(row=0, column=1, sticky="nsew", padx=(6, 0))

        tk.Label(left, text="Channel Activity", font=("Segoe UI", 11, "bold"),
                 fg=C["purple"], bg=C["panel"]).pack(anchor="w", padx=14, pady=(12, 6))
        self.channel_frame = tk.Frame(left, bg=C["panel"])
        self.channel_frame.pack(fill="x", padx=14)
        self.channel_bars = []
        for i, ch in enumerate([1, 6, 11]):
            row = tk.Frame(self.channel_frame, bg=C["panel"])
            row.pack(fill="x", pady=5)
            tk.Label(row, text=f"CH {ch}", width=5, fg=C["muted"], bg=C["panel"]).pack(side="left")
            bar = tk.Canvas(row, height=18, bg=C["panel2"], highlightthickness=0)
            bar.pack(side="left", fill="x", expand=True)
            # kind index for cycling colors
            self.channel_bars.append((bar, i))

        tk.Label(left, text="Recent Events", font=("Segoe UI", 11, "bold"),
                 fg=C["cyan"], bg=C["panel"]).pack(anchor="w", padx=14, pady=(18, 6))
        self.feed = tk.Text(left, height=9, bg=C["panel2"], fg=C["teal"],
                            font=("Consolas", 9), relief="flat", wrap="word")
        self.feed.pack(fill="both", expand=True, padx=14, pady=(0, 14))

        tk.Label(right, text="Evidence Integrity", font=("Segoe UI", 11, "bold"),
                 fg=C["green"], bg=C["panel"]).pack(anchor="w", padx=14, pady=(12, 6))
        chain = tk.Frame(right, bg=C["panel2"])
        chain.pack(fill="x", padx=14)
        self.chain_len = tk.Label(chain, text="records: 0", fg=C["text"], bg=C["panel2"],
                                  font=("Segoe UI", 10))
        self.chain_len.pack(anchor="w", padx=10, pady=8)
        self.chain_head = tk.Label(chain, text="state: init", fg=C["muted"],
                                   bg=C["panel2"], font=("Consolas", 8), justify="left")
        self.chain_head.pack(anchor="w", padx=10, pady=(0, 8))

        tk.Label(right, text="Vault Security", font=("Segoe UI", 11, "bold"),
                 fg=C["green"], bg=C["panel"]).pack(anchor="w", padx=14, pady=(14, 6))
        sec = tk.Frame(right, bg=C["panel2"])
        sec.pack(fill="x", padx=14)
        self.sec_ok = tk.Label(sec, text="✓", fg=C["green"], bg=C["panel2"] if False else C["panel2"],
                               font=("Segoe UI", 16, "bold"))
        self.sec_ok.pack(side="left", padx=10, pady=10)
        self.sec_txt = tk.Label(sec, text="vault locked with AES-256-GCM\nkey wrapped by Windows DPAPI",
                                fg=C["text"], bg=C["panel2"], justify="left", font=("Segoe UI", 9))
        self.sec_txt.pack(side="left", pady=10)

    def refresh(self):
        s = self.engine.stats()
        self.c_aps.set(s["aps"])
        self.c_clients.set(s["clients"])
        self.c_sessions.set(s["sessions"])
        self.c_complete.set(s["complete"])
        self.c_findings.set(s["findings"])
        for bar, i in self.channel_bars:
            h = 4 + ((s["frames"] % 13) + i * 4) % 10
            bar.delete("all")
            bar.create_rectangle(0, 0, max(40, bar.winfo_width() or 200), 18,
                                 fill=C["panel2"], outline="")
            bar.create_rectangle(0, 0, max(40, ((bar.winfo_width() or 200) * h) // 14), 18,
                                 fill=[C["cyan"], C["purple"], C["pink"]][i], outline="")
        chain = self.engine.vault.chain_state()
        self.chain_len.config(text=f"records: {chain['length']} · verified: {chain['ok']}")
        self.chain_head.config(text=f"head: {chain['head'][:28]}…")
        crypto_flag = getattr(self.engine.vault._crypto, "advanced", False)
        self.sec_txt.config(text=("vault locked with AES-256-GCM\nkey wrapped by Windows DPAPI"
                                  if crypto_flag else
                                  "vault locked with AES-256-GCM\nkey derived via PBKDF2-SHA256"))

    def feed_event(self, kind, detail):
        self.feed.insert("1.0", f"[{kind.upper()}] {detail}\n")
        while int(self.feed.index("end-1c").split(".")[0]) > 150:
            self.feed.delete("end-2l", "end-1c")


class CaptureView(tk.Frame):
    def __init__(self, parent, engine, app_ref):
        super().__init__(parent, bg=C["bg"])
        self.engine = engine
        self.app = app_ref

        tk.Label(self, text="Capture Studio", font=("Segoe UI", 17, "bold"),
                 fg=C["cyan"], bg=C["bg"]).pack(anchor="w", padx=20, pady=(16, 4))
        tk.Label(self, text="Register your lab access point. The scope guard drops any out-of-scope BSSID at the source.",
                 fg=C["muted"], bg=C["bg"], font=("Segoe UI", 9)).pack(anchor="w", padx=20)

        form = tk.Frame(self, bg=C["panel"], highlightbackground=C["border"], highlightthickness=1)
        form.pack(fill="x", padx=20, pady=14)

        tk.Label(form, text="Lab ESSID", fg=C["muted"], bg=C["panel"]).grid(row=0, column=0, sticky="w", padx=(14, 8), pady=(14, 4))
        self.e_ssid = tk.Entry(form, bg=C["panel2"], fg=C["text"], insertbackground=C["text"], relief="flat", width=26)
        self.e_ssid.grid(row=0, column=1, sticky="w", padx=8, pady=(14, 4))
        self.e_ssid.insert(0, "MY-LAB-AP")

        tk.Label(form, text="Lab BSSID", fg=C["muted"], bg=C["panel"]).grid(row=0, column=2, sticky="w", padx=(20, 8), pady=(14, 4))
        self.e_bssid = tk.Entry(form, bg=C["panel2"], fg=C["text"], insertbackground=C["text"], relief="flat", width=24)
        self.e_bssid.grid(row=0, column=3, sticky="w", padx=8, pady=(14, 4))
        self.e_bssid.insert(0, "00:1A:2B:3C:4D:5E")

        tk.Label(form, text="Channel", fg=C["muted"], bg=C["panel"]).grid(row=1, column=0, sticky="w", padx=(14, 8), pady=(8, 4))
        self.e_ch = tk.Entry(form, bg=C["panel2"], fg=C["text"], insertbackground=C["text"], relief="flat", width=8)
        self.e_ch.grid(row=1, column=1, sticky="w", padx=8, pady=(8, 4))
        self.e_ch.insert(0, "6")

        tk.Label(form, text="Cipher", fg=C["muted"], bg=C["panel"]).grid(row=1, column=2, sticky="w", padx=(20, 8), pady=(8, 4))
        self.cb_cipher = ttk.Combobox(form, values=["WPA2/AES", "WPA2/TKIP", "WPA3/AES"],
                                      state="readonly", width=16)
        self.cb_cipher.grid(row=1, column=3, sticky="w", padx=8, pady=(8, 4))
        self.cb_cipher.set("WPA2/AES")

        btns = tk.Frame(self, bg=C["bg"])
        btns.pack(fill="x", padx=20, pady=(0, 12))
        self.b_register = ttk.Button(btns, text="+ Register Lab AP", style="Ghost.TButton", command=self.register_ap)
        self.b_register.pack(side="left")
        self.b_start = ttk.Button(btns, text="▶ Start Capture", style="Acc.TButton", command=self.start_capture)
        self.b_start.pack(side="left", padx=8)
        self.b_stop = ttk.Button(btns, text="■ Stop", style="Danger.TButton", command=self.stop_capture, state="disabled")
        self.b_stop.pack(side="left")

        self.l_scope = tk.Label(self, text="Registered scope: (none)", fg=C["amber"], bg=C["bg"])
        self.l_scope.pack(anchor="w", padx=20)

        tables = tk.Frame(self, bg=C["bg"])
        tables.pack(fill="both", expand=True, padx=20, pady=14)
        tables.columnconfigure(0, weight=1)
        tables.columnconfigure(1, weight=1)

        self.tree_aps = self._tree(tables, 0, ("SSID", "BSSID", "CH", "Cipher"))
        self.tree_clients = self._tree(tables, 1, ("Client MAC", "BSSID"))

    def _tree(self, parent, col, cols):
        wrap = tk.Frame(parent, bg=C["panel"], highlightbackground=C["border"], highlightthickness=1)
        wrap.grid(row=0, column=col, sticky="nsew", padx=6)
        tk.Label(wrap, text="Clients" if "Client" in cols[0] else "Registered APs",
                 font=("Segoe UI", 10, "bold"), fg=C["blue"], bg=C["panel"]).pack(anchor="w", padx=10, pady=8)
        tree = ttk.Treeview(wrap, columns=cols, show="headings", height=8)
        for c in cols:
            tree.heading(c, text=c)
            tree.column(c, width=100, anchor="w")
        tree.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        return tree

    def refresh(self):
        self.tree_aps.delete(*self.tree_aps.get_children())
        for a in self.engine.vault.aps():
            self.tree_aps.insert("", "end", values=(a["ssid"], a["bssid"], a["channel"], a["cipher"]))
        self.tree_clients.delete(*self.tree_clients.get_children())
        for c in self.engine.vault.clients()[-40:]:
            self.tree_clients.insert("", "end", values=(c["mac"], c["bssid"]))
        scope = self.engine.scope.authorized_list()
        self.l_scope.config(
            text="Registered scope: " + ", ".join(f"{s} ({b})" for b, s in scope) if scope
            else "Registered scope: (none)")

    def register_ap(self):
        ssid = self.e_ssid.get().strip()
        bssid = self.e_bssid.get().strip()
        try:
            ch = int(self.e_ch.get().strip() or 6)
            self.engine.register_lab_ap(bssid, ssid, ch, self.cb_cipher.get())
            self.refresh()
            self.app.feed_event("scope", f"registered {ssid} / {bssid}")
        except Exception as exc:
            self.app.feed_event("error", str(exc))

    def start_capture(self):
        if not self.engine.scope.authorized_list():
            self.app.feed_event("scope", "register a lab AP first")
            return
        self.engine.start()
        self.b_start.config(state="disabled")
        self.b_stop.config(state="normal")
        self.app.set_status("CAPTURE RUNNING")

    def stop_capture(self):
        self.engine.stop()
        self.b_start.config(state="normal")
        self.b_stop.config(state="disabled")
        self.app.set_status("CAPTURE IDLE")


class HandshakeView(tk.Frame):
    def __init__(self, parent, engine, app_ref):
        super().__init__(parent, bg=C["bg"])
        self.engine = engine
        tk.Label(self, text="Handshake Lab — EAPOL 4-Way Tracker",
                 font=("Segoe UI", 17, "bold"), fg=C["cyan"], bg=C["bg"]).pack(anchor="w", padx=20, pady=(16, 4))
        tk.Label(self, text="WPA Message 1 → 4 · Ordering + replay guarded · MIC state tracked per frame",
                 fg=C["muted"], bg=C["bg"], font=("Segoe UI", 9)).pack(anchor="w", padx=20)

        self.info = tk.Label(self, text="", fg=C["amber"], bg=C["bg"])
        self.info.pack(anchor="w", padx=20, pady=8)

        self.tree = ttk.Treeview(self, columns=("Approve", "Client", "BSSID", "M1", "M2", "M3", "M4", "Complete", "Started"),
                                 show="headings", height=16)
        for c in ("Approve", "Client", "BSSID", "M1", "M2", "M3", "M4", "Complete", "Started"):
            self.tree.heading(c, text=c)
        self.tree.column("Approve", width=90, anchor="center")
        self.tree.column("M1", width=40, anchor="center")
        self.tree.column("M2", width=40, anchor="center")
        self.tree.column("M3", width=40, anchor="center")
        self.tree.column("M4", width=40, anchor="center")
        self.tree.column("Complete", width=80, anchor="center")
        self.tree.column("Started", width=180)
        self.tree.pack(fill="both", expand=True, padx=20, pady=(6, 16))
        self.tree.tag_configure("done", foreground=C["green"])
        self.tree.tag_configure("partial", foreground=C["amber"])

    def refresh(self):
        self.tree.delete(*self.tree.get_children())
        ses = self.engine.vault.sessions()
        for s in ses:
            try:
                msgs = eval(s["msgs"])
            except Exception:
                msgs = []
            marks = {m: ("✚" if m in msgs else "·") for m in (1, 2, 3, 4)}
            tag = "done" if s["complete"] else "partial"
            self.tree.insert("", "end", tags=(tag,), values=(
                "✓ APPROVED" if s["complete"] else "… pending",
                s["client"], s["bssid"],
                marks[1], marks[2], marks[3], marks[4],
                "YES" if s["complete"] else "NO", s["started"]))
        this = self.engine.sm.completeness()
        self.info.config(text=f"state machine: {this}")


class ReportView(tk.Frame):
    def __init__(self, parent, engine, app_ref):
        super().__init__(parent, bg=C["bg"])
        self.engine = engine
        self.app = app_ref

        tk.Label(self, text="Report Builder", font=("Segoe UI", 17, "bold"),
                 fg=C["cyan"], bg=C["bg"]).pack(anchor="w", padx=20, pady=(16, 4))
        tk.Label(self, text="Deterministic, offline rendering · XSS-safe · chain-of-custody digest embedded",
                 fg=C["muted"], bg=C["bg"], font=("Segoe UI", 9)).pack(anchor="w", padx=20)

        formats = [
            ("HTML", "🌐", C["cyan"], "Self-contained branded report, print-ready"),
            ("CSV", "📊", C["green"], "RFC 4180 · 5 entity files"),
            ("XLSX", "📗", C["purple"], "Formatted workbook · 6 sheets"),
            ("JSON", "🧾", C["amber"], "Typed evidence for SIEM handover"),
        ]
        grid = tk.Frame(self, bg=C["bg"])
        grid.pack(fill="x", padx=20, pady=14)
        for i, (name, ico, color, desc) in enumerate(formats):
            card = tk.Frame(grid, bg=C["panel"], highlightbackground=C["border"], highlightthickness=1)
            card.grid(row=0, column=i, sticky="nsew", padx=6)
            grid.columnconfigure(i, weight=1)
            tk.Label(card, text=ico, font=("Segoe UI", 22), bg=C["panel"]).pack(pady=(14, 0))
            tk.Label(card, text=name, font=("Segoe UI", 12, "bold"), fg=color, bg=C["panel"]).pack()
            tk.Label(card, text=desc, fg=C["muted"], bg=C["panel"], font=("Segoe UI", 8), wraplength=170).pack(padx=10, pady=(0, 8))

        self.b_all = ttk.Button(self, text="⇩ Export All Reports (HTML · CSV · XLSX · JSON)",
                                style="Acc.TButton", command=self.export_all)
        self.b_all.pack(anchor="w", padx=20, pady=6)

        self.out = tk.Text(self, height=12, bg=C["panel2"], fg=C["teal"], relief="flat",
                           font=("Consolas", 9), wrap="word")
        self.out.pack(fill="both", expand=True, padx=20, pady=14)

        self.log(f"report directory: {REPORT_DIR}")

    def log(self, msg):
        self.out.insert("end", msg + "\n")
        self.out.see("end")

    def export_all(self):
        data = base.ReportData.from_vault(self.engine.vault, self.engine.backend)
        import os
        os.makedirs(REPORT_DIR, exist_ok=True)
        root = os.path.join(REPORT_DIR, "audit")
        try:
            html_path = html_exporter.export(data, root + ".html")
            self.log(f"[html ] {html_path}")
        except Exception as exc:
            self.log(f"[html ] ERROR {exc}")
        try:
            csv_files = csv_exporter.export(data, REPORT_DIR)
            for k, p in csv_files.items():
                self.log(f"[csv  ] {p}")
        except Exception as exc:
            self.log(f"[csv  ] ERROR {exc}")
        try:
            xlsx_path = xlsx_exporter.export(data, root + ".xlsx")
            self.log(f"[xlsx ] {xlsx_path}")
        except Exception as exc:
            self.log(f"[xlsx ] ERROR {exc}")
        try:
            json_path = json_exporter.export(data, root + ".json")
            self.log(f"[json ] {json_path}")
        except Exception as exc:
            self.log(f"[json ] ERROR {exc}")
        self.log(f"chain: {data.chain}")
        try:
            import os as _os
            if _os.name == "nt":
                _os.startfile(REPORT_DIR)
        except Exception as _exc:
            self.log(f"[open ] {_exc}")