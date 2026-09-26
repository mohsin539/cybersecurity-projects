"""Colorful Tkinter GUI console for the C2 Study Lab.

Layout
- Top: brand banner
- Dashboard row: live KPI cards (beacons / tasks / results / status)
- Server panel: host/port + Start / Stop controls
- Beacon table: inventory treeview
- Task panel: dispatch a whitelisted task to a selected beacon
- Audit / Log panel: color-coded live console
- Report bar: export .xlsx / .csv / .html buttons

All heavy work (listener, beacons) runs on daemon threads; the GUI only
drains the log queue via root.after(), which keeps tkinter single-threaded.
"""
import os
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from .beacon import Beacon
from .c2logging import AuditLog, setup_logging
from .config import (
    DEFAULT_HOST,
    DEFAULT_PORT,
    APP_NAME,
    APP_VERSION,
    TAGLINE,
)
from .listener import C2Listener, probe_port
from .registry import BeaconRegistry
from .reporting import export_all, export_csv, export_html, export_xlsx

# ---- palette ----------------------------------------------------------------
PALETTE = {
    "bg": "#1E1E2E",
    "panel": "#2A2A40",
    "panel2": "#232338",
    "text": "#ECEFF4",
    "muted": "#9AA0B5",
    "accent": "#7C4DFF",
    "green": "#27AE60",
    "amber": "#F39C12",
    "red": "#E74C3C",
    "blue": "#2E86DE",
    "border": "#3A3A55",
}
COLORS = {
    10: "#6FC3FF",  # DEBUG (cornflower)
    20: "#67E08F",  # INFO (green)
    30: "#FFC46B",  # WARNING (amber)
    40: "#FF8A93",  # ERROR (red)
    50: "#FF6B7A",  # CRITICAL
}

TASK_NAMES = ("get-sysinfo", "get-timestamp", "get-uptime", "heartbeat-test")


class C2Gui(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(f"{APP_NAME} v{APP_VERSION} - {TAGLINE}")
        self.configure(bg=PALETTE["bg"])
        self.geometry("1180x780")
        self.minsize(980, 640)

        self.logger, self.log_queue = setup_logging("logs")
        self.audit = AuditLog("logs/audit.jsonl")
        self.listener: C2Listener | None = None
        self.registry = BeaconRegistry()
        self._stop_beacons = []
        self._poll_job = None

        self._build_styles()
        self._build_layout()

        self.after(150, self._drain_logs)
        self.after(1000, self._refresh_dashboards)
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self.logger.info("%s %s started", APP_NAME, APP_VERSION)

    # ------------------------------------------------------------------ UI
    def _build_styles(self):
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("TFrame", background=PALETTE["bg"])
        style.configure("Panel.TFrame", background=PALETTE["panel"])
        style.configure(
            "TLabel", background=PALETTE["panel"], foreground=PALETTE["text"], font=("Segoe UI", 10)
        )
        style.configure(
            "Muted.TLabel", background=PALETTE["panel"], foreground=PALETTE["muted"], font=("Segoe UI", 9)
        )
        style.configure("TButton", font=("Segoe UI", 10, "bold"), padding=6)
        style.configure(
            "Start.TButton", background=PALETTE["green"], foreground="#0d1f14",
        )
        style.configure(
            "Stop.TButton", background=PALETTE["red"], foreground="#3a0d0d",
        )
        style.configure(
            "Accent.TButton", background=PALETTE["accent"], foreground="#ffffff",
        )
        style.configure(
            "Treeview",
            background=PALETTE["panel2"],
            fieldbackground=PALETTE["panel2"],
            foreground=PALETTE["text"],
            rowheight=26,
            borderwidth=0,
            font=("Consolas", 9),
        )
        style.configure(
            "Treeview.Heading", background="#34345A", foreground="#FFFFFF", font=("Segoe UI", 9, "bold")
        )
        style.map("Treeview", background=[("selected", PALETTE["accent"])])

    def _build_layout(self):
        # banner
        banner = tk.Frame(self, bg="#14141F", height=72)
        banner.pack(fill="x")
        banner.pack_propagate(False)
        tk.Label(
            banner, text=f"\U0001F512  {APP_NAME}",
            bg="#14141F", fg=PALETTE["accent"], font=("Segoe UI", 20, "bold"),
        ).pack(side="left", padx=18)
        tk.Label(
            banner, text=TAGLINE, bg="#14141F", fg=PALETTE["muted"], font=("Segoe UI", 10),
        ).pack(side="left", padx=6, pady=(4, 0))

        # main area
        body = tk.Frame(self, bg=PALETTE["bg"])
        body.pack(fill="both", expand=True, padx=12, pady=10)

        # KPIs
        kpi = tk.Frame(body, bg=PALETTE["bg"])
        kpi.pack(fill="x")
        self.kpis = {}
        cards = [
            ("beacons", "Beacons", PALETTE["accent"]),
            ("tasks", "Tasks", PALETTE["blue"]),
            ("results", "Results", PALETTE["green"]),
            ("status", "Listener", PALETTE["amber"]),
        ]
        for i, (key, label, color) in enumerate(cards):
            card = tk.Frame(kpi, bg=PALETTE["panel"], highlightbackground=PALETTE["border"], highlightthickness=1)
            card.grid(row=0, column=i, padx=(0 if i == 0 else 8, 0), sticky="ew")
            kpi.grid_columnconfigure(i, weight=1)
            tk.Label(card, text="—", bg=PALETTE["panel"], fg=color, font=("Segoe UI", 24, "bold")).pack(pady=(10, 0))
            tk.Label(card, text=label, bg=PALETTE["panel"], fg=PALETTE["muted"], font=("Segoe UI", 9)).pack(pady=(0, 10))
            self.kpis[key] = card.winfo_children()[0]

        # server + beacon row
        row = tk.Frame(body, bg=PALETTE["bg"])
        row.pack(fill="both", expand=True, pady=(12, 0))
        row.grid_columnconfigure(1, weight=1)
        row.grid_rowconfigure(0, weight=1)

        # server control panel
        panel = tk.Frame(row, bg=PALETTE["panel"], highlightbackground=PALETTE["border"], highlightthickness=1)
        panel.grid(row=0, column=0, sticky="ns", padx=(0, 10))
        tk.Label(panel, text="C2 LISTENER", font=("Segoe UI", 10, "bold"),
                 foreground=PALETTE["accent"]).pack(anchor="w", padx=12, pady=(10, 4))

        frm = tk.Frame(panel, bg=PALETTE["panel"])
        frm.pack(fill="x", padx=12)
        tk.Label(frm, text="Host", bg=PALETTE["panel"], fg=PALETTE["muted"]).grid(row=0, column=0, sticky="w")
        tk.Label(frm, text="Port", bg=PALETTE["panel"], fg=PALETTE["muted"]).grid(row=1, column=0, sticky="w", pady=(6, 0))
        self.host_var = tk.StringVar(value=DEFAULT_HOST)
        self.port_var = tk.StringVar(value=str(DEFAULT_PORT))
        host_entry = tk.Entry(frm, textvariable=self.host_var, bg=PALETTE["panel2"], fg=PALETTE["text"],
                              insertbackground=PALETTE["text"], relief="flat")
        port_entry = tk.Entry(frm, textvariable=self.port_var, bg=PALETTE["panel2"], fg=PALETTE["text"],
                              insertbackground=PALETTE["text"], relief="flat", width=8)
        host_entry.grid(row=0, column=1, sticky="ew", padx=(8, 0))
        port_entry.grid(row=1, column=1, sticky="w", padx=(8, 0), pady=(6, 0))
        frm.grid_columnconfigure(1, weight=1)

        self.btn_start = tk.Button(panel, text="START", command=self.start_listener, bg=PALETTE["green"],
                                   fg="#06130b", font=("Segoe UI", 11, "bold"), relief="flat", pady=8)
        self.btn_start.pack(fill="x", padx=12, pady=(10, 6))
        self.btn_stop = tk.Button(panel, text="STOP", command=self.stop_listener, state="disabled",
                                  bg=PALETTE["red"], fg="#330b0b", font=("Segoe UI", 11, "bold"), relief="flat", pady=8)
        self.btn_stop.pack(fill="x", padx=12, pady=(0, 6))
        tk.Label(panel, text="Confirm each register/task in the audit tab.",
                 bg=PALETTE["panel"], fg=PALETTE["muted"], wraplength=200).pack(padx=12, pady=(0, 10), anchor="w")

        # right: beacons table + tabs
        right = tk.Frame(row, bg=PALETTE["bg"])
        right.grid(row=0, column=1, sticky="nsew")

        nb = ttk.Notebook(right)
        nb.pack(fill="both", expand=True)

        # ---- beacons tab
        beacons_tab = tk.Frame(nb, bg=PALETTE["panel"])
        nb.add(beacons_tab, text="  Beacons  ")
        self.beacon_tree = ttk.Treeview(
            beacons_tab, columns=("id", "host", "os", "ip", "seen"), show="headings"
        )
        for col, txt, w in (("id", "Beacon ID", 150), ("host", "Hostname", 150),
                            ("os", "OS", 220), ("ip", "Source IP", 120), ("seen", "Last Seen", 190)):
            self.beacon_tree.heading(col, text=txt)
            self.beacon_tree.column(col, width=w, anchor="w")
        self.beacon_tree.pack(fill="both", expand=True, padx=8, pady=8)
        tk.Button(beacons_tab, text="Refresh", command=self.refresh_beacons,
                  bg=PALETTE["panel2"], fg=PALETTE["text"]).pack(pady=(0, 8))

        # ---- tasking tab
        task_tab = tk.Frame(nb, bg=PALETTE["panel"])
        nb.add(task_tab, text="  Tasking  ")
        tf = tk.Frame(task_tab, bg=PALETTE["panel"])
        tf.pack(fill="x", padx=10, pady=8)

        tk.Label(tf, text="Beacon", bg=PALETTE["panel"], fg=PALETTE["text"]).grid(row=0, column=0, sticky="w")
        self.task_beacon_var = tk.StringVar()
        self.task_beacon_cb = ttk.Combobox(tf, textvariable=self.task_beacon_var, state="readonly", width=30)
        self.task_beacon_cb.grid(row=0, column=1, padx=(8, 0), sticky="w")

        tk.Label(tf, text="Task", bg=PALETTE["panel"], fg=PALETTE["text"]).grid(row=1, column=0, sticky="w", pady=(6, 0))
        self.task_name_var = tk.StringVar(value=TASK_NAMES[0])
        tk.OptionMenu(tf, self.task_name_var, *TASK_NAMES).grid(row=1, column=1, padx=(8, 0), sticky="w", pady=(6, 0))

        tk.Button(tf, text="Dispatch \u2192", command=self.dispatch_task,
                  bg=PALETTE["accent"], fg="#ffffff", font=("Segoe UI", 10, "bold"), relief="flat").grid(
            row=0, column=2, rowspan=2, padx=16, sticky="ns")

        self.task_note = tk.Label(task_tab, text="Only whitelisted, pure-Python tasks can execute "
                                                 "(no shell, no persistence).",
                                  bg=PALETTE["panel"], fg=PALETTE["muted"]); self.task_note.pack(anchor="w", padx=12)

        self.task_tree = ttk.Treeview(task_tab, columns=("tid", "beacon", "name", "status", "queued", "out"),
                                       show="headings")
        for col, txt, w in (("tid", "Task ID", 120), ("beacon", "Beacon", 130), ("name", "Task", 140),
                            ("status", "Status", 90), ("queued", "Queued", 170), ("out", "Output (truncated)", 220)):
            self.task_tree.heading(col, text=txt)
            self.task_tree.column(col, width=w, anchor="w")
        self.task_tree.pack(fill="both", expand=True, padx=8, pady=(0, 8))

        # ---- audit tab
        audit_tab = tk.Frame(nb, bg=PALETTE["panel"])
        nb.add(audit_tab, text="  Audit  ")
        self.audit_tree = ttk.Treeview(audit_tab, columns=("ts", "event", "actor", "subject", "sev"),
                                       show="headings")
        for col, txt, w in (("ts", "Timestamp", 200), ("event", "Event", 190),
                            ("actor", "Actor", 220), ("subject", "Subject", 220), ("sev", "Severity", 90)):
            self.audit_tree.heading(col, text=txt)
            self.audit_tree.column(col, width=w, anchor="w")
        self.audit_tree.pack(fill="both", expand=True, padx=8, pady=8)

        # ---- reports bar
        rep_bar = tk.Frame(body, bg=PALETTE["panel"], highlightbackground=PALETTE["border"], highlightthickness=1)
        rep_bar.pack(fill="x", pady=(10, 0))
        tk.Label(rep_bar, text="EXPORT REPORT ", font=("Segoe UI", 10, "bold"),
                 foreground=PALETTE["accent"]).pack(side="left", padx=12, pady=8)
        tk.Button(rep_bar, text=".XLSX", command=self.export_xlsx,
                  bg=PALETTE["green"], fg="#0b1a10", relief="flat", width=8).pack(side="left", padx=4, pady=8)
        tk.Button(rep_bar, text=".CSV", command=self.export_csv,
                  bg=PALETTE["blue"], fg="#0b1624", relief="flat", width=8).pack(side="left", padx=4, pady=8)
        tk.Button(rep_bar, text=".HTML", command=self.export_html,
                  bg=PALETTE["amber"], fg="#241a05", relief="flat", width=8).pack(side="left", padx=4, pady=8)
        tk.Button(rep_bar, text="ALL", command=self.export_all,
                  bg=PALETTE["accent"], fg="#fff", relief="flat", width=8).pack(side="left", padx=4, pady=8)
        self.rep_status = tk.Label(rep_bar, text="", bg=PALETTE["panel"], fg=PALETTE["muted"]); self.rep_status.pack(side="left", padx=12)

        # ---- live console
        log_frame = tk.Frame(body, bg=PALETTE["panel"], highlightbackground=PALETTE["border"], highlightthickness=1)
        log_frame.pack(fill="both", expand=True, pady=(10, 0))
        tk.Label(log_frame, text="LIVE CONSOLE", font=("Segoe UI", 10, "bold"),
                 foreground=PALETTE["accent"]).pack(anchor="w", padx=12, pady=(8, 2))
        self.log_text = tk.Text(
            log_frame, height=10, bg="#12121D", fg=PALETTE["text"], insertbackground=PALETTE["text"],
            relief="flat", font=("Consolas", 9), state="disabled", wrap="none",
        )
        self.log_text.pack(fill="both", expand=True, padx=8, pady=(0, 8))

        # status bar
        sb = tk.Label(self, text=" \u26A0 Authorized laboratory use only \u00B7 "
                                 "ISO 27001 / NIST / OWASP Top 10 tracked",
                      bg="#14141F", fg=PALETTE["muted"], anchor="w", font=("Segoe UI", 9))
        sb.pack(fill="x", side="bottom")

    # ------------------------------------------------------------------ ops
    def start_listener(self):
        try:
            host = self.host_var.get().strip() or DEFAULT_HOST
            port = int(self.port_var.get().strip() or DEFAULT_PORT)
        except ValueError:
            messagebox.showerror("Invalid port", "Port must be an integer.")
            return
        if probe_port(host, port):
            messagebox.showerror("Port busy", f"{host}:{port} is already in use.")
            return
        li = C2Listener(host=host, port=port, audit=self.audit, logger=self.logger)
        li.start()
        self.listener = li
        self.btn_start.config(state="disabled")
        self.btn_stop.config(state="normal")
        threading.Thread(target=self._spawn_demo_beacon, daemon=True).start()

    def stop_listener(self):
        if self.listener:
            self.listener.stop()
            self.listener = None
        for b in self._stop_beacons:
            b.stop()
        self.btn_start.config(state="normal")
        self.btn_stop.config(state="disabled")

    def _spawn_demo_beacon(self):
        """Spin up an in-process demo beacon so the lab is immediately alive."""
        if not self.listener:
            return
        b = Beacon(beacon_id=f"beacon-demo-{os.getpid()}", server_url=self.listener.url,
                   logger=self.logger, interval=2)
        self._stop_beacons.append(b)
        b.run_forever()

    # ------------------------------------------------------------------ tasks
    def dispatch_task(self):
        if not self.listener:
            messagebox.showwarning("Listener offline", "Start the listener first.")
            return
        bid = self.task_beacon_var.get()
        if not bid:
            messagebox.showwarning("No beacon", "Select a beacon from the dropdown.")
            return
        self.listener.handle_new_task({"beacon_id": bid, "task": {"name": self.task_name_var.get()}})
        self.logger.info("dispatched task '%s' to %s", self.task_name_var.get(), bid)

    # ------------------------------------------------------------------ refresh
    def refresh_beacons(self):
        beacons = self.listener.registry.snapshot() if self.listener else self.registry.snapshot()
        self.beacon_tree.delete(*self.beacon_tree.get_children())
        self._beacons = beacons
        ids = []
        for b in beacons:
            meta = b.get("meta") or {}
            self.beacon_tree.insert("", "end", values=(
                b.get("beacon_id"), meta.get("hostname"), meta.get("os") or meta.get("system"),
                b.get("ip"), b.get("last_seen")))
            ids.append(b.get("beacon_id"))
        self.task_beacon_cb["values"] = ids
        if not self.task_beacon_var.get() and ids:
            self.task_beacon_var.set(ids[0])

    def _refresh_dashboards(self):
        try:
            counts = self.listener.registry.counts() if self.listener else {"beacons": 0, "tasks": 0, "results": 0}
            self.kpis["beacons"].config(text=counts["beacons"])
            self.kpis["tasks"].config(text=counts["tasks"])
            self.kpis["results"].config(text=counts["results"])
            self.kpis["status"].config(text="RUNNING" if self.listener and self.listener.running else "OFF",
                                       fg=PALETTE["green"] if self.listener else PALETTE["red"])
            self.refresh_beacons()
            self.refresh_task_tree()
            self.refresh_audit()
        except Exception:
            pass
        self.after(2000, self._refresh_dashboards)

    def refresh_task_tree(self):
        tasks = self.listener.registry.all_tasks() if self.listener else []
        self.task_tree.delete(*self.task_tree.get_children())
        for t in tasks[-60:]:
            out = str(t.get("output") or "")
            self.task_tree.insert("", "end", values=(
                t.get("task_id"), t.get("beacon_id"), t.get("name"), t.get("status"),
                t.get("queued_at"), out[:80] + ("…" if len(out) > 80 else "")))

    def refresh_audit(self):
        events = self.audit.read_all()
        self.audit_tree.delete(*self.audit_tree.get_children())
        for e in events[-200:]:
            self.audit_tree.insert("", "end", values=(
                e.get("ts"), e.get("event"), e.get("actor"), e.get("subject"), e.get("severity")))

    # ------------------------------------------------------------------ logs
    def _drain_logs(self):
        try:
            while True:
                level, line = self.log_queue.get_nowait()
                self._append_log(line, level)
        except Exception:
            pass
        self.after(150, self._drain_logs)

    def _append_log(self, line: str, level: int):
        self.log_text.configure(state="normal")
        self.log_text.insert("end", line + "\n", str(level))
        self.log_text.tag_config(str(level), foreground=COLORS.get(level, PALETTE["text"]))
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

    # ------------------------------------------------------------------ reports
    def _snapshot(self):
        beacons = self.listener.registry.snapshot() if self.listener else []
        tasks = self.listener.registry.all_tasks() if self.listener else []
        events = self.audit.read_all()
        return beacons, tasks, events

    def _pick_dir(self) -> str | None:
        d = filedialog.askdirectory(title="Choose report output folder")
        return d if d else None

    def _announce(self, message: str):
        self.rep_status.config(text=message, foreground=PALETTE["green"])
        self.logger.info(message)

    def export_xlsx(self):
        d = self._pick_dir()
        if not d:
            return
        beacons, tasks, events = self._snapshot()
        path = export_xlsx(beacons, events, tasks, d)
        self._announce(f".xlsx written -> {path}")

    def export_csv(self):
        d = self._pick_dir()
        if not d:
            return
        beacons, tasks, events = self._snapshot()
        paths = export_csv(beacons, events, tasks, d)
        self._announce(f".csv written -> {', '.join(paths)}")

    def export_html(self):
        d = self._pick_dir()
        if not d:
            return
        beacons, tasks, events = self._snapshot()
        path = export_html(beacons, events, tasks, d)
        self._announce(f".html written -> {path}")

    def export_all(self):
        d = self._pick_dir()
        if not d:
            return
        beacons, tasks, events = self._snapshot()
        out = export_all(beacons, events, tasks, d)
        self._announce("All reports written to " + d)

    def _on_close(self):
        self.stop_listener()
        self.destroy()


def run():
    app = C2Gui()
    app.mainloop()


if __name__ == "__main__":
    run()