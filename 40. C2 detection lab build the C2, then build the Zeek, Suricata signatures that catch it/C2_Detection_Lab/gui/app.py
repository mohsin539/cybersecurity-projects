"""C2 Detection Lab - main GUI console (L4, tkinter -> PyInstaller .EXE).

Tabs:  Lab Control | C2 Builder | Signature Builder | Live Alerts | Reports | Compliance
"""

from __future__ import annotations

import queue
import time
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk

from core.compliance import COMPLIANCE_MATRIX, OWASP_CHECKLIST
from core.config import LabConfig
from core.lab_runner import LabRunner
from gui.security import PinVault
from gui.theme import (BG0, BG1, CARD, HOVER, MUT, RPT, SER, SEVERITY_COLORS,
                       TXT, ZK)
from reporting.csv_report import write_csv
from reporting.html_report import write_html
from reporting.xlsx_report import write_xlsx

BG = BG1
FG = TXT


def _configure_styles(root: tk.Tk):
    style = ttk.Style(root)
    try:
        style.theme_use("clam")
    except tk.TclError:
        pass
    root.configure(bg=BG)
    for name in ("TNotebook", "TNotebook.Tab"):
        style.configure(name, background=BG1, foreground=FG,
                        borderwidth=0)
    style.map("TNotebook.Tab", background=[("selected", ZK)],
              foreground=[("selected", "#0a0a1a")])
    for name in ("TFrame",):
        style.configure(name, background=BG)
    for name in ("TLabel",):
        style.configure(name, background=BG, foreground=FG)
    for name in ("TLabelframe", "TLabelframe.Label"):
        style.configure(name, background=BG, foreground=SER)
    style.configure("Treeview", background=CARD, fieldbackground=CARD, foreground=FG,
                    rowheight=24, borderwidth=0)
    style.configure("Treeview.Heading", background=BG1, foreground=SER,
                    borderwidth=0)
    style.map("Treeview", background=[("selected", ZK)],
              foreground=[("selected", "#0a0a1a")])
    style.configure("TButton", background=BG1, foreground=FG, padding=6)
    style.map("TButton", background=[("active", HOVER), ("pressed", ZK)])


class C2LabApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("C2 Detection Lab - Console")
        self.geometry("1280x820")
        self.minsize(1000, 680)
        _configure_styles(self)

        self.base_dir = "labs"
        self.vault = PinVault(self.base_dir)
        self.cfg = LabConfig(outdir=f"{self.base_dir}/runs")
        self.runner: LabRunner | None = None
        self.last_result: dict | None = None
        self.ev_queue: queue.Queue = queue.Queue()

        self._lock_console()

    # ---------------------------------------------------------------- PIN #
    def _lock_console(self):
        lock = tk.Toplevel(self)
        lock.title("C2 Detection Lab - PIN Lock")
        lock.configure(bg=BG)
        lock.resizable(False, False)
        lock.grab_set()

        ttk.Label(lock, text="🔐 Enter PIN to access lab console",
                  font=("Segoe UI", 13, "bold")).pack(padx=28, pady=(24, 6))
        ttk.Label(lock, text="RBAC gate · ISO A.9 / OWASP A01 · attempts limited",
                  foreground=MUT).pack(padx=28)
        pin_var = tk.StringVar()
        entry = ttk.Entry(lock, textvariable=pin_var, show="*", width=24)
        entry.pack(padx=28, pady=12)
        status = ttk.Label(lock, text="", foreground="#ffab7d")
        status.pack()
        self._unlocked = False

        def hard_exit():
            self.destroy()
            raise SystemExit(0)

        def on_close():
            if self.vault.data.get("locked_until", 0) > __import__("time").time():
                messagebox.showerror("Locked", "Too many attempts - lockout in effect.")
                return
            if messagebox.askokcancel("Exit", "Close lab console?"):
                hard_exit()

        lock.protocol("WM_DELETE_WINDOW", on_close)

        def attempt(_ev=None):
            if self.vault.check(pin_var.get()):
                self._unlocked = True
                lock.destroy()
            else:
                status.config(text="Invalid PIN - retrying (lockout after 5 fails)")
                pin_var.set("")

        btn = ttk.Button(lock, text="Unlock", command=attempt)
        btn.pack(pady=(0, 24))
        entry.bind("<Return>", attempt)
        entry.focus_set()
        self.wait_window(lock)
        if not self._unlocked:
            hard_exit()
        self._build_tabs()

    # ---------------------------------------------------------------- tabs #
    def _build_tabs(self):
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=8, pady=8)
        self.tab_control = self._tab("🎛 Lab Control")
        self.tab_builder = self._tab("✍️ C2 Builder")
        self.tab_sigs = self._tab("📜 Signature Builder")
        self.tab_alerts = self._tab("🚨 Live Alerts")
        self.tab_reports = self._tab("📊 Reports")
        self.tab_compliance = self._tab("✅ Compliance")

        self._build_control_tab()
        self._build_builder_tab()
        self._build_signatures_tab()
        self._build_alerts_tab()
        self._build_reports_tab()
        self._build_compliance_tab()

        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self.after(400, self._poll_alerts)

    def _tab(self, title: str) -> ttk.Frame:
        fr = ttk.Frame(self.notebook)
        self.notebook.add(fr, text=title)
        return fr

    def _label_row(self, parent, text: str, var: tk.StringVar, width: int = 14,
                   row: int = 0, **kw):
        ttk.Label(parent, text=text, background=BG).grid(
            row=row, column=0, sticky="e", padx=(16, 8), pady=5)
        e = ttk.Entry(parent, textvariable=var, width=width, **kw)
        e.grid(row=row, column=1, sticky="w", pady=5)
        return e

    # ------------------------------------------------------- Lab Control #
    def _build_control_tab(self):
        pad = ttk.Frame(self.tab_control, padding=16)
        pad.pack(fill="both", expand=True)
        ttk.Label(pad, text="Lab Run Control",
                  font=("Segoe UI", 14, "bold"), foreground=SER).pack(anchor="w")

        box = ttk.Labelframe(pad, text=" Run parameters ")
        box.pack(fill="x", padx=4, pady=10)
        for i, (lbl, key, default) in enumerate([
                ("Beacon interval (s)", "beacon_interval", "5.0"),
                ("Jitter (%)", "jitter_pct", "20"),
                ("Agents", "agent_count", "3"),
                ("Run duration (s)", "run_duration", "30"),
                ("Benign noise /s", "benign_rate", "2.0"),
                ("Channel (http|https|dns)", "channel", "http")]):
            setattr(self, "v_" + key, tk.StringVar(value=default))
            self._label_row(box, lbl, getattr(self, "v_" + key), row=i)

        ctrl = ttk.Frame(pad)
        ctrl.pack(fill="x", pady=12)
        self.btn_start = ttk.Button(ctrl, text="▶ Start Lab Run",
                                    command=self._start_lab, style="TButton")
        self.btn_start.pack(side="left", padx=4)
        self.btn_cancel = ttk.Button(ctrl, text="■ Cancel", command=self._cancel_lab)
        self.btn_cancel.pack(side="left", padx=4)
        self.lbl_status = ttk.Label(pad, text="status: idle", foreground=MUT)
        self.lbl_status.pack(anchor="w", pady=(0, 8))

        self.console = scrolledtext.ScrolledText(pad, height=16, bg=CARD,
                                                 fg=TXT, font=("Consolas", 10),
                                                 relief="flat", state="disabled")
        self.console.pack(fill="both", expand=True)

    def log(self, msg: str):
        ts = time.strftime("%H:%M:%S")
        self.console.configure(state="normal")
        self.console.insert("end", f"[{ts}] {msg}\n")
        self.console.see("end")
        self.console.configure(state="disabled")

    def _apply_cfg_from_ui(self) -> bool:
        def f(key, typ):
            try:
                return typ(getattr(self, "v_" + key).get())
            except (ValueError, TypeError):
                raise ValueError(f"Invalid value for {key}")

        try:
            self.cfg.beacon_interval = f("beacon_interval", float)
            self.cfg.jitter_pct = f("jitter_pct", float)
            self.cfg.agent_count = int(f("agent_count", int))
            self.cfg.run_duration = f("run_duration", float)
            self.cfg.benign_rate = f("benign_rate", float)
            self.cfg.channel = f("channel", str)
        except ValueError as exc:
            messagebox.showerror("Invalid input", str(exc))
            return False
        issues = self.cfg.validate()
        if issues:
            messagebox.showerror("Validation", "\n".join(issues))
            return False
        self.cfg.outdir = f"{self.base_dir}/runs"
        return True

    def _start_lab(self):
        if not self._apply_cfg_from_ui():
            return
        self.runner = LabRunner(self.cfg)
        self.log(f"Starting lab run {self.cfg.run_id} "
                 f"(interval={self.cfg.beacon_interval}s, channel={self.cfg.channel})")
        self.lbl_status.config(text="status: running", foreground=RPT)
        self.runner.run_async(on_done=self._on_lab_done,
                              on_error=self._on_lab_error)

    def _cancel_lab(self):
        if self.runner:
            self.runner.cancel()
            self.log("Cancel requested")

    def _on_lab_done(self, result: dict):
        self.last_result = result
        self.lbl_status.config(text="status: idle - run complete",
                               foreground=TXT)
        m = result["metrics"]
        self.log(f"run complete | alerts={m['alerts']} tp={m['true_positives']} "
                 f"fp={m['false_positives']} fn={m['false_negatives']} "
                 f"precision={m['precision']} recall={m['recall']} f1={m['f1']}")
        self._refresh_signatures()
        self._refresh_alerts()

    def _on_lab_error(self, exc: Exception):
        self.lbl_status.config(text="status: error", foreground="#ff2d78")
        self.log(f"ERROR: {exc}")
        messagebox.showerror("Lab error", str(exc))

    # ------------------------------------------------------- C2 Builder #
    def _build_builder_tab(self):
        pad = ttk.Frame(self.tab_builder, padding=16)
        pad.pack(fill="both", expand=True)
        ttk.Label(pad, text="C2 Simulation Builder (L2)",
                  font=("Segoe UI", 14, "bold"), foreground="#" + "ff6b2c").pack(anchor="w")
        ttk.Label(pad, text="Actually spawns a localhost C2 implant + agent fleet "
                            "on an ephemeral port. Traffic is captured for the engines.",
                  foreground=MUT).pack(anchor="w", pady=(0, 10))
        box = ttk.Labelframe(pad, text=" Implant profile ")
        box.pack(fill="x", padx=4, pady=10)
        for i, (lbl, key, default) in enumerate([
                ("Server host", "server_host", "127.0.0.1"),
                ("User-Agent", "user_agent",
                 "Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 C2DetectLab/1.0"),
                ("Payload magic (hex)", "magic", "00 7f")]):
            setattr(self, "vb_" + key, tk.StringVar(value=default))
            self._label_row(box, lbl, getattr(self, "vb_" + key), row=i)
        ttk.Button(pad, text="▶ Generate C2 + signatures from this profile",
                   command=self._gen_from_builder).pack(anchor="w", pady=8)

    def _gen_from_builder(self):
        if not self._apply_cfg_from_ui():
            return
        self.cfg.server_host = self.vb_server_host.get()
        self.cfg.user_agent = self.vb_user_agent.get()
        self.cfg.magic = self.vb_magic.get()
        try:
            self._apply_cfg_from_ui()
        except Exception:
            pass
        self.runner = LabRunner(self.cfg)
        self.log("Signature-only build (no traffic)")
        self._build_signatures_write()
        messagebox.showinfo("Signatures",
                            "beacon.zeek + c2_beacon.rules written to\n"
                            + str(self.cfg.detection_dir))

    def _build_signatures_write(self):
        from detectors.suricata import generate_suricata
        from detectors.zeek import generate_zeek
        z = generate_zeek(self.cfg.detection_dir, self.cfg.beacon_interval)
        s = generate_suricata(self.cfg.detection_dir)
        self._load_sig_texts()
        return z, s

    # ------------------------------------------------- Signature builder #
    def _build_signatures_tab(self):
        pad = ttk.Frame(self.tab_sigs, padding=16)
        pad.pack(fill="both", expand=True)
        ttk.Label(pad, text="Signature Preview (L3)",
                  font=("Segoe UI", 14, "bold"), foreground=ZK).pack(anchor="w")
        ttk.Label(pad, text="beacon.zeek (Zeek 6.x) — generated by your run:",
                  foreground=MUT).pack(anchor="w", pady=(6, 2))
        self.txt_zeek = scrolledtext.ScrolledText(pad, height=13, bg=CARD, fg="#c9a4ff",
                                                  font=("Consolas", 9), relief="flat")
        self.txt_zeek.pack(fill="both", expand=True, pady=(0, 8))
        ttk.Label(pad, text="c2_beacon.rules (Suricata 7.x):",
                  foreground=MUT).pack(anchor="w")
        self.txt_suri = scrolledtext.ScrolledText(pad, height=13, bg=CARD, fg="#ffab7d",
                                                  font=("Consolas", 9), relief="flat")
        self.txt_suri.pack(fill="both", expand=True)

    def _refresh_signatures(self):
        if not self.last_result:
            return
        self._load_sig_texts()

    def _load_sig_texts(self):
        from core import config as cfg_mod
        sigs = {}
        det_dir = self.cfg.detection_dir
        for name in ("beacon.zeek", "c2_beacon.rules"):
            p = det_dir / name
            sigs[name] = p.read_text(encoding="utf-8") if p.exists() else "(not written)"
        self.txt_zeek.configure(state="normal")
        self.txt_zeek.delete("1.0", "end")
        self.txt_zeek.insert("1.0", sigs.get("beacon.zeek", ""))
        self.txt_zeek.configure(state="disabled")
        self.txt_suri.configure(state="normal")
        self.txt_suri.delete("1.0", "end")
        self.txt_suri.insert("1.0", sigs.get("c2_beacon.rules", ""))
        self.txt_suri.configure(state="disabled")

    # -------------------------------------------------------- Live alerts #
    def _build_alerts_tab(self):
        pad = ttk.Frame(self.tab_alerts, padding=16)
        pad.pack(fill="both", expand=True)
        ttk.Label(pad, text="Live Alert Stream (L3 -> L4)",
                  font=("Segoe UI", 14, "bold"), foreground="#" + "ff2d78").pack(anchor="w")
        cols = ("ts", "detector", "severity", "score", "src", "dst", "rule", "mitre")
        self.tree = ttk.Treeview(pad, columns=cols, show="headings", height=22)
        heads = {"ts": 150, "detector": 90, "severity": 80, "score": 60,
                 "src": 140, "dst": 140, "rule": 300, "mitre": 110}
        for c in cols:
            self.tree.heading(c, text=c.upper())
            self.tree.column(c, width=heads[c], anchor="w")
        self.tree.pack(fill="both", expand=True, pady=8)
        for sev in SEVERITY_COLORS:
            self.tree.tag_configure(sev, foreground=SEVERITY_COLORS[sev])
        ttk.Button(pad, text="Clear view", command=lambda: self.tree.delete(*self.tree.get_children())
                   ).pack(anchor="w")

    def _refresh_alerts(self):
        if not self.last_result:
            return
        for a in self.last_result["alerts"]:
            sev = str(a["severity"]).lower()
            tag = sev if sev in SEVERITY_COLORS else "medium"
            self.tree.insert("", "end", values=(
                a["ts_iso"], a["detector"], a["severity"], a["score"],
                a["src_ip"], a["dst_ip"], a["rule_id"][:60], a["mitre_technique"]),
                tags=(tag,))

    def _poll_alerts(self):
        # Reschedule even if nothing new
        self.after(400, self._poll_alerts)

    # ------------------------------------------------------------- Reports #
    def _build_reports_tab(self):
        pad = ttk.Frame(self.tab_reports, padding=16)
        pad.pack(fill="both", expand=True)
        ttk.Label(pad, text="Report & Evidence Export (L5)",
                  font=("Segoe UI", 14, "bold"), foreground=RPT).pack(anchor="w")
        ttk.Label(pad, text="Download formats: .XLSX · .CSV · .HTML (+ audit evidence)",
                  foreground=MUT).pack(anchor="w", pady=(0, 12))

        def _guarded(fn):
            if not self.last_result:
                messagebox.showwarning("No run", "Run a lab first.")
                return
            folder = filedialog.askdirectory(
                title="Choose report output folder")
            if not folder:
                return
            try:
                paths = fn(folder)
                for p in paths:
                    self.log("exported " + str(p))
                messagebox.showinfo("Export done", "\n".join(map(str, paths)))
            except Exception as exc:  # noqa: BLE001
                messagebox.showerror("Export failed", str(exc))

        ttk.Button(pad, text="📗 Export .XLSX",
                   command=lambda: _guarded(self._export_xlsx)).pack(anchor="w", pady=4)
        ttk.Button(pad, text="📄 Export .CSV set",
                   command=lambda: _guarded(self._export_csv)).pack(anchor="w", pady=4)
        ttk.Button(pad, text="🌐 Export .HTML dashboard",
                   command=lambda: _guarded(self._export_html)).pack(anchor="w", pady=4)

        ttk.Label(pad, text="Evidence (SHA-256 audit chain):",
                  foreground=MUT).pack(anchor="w", pady=(14, 4))
        self.txt_ev = scrolledtext.ScrolledText(pad, height=14, bg=CARD, fg="#7deed0",
                                                font=("Consolas", 9), relief="flat",
                                                state="disabled")
        self.txt_ev.pack(fill="both", expand=True)

    def _result_with_evidence(self) -> dict:
        res = dict(self.last_result)
        if self.runner and self.runner.auditor.entries:
            res["evidence_entries"] = self.runner.auditor.entries
            self.txt_ev.configure(state="normal")
            self.txt_ev.delete("1.0", "end")
            for e in self.runner.auditor.entries:
                self.txt_ev.insert("end",
                                   f"{e['ts_iso']}  {e['event']:26s} "
                                   f"{e['sha256'][:16] + '..' if e.get('sha256') else '-'}\n")
            self.txt_ev.configure(state="disabled")
        return res

    def _export_xlsx(self, folder: str):
        from core.audit import sha256_file
        from pathlib import Path
        folder = Path(folder)
        p = write_xlsx(self._result_with_evidence(), folder / f"report_{self.cfg.run_id}.xlsx")
        return [str(p), f"SHA256 {sha256_file(p)[:32]}..."]

    def _export_csv(self, folder: str):
        res = dict(self.last_result)
        if self.runner and self.runner.auditor.entries:
            res["evidence_entries"] = self.runner.auditor.entries
        return [str(p) for p in write_csv(res, folder)]

    def _export_html(self, folder: str):
        return [str(write_html(self._result_with_evidence(),
                               str(folder) + f"/report_{self.cfg.run_id}.html"))]

    # ---------------------------------------------------------- Compliance #
    def _build_compliance_tab(self):
        pad = ttk.Frame(self.tab_compliance, padding=16)
        pad.pack(fill="both", expand=True)
        ttk.Label(pad, text="Security Framework Mapping",
                  font=("Segoe UI", 14, "bold"), foreground="#" + "ffd93b").pack(anchor="w")
        ttk.Label(pad, text="Confirmed: ISO 27001 · NIST CSF 2.0 · NIST 800-53 · OWASP "
                            "Top 10 (architecture.md section 5)",
                  foreground=MUT).pack(anchor="w", pady=(0, 10))

        self.tree_comp = ttk.Treeview(pad, columns=("fw", "ctrl", "topic", "artifact"),
                                      show="headings", height=12)
        for c, t, w in [("fw", "FRAMEWORK", 110), ("ctrl", "CONTROL", 120),
                        ("topic", "TOPIC", 220), ("artifact", "IMPLEMENTED BY", 380)]:
            self.tree_comp.heading(c, text=t)
            self.tree_comp.column(c, width=w)
        self.tree_comp.pack(fill="x", pady=6)
        for c in COMPLIANCE_MATRIX:
            self.tree_comp.insert("", "end", values=(
                c["framework"], c["control"], c["topic"], c["artifact"]))

        ttk.Label(pad, text="OWASP Top 10 (2021) — app self-check:",
                  foreground=SER).pack(anchor="w", pady=(10, 2))
        self.tree_owasp = ttk.Treeview(pad, columns=("risk", "check", "status"),
                                       show="headings", height=8)
        for c, t, w in [("risk", "RISK", 260), ("check", "MITIGATION", 520),
                        ("status", "STATUS", 90)]:
            self.tree_owasp.heading(c, text=t)
            self.tree_owasp.column(c, width=w)
        self.tree_owasp.pack(fill="x", pady=6)
        for c in OWASP_CHECKLIST:
            self.tree_owasp.insert("", "end", values=(c["risk"], c["check"], c["status"]))

    # ----------------------------------------------------------------- close #
    def _on_close(self):
        if messagebox.askokcancel("Exit", "Teardown lab and close?"):
            if self.runner:
                self.runner.cancel()
            self.destroy()


def main():
    app = C2LabApp()
    app.mainloop()


if __name__ == "__main__":
    main()