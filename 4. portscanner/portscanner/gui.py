"""Tkinter GUI (architecture.md §1 G6, security.md authorization gate).

Stdlib-only desktop front-end. Runs the scan in a worker thread and consumes
progress via a thread-safe queue. The authorization checkbox is mandatory for
non-private targets — the scan refuses to start otherwise.
"""
from __future__ import annotations

import queue
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from .config import ScanType, validate
from .security import CONFIRM_PHRASE, authorization_gate, is_admin, is_local_or_private
from .scanner import Scanner

SCAN_TYPES = [t.value for t in ScanType]
FORMATS = ["table", "json", "jsonl", "csv", "greppable"]


class PortScannerGUI(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("Port Scanner — authorized use only")
        self.geometry("980x640")
        self.minsize(860, 560)

        self._queue: queue.Queue = queue.Queue()
        self._scanner: Scanner | None = None
        self._worker: threading.Thread | None = None

        self._build_ui()
        self.after(150, self._poll_queue)

    # ---------------- UI construction ----------------
    def _build_ui(self) -> None:
        frm = ttk.Frame(self, padding=10)
        frm.pack(fill="both", expand=True)

        # -- targets row --
        row1 = ttk.Frame(frm); row1.pack(fill="x", pady=4)
        ttk.Label(row1, text="Targets:").pack(side="left")
        self.targets_var = tk.StringVar(value="127.0.0.1, 10.0.0.0/30")
        ttk.Entry(row1, textvariable=self.targets_var).pack(
            side="left", fill="x", expand=True, padx=6)

        # -- ports row --
        row2 = ttk.Frame(frm); row2.pack(fill="x", pady=4)
        ttk.Label(row2, text="Ports:").pack(side="left")
        self.ports_var = tk.StringVar(value="top100")
        ttk.Entry(row2, textvariable=self.ports_var, width=28).pack(side="left", padx=6)
        ttk.Label(row2, text="Scan type:").pack(side="left", padx=(16, 2))
        self.scan_type_var = tk.StringVar(value=ScanType.CONNECT.value)
        ttk.Combobox(row2, textvariable=self.scan_type_var, values=SCAN_TYPES,
                     state="readonly", width=10).pack(side="left")
        ttk.Label(row2, text="Output:").pack(side="left", padx=(16, 2))
        self.fmt_var = tk.StringVar(value="table")
        ttk.Combobox(row2, textvariable=self.fmt_var, values=FORMATS,
                     state="readonly", width=10).pack(side="left")

        # -- tuning row --
        row3 = ttk.Frame(frm); row3.pack(fill="x", pady=4)
        ttk.Label(row3, text="Workers:").pack(side="left")
        self.workers_var = tk.IntVar(value=256)
        ttk.Spinbox(row3, from_=1, to=2048, textvariable=self.workers_var,
                    width=7).pack(side="left", padx=4)
        ttk.Label(row3, text="Rate/s (0=∞):").pack(side="left", padx=(12, 0))
        self.rate_var = tk.DoubleVar(value=0.0)
        ttk.Spinbox(row3, from_=0, to=100000, textvariable=self.rate_var,
                    width=8).pack(side="left", padx=4)
        ttk.Label(row3, text="Timeout s:").pack(side="left", padx=(12, 0))
        self.timeout_var = tk.DoubleVar(value=1.0)
        ttk.Spinbox(row3, from_=0.05, to=60, increment=0.05,
                    textvariable=self.timeout_var, width=6).pack(side="left", padx=4)
        self.svc_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(row3, text="Service detection",
                        variable=self.svc_var).pack(side="left", padx=(16, 0))

        # -- authorization gate (security.md §2) --
        row4 = ttk.Frame(frm); row4.pack(fill="x", pady=4)
        self.auth_var = tk.BooleanVar(value=False)
        self.auth_chk = ttk.Checkbutton(
            row4,
            text=f'Authorization: "{CONFIRM_PHRASE}"',
            variable=self.auth_var,
        )
        self.auth_chk.pack(side="left")
        self.admin_lbl = ttk.Label(
            row4, text=f"raw-scan privilege: {'yes' if is_admin() else 'no (connect/udp only)'}",
            foreground="#666",
        )
        self.admin_lbl.pack(side="left", padx=16)

        # -- action row --
        row5 = ttk.Frame(frm); row5.pack(fill="x", pady=6)
        self.start_btn = ttk.Button(row5, text="Start scan", command=self.start)
        self.start_btn.pack(side="left")
        self.stop_btn = ttk.Button(row5, text="Stop", command=self.stop,
                                   state="disabled")
        self.stop_btn.pack(side="left", padx=8)
        self.save_btn = ttk.Button(row5, text="Save report…", command=self.save,
                                   state="disabled")
        self.save_btn.pack(side="left", padx=8)
        self.status_lbl = ttk.Label(row5, text="idle")
        self.status_lbl.pack(side="left", padx=16)

        # -- progress --
        self.progress = ttk.Progressbar(frm, mode="indeterminate")
        self.progress.pack(fill="x", pady=2)

        # -- results --
        cols = ("host", "port", "state", "service", "product", "version")
        self.tree = ttk.Treeview(frm, columns=cols, show="headings", height=16)
        widths = (160, 70, 90, 110, 140, 120)
        for c, w in zip(cols, widths):
            self.tree.heading(c, text=c.title())
            self.tree.column(c, width=w, anchor="w")
        self.tree.pack(fill="both", expand=True, pady=6)
        self.tree.tag_configure("open", foreground="#0a7d20")

        # -- log --
        self.log = tk.Text(frm, height=6, state="disabled", font=("Consolas", 9))
        self.log.pack(fill="x")

    # ---------------- actions ----------------
    def start(self) -> None:
        targets = [t.strip() for t in self.targets_var.get().split(",") if t.strip()]
        try:
            cfg = validate(
                targets=targets,
                ports_spec=self.ports_var.get(),
                scan_type=self.scan_type_var.get(),
                workers=int(self.workers_var.get()),
                rate_limit=float(self.rate_var.get()),
                timeout_s=float(self.timeout_var.get()),
                service_detect=bool(self.svc_var.get()),
                output_format=self.fmt_var.get(),
                authorized=bool(self.auth_var.get()),
            )
        except ValueError as exc:
            messagebox.showerror("Invalid configuration", str(exc))
            return

        non_private = [t for t in cfg.targets if not is_local_or_private(t)]
        if non_private and not authorization_gate(non_private, interactive=True,
                                                  yes=bool(self.auth_var.get())):
            messagebox.showerror(
                "Authorization required",
                "Scan cancelled: authorization not confirmed.\n"
                "The attempt has been recorded in the audit log.",
            )
            return

        self._set_running(True)
        self.tree.delete(*self.tree.get_children())
        self.status_lbl.config(text="resolving targets…")
        self._worker = threading.Thread(target=self._run_scan, args=(cfg,),
                                        daemon=True)
        self._worker.start()

    def stop(self) -> None:
        if self._scanner:
            self._scanner.stop()
        self.status_lbl.config(text="stopping…")

    def save(self) -> None:
        text = getattr(self, "_last_output", "")
        if not text:
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Report", "*.txt *.json *.jsonl *.csv"), ("All", "*.*")],
        )
        if path:
            try:
                from pathlib import Path
                Path(path).write_text(text, encoding="utf-8")
                self._log(f"report saved: {path}")
            except OSError as exc:
                messagebox.showerror("Save failed", str(exc))

    # ---------------- worker thread ----------------
    def _run_scan(self, cfg) -> None:
        try:
            scanner = Scanner(cfg)
            self._scanner = scanner
            scanner.bus.subscribe(self._on_event)
            output = scanner.run()
            self._queue.put(("done", output))
        except Exception as exc:  # noqa: BLE001 — surface to UI, never crash thread
            self._queue.put(("error", str(exc)))

    def _on_event(self, ev) -> None:
        # called from worker thread: marshal into UI queue
        from .events import PortResultEvent, ScanStarted, ScanFinished
        if isinstance(ev, ScanStarted):
            self._queue.put(("status", f"scanning {ev.targets} hosts × {ev.ports} ports ({ev.engine})"))
        elif isinstance(ev, PortResultEvent):
            if ev.state == "open":
                self._queue.put(("open", ev))
        elif isinstance(ev, ScanFinished):
            self._queue.put(("stats", ev))

    # ---------------- UI pump ----------------
    def _poll_queue(self) -> None:
        try:
            while True:
                kind, payload = self._queue.get_nowait()
                if kind == "open":
                    self.tree.insert("", "end", tags=("open",),
                                     values=(payload.host, payload.port, "open",
                                             "…", "", ""))
                elif kind == "status":
                    self.status_lbl.config(text=str(payload))
                    self.progress.start(40)
                elif kind == "stats":
                    counts = payload.counts
                    self.status_lbl.config(
                        text=f"finished in {payload.duration_s:.1f}s — "
                             f"open={counts.get('open', 0)} "
                             f"closed={counts.get('closed', 0)} "
                             f"filtered={counts.get('filtered', 0)}")
                    self.progress.stop()
                    self._set_running(False)
                elif kind == "done":
                    self._last_output = payload
                    self.log.config(state="normal")
                    self.log.delete("1.0", "end")
                    self.log.insert("1.0", payload[:8000])
                    self.log.config(state="disabled")
                    self.save_btn.config(state="normal")
                elif kind == "error":
                    self.status_lbl.config(text="failed")
                    self.progress.stop()
                    self._set_running(False)
                    messagebox.showerror("Scan failed", str(payload))
        except queue.Empty:
            pass
        self.after(150, self._poll_queue)

    def _log(self, msg: str) -> None:
        self.log.config(state="normal")
        self.log.insert("end", msg + "\n")
        self.log.config(state="disabled")

    def _set_running(self, running: bool) -> None:
        self.start_btn.config(state="disabled" if running else "normal")
        self.stop_btn.config(state="normal" if running else "disabled")


def main() -> None:
    app = PortScannerGUI()
    app.mainloop()


if __name__ == "__main__":
    main()
