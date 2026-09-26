"""GUI front-end for the SIEM log correlator (ingest -> normalize -> correlate -> alert).

Wraps the same siem_correlator pipeline as main.py but exposes it through a
tkinter desktop app. Stdlib only (tkinter ships with CPython on Windows).

Features:
  * pick ingest / rules / output directories
  * scan once or continuously watch a log directory
  * live tables of normalized events and alerts (severity colored)
  * ad-hoc test of a single log line through the full pipeline
  * reload historical events/alerts already written under the output dir
"""
from __future__ import annotations

import json
import os
import queue
import sys
import threading
import time
import tkinter as tk
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
os.chdir(ROOT)

from siem_correlator import ingest as ing
from siem_correlator.alerting import JsonlWriter, Router
from siem_correlator.correlate import RuleEngine
from siem_correlator.model import Alert, Event, RawEvent
from siem_correlator.normalize import build_normalizer
from siem_correlator.store import AlertIndex, EventStore, summarize_alerts

SEVERITIES = ["info", "low", "medium", "high", "critical"]
SEV_COLORS = {
    "info": "#6c757d",
    "low": "#28a745",
    "medium": "#b8860b",
    "high": "#e67e22",
    "critical": "#c0392b",
}

SCAN_EXT = {".log", ".txt", ".jsonl", ".sys"}
MAX_EVENT_ROWS = 2000
MAX_ALERT_ROWS = 2000
POLL_MS = 120
BATCH = 400

EV_FIELDS = ("ts", "source_ip", "dest_ip", "dest_port", "user", "action",
             "category", "severity", "message", "source", "extra")


class _QueueWriter:
    """Router channel that forwards routed alerts to the UI thread."""

    def __init__(self, q: queue.Queue):
        self._q = q

    def write(self, alert: Alert) -> None:
        try:
            self._q.put(alert)
        except Exception:
            pass


class SiemApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        root.title("Lightweight SIEM Log Correlator  |  ingest -> normalize -> correlate -> alert")
        root.geometry("1180x740")
        root.minsize(960, 560)

        self.ingest_var = tk.StringVar(value="samples")
        self.rules_var = tk.StringVar(value="rules")
        self.out_var = tk.StringVar(value="data")
        self.sev_var = tk.StringVar(value="info")
        self.poll_var = tk.DoubleVar(value=1.0)
        self.test_var = tk.StringVar()
        self.autoscroll_var = tk.BooleanVar(value=True)
        self.status_var = tk.StringVar(value="Ready.")

        self._event_q: queue.Queue = queue.Queue()
        self._alert_q: queue.Queue = queue.Queue()
        self._log_q: queue.Queue = queue.Queue()

        self._pipeline_lock = threading.Lock()
        self._stop_event = threading.Event()
        self._worker: threading.Thread | None = None
        self._running = False

        self._alert_items: dict[str, str] = {}
        self._stats = {"raw": 0, "events": 0, "quarantine": 0, "alerts": 0, "started": 0.0}

        self._offsets: ing.OffsetTracker | None = None
        self._quarantine: ing.Quarantine | None = None
        self._normalizer = None
        self._engine = RuleEngine()
        self._router: Router | None = None
        self._event_store: EventStore | None = None
        self._alert_index: AlertIndex | None = None

        self._build_ui()
        self._log("ready. pick directories, then Run Once or Watch a log dir.")
        self.root.after(POLL_MS, self._poll)

    # ------------------------------------------------------------------ UI
    def _build_ui(self) -> None:
        cfg = ttk.LabelFrame(self.root, text="Inputs / Outputs", padding=(8, 6))
        cfg.pack(fill="x", padx=8, pady=(8, 4))
        cfg.columnconfigure(1, weight=1)

        for row, (label, var, kind) in enumerate((
            ("Ingest dir", self.ingest_var, "ingest"),
            ("Rules dir", self.rules_var, "rules"),
            ("Output dir", self.out_var, "out"),
        )):
            ttk.Label(cfg, text=label).grid(row=row, column=0, sticky="w", padx=(0, 6))
            ttk.Entry(cfg, textvariable=var).grid(row=row, column=1, sticky="ew", padx=(0, 6))
            ttk.Button(cfg, text="Browse...", width=10,
                       command=lambda k=kind: self._browse(k)).grid(row=row, column=2)

        act = ttk.Frame(self.root, padding=(8, 2))
        act.pack(fill="x")
        ttk.Label(act, text="Min severity:").pack(side="left")
        ttk.Combobox(act, textvariable=self.sev_var, values=SEVERITIES,
                     state="readonly", width=10).pack(side="left", padx=(4, 10))
        ttk.Label(act, text="Poll (s):").pack(side="left")
        ttk.Spinbox(act, from_=0.5, to=30, increment=0.5, width=5,
                    textvariable=self.poll_var).pack(side="left", padx=(4, 12))

        self._btn_run = ttk.Button(act, text="Run Once", command=lambda: self._start(False))
        self._btn_run.pack(side="left")
        self._btn_watch = ttk.Button(act, text="Watch (tail)", command=lambda: self._start(True))
        self._btn_watch.pack(side="left", padx=(6, 0))
        self._btn_stop = ttk.Button(act, text="Stop", command=self._stop, state="disabled")
        self._btn_stop.pack(side="left", padx=(6, 12))
        ttk.Button(act, text="Reset State", command=self._reset_state).pack(side="left")
        ttk.Button(act, text="Reload History", command=self._load_history).pack(side="left", padx=(6, 0))
        ttk.Button(act, text="Clear Tables", command=self._clear_tables).pack(side="left", padx=(6, 0))
        ttk.Checkbutton(act, text="Auto-scroll", variable=self.autoscroll_var).pack(side="right")

        tst = ttk.Frame(self.root, padding=(8, 2, 8, 4))
        tst.pack(fill="x")
        tst.columnconfigure(0, weight=1)
        ttk.Label(tst, text="Test log line:").grid(row=0, column=0, sticky="w")
        ttk.Entry(tst, textvariable=self.test_var).grid(row=0, column=1, sticky="ew", padx=(6, 6))
        ttk.Button(tst, text="Process + Correlate", command=self._process_test_line).grid(row=0, column=2)
        tst.bind("<Return>", lambda _e: self._process_test_line())

        nb = ttk.Notebook(self.root)
        nb.pack(fill="both", expand=True, padx=8, pady=(4, 4))

        ev_tab = ttk.Frame(nb)
        al_tab = ttk.Frame(nb)
        log_tab = ttk.Frame(nb)
        nb.add(ev_tab, text="Normalized Events")
        nb.add(al_tab, text="Alerts")
        nb.add(log_tab, text="Activity Log")

        self._event_tree = self._make_tree(
            ev_tab, ("ts", "source", "action", "category", "severity", "src_ip", "user", "port", "msg"),
            {"ts": "Time", "source": "Source", "action": "Action", "category": "Category",
             "severity": "Severity", "src_ip": "Src IP", "user": "User", "port": "Port", "msg": "Message"},
            {"ts": 150, "source": 130, "action": 90, "category": 95, "severity": 70,
             "src_ip": 110, "user": 90, "port": 45, "msg": 520},
        )
        self._alert_tree = self._make_tree(
            al_tab, ("ts", "severity", "rule_id", "rule_name", "incident", "count"),
            {"ts": "Time", "severity": "Severity", "rule_id": "Rule ID",
             "rule_name": "Rule Name", "incident": "Incident", "count": "Count"},
            {"ts": 150, "severity": 70, "rule_id": 150, "rule_name": 280, "incident": 200, "count": 55},
        )

        self._log_text = tk.Text(log_tab, wrap="word", state="disabled", bg="#0f1115",
                                 fg="#c9d1d9", insertbackground="#c9d1d9", font=("Consolas", 9))
        sb = ttk.Scrollbar(log_tab, orient="vertical", command=self._log_text.yview)
        self._log_text.configure(yscrollcommand=sb.set)
        self._log_text.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")

        ttk.Label(self.root, textvariable=self.status_var, anchor="w",
                  padding=(10, 4), relief="sunken").pack(fill="x", side="bottom")

        for sev, color in SEV_COLORS.items():
            self._event_tree.tag_configure(f"sev_{sev}", foreground=color)
            self._alert_tree.tag_configure(f"sev_{sev}", foreground=color)

    def _make_tree(self, parent, cols, heads, widths) -> ttk.Treeview:
        tree = ttk.Treeview(parent, columns=cols, show="headings", selectmode="browse")
        for c in cols:
            tree.heading(c, text=heads[c])
            tree.column(c, width=widths[c], anchor="w" if c != "count" else "center")
        vsb = ttk.Scrollbar(parent, orient="vertical", command=tree.yview)
        hsb = ttk.Scrollbar(parent, orient="horizontal", command=tree.xview)
        tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        parent.rowconfigure(0, weight=1)
        parent.columnconfigure(0, weight=1)
        return tree

    # ----------------------------------------------------------- UI actions
    def _browse(self, kind: str) -> None:
        var = {"ingest": self.ingest_var, "rules": self.rules_var, "out": self.out_var}[kind]
        initial = Path(var.get()).resolve() if var.get() else ROOT
        if kind == "out":
            sel = filedialog.askdirectory(title="Select output directory",
                                          initialdir=str(initial) if initial.is_dir() else str(ROOT))
        else:
            sel = filedialog.askdirectory(title="Select directory",
                                          initialdir=str(initial) if initial.is_dir() else str(ROOT))
        if sel:
            var.set(sel)

    def _start(self, tail: bool) -> None:
        if self._running:
            return
        try:
            with self._pipeline_lock:
                self._ensure_pipeline()
        except Exception as exc:
            self._log(f"start failed: {exc}")
            messagebox.showerror("Pipeline start failed", str(exc))
            return
        self._running = True
        self._stats.update(raw=0, events=0, quarantine=0, alerts=0, started=time.time())
        self._stop_event.clear()
        poll_s = max(0.2, float(self.poll_var.get()))
        self._worker = threading.Thread(target=self._worker_fn, args=(tail, poll_s), daemon=True)
        self._worker.start()
        self._log("watch started (continuous tailing)...")
        self._update_buttons()

    def _stop(self) -> None:
        if not self._running:
            return
        self._stop_event.set()
        self._log("stop requested, draining current poll...")

    def _process_test_line(self) -> None:
        line = self.test_var.get().strip()
        if not line:
            return
        try:
            with self._pipeline_lock:
                self._ensure_pipeline()
                self._handle_raw(RawEvent(source="manual:test", seq=1, raw=line))
            self._log(f"[test] ok: {line[:70]}")
        except Exception as exc:
            self._log(f"[test] error: {exc}")
            messagebox.showerror("Test line failed", str(exc))
        finally:
            self.test_var.set("")

    def _reset_state(self) -> None:
        out = Path(self.out_var.get())
        p = out / "state" / "ingest_offsets.json"
        if p.exists():
            try:
                p.unlink()
                self._log("ingest state reset: files will re-read from byte 0 on next scan")
            except OSError as exc:
                self._log(f"reset failed: {exc}")
        else:
            self._log("no ingest state found to reset")

    def _clear_tables(self) -> None:
        self._event_tree.delete(*self._event_tree.get_children())
        self._alert_tree.delete(*self._alert_tree.get_children())
        self._alert_items.clear()
        self._log("tables cleared")

    def _load_history(self) -> None:
        out = Path(self.out_var.get())
        idx = out / "alerts_index.jsonl"
        if idx.exists():
            for rec in reversed(summarize_alerts(idx, limit=MAX_ALERT_ROWS)):
                try:
                    self._insert_alert(Alert(**{k: v for k, v in rec.items()
                                                if k in ("rule_id", "rule_name", "severity",
                                                         "evidence", "incident_id", "ts", "count")}))
                except (TypeError, ValueError):
                    continue
        ev_root = out / "events"
        if ev_root.is_dir():
            lines: list = []
            for part in sorted(p for p in ev_root.iterdir() if p.is_dir()):
                f = part / "events.jsonl"
                if f.exists():
                    lines.extend(f.read_text(encoding="utf-8", errors="replace").splitlines())
            for line in lines[-MAX_EVENT_ROWS:]:
                try:
                    obj = json.loads(line)
                    self._insert_event(Event(**{k: v for k, v in obj.items() if k in EV_FIELDS}))
                except (json.JSONDecodeError, TypeError, ValueError):
                    continue
        self._log("history reloaded into tables")

    # --------------------------------------------------------------- pipeline
    def _ensure_pipeline(self) -> None:
        if self._event_store is not None:
            return
        out = Path(self.out_var.get()).resolve()
        rules = Path(self.rules_var.get()).resolve()
        out.mkdir(parents=True, exist_ok=True)
        if not rules.is_dir():
            raise FileNotFoundError(f"rules dir not found: {rules}")
        self._offsets = ing.OffsetTracker(out / "state")
        self._quarantine = ing.Quarantine(out / "quarantine")
        self._normalizer = build_normalizer(quarantine_io=self._quarantine)
        self._engine = RuleEngine()
        self._engine.load_rules(rules)
        self._engine.on_alert = self._on_alert
        self._router = Router(min_severity=self.sev_var.get())
        self._router.add_channel(JsonlWriter(out / "alerts.jsonl"))
        self._router.add_channel(_QueueWriter(self._alert_q))
        self._event_store = EventStore(out / "events")
        self._alert_index = AlertIndex(out / "alerts_index.jsonl")
        self._log(f"pipeline ready: {len(self._engine.threshold_rules)} rule(s) from {rules}")

    def _worker_fn(self, tail: bool, poll_s: float) -> None:
        try:
            while True:
                with self._pipeline_lock:
                    self._poll_ingest()
                if not tail or self._stop_event.is_set():
                    break
                time.sleep(poll_s)
        except Exception as exc:
            self._log(f"pipeline error: {exc}")
        finally:
            self._running = False
            self._log("pipeline stopped.")

    def _poll_ingest(self) -> None:
        d = Path(self.ingest_var.get())
        if not d.is_dir():
            self._log(f"ingest dir not found: {d}")
            return
        for path in sorted(d.iterdir()):
            if not path.is_file() or path.suffix.lower() not in SCAN_EXT:
                continue
            for raw in ing.FileTailer(path, self._offsets):
                self._handle_raw(raw)

    def _handle_raw(self, raw: RawEvent) -> None:
        self._stats["raw"] += 1
        ev = self._normalizer(raw)
        if ev is None:
            self._stats["quarantine"] += 1
            return
        self._stats["events"] += 1
        self._event_store.append(ev)
        self._event_q.put(ev)
        self._engine.handle(ev)

    def _on_alert(self, engine, _ev, _rule, alert: Alert) -> None:
        self._stats["alerts"] += 1
        self._alert_index.add(alert)
        self._router.route(alert)
        self._alert_q.put(alert)

    # ------------------------------------------------------------------ view
    def _insert_event(self, ev: Event) -> None:
        tree = self._event_tree
        tree.insert("", "end", values=(
            ev.ts, ev.source, ev.action, ev.category, ev.severity,
            ev.source_ip, ev.user, ev.dest_port, ev.message,
        ), tags=(f"sev_{ev.severity}",))
        if len(tree.get_children()) > MAX_EVENT_ROWS:
            tree.delete(tree.get_children()[0])

    def _insert_alert(self, alert: Alert) -> None:
        tree = self._alert_tree
        item = self._alert_items.get(alert.incident_id)
        if item:
            tree.set(item, "count", str(alert.count))
            tree.set(item, "ts", alert.ts)
            return
        item = tree.insert("", "end", iid=alert.incident_id, values=(
            alert.ts, alert.severity, alert.rule_id, alert.rule_name,
            alert.incident_id, alert.count,
        ), tags=(f"sev_{alert.severity}",))
        self._alert_items[alert.incident_id] = item
        if len(tree.get_children()) > MAX_ALERT_ROWS:
            oldest = tree.get_children()[0]
            self._alert_items = {k: v for k, v in self._alert_items.items() if v != oldest}
            tree.delete(oldest)

    def _insert_log(self, line: str) -> None:
        stamp = datetime.now().strftime("%H:%M:%S")
        self._log_text.configure(state="normal")
        self._log_text.insert("end", f"[{stamp}] {line}\n")
        if self.autoscroll_var.get():
            self._log_text.see("end")
        if int(self._log_text.index("end-1c").split(".")[0]) > 1500:
            self._log_text.delete("1.0", "500.0")
        self._log_text.configure(state="disabled")

    def _log(self, line: str) -> None:
        self._log_q.put(line)

    def _drain(self) -> None:
        for _ in range(BATCH):
            try:
                ev = self._event_q.get_nowait()
            except queue.Empty:
                break
            self._insert_event(ev)
        for _ in range(BATCH):
            try:
                al = self._alert_q.get_nowait()
            except queue.Empty:
                break
            self._insert_alert(al)
        while True:
            try:
                line = self._log_q.get_nowait()
            except queue.Empty:
                break
            self._insert_log(line)

    def _update_status(self) -> None:
        active = "● running" if self._running else "idle"
        el = time.time() - self._stats["started"] if self._stats["started"] else 0.0
        self.status_var.set(
            f"{active} | raw={self._stats['raw']}  normalized={self._stats['events']}  "
            f"quarantined={self._stats['quarantine']}  alerts={self._stats['alerts']}  "
            f"rules={len(self._engine.threshold_rules)}  elapsed={el:.1f}s  |  "
            f"event rows={len(self._event_tree.get_children())}  alert rows={len(self._alert_tree.get_children())}")

    def _update_buttons(self) -> None:
        state = "disabled" if self._running else "normal"
        self._btn_run.configure(state=state)
        self._btn_watch.configure(state=state)
        self._btn_stop.configure(state="normal" if self._running else "disabled")

    def _poll(self) -> None:
        self._drain()
        self._update_status()
        self._update_buttons()
        self.root.after(POLL_MS, self._poll)

    def _on_close(self) -> None:
        self._stop_event.set()
        with self._pipeline_lock:
            for fh in (self._alert_index, self._event_store, self._quarantine):
                if fh is not None:
                    try:
                        fh.close()
                    except Exception:
                        pass
        self.root.destroy()


def main() -> None:
    root = tk.Tk()
    app = SiemApp(root)
    root.protocol("WM_DELETE_WINDOW", app._on_close)
    root.mainloop()


if __name__ == "__main__":
    main()