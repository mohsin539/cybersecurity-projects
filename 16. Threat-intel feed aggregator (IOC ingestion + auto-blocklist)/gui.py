"""Threat-intel feed aggregator — GUI dashboard (tkinter, stdlib only).

Run:
    py gui.py

Tabs:
  Blocklist   review/approve/drop tiered records, see provenance
  Ingest      add IOCs manually, load JSON/CSV fixtures or a Project-15 honeypot event
  Feed Config view/edit per-feed trust thresholds (auto_confidence / TLP / consumer)
  Consumer    diff-sync a json or pfSense-style driver against the release file
  Audit       append-only decision log
  Log         console output from background pipeline runs
"""
from __future__ import annotations

import json
import queue
import sys
import threading
import traceback
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

BASE = Path(__file__).resolve().parent
if str(BASE) not in sys.path:
    sys.path.insert(0, str(BASE))
import os
os.chdir(BASE)

from aggregator import api

TYPES = ("ipv4", "ipv6", "cidr", "domain", "url", "file_hash")
TLPS = ("white", "green", "amber", "red")
CONSUMERS = ("json", "pf")
_ERR = object()


class AggregatorApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Threat-Intel Aggregator — IOC ingestion + auto-blocklist")
        self.geometry("1200x760")
        self.minsize(940, 600)

        self.config_path = Path(api.DEFAULT_CONFIG)
        self.state_dir = Path(api.DEFAULT_STATE)
        self.fixture_path: Path | None = None

        self.worker_q: "queue.Queue[tuple[object, object, object]]" = queue.Queue()
        self.status_var = tk.StringVar(value="ready")
        self._build_ui()

        self.after(150, self._poll_queue)
        self.log(f"state dir : {self.state_dir}")
        self.log(f"config    : {self.config_path}")
        self.refresh_all()

    # ------------------------------------------------------------------ UI --
    def _build_ui(self) -> None:
        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, padx=6, pady=6)

        nb.add(self._build_blocklist_tab(nb), text="Blocklist")
        nb.add(self._build_ingest_tab(nb), text="Ingest")
        nb.add(self._build_config_tab(nb), text="Feed Config")
        nb.add(self._build_consumer_tab(nb), text="Consumer")
        nb.add(self._build_audit_tab(nb), text="Audit")
        nb.add(self._build_log_tab(nb), text="Log")

        bar = ttk.Frame(self)
        bar.pack(fill="x", padx=6, pady=(0, 6))
        ttk.Label(bar, textvariable=self.status_var).pack(side="left")

    def _build_blocklist_tab(self, parent: object) -> ttk.Frame:
        f = ttk.Frame(parent)
        toolbar = ttk.Frame(f)
        toolbar.pack(fill="x", pady=4)
        ttk.Button(toolbar, text="Refresh", command=self.refresh_all).pack(side="left", padx=2)
        ttk.Button(toolbar, text="Approve selected", command=self.on_approve).pack(side="left", padx=2)
        ttk.Button(toolbar, text="Drop / Rollback selected", command=self.on_drop).pack(side="left", padx=2)
        ttk.Button(toolbar, text="Retire expired", command=self.on_retire_expired).pack(side="left", padx=2)
        self.bl_status = tk.StringVar(value="")
        ttk.Label(toolbar, textvariable=self.bl_status).pack(side="left", padx=12)

        cols = ("value", "type", "tier", "status", "confidence",
                "sources", "added_at", "expires_at", "approved_by")
        heads = {"value": "Indicator", "type": "Type", "tier": "Tier", "status": "Status",
                 "confidence": "Conf", "sources": "Sources", "added_at": "Added",
                 "expires_at": "Expires", "approved_by": "By"}
        widths = {"value": 220, "type": 70, "tier": 70, "status": 85, "confidence": 55,
                  "sources": 150, "added_at": 130, "expires_at": 130, "approved_by": 80}
        self.bl_tree = self._tree(f, cols, heads, widths)
        self.rec_keys: list[str] = []
        return f

    def _build_ingest_tab(self, parent: object) -> ttk.Frame:
        f = ttk.Frame(parent)
        left = ttk.LabelFrame(f, text="Manual IOC")
        left.pack(side="left", fill="y", padx=6, pady=6)
        inputs: dict[str, object] = {}

        rows = [
            ("value", "Indicator value", ""),
            ("ioc_type", "IOC type", TYPES),
            ("confidence", "Confidence (0-1)", "0.7"),
            ("tlp", "TLP", TLPS),
            ("feed_id", "Feed id", "manual"),
            ("expires_at", "Expires (ISO)", "2026-12-31T23:59:59Z"),
            ("tags", "Tags (comma sep)", "manual"),
        ]
        self.ing = {}
        for i, (key, label, default) in enumerate(rows):
            ttk.Label(left, text=label).grid(row=i, column=0, sticky="w", padx=6, pady=3)
            if isinstance(default, tuple):
                var = tk.StringVar(value=default[0])
                w = ttk.Combobox(left, textvariable=var, values=list(default), width=34, state="readonly")
            else:
                var = tk.StringVar(value=str(default))
                w = ttk.Entry(left, textvariable=var, width=36)
            w.grid(row=i, column=1, sticky="we", padx=6, pady=3)
            self.ing[key] = var

        btns = ttk.Frame(left)
        btns.grid(row=len(rows), column=0, columnspan=2, pady=8)
        ttk.Button(btns, text="Add & Apply", command=self.on_add_ioc).pack(side="left", padx=3)
        ttk.Button(btns, text="Write-only (no sync)", command=self.on_add_ioc_store_only).pack(side="left", padx=3)

        mid = ttk.LabelFrame(f, text="Files / events")
        mid.pack(side="left", fill="both", expand=True, padx=6, pady=6)
        ttk.Button(mid, text="Choose JSON / CSV fixture…", command=self.on_pick_fixture).pack(anchor="w", padx=8, pady=4)
        ttk.Button(mid, text="Choose honeypot event JSON…", command=self.on_pick_honeypot).pack(anchor="w", padx=8, pady=4)
        self.file_lbl = tk.StringVar(value="no file selected")
        ttk.Label(mid, textvariable=self.file_lbl, wraplength=340, justify="left").pack(anchor="w", padx=8)

        ttk.Separator(mid, orient="horizontal").pack(fill="x", pady=8)
        ttk.Button(mid, text="Run full pipeline (ingest + consumer sync)",
                   command=self.on_run_pipeline).pack(anchor="w", padx=8, pady=6)

        self.summary_txt = tk.Text(mid, height=10, width=52, state="disabled")
        self.summary_txt.pack(fill="both", expand=True, padx=8, pady=8)
        return f

    def _build_config_tab(self, parent: object) -> ttk.Frame:
        f = ttk.Frame(parent)
        top = ttk.Frame(f)
        top.pack(fill="x", pady=4)
        ttk.Button(top, text="Load config", command=self.on_config_load).pack(side="left", padx=2)
        ttk.Button(top, text="Save config", command=self.on_config_save).pack(side="left", padx=2)
        self.cfg_status = tk.StringVar(value="")
        ttk.Label(top, textvariable=self.cfg_status).pack(side="left", padx=12)

        pane = ttk.Panedwindow(f, orient="horizontal")
        pane.pack(fill="both", expand=True)
        self.cfg_txt = tk.Text(pane, width=60, font=("Consolas", 10))
        pane.add(self.cfg_txt, weight=3)

        right = ttk.Frame(pane)
        pane.add(right, weight=2)
        ttk.Label(right, text="Effective per-feed policy (merged with global)").pack(anchor="w", padx=6, pady=2)
        cols = ("feed", "auto_conf", "quar_conf", "tlp", "consumer")
        heads = {"feed": "Feed", "auto_conf": "Auto conf", "quar_conf": "Quarantine",
                 "tlp": "TLP", "consumer": "Consumer"}
        widths = {"feed": 150, "auto_conf": 80, "quar_conf": 80, "tlp": 60, "consumer": 90}
        self.cfg_tree = self._tree(right, cols, heads, widths)
        self._config_load_into_text()
        return f

    def _build_consumer_tab(self, parent: object) -> ttk.Frame:
        f = ttk.Frame(parent)
        top = ttk.LabelFrame(f, text="Consumer driver")
        top.pack(fill="x", padx=6, pady=6)
        ttk.Label(top, text="Driver").grid(row=0, column=0, padx=6, pady=4, sticky="w")
        self.consumer_var = tk.StringVar(value="json")
        ttk.Combobox(top, textvariable=self.consumer_var, values=CONSUMERS, state="readonly", width=12).grid(row=0, column=1, padx=6, pady=4)
        ttk.Label(top, text="Destination file").grid(row=0, column=2, padx=6, pady=4, sticky="w")
        self.dest_var = tk.StringVar(value=str(self.state_dir / "blocklist.json"))
        ttk.Entry(top, textvariable=self.dest_var, width=52).grid(row=0, column=3, padx=6, pady=4)

        btns = ttk.Frame(top)
        btns.grid(row=1, column=0, columnspan=4, sticky="w", padx=6, pady=4)
        ttk.Button(btns, text="Sync now", command=self.on_consumer_sync).pack(side="left", padx=3)
        ttk.Button(btns, text="View release file", command=self.on_view_release).pack(side="left", padx=3)
        self.consumer_status = tk.StringVar(value="")
        ttk.Label(btns, textvariable=self.consumer_status).pack(side="left", padx=12)

        self.release_txt = tk.Text(f, height=18, state="disabled", font=("Consolas", 10))
        self.release_txt.pack(fill="both", expand=True, padx=6, pady=6)
        return f

    def _build_audit_tab(self, parent: object) -> ttk.Frame:
        f = ttk.Frame(parent)
        top = ttk.Frame(f)
        top.pack(fill="x", pady=4)
        ttk.Button(top, text="Refresh audit", command=self.refresh_audit).pack(side="left", padx=2)
        ttk.Label(top, text="blocklist_audit.jsonl (append-only log)").pack(side="left", padx=12)
        cols = ("ts", "action", "tier", "value", "why")
        heads = {"ts": "Timestamp", "action": "Action", "tier": "Tier", "value": "Indicator", "why": "Reason"}
        widths = {"ts": 150, "action": 90, "tier": 80, "value": 200, "why": 320}
        self.audit_tree = self._tree(f, cols, heads, widths)
        return f

    def _build_log_tab(self, parent: object) -> ttk.Frame:
        f = ttk.Frame(parent)
        self.log_txt = tk.Text(f, state="disabled", font=("Consolas", 9), wrap="word")
        sb = ttk.Scrollbar(f, command=self.log_txt.yview)
        self.log_txt.configure(yscrollcommand=sb.set)
        self.log_txt.pack(side="left", fill="both", expand=True, padx=2, pady=2)
        sb.pack(side="right", fill="y")
        return f

    def _tree(self, parent: object, cols, heads, widths) -> ttk.Treeview:
        frame = ttk.Frame(parent)
        frame.pack(fill="both", expand=True, padx=6, pady=6)
        tree = ttk.Treeview(frame, columns=cols, show="headings", selectmode="browse")
        for c in cols:
            tree.heading(c, text=heads[c])
            tree.column(c, width=widths[c], anchor="w", stretch=(c == cols[0]))
        ys = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
        xs = ttk.Scrollbar(frame, orient="horizontal", command=tree.xview)
        tree.configure(yscrollcommand=ys.set, xscrollcommand=xs.set)
        tree.grid(row=0, column=0, sticky="nsew")
        ys.grid(row=0, column=1, sticky="ns")
        xs.grid(row=1, column=0, sticky="ew")
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)
        return tree

    # ------------------------------------------------------------- logging --
    def log(self, msg: str) -> None:
        self.log_txt.configure(state="normal")
        self.log_txt.insert("end", msg.rstrip() + "\n")
        self.log_txt.see("end")
        self.log_txt.configure(state="disabled")

    def _set_status(self, msg: str) -> None:
        self.status_var.set(msg)

    # ------------------------------------------------------------ threading --
    def _submit(self, fn, on_ok, *args) -> None:
        def task() -> None:
            try:
                data = fn(*args)
            except Exception as exc:  # noqa: BLE001
                tb = traceback.format_exc()
                self.worker_q.put((on_ok, _ERR, f"{exc}\n{tb}"))
            else:
                self.worker_q.put((on_ok, None, data))
        threading.Thread(target=task, daemon=True).start()

    def _poll_queue(self) -> None:
        try:
            while True:
                cb, err, data = self.worker_q.get_nowait()
                if err is _ERR:
                    messagebox.showerror("Operation failed", str(data))
                    self.log("ERROR\n" + str(data))
                else:
                    self.log("operation complete")
                    if cb:
                        cb(data)
        except queue.Empty:
            pass
        self.after(150, self._poll_queue)

    # --------------------------------------------------------------- actions --
    def _current_config(self) -> dict:
        config = api.load_config(self.config_path)
        config["consumer"] = self.consumer_var.get()
        config["consumer_dest"] = self.dest_var.get()
        return config

    def refresh_all(self) -> None:
        self.refresh_blocklist()
        self.refresh_audit()

    def refresh_blocklist(self) -> None:
        self._submit(lambda: api.list_records(self.state_dir), self._on_blocklist)

    def _on_blocklist(self, records: list) -> None:
        self.bl_tree.delete(*self.bl_tree.get_children())
        self.rec_keys = []
        counts = {"active": 0, "expiring": 0, "quarantined": 0, "suspected": 0, "retired": 0}
        for rec in records:
            counts[rec.get("status", "?")] = counts.get(rec.get("status", "?"), 0) + 1
            self.rec_keys.append(rec["key"])
            self.bl_tree.insert("", "end", iid=str(len(self.rec_keys) - 1), values=(
                rec.get("value", ""), rec.get("ioc_type", ""), rec.get("tier", ""),
                rec.get("status", ""), f"{rec.get('confidence', 0):.2f}",
                ",".join(rec.get("sources", [])), str(rec.get("added_at", ""))[:19],
                str(rec.get("expires_at", ""))[:19], rec.get("approved_by", "auto")))
        self.bl_status.set(
            f"active={counts['active']} expiring={counts['expiring']} "
            f"quarantined={counts['quarantined']} suspected={counts['suspected']} "
            f"retired={counts['retired']}  total={len(records)}")

    def refresh_audit(self) -> None:
        self._submit(lambda: api.tail_audit(self.state_dir), self._on_audit)

    def _on_audit(self, rows: list) -> None:
        self.audit_tree.delete(*self.audit_tree.get_children())
        for i, r in enumerate(reversed(rows)):
            self.audit_tree.insert("", "end", iid=str(i), values=(
                r.get("ts", ""), r.get("action", ""), r.get("tier", ""),
                r.get("value", ""), r.get("why", "")))

    # Blocklist buttons
    def _selected_key(self) -> str | None:
        sel = self.bl_tree.selection()
        if not sel:
            messagebox.showinfo("Nothing selected", "Select a row in the Blocklist first.")
            return None
        idx = int(sel[0])
        return self.rec_keys[idx] if idx < len(self.rec_keys) else None

    def on_approve(self) -> None:
        key = self._selected_key()
        if key is None:
            return
        self._submit(lambda: api.approve_record(self.state_dir, key, by="gui"),
                     lambda _r: self.refresh_all())

    def on_drop(self) -> None:
        key = self._selected_key()
        if key is None:
            return
        if not messagebox.askyesno("Drop / Rollback",
                                   "Mark this record retired? It will be removed from "
                                   "consumers on the next sync. Continue?"):
            return
        self._submit(lambda: api.drop_record(self.state_dir, key, by="gui"),
                     lambda _r: self.refresh_all())

    def on_retire_expired(self) -> None:
        self._submit(lambda: api.retire_expired(self.state_dir),
                     lambda _r: self.refresh_all())

    # Ingest
    def on_add_ioc(self) -> None:
        self._add_ioc(sync=True)

    def on_add_ioc_store_only(self) -> None:
        self._add_ioc(sync=False)

    def _add_ioc(self, sync: bool) -> None:
        try:
            ioc = api.ioc_from_dict({
                "value": self.ing["value"].get(),
                "ioc_type": self.ing["ioc_type"].get(),
                "confidence": float(self.ing["confidence"].get() or 0),
                "tlp": self.ing["tlp"].get(),
                "feed_id": self.ing["feed_id"].get(),
                "expires_at": self.ing["expires_at"].get(),
                "tags": [t.strip() for t in self.ing["tags"].get().split(",") if t.strip()],
            })
        except Exception as exc:
            messagebox.showerror("Invalid IOC", str(exc))
            return
        if not ioc.value:
            messagebox.showerror("Invalid IOC", "Indicator value is required.")
            return
        self.log(f"adding IOC {ioc.value} ({ioc.ioc_type}, conf={ioc.confidence}, tlp={ioc.tlp})")
        if sync:
            self._submit(
                lambda: api.run_pipeline(self._current_config(), self.state_dir, iocs=[ioc]),
                self._on_pipeline)
        else:
            self._submit(
                lambda: api.run_pipeline(self._current_config(), self.state_dir,
                                         iocs=[ioc], sync=False),
                self._on_pipeline)

    def on_pick_fixture(self) -> None:
        path = filedialog.askopenfilename(
            filetypes=[("IOC fixtures", "*.json *.csv"), ("All files", "*.*")])
        if not path:
            return
        self.fixture_path = Path(path)
        self.file_lbl.set(f"fixture: {path}")

    def on_pick_honeypot(self) -> None:
        path = filedialog.askopenfilename(
            filetypes=[("JSON", "*.json"), ("All files", "*.*")])
        if not path:
            return
        try:
            events = json.loads(Path(path).read_text(encoding="utf-8"))
        except Exception as exc:
            messagebox.showerror("Bad event file", str(exc))
            return
        if isinstance(events, dict):
            events = [events]
        self.honeypot_events = [e for e in events if isinstance(e, dict)]
        self.fixture_path = None
        self.file_lbl.set(f"honeypot events: {path} ({len(self.honeypot_events)})")
        self.log(f"loaded {len(self.honeypot_events)} honeypot event(s) from {path}")

    def on_run_pipeline(self) -> None:
        config = self._current_config()
        fixture = Path(self.fixture_path) if self.fixture_path is not None else None
        events = getattr(self, "honeypot_events", None)
        self._set_status("running pipeline…")
        self._submit(
            lambda: api.run_pipeline(config, self.state_dir,
                                     fixture=fixture, honeypot_events=events),
            self._on_pipeline)

    def _on_pipeline(self, res: dict) -> None:
        self._set_status("ready")
        self.summary_txt.configure(state="normal")
        self.summary_txt.delete("1.0", "end")
        lines = [
            f"Ingested  : {len(res['ingested'])} IOC(s)",
            f"Applied   : {len(res['applied'])}",
        ]
        for r in res["applied"]:
            lines.append(f"  {r['tier']:>9}/{r['status']:<11} {r['value']}  src={r['sources']}")
        lines.append(f"Consumer  : {res['consumer']} → {res['consumer_dest']}")
        lines.append(f"  pushed={res['pushed']} removed={res['removed']} ok={res['consumer_ok']}")
        lines.append(f"Lifecycle : retired={len(res['retired'])}")
        for r in res["retired"]:
            lines.append(f"  retired {r['value']}")
        self.summary_txt.insert("1.0", "\n".join(lines))
        self.summary_txt.configure(state="disabled")
        for line in lines:
            self.log(line)
        self.refresh_all()

    # Config
    def _config_load_into_text(self) -> None:
        config = api.load_config(self.config_path)
        self.cfg_txt.delete("1.0", "end")
        self.cfg_txt.insert("1.0", json.dumps(config, indent=2))
        self._refresh_cfg_tree(config)

    def _refresh_cfg_tree(self, config: dict) -> None:
        self.cfg_tree.delete(*self.cfg_tree.get_children())
        for feed_id in sorted(dict(config.get("feeds", {})).keys()):
            eff = api.feed_settings(config, feed_id)
            self.cfg_tree.insert("", "end", values=(
                feed_id, eff.get("auto_confidence", "-"), eff.get("quarantine_confidence", "-"),
                eff.get("ip_feed_tlp", "white"), eff.get("consumer", "json")))
        self.cfg_tree.insert("", "end", values=(
            "(global default)", config.get("auto_confidence", 0.7),
            config.get("quarantine_confidence", 0.4), "white", config.get("consumer", "json")))

    def on_config_load(self) -> None:
        path = filedialog.askopenfilename(filetypes=[("JSON config", "*.json"), ("All files", "*.*")])
        if not path:
            return
        self.config_path = Path(path)
        self._config_load_into_text()
        self.cfg_status.set(f"loaded {path}")
        self.log(f"config loaded from {path}")

    def on_config_save(self) -> None:
        try:
            config = json.loads(self.cfg_txt.get("1.0", "end"))
        except json.JSONDecodeError as exc:
            messagebox.showerror("Invalid JSON", str(exc))
            return
        path = api.save_config(config, self.config_path)
        self._refresh_cfg_tree(config)
        self.cfg_status.set(f"saved {path}")
        self.log(f"config saved to {path}")

    # Consumer
    def on_consumer_sync(self) -> None:
        config = self._current_config()
        self._set_status("syncing consumer…")
        self._submit(lambda: api.sync_consumer(config, self.state_dir), self._on_sync_done)

    def _on_sync_done(self, res: dict) -> None:
        self._set_status("ready")
        self.consumer_status.set(f"pushed={res['pushed']} removed={res['removed']} ok={res['ok']}")
        self.log(f"consumer sync {res['consumer']} → {res['dest']}: "
                 f"pushed={res['pushed']} removed={res['removed']}")

    def on_view_release(self) -> None:
        config = self._current_config()
        text = api.tail_release(config, self.state_dir, n=2000)
        self.release_txt.configure(state="normal")
        self.release_txt.delete("1.0", "end")
        self.release_txt.insert("1.0", text)
        self.release_txt.configure(state="disabled")


def main() -> int:
    app = AggregatorApp()
    app.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())