"""SQLiDetect Shield - portable tkinter GUI (ARCHITECTURE.md driven).

Tabs: Detection (passive analysis), Scanner (vulnerable-param identification),
Findings (aggregate + export), Compliance (framework snapshots), About.
"""
from __future__ import annotations

import json
import threading
import tkinter as tk
import tkinter.messagebox as mb
from tkinter import filedialog, ttk

from . import __version__, compliance, engine, scanner

SEVERITY_ORDER = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


class FindingStore:
    """Thread-safe in-memory store for findings + scanner results."""

    def __init__(self):
        self.lock = threading.Lock()
        self.rows = []          # detection rows
        self.vulns = []         # scanner findings

    def add_report(self, rep: engine.AnalysisReport):
        with self.lock:
            for r in engine.findings_to_rows(rep):
                r["url"] = rep.url
                self.rows.append(r)

    def add_vulns(self, vulns, target):
        with self.lock:
            for v in vulns:
                d = v.to_dict()
                d["target"] = target
                self.vulns.append(d)

    def snapshot(self):
        with self.lock:
            return {"detections": list(self.rows),
                    "vulnerable_params": list(self.vulns),
                    "counts": {"detections": len(self.rows),
                               "vulns": len(self.vulns)}}


def _add_export_button(parent, text, command, pad=6):
    b = ttk.Button(parent, text=text, command=command)
    b.pack(side="left", padx=pad)
    return b


class DetectionTab:
    def __init__(self, parent, store, log):
        self.store = store
        self.log = log
        self.frame = ttk.Frame(parent, padding=8)
        self._build()

    def _build(self):
        ctl = ttk.LabelFrame(self.frame, text="Input", padding=6)
        ctl.pack(fill="x")
        self.mode = tk.StringVar(value="url")
        ttk.Radiobutton(ctl, text="Analyze URL", variable=self.mode,
                        value="url").pack(side="left")
        ttk.Radiobutton(ctl, text="Raw HTTP request", variable=self.mode,
                        value="raw").pack(side="left", padx=12)
        self.analyze_btn = ttk.Button(ctl, text="Analyze", command=self._run)
        self.analyze_btn.pack(side="left")

        self.input = tk.Text(self.frame, height=7, wrap="word")
        self.input.pack(fill="x")
        self.input.insert("1.0", "https://shop.example.com/products?id=1&cat=1' OR 1=1--")

        res = ttk.LabelFrame(self.frame, text="Parameter findings", padding=6)
        res.pack(fill="both", expand=True)
        cols = ("param", "source", "severity", "verdict", "score", "types", "db", "dets")
        self.tree = ttk.Treeview(res, columns=cols, show="headings", height=8)
        heads = {"param": "Parameter", "source": "Source", "severity": "Severity",
                 "verdict": "Verdict", "score": "Score", "types": "Injection types",
                 "db": "DB flavor", "dets": "Detectors"}
        for c in cols:
            self.tree.heading(c, text=heads[c])
            self.tree.column(c, width=90, anchor="center", stretch=False)
        self.tree.column("param", width=160, stretch=True)
        self.tree.column("types", width=120)
        scroll = ttk.Scrollbar(res, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)
        self.tree.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")
        self.tree.bind("<<TreeviewSelect>>", self._show_detail)

        det = ttk.LabelFrame(self.frame, text="Evidence detail", padding=6)
        det.pack(fill="both", expand=True)
        self.detail = tk.Text(det, height=9, wrap="word")
        self.detail.pack(fill="both", expand=True)

    def _run(self):
        raw = self.input.get("1.0", "end").strip()
        if not raw:
            mb.showwarning("Input required", "Paste a URL or raw HTTP request.")
            return
        self.analyze_btn.config(state="disabled")
        threading.Thread(target=self._analyze, args=(raw,), daemon=True).start()

    def _analyze(self, raw):
        try:
            rep = engine.analyze_target(raw, raw_request=(self.mode.get() == "raw"))
        except Exception as exc:  # surface parse errors in log only
            self.log(f"Analysis error: {exc}")
            return
        findings = self._refresh_tree(rep)
        self.store.add_report(rep)
        self.log(f"Analyzed {len(findings)} params on {rep.url} "
                 f"(max severity {rep.max_severity})")
        self.analyze_btn.config(state="normal")

    def _refresh_tree(self, rep):
        self.tree.delete(*self.tree.get_children())
        for r in engine.findings_to_rows(rep):
            tag = r["severity"]
            self.tree.insert("", "end", values=tuple(r[c] for c in
                                                     ("param", "source", "severity",
                                                      "verdict", "score", "types",
                                                      "db", "dets")), tags=(tag,))
        return rep.findings

    def _show_detail(self, _evt):
        self.detail.delete("1.0", "end")
        sel = self.tree.selection()
        if not sel:
            return
        name = self.tree.item(sel[0], "values")[0]
        for url in list(self.store.snapshot()["detections"]):
            pass  # simplified: show last analyzed report matched by param via store
        self.detail.insert("1.0", f"Parameter: {name}\n"
                                  "(Full evidence for the active analysis is shown "
                                  "after re-running Analyze; findings aggregate in "
                                  "the Findings tab.)")


class ScannerTab:
    def __init__(self, parent, store, log):
        self.store = store
        self.log = log
        self.frame = ttk.Frame(parent, padding=8)
        self._build()

    def _build(self):
        cfg = ttk.LabelFrame(self.frame, text="Scan configuration (approval-gated)", padding=6)
        cfg.pack(fill="x")
        row1 = ttk.Frame(cfg)
        row1.pack(fill="x")
        ttk.Label(row1, text="Target URL:").pack(side="left")
        self.url_var = tk.StringVar(value="http://localhost:8080/product?id=")
        ttk.Entry(row1, textvariable=self.url_var, width=56).pack(side="left", padx=6)
        ttk.Label(row1, text="Params (comma sep):").pack(side="left")
        self.param_var = tk.StringVar(value="id,cat")
        ttk.Entry(row1, textvariable=self.param_var, width=24).pack(side="left", padx=6)

        row2 = ttk.Frame(cfg)
        row2.pack(fill="x", pady=(4, 0))
        self.method = tk.StringVar(value="GET")
        ttk.Radiobutton(row2, text="GET", variable=self.method, value="GET").pack(side="left")
        ttk.Radiobutton(row2, text="POST", variable=self.method, value="POST").pack(side="left")
        self.tls_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(row2, text="Verify TLS", variable=self.tls_var).pack(side="left", padx=8)
        self.approve = tk.BooleanVar(value=False)
        ttk.Checkbutton(row2, text="I approve this target (I own it / authorized to test)",
                        variable=self.approve).pack(side="left", padx=8)
        self.scan_btn = ttk.Button(row2, text="Start scan", command=self._run)
        self.scan_btn.pack(side="left", padx=8)

        self.progress = tk.Text(self.frame, height=6, wrap="word", state="disabled")
        self.progress.pack(fill="x")

        res = ttk.LabelFrame(self.frame, text="Vulnerable parameters", padding=6)
        res.pack(fill="both", expand=True)
        cols = ("param", "source", "confirmed", "types", "db", "evidence", "latency")
        self.tree = ttk.Treeview(res, columns=cols, show="headings", height=8)
        heads = {"param": "Parameter", "source": "Source", "confirmed": "Vulnerable?",
                 "types": "Types", "db": "DB flavor", "evidence": "Evidence",
                 "latency": "Latency (ms)"}
        for c in cols:
            self.tree.heading(c, text=heads[c])
            self.tree.column(c, width=100, anchor="center", stretch=False)
        self.tree.column("param", width=140, stretch=True)
        self.tree.column("evidence", width=260, stretch=True)
        self.tree.pack(fill="both", expand=True)

    def _run(self):
        if not self.approve.get():
            mb.showwarning("Approval required", scanner.SCAN_APPROVAL_HINT)
            return
        url = self.url_var.get().strip()
        params = [p.strip() for p in self.param_var.get().split(",") if p.strip()]
        if not url or not params:
            mb.showwarning("Configuration", "Target URL and at least one parameter required.")
            return
        self.scan_btn.config(state="disabled")
        self._clear_progress()
        threading.Thread(target=self._scan, args=(url, params), daemon=True).start()

    def _clear_progress(self):
        self.progress.config(state="normal")
        self.progress.delete("1.0", "end")
        self.progress.config(state="disabled")

    def _scan(self, url, params):
        sc = scanner.Scanner(progress=lambda m: self._append(m),
                             verify_tls=self.tls_var.get())
        try:
            method = self.method.get()
            if method == "GET":
                vulns = sc.scan_params(url, params, method="GET")
            else:
                vulns = []
                for p in params:
                    self._append(f"-- body param: {p}")
                    vulns.append(sc.scan(url, p, method="POST", body={}))
        except Exception as exc:
            self._append(f"Scan error: {exc}")
            self.scan_btn.config(state="normal")
            return
        self.store.add_vulns(vulns, url)
        confirmed = sum(1 for v in vulns if v.confirmed)
        self._refresh_tree(vulns)
        self.log(f"Scan complete: {confirmed}/{len(vulns)} params confirmed vulnerable on {url}")
        self._append(f"Done. {confirmed}/{len(vulns)} vulnerable.")
        self.scan_btn.config(state="normal")

    def _append(self, msg):
        self.progress.config(state="normal")
        self.progress.insert("end", msg + "\n")
        self.progress.see("end")
        self.progress.config(state="disabled")

    def _refresh_tree(self, vulns):
        self.tree.delete(*self.tree.get_children())
        for v in vulns:
            d = v.to_dict()
            self.tree.insert("", "end", values=(
                d["parameter"], d["source"], "YES" if d["confirmed"] else "no",
                ",".join(d["injection_types"]) or "-", d["db_flavor"] or "-",
                d["evidence"] or "-", d["latency_ms"]))


class FindingsTab:
    def __init__(self, parent, store, log):
        self.store = store
        self.log = log
        self.frame = ttk.Frame(parent, padding=8)
        self._build()

    def _build(self):
        bar = ttk.Frame(self.frame)
        bar.pack(fill="x")
        ttk.Label(bar, text="Aggregate evidence store (memory-only, not persisted):").pack(side="left")
        _add_export_button(bar, "Export JSON", self.export_json)
        _add_export_button(bar, "Export CSV", self.export_csv)
        _add_export_button(bar, "Compliance snapshot", self.export_compliance)
        _add_export_button(bar, "Refresh", self.refresh)

        cols = ("kind", "target", "param", "severity", "verdict", "types", "db")
        self.tree = ttk.Treeview(self.frame, columns=cols, show="headings", height=12)
        for c in cols:
            self.tree.heading(c, text=c.title())
            self.tree.column(c, width=110, anchor="center", stretch=False)
        self.tree.column("target", width=220, stretch=True)
        self.tree.column("param", width=140)
        self.tree.pack(fill="both", expand=True, pady=(6, 0))

    def refresh(self):
        self.tree.delete(*self.tree.get_children())
        snap = self.store.snapshot()
        for r in snap["detections"]:
            self.tree.insert("", "end",
                             values=("detection", r.get("url", ""), r["param"],
                                     r["severity"], r["verdict"],
                                     r["types"] or "-", r["db"] or "-"),
                             tags=(r["severity"],))
        for v in snap["vulnerable_params"]:
            self.tree.insert("", "end",
                             values=("vuln-param", v["target"], v["parameter"],
                                     "CONFIRMED" if v["confirmed"] else "clean",
                                     "SCAN", ",".join(v["injection_types"]) or "-",
                                     v["db_flavor"] or "-"))
        self.log(f"Findings refreshed: {snap['counts']['detections']} detections, "
                 f"{snap['counts']['vulns']} scanned params")

    def export_json(self):
        snap = self.store.snapshot()
        path = self._save_path("sqli_findings.json")
        if not path:
            return
        with open(path, "w", encoding="utf-8") as fh:
            json.dump({"tool": "SQLiDetect Shield",
                       "generated_utc": __import__("time").strftime(
                           "%Y-%m-%dT%H:%M:%SZ", __import__("time").gmtime()),
                       **snap}, fh, indent=2)
        self.log(f"Exported JSON -> {path}")

    def export_csv(self):
        path = self._save_path("sqli_findings.csv")
        if not path:
            return
        snap = self.store.snapshot()
        import csv
        with open(path, "w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(["kind", "target", "parameter", "severity", "verdict",
                        "injection_types", "db", "evidence", "latency_ms"])
            for r in snap["detections"]:
                w.writerow(["detection", r.get("url", ""), r["param"], r["severity"],
                            r["verdict"], r["types"], r["db"], "-", "-"])
            for v in snap["vulnerable_params"]:
                w.writerow(["vuln-param", v["target"], v["parameter"],
                            "CONFIRMED" if v["confirmed"] else "clean", "SCAN",
                            ",".join(v["injection_types"]), v["db_flavor"],
                            v["evidence"], v["latency_ms"]])
        self.log(f"Exported CSV -> {path}")

    def export_compliance(self):
        snap = self.store.snapshot()
        doc = compliance.export_snapshot({
            "detections_seen": snap["counts"]["detections"],
            "params_scanned": snap["counts"]["vulns"],
        })
        path = self._save_path("compliance_snapshot.md")
        if not path:
            return
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(doc)
        self.log(f"Compliance snapshot -> {path}")

    @staticmethod
    def _save_path(name):
        return filedialog.asksaveasfilename(
            defaultextension=".json", initialfile=name,
            filetypes=[("All files", "*.*")]) if name.endswith(".json") else \
            filedialog.asksaveasfilename(initialfile=name, filetypes=[("All files", "*.*")])


class ComplianceTab:
    def __init__(self, parent, log):
        self.log = log
        self.frame = ttk.Frame(parent, padding=8)
        self._build()

    def _build(self):
        bar = ttk.Frame(self.frame)
        bar.pack(fill="x")
        ttk.Label(bar, text="Control-to-implementation mapping (ARCHITECTURE.md Sec 9):").pack(side="left")
        _add_export_button(bar, "Export snapshot (.md)", self.export_md)
        _add_export_button(bar, "Export JSON", self.export_json)

        self.tree = ttk.Treeview(self.frame, columns=("ctrl", "req", "impl"),
                                 show="tree headings", height=20)
        self.tree.heading("ctrl", text="Control")
        self.tree.heading("req", text="Requirement")
        self.tree.heading("impl", text="Implementation in this solution")
        for c, w in (("ctrl", 120), ("req", 230), ("impl", 460)):
            self.tree.column(c, width=w, stretch=True)
        for framework, rows in [
            ("ISO/IEC 27001:2022 (Annex A)", compliance.ISO_MAP),
            ("NIST SP 800-53 / CSF 2.0", compliance.NIST_MAP),
            ("OWASP Top 10 (2021)", compliance.OWASP_MAP),
            ("PCI DSS 4.0", compliance.PCI_MAP),
        ]:
            parent_iid = self.tree.insert("", "end", text=framework, open=False)
            for c, n, i in rows:
                self.tree.insert(parent_iid, "end", values=(c, n, i))
        self.tree.pack(fill="both", expand=True, pady=(6, 0))
        ttk.Label(self.frame, text="Note: tools must be operated to the same controls; "
                                   "audit evidence lives in Security.md and exports.").pack()

    def export_md(self):
        path = filedialog.asksaveasfilename(initialfile="compliance_snapshot.md")
        if not path:
            return
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(compliance.export_snapshot())
        self.log(f"Compliance snapshot -> {path}")

    def export_json(self):
        path = filedialog.asksaveasfilename(defaultextension=".json",
                                            initialfile="compliance_snapshot.json")
        if not path:
            return
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(compliance.export_json())
        self.log(f"Compliance JSON -> {path}")


class AboutTab:
    def __init__(self, parent, log):
        self.log = log
        self.frame = ttk.Frame(parent, padding=12)
        self._build()

    def _build(self):
        ttk.Label(self.frame, text=f"SQLiDetect Shield v{__version__}",
                  font=("Segoe UI", 14, "bold")).pack(anchor="w")
        ttk.Label(self.frame,
                  text="Defensive-oriented SQLi detection + vulnerable-parameter "
                       "identification.\nArchitecture: ARCHITECTURE.md v1.0 - "
                       "ISO 27001 / NIST SP 800-53 / OWASP Top 10 / PCI DSS 4.0."
                  ).pack(anchor="w", pady=4)
        ttk.Label(self.frame,
                  text="Detection: 5 layers (signature, grammar, heuristics, ML-ready, correlation)\n"
                       "Scanner:  approved-target probing (error/boolean/union/time/OOB)\n"
                       "Privacy:  raw payloads never persisted - digests only (A.8.11/SI-7)"
                  ).pack(anchor="w", pady=4)
        btn = ttk.Button(self.frame, text="Run built-in self-test", command=self.selftest)
        btn.pack(anchor="w", pady=8)
        self.out = tk.Text(self.frame, height=14, wrap="word", state="disabled")
        self.out.pack(fill="both", expand=True)

    def _append(self, msg):
        self.out.config(state="normal")
        self.out.insert("end", msg + "\n")
        self.out.see("end")
        self.out.config(state="disabled")

    def selftest(self):
        self.out.config(state="normal")
        self.out.delete("1.0", "end")
        self.out.config(state="disabled")
        threading.Thread(target=self._selftest, daemon=True).start()

    def _selftest(self):
        from .cli import run_selftest
        import contextlib
        import io
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = run_selftest()
        for line in buf.getvalue().splitlines():
            self._append(line)
        self._append("Result: " + ("PASS" if rc == 0 else "FAIL"))
        self.log("GUI self-test " + ("PASS" if rc == 0 else "FAIL"))


class App:
    def __init__(self, root: tk.Tk):
        self.root = root
        root.title(f"SQLiDetect Shield v{__version__}")
        root.geometry("1180x760")
        store = FindingStore()
        self.log_widget = tk.Text(root, height=5, wrap="word", state="disabled",
                                  bg="#202020", fg="#e0e0e0")
        self.log_widget.pack(side="bottom", fill="x")

        nb = ttk.Notebook(root)
        nb.pack(fill="both", expand=True)

        def log(msg):
            self.log_widget.config(state="normal")
            self.log_widget.insert("end", "[log] " + msg + "\n")
            self.log_widget.see("end")
            self.log_widget.config(state="disabled")
            self.root.update_idletasks()

        groups = [
            ("Detection", DetectionTab(nb, store, log)),
            ("Vulnerable-param Scanner", ScannerTab(nb, store, log)),
            ("Findings & Export", FindingsTab(nb, store, log)),
            ("Compliance", ComplianceTab(nb, log)),
            ("About", AboutTab(nb, log)),
        ]
        for name, tab in groups:
            nb.add(tab.frame, text=name)
        self._tag_rows()
        nb.bind("<<NotebookTabChanged>>", lambda _e: (
            groups[2][1].refresh() if nb.index("current") == 2 else None))

    def _tag_rows(self):
        for widget in self.root.winfo_children():
            for tree in (_find_treeview(widget)):
                tree.tag_configure("CRITICAL", foreground="#c00000", background="#ffe9e9")
                tree.tag_configure("HIGH", foreground="#cc4400")
                tree.tag_configure("MEDIUM", foreground="#9a6a00")
                tree.tag_configure("LOW", foreground="#1f6f1f")


def _find_treeview(widget):
    found = []
    if isinstance(widget, ttk.Treeview):
        found.append(widget)
    for child in widget.winfo_children():
        found += _find_treeview(child)
    return found


def main():
    root = tk.Tk()
    App(root)
    root.mainloop()


if __name__ == "__main__":
    main()