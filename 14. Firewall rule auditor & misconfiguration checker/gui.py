"""Desktop GUI for the Firewall Rule Auditor.

Workflow:
  1. Enter the firewall IP / device name.
  2. Load rules (JSON fixture or CSV) or use the bundled sample.
  3. Tick the report format(s) you want: CSV, XLSX, PDF.
  4. Click "Audit & Download" and pick where to save — files are written next
     to your chosen path with the matching extension.

Run with:  py gui.py     (or double-click gui.bat)
"""
from __future__ import annotations

import ctypes
import os
import sys
import time
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
os.chdir(ROOT)

try:
    ctypes.windll.shcore.SetProcessDpiAwareness(1)
except Exception:
    pass

import fw_auditor.analyze as analyze
import fw_auditor.score as score
from fw_auditor.collect import load_fixture
from fw_auditor.pdf import write_report_pdf
from fw_auditor.report import remediation_suggestion, write_report_csv, write_report_xlsx

SEV_COLORS = {"critical": "#e74c3c", "high": "#f39c12", "medium": "#f1c40f", "low": "#2ecc71"}
FORMAT_ORDER = ("CSV", "XLSX", "PDF")


class AuditorApp(tk.Tk):
    COLS = ("severity", "kind", "rule_id", "device", "evidence", "remediation")

    def __init__(self):
        super().__init__()
        self.title("Firewall Rule Auditor & Misconfiguration Checker")
        self.geometry("1020x660")
        self.minsize(860, 560)

        self.rules = []
        self.findings = []
        self.agg = {}

        self.ip_var = tk.StringVar()
        self.file_var = tk.StringVar(value="no rules loaded")
        self.status_var = tk.StringVar(value="Ready")
        self.summary_var = tk.StringVar(value="")
        self.fmt_vars = {fmt: tk.BooleanVar(value=True) for fmt in FORMAT_ORDER}
        self._audit_job = None

        self._build()
        self.after(150, self.load_sample)

    def _build(self) -> None:
        pad = {"padx": 10, "pady": 5}

        top = ttk.Frame(self)
        top.pack(fill="x", **pad)
        ttk.Label(top, text="Firewall IP / Device:").pack(side="left")
        ip_entry = ttk.Entry(top, textvariable=self.ip_var, width=28)
        ip_entry.pack(side="left", padx=6)
        ttk.Label(top, text="(used as the audited device label)",
                  foreground="#777").pack(side="left")

        rules = ttk.Frame(self)
        rules.pack(fill="x", **pad)
        ttk.Button(rules, text="Load Rules File...", command=self.load_file).pack(side="left")
        ttk.Button(rules, text="Load Sample Rules", command=self.load_sample).pack(side="left", padx=6)
        ttk.Label(rules, textvariable=self.file_var, foreground="#555").pack(side="left", padx=8)
        ttk.Label(rules, text="(accepts .json or .csv — csv columns: "
                              "id,action,proto,src,dst,ports,direction,priority,log,device)",
                  foreground="#888").pack(side="left", padx=8)

        fmt = ttk.LabelFrame(self, text="Download report format (your choice)")
        fmt.pack(fill="x", **pad)
        for name in FORMAT_ORDER:
            ttk.Checkbutton(
                fmt, text=f".{name.lower()}", variable=self.fmt_vars[name],
                command=self._refresh_summary).pack(side="left", padx=12, pady=4)

        mid = ttk.Frame(self)
        mid.pack(fill="x", **pad)
        ttk.Label(mid, textvariable=self.summary_var, font=("Segoe UI", 10, "bold")).pack(side="left")
        ttk.Button(mid, text="Refresh Audit", command=self._run_audit).pack(side="right")

        view = ttk.Frame(self)
        view.pack(fill="both", expand=True, **pad)
        self.tree = ttk.Treeview(view, columns=self.COLS, show="headings", height=14)
        widths = {"severity": 80, "kind": 120, "rule_id": 160, "device": 110,
                  "evidence": 300, "remediation": 300}
        for c in self.COLS:
            self.tree.heading(c, text=c.replace("_", " ").title())
            self.tree.column(c, width=widths[c], anchor="w", stretch=(c in ("evidence", "remediation")))
        for sev, color in SEV_COLORS.items():
            self.tree.tag_configure(sev, background=color)
        vsb = ttk.Scrollbar(view, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")

        bottom = ttk.Frame(self)
        bottom.pack(fill="x", **pad)
        fmt_note = " / ".join(f".{n.lower()}" for n in FORMAT_ORDER)
        ttk.Button(bottom, text=f"Audit & Download ({fmt_note})",
                   command=self.download).pack(side="right")
        ttk.Label(bottom, textvariable=self.status_var, foreground="#555").pack(side="left")

        self.ip_var.trace_add("write", self._on_ip_change)

    def _refresh_summary(self) -> None:
        if not self.agg:
            self.summary_var.set("")
            return
        chosen = [n for n in FORMAT_ORDER if self.fmt_vars[n].get()]
        a = self.agg
        tail = f"  |  download: {', '.join(chosen) if chosen else 'none selected'}"
        self.summary_var.set(
            f"Device {a.get('device','?')}  •  score {a.get('score',0.0)}/100  •  "
            f"critical={a.get('critical',0)} high={a.get('high',0)} "
            f"medium={a.get('medium',0)} low={a.get('low',0)}  •  "
            f"findings={a.get('count',len(self.findings))}{tail}")

    def _on_ip_change(self, *_):
        if self._audit_job:
            self.after_cancel(self._audit_job)
        self._audit_job = self.after(300, self._run_audit)

    def load_sample(self) -> None:
        try:
            self.rules = load_fixture(ROOT / "fixtures" / "aws_sg.json")
        except Exception as exc:
            messagebox.showerror("Load error", str(exc))
            return
        self.file_var.set(f"{len(self.rules)} rules loaded (sample: fixtures/aws_sg.json)")
        self._run_audit()
        self.status_var.set("Sample rules loaded — enter a firewall IP to audit")

    def load_file(self) -> None:
        path = filedialog.askopenfilename(
            title="Load firewall rules",
            filetypes=[("Rules", "*.json *.csv"), ("JSON", "*.json"),
                       ("CSV", "*.csv"), ("All files", "*.*")])
        if not path:
            return
        try:
            self.rules = load_fixture(Path(path))
        except Exception as exc:
            messagebox.showerror("Load error", f"Could not load {path}\n{exc}")
            return
        self.file_var.set(f"{len(self.rules)} rules loaded from {Path(path).name}")
        self._run_audit()
        self.status_var.set("Rules loaded — enter a firewall IP to audit")

    def _run_audit(self) -> None:
        ip = self.ip_var.get().strip()
        if not self.rules:
            self.status_var.set("Load or generate rules first")
            return
        self.snap = time.strftime("%Y%m%d-%H%M%S")
        findings = []
        for probe in analyze.PROBES:
            findings.extend(probe(self.rules))
        device = ip or self.rules[0].device or "unknown"
        for f in findings:
            f["device"] = device
            f["remediation"] = remediation_suggestion(f)
        self.findings = findings
        self.agg = score.aggregate(findings, device=device)
        self._populate_tree()
        self._refresh_summary()
        self.status_var.set(f"Audit complete — {len(findings)} finding(s), "
                            f"{len(self.rules)} rule(s)")

    def _populate_tree(self) -> None:
        self.tree.delete(*self.tree.get_children())
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        for f in sorted(self.findings, key=lambda x: order.get(x.get("severity", "low"), 9)):
            self.tree.insert("", "end", values=(
                f.get("severity", ""), f.get("kind", ""), f.get("rule_id", ""),
                f.get("device", ""), f.get("evidence", ""), f.get("remediation", "")),
                tags=(f.get("severity", "low"),))

    def download(self) -> None:
        chosen = [n for n in FORMAT_ORDER if self.fmt_vars[n].get()]
        if not chosen:
            messagebox.showwarning("No format", "Select at least one format to download.")
            return
        if not self.rules:
            messagebox.showwarning("No rules", "Load rules before downloading a report.")
            return
        self._run_audit()
        if not self.findings:
            messagebox.showinfo("No findings", "No misconfigurations found — report will be empty.")
            return

        ip = self.ip_var.get().strip() or "unknown"
        safe_ip = "".join(c if (c.isalnum() or c == "-") else "-" for c in ip)
        base = filedialog.asksaveasfilename(
            title="Save audit report",
            initialdir=str(ROOT / "data"),
            initialfile=f"fw-audit-{safe_ip}-{self.snap}",
            defaultextension="." + chosen[0].lower(),
            filetypes=[("Excel workbook", "*.xlsx"), ("CSV", "*.csv"),
                       ("PDF", "*.pdf"), ("All files", "*.*")])
        if not base:
            return
        base = Path(base)
        if base.suffix:
            base = base.with_suffix("")

        saved, failed = [], []
        files = {
            "CSV": (base.with_suffix(".csv"), write_report_csv),
            "XLSX": (base.with_suffix(".xlsx"), write_report_xlsx),
            "PDF": (base.with_suffix(".pdf"),
                    lambda f, p: write_report_pdf(f, p, self.snap, self.agg)),
        }
        for name in chosen:
            path, writer = files[name]
            try:
                writer(self.findings, path)
                saved.append(path.name)
            except Exception as exc:
                failed.append(f"{path.name}: {exc}")
        if failed:
            messagebox.showerror("Download error", "\n".join(failed))
        else:
            messagebox.showinfo("Report saved",
                                "Downloaded:\n" + "\n".join(
                                    f"• {Path(p).resolve()}" for p in
                                    (base.with_suffix("." + n.lower()) for n in chosen)))
        self.status_var.set("Report downloaded ✓" if not failed else "Some files failed")

    def run(self) -> None:
        self.mainloop()


def main() -> int:
    app = AuditorApp()
    app.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())