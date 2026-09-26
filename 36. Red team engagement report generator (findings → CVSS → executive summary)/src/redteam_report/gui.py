"""Tkinter desktop GUI for the Red Team Engagement Report Generator.

Launches a portable GUI (dev: ``python -m redteam_report.gui``, packaged:
``PyInstaller redteam_report.spec``) that drives the same pipeline as the
CLI: load an engagement JSON, preview the CVSS-scored findings, choose the
output directory and formats, generate reports on a worker thread, and open
the results folder.

The GUI is dependency-light (stdlib ``tkinter`` only) so the PyInstaller
single-file executable stays small and runs offline / air-gapped.
"""

from __future__ import annotations

import subprocess
import sys
import threading
from pathlib import Path

import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from .pipeline import REPORTERS, generate, load_engagement

SEVERITY_KEYS = ("critical", "high", "medium", "low", "none")

HELP = """\
How to use
==========
1. Click "Load Findings..." and pick an engagement JSON
   (see sample_findings.json for the schema).
2. Inspect the scored findings table.
3. Choose an output folder and the report formats to emit.
4. Click "Generate Reports". Files are written next to your
   selection and the output folder is highlighted when done.

Formats
-------
* CSV  - machine-friendly UTF-8 files (findings, cvss, coverage, summary)
* XLSX - six-sheet styled workbook with conditional color scales
* HTML - self-contained colorful executive dashboard

Everything runs locally. No data leaves this machine.
"""


class RedTeamReportApp(tk.Tk):
    """Main application window."""

    def __init__(self) -> None:
        super().__init__()
        self.title("Red Team Engagement Report Generator")
        self.geometry("1080x720")
        self.minsize(900, 600)

        self._engagement = None
        self._working = False

        self._build_styles()
        self._build_layout()

        self._log("Ready. Load an engagement JSON to begin.")
        self.after(0, self._restore_state)

    # ------------------------------------------------------------------ UI
    def _build_styles(self) -> None:
        style = ttk.Style(self)
        if "clam" in style.theme_names():
            style.theme_use("clam")
        for band, color in (
            ("critical", "#E03131"),
            ("high", "#F76707"),
            ("medium", "#FAB005"),
            ("low", "#40C057"),
            ("none", "#868E96"),
        ):
            style.configure(f"{band}.Treeview", background=color, fieldbackground=color)

    def _build_layout(self) -> None:
        root = ttk.Frame(self, padding=12)
        root.pack(fill=tk.BOTH, expand=True)
        root.columnconfigure(0, weight=1)
        root.rowconfigure(3, weight=1)

        # -- header / file row -----------------------------------------
        header = ttk.Frame(root)
        header.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        header.columnconfigure(1, weight=1)

        self.input_var = tk.StringVar()
        ttk.Label(header, text="Findings JSON:").grid(row=0, column=0, sticky="w")
        ttk.Entry(header, textvariable=self.input_var).grid(
            row=0, column=1, sticky="ew", padx=6
        )
        ttk.Button(header, text="Browse...", command=self._pick_input).grid(
            row=0, column=2, padx=(0, 6)
        )
        ttk.Button(header, text="Help", command=self._show_help).grid(row=0, column=3)

        # -- engagement metadata ---------------------------------------
        meta = ttk.LabelFrame(root, text="Engagement")
        meta.grid(row=1, column=0, sticky="ew", pady=(0, 8))
        meta.columnconfigure(1, weight=1)

        self.meta_name = tk.StringVar(value="—")
        self.meta_customer = tk.StringVar(value="—")
        self.meta_period = tk.StringVar(value="—")
        self.meta_scope = tk.StringVar(value="—")
        self.meta_risk = tk.StringVar(value="—")

        ttk.Label(meta, text="Name").grid(row=0, column=0, sticky="w", padx=6, pady=2)
        ttk.Label(meta, textvariable=self.meta_name, font=("Segoe UI", 10, "bold")).grid(
            row=0, column=1, sticky="w", padx=6
        )
        ttk.Label(meta, text="Customer").grid(row=0, column=2, sticky="w", padx=6)
        ttk.Label(meta, textvariable=self.meta_customer).grid(
            row=0, column=3, sticky="w", padx=6
        )
        ttk.Label(meta, text="Period").grid(row=1, column=0, sticky="w", padx=6, pady=2)
        ttk.Label(meta, textvariable=self.meta_period).grid(
            row=1, column=1, sticky="w", padx=6, pady=2
        )
        ttk.Label(meta, text="Scope").grid(row=1, column=2, sticky="w", padx=6)
        ttk.Label(meta, textvariable=self.meta_scope).grid(row=1, column=3, sticky="w", padx=6)

        self.risk_var = tk.StringVar(value="Risk posture: —")
        ttk.Label(meta, textvariable=self.risk_var, foreground="#1d4ed8",
                  font=("Segoe UI", 10, "bold")).grid(
            row=2, column=0, columnspan=4, sticky="w", padx=6, pady=(4, 2)
        )

        # -- findings table ---------------------------------------------
        table_frame = ttk.LabelFrame(root, text="Findings (CVSS v3.1 scored)")
        table_frame.grid(row=3, column=0, sticky="nsew", pady=(0, 8))
        table_frame.columnconfigure(0, weight=1)
        table_frame.rowconfigure(0, weight=1)

        columns = ("id", "title", "asset", "severity", "base", "owasp")
        self.tree = ttk.Treeview(
            table_frame,
            columns=columns,
            show="headings",
            selectmode="browse",
        )
        for col, text, width in (
            ("id", "ID", 110),
            ("title", "Title", 380),
            ("asset", "Asset", 180),
            ("severity", "Severity", 90),
            ("base", "Base Score", 90),
            ("owasp", "OWASP", 70),
        ):
            self.tree.heading(col, text=text)
            self.tree.column(col, width=width, anchor="w")

        yscroll = ttk.Scrollbar(table_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=yscroll.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        yscroll.grid(row=0, column=1, sticky="ns")
        for key in SEVERITY_KEYS:
            self.tree.tag_configure(key, foreground="#111111", font=("Segoe UI", 9))

        # -- generation controls ----------------------------------------
        gen = ttk.LabelFrame(root, text="Generate Reports")
        gen.grid(row=4, column=0, sticky="ew")
        gen.columnconfigure(1, weight=1)

        self.fmt_vars = {fmt: tk.BooleanVar(value=True) for fmt in REPORTERS}
        for idx, fmt in enumerate(REPORTERS):
            ttk.Checkbutton(
                gen, text=fmt.upper(), variable=self.fmt_vars[fmt]
            ).grid(row=0, column=idx, padx=(6, 2), pady=8)

        self.out_var = tk.StringVar()
        self.out_entry = ttk.Entry(gen, textvariable=self.out_var, width=40)
        self.out_entry.grid(row=0, column=1, columnspan=2, sticky="ew", padx=8)
        ttk.Button(gen, text="Output...", command=self._pick_output).grid(
            row=0, column=3, padx=(0, 6)
        )
        self.generate_btn = ttk.Button(
            gen, text="Generate Reports", command=self._generate
        )
        self.generate_btn.grid(row=0, column=4, padx=6, rowspan=2)
        self.open_btn = ttk.Button(
            gen, text="Open Folder", command=self._open_output, state=tk.DISABLED
        )
        self.open_btn.grid(row=1, column=4, padx=6, pady=(0, 8))

        # -- status / log ------------------------------------------------
        status = ttk.Frame(root)
        status.grid(row=5, column=0, sticky="ew", pady=(8, 0))
        status.columnconfigure(1, weight=1)
        self.status_var = tk.StringVar(value="Idle")
        ttk.Label(status, textvariable=self.status_var, font=("Segoe UI", 10, "bold")).grid(
            row=0, column=0, sticky="w"
        )

        self.log = tk.Text(status, height=6, state=tk.DISABLED, wrap=tk.WORD,
                           font=("Consolas", 9), bg="#0b1220", fg="#8fa3c0")
        self.log.grid(row=1, column=0, columnspan=2, sticky="nsew", pady=(4, 0))

    # --------------------------------------------------------------- state
    def _state_dir(self) -> Path:
        root_dir = Path(
            __import__("os").environ.get("LOCALAPPDATA")
            or Path.home() / ".redteam_report"
        )
        return root_dir / "redteam_report"

    def _restore_state(self) -> None:
        try:
            from .state_store import load_state
        except ImportError:
            return
        state = load_state(self._state_dir())
        if not state.get("output_dir") and not state.get("input_file"):
            return
        if state.get("output_dir"):
            self.out_var.set(str(state["output_dir"]))
        if state.get("input_file") and Path(state["input_file"]).exists():
            self.input_var.set(str(state["input_file"]))
            self._log(f"Restored last session: {state['input_file']}")

    def _save_state(self, output_path: Path | None = None) -> None:
        try:
            from .state_store import save_state
        except ImportError:
            return
        state = {"input_file": self.input_var.get() or None}
        if output_path is not None:
            state["output_dir"] = str(output_path)
        elif self.out_var.get():
            state["output_dir"] = self.out_var.get()
        save_state(self._state_dir(), state)

    # ------------------------------------------------------------- actions
    def _pick_input(self) -> None:
        start = self.input_var.get() or str(Path.cwd())
        path = filedialog.askopenfilename(
            title="Select engagement JSON",
            initialdir=start,
            filetypes=[("Engagement JSON", "*.json"), ("All files", "*.*")],
        )
        if not path:
            return
        self.input_var.set(path)
        self._load_input(Path(path))

    def _pick_output(self) -> None:
        start = self.out_var.get() or str(Path.cwd())
        path = filedialog.askdirectory(title="Select output directory", initialdir=start)
        if path:
            self.out_var.set(path)
            self._log(f"Output directory set: {path}")

    def _load_input(self, path: Path) -> None:
        try:
            engagement = load_engagement(path)
        except Exception as exc:
            messagebox.showerror("Load failed", f"Could not read engagement file:\n{exc}")
            self._log(f"ERROR: {exc}")
            return

        self._engagement = engagement
        self.meta_name.set(engagement.name)
        self.meta_customer.set(engagement.customer or "—")
        self.meta_period.set(engagement.period or "—")
        self.meta_scope.set(engagement.scope or "—")

        summary = engagement.executive_summary()
        self.risk_var.set(
            f"Risk posture: {summary.risk_rating} (index {summary.risk_score:.0f}/100)"
        )
        for item in self.tree.get_children():
            self.tree.delete(item)
        for finding in engagement.findings:
            self.tree.insert(
                "",
                tk.END,
                values=(
                    finding.id,
                    finding.title,
                    finding.asset,
                    finding.severity.value,
                    f"{finding.base_score:.1f}",
                    finding.owasp_id,
                ),
                tags=(finding.severity.value.lower(),),
            )
        self._save_state(output_path=None)
        self._log(
            f"Loaded {len(engagement.findings)} finding(s) from {path.name}; "
            f"risk {summary.risk_rating} ({summary.risk_score:.0f}/100)."
        )

    def _log(self, message: str) -> None:
        self._write_log(message)

    def _write_log(self, message: str) -> None:
        self.log.configure(state=tk.NORMAL)
        self.log.insert(tk.END, message.rstrip("\n") + "\n")
        self.log.see(tk.END)
        self.log.configure(state=tk.DISABLED)

    def _show_help(self) -> None:
        messagebox.showinfo("Red Team Engagement Report Generator", HELP)

    def _open_output(self) -> None:
        path = Path(self.out_var.get())
        if not path.exists():
            messagebox.showwarning("Open Folder", "Output directory does not exist yet.")
            return
        try:
            if sys.platform.startswith("win"):
                subprocess.Popen(["explorer", str(path.resolve())])
            elif sys.platform == "darwin":
                subprocess.Popen(["open", str(path.resolve())])
            else:
                subprocess.Popen(["xdg-open", str(path.resolve())])
        except Exception as exc:
            self._write_log(f"Could not open folder: {exc}")

    # ----------------------------------------------------------- generate
    def _generate(self) -> None:
        if self._working:
            return
        if not self._engagement:
            messagebox.showwarning("Nothing to do", "Load an engagement JSON first.")
            return
        formats = [f for f, var in self.fmt_vars.items() if var.get()]
        if not formats:
            messagebox.showwarning("Select a format", "Tick at least one report format.")
            return
        out = Path(self.out_var.get() or "reports")
        try:
            out.mkdir(parents=True, exist_ok=True)
        except Exception as exc:
            messagebox.showerror("Output error", str(exc))
            return

        self._working = True
        self.generate_btn.configure(state=tk.DISABLED)
        self._write_log("Generating reports...")
        self.status_var.set(f"Generating {', '.join(f.upper() for f in formats)}...")

        def worker() -> None:
            try:
                results = generate(self._engagement, out, formats)
            except Exception as exc:  # pragma: no cover - surfaced in UI
                self.after(0, lambda: self._on_generate_done(None, exc))
                return
            self.after(0, lambda: self._on_generate_done(results, None))

        threading.Thread(target=worker, daemon=True).start()

    def _on_generate_done(self, results, error: Exception | None) -> None:
        self._working = False
        self.generate_btn.configure(state=tk.NORMAL)
        if error is not None:
            self.status_var.set("Generation failed")
            self._write_log(f"ERROR: {error}")
            messagebox.showerror("Generation failed", str(error))
            return
        assert results is not None
        self.status_var.set("Done")
        self.save_folder = Path(self.out_var.get() or "reports")
        self._write_log("Generated:")
        for fmt, result in results.items():
            for kind, path in result.files.items():
                self._write_log(f"  [{fmt}] {kind}: {path}")
        self.open_btn.configure(state=tk.NORMAL)
        self._save_state(output_path=self.save_folder)
        self._write_log(f"Output directory: {self.save_folder}")
        self._write_log("Ready.")

    # ------------------------------------------------------------- runner
    def run(self) -> int:
        self.mainloop()
        return 0


def main(argv=None) -> int:
    """Launch the desktop GUI (returns an exit code)."""
    app = RedTeamReportApp()
    return app.run()


if __name__ == "__main__":
    raise SystemExit(main())