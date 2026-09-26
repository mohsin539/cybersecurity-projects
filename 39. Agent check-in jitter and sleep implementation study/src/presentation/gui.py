"""CustomTkinter desktop GUI - study designer, runner, results, exporter."""
from __future__ import annotations

import json
import os
import queue
import re
import threading
import traceback
from pathlib import Path
from typing import Any

import customtkinter as ctk

from src.app.orchestrator import StudyCancelled, run_study, study_verdict
from src.config import Scenario, scenario_from_dict
from src.paths import audit_log_path, data_dir, out_dir
from src.reporting.bundle import write_full_bundle
from src.reporting.report_data import build_report_model
from src.security.audit import AuditLog
from src.security import vault

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

_INT_RE = re.compile(r"^\s*\d+\s*$")


class _F(ctk.CTkFrame):
    pass


class App(ctk.CTk):
    def __init__(self) -> None:
        super().__init__()
        self.title("Agent Check-in Jitter & Sleep Study - Portable Toolkit")
        self.geometry("1180x800")
        self.minsize(980, 700)

        self.audit = AuditLog(audit_log_path())
        self.audit_ok = self.audit.verify()

        self.result_queue: queue.Queue = queue.Queue()
        self.cancel_event = threading.Event()
        self.worker: threading.Thread | None = None
        self.result: Any = None
        self.model: dict | None = None
        self.out_dir = out_dir()

        self._grid = ctk.CTkFrame(self, corner_radius=14)
        self._grid.pack(fill="both", expand=True, padx=12, pady=12)
        self._grid.grid_columnconfigure(0, weight=1)
        self._grid.grid_rowconfigure(1, weight=1)

        header = ctk.CTkLabel(
            self._grid,
            text="Agent Check-in Jitter & Sleep — Implementation Study",
            font=ctk.CTkFont(size=22, weight="bold"),
            text_color="#7dd3fc",
        )
        header.grid(row=0, column=0, padx=14, pady=(12, 4), sticky="w")

        audit_txt = "audit chain: OK (append-only + hash-linked)" if self.audit_ok else "AUDIT CHAIN FAILED - integrity review required"
        sub = ctk.CTkLabel(self._grid, text=f"{data_dir()}  |  {audit_txt}", font=ctk.CTkFont(size=12),
                           text_color="#fb7185" if not self.audit_ok else "#34d399")
        sub.grid(row=1, column=0, padx=16, sticky="w")

        self.tabs = ctk.CTkTabview(self._grid, corner_radius=12)
        self.tabs.grid(row=2, column=0, sticky="nsew", padx=14, pady=(6, 12))
        self._grid.grid_rowconfigure(2, weight=1)
        self.design_tab = self.tabs.add("Design & Run")
        self.results_tab = self.tabs.add("Results")
        self.export_tab = self.tabs.add("Export")

        self._build_design_tab()
        self._build_results_tab()
        self._build_export_tab()

    # ---------------------------------------------------------- design tab
    def _build_design_tab(self) -> None:
        tab = self.design_tab
        tab.grid_columnconfigure(0, weight=1)

        self.fields: dict[str, Any] = {}
        defaults = Scenario().model_dump()

        form = ctk.CTkScrollableFrame(tab, corner_radius=12)
        form.grid(row=0, column=0, sticky="nsew", padx=3, pady=3)
        tab.grid_rowconfigure(0, weight=1)
        form.grid_columnconfigure(0, weight=1)
        form.grid_columnconfigure(1, weight=1)

        def add_section(title: str) -> None:
            ctk.CTkLabel(form, text=title, font=ctk.CTkFont(size=15, weight="bold"),
                         text_color="#a78bfa").grid(row=_sec_row(), column=0, columnspan=2, sticky="w", pady=(14, 2))

        def _sec_row() -> int:
            return len(form.grid_slaves()) // 3

        def add_num(key: str, label: str, lo: float | None = 0, hi: float | None = 1e9, step: float = 1.0, is_int: bool = True) -> None:
            row = len(form.grid_slaves()) // 2
            ctk.CTkLabel(form, text=label).grid(row=row, column=0, sticky="e", padx=8, pady=4)
            box = ctk.CTkEntry(form, width=170)
            box.grid(row=row, column=1, sticky="w", padx=8, pady=4)
            box.insert(0, str(defaults.get(key, "0")))
            self.fields[key] = {"widget": box, "int": is_int, "lo": lo, "hi": hi}
            return None

        def add_menu(key: str, label: str, values: list[str]) -> None:
            row = len(form.grid_slaves()) // 2
            ctk.CTkLabel(form, text=label).grid(row=row, column=0, sticky="e", padx=8, pady=4)
            menu = ctk.CTkOptionMenu(form, values=values, width=170)
            menu.set(str(defaults.get(key, values[0])))
            menu.grid(row=row, column=1, sticky="w", padx=8, pady=4)
            self.fields[key] = {"widget": menu, "menu": True}

        add_section("Population & Timing")
        add_num("agents", "Agents", 10, 100_000, 100)
        add_num("interval_sec", "Base interval (s)", 0.1, 86_400, 1, False)
        add_num("jitter_pct", "Jitter (%)", 0, 100, 1, False)
        add_menu("jitter_type", "Jitter distribution", ["uniform", "gaussian", "poisson", "triangular", "exp-truncated"])
        add_menu("sleep_mode", "Sleep mode", ["fixed", "random", "adaptive", "burst"])
        add_num("sleep_base_sec", "Sleep base (s)", 0.1, 86_400, 1, False)
        add_num("run_length_sec", "Run length (s)", 2, 604_800, 60, False)

        add_section("Study Design")
        add_num("replicas", "Replicates", 1, 50, 1)
        add_num("seed", "Seed", 0, 2**32, 1)
        add_menu("engine", "Simulation engine", ["exact", "fast"])
        ctk.CTkLabel(form, text="Compare vs no-jitter baseline").grid(row=len(form.grid_slaves()) // 2, column=0, sticky="e", padx=8, pady=6)
        self.sw_compare = ctk.CTkSwitch(form, text="on")
        self.sw_compare.grid(row=len(form.grid_slaves()) // 2, column=1, sticky="w", padx=8, pady=6)
        self.sw_compare.select()

        add_section("Server Model")
        add_num("server_workers", "Workers", 1, 100_000, 1)
        add_num("server_service_ms", "Service time (ms)", 0.01, 10_000, 1, False)
        add_num("server_queue_cap", "Queue capacity", 0, 1_000_000, 10)
        add_num("retry_backoff_base_sec", "Retry backoff (s)", 0.1, 3600, 1, False)

        add_section("Power Profile")
        add_num("power_active_ma", "Active draw (mA)", 0, 1000, 1, False)
        add_num("power_sleep_ua", "Sleep draw (uA)", 0, 100_000, 1, False)

        row = len(form.grid_slaves()) // 2
        ctk.CTkButton(form, text="Save scenario JSON", width=180,
                      command=self._save_scenario).grid(row=row, column=0, sticky="e", padx=8, pady=14)
        ctk.CTkButton(form, text="Load scenario JSON", width=180,
                      command=self._load_scenario).grid(row=row, column=1, sticky="w", padx=8, pady=14)

        # control bar (outside scroll)
        bar = ctk.CTkFrame(tab, fg_color="transparent")
        bar.grid(row=1, column=0, sticky="ew", pady=4)
        bar.grid_columnconfigure(0, weight=1)
        self.btn_run = ctk.CTkButton(bar, text="\u25b6  Run Study", width=190, height=40,
                                     font=ctk.CTkFont(weight="bold"), command=self._start_study)
        self.btn_run.grid(row=0, column=0, sticky="w", padx=4)
        self.btn_cancel = ctk.CTkButton(bar, text="Cancel", width=100, height=40,
                                        fg_color="#b91c1c", hover_color="#7f1d1d", command=self._cancel_study, state="disabled")
        self.btn_cancel.grid(row=0, column=1, padx=4)
        self.progress = ctk.CTkProgressBar(bar, width=300)
        self.progress.grid(row=0, column=2, padx=10)
        self.progress.set(0)
        self.status = ctk.CTkLabel(bar, text="ready", font=ctk.CTkFont(size=12), text_color="#8fa0c8")
        self.status.grid(row=0, column=3, sticky="e")

    # ---------------------------------------------------------- results tab
    def _build_results_tab(self) -> None:
        tab = self.results_tab
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(1, weight=1)
        self.verdict = ctk.CTkLabel(tab, text="No study run yet.", font=ctk.CTkFont(size=16, weight="bold"),
                                    text_color="#8fa0c8")
        self.verdict.grid(row=0, column=0, sticky="w", padx=6, pady=4)
        self.out_text = ctk.CTkTextbox(tab, state="disabled", font=ctk.CTkFont(family="Consolas", size=13))
        self.out_text.grid(row=1, column=0, sticky="nsew", padx=6, pady=4)

    # ---------------------------------------------------------- export tab
    def _build_export_tab(self) -> None:
        tab = self.export_tab
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(3, weight=1)

        row = 0
        ctk.CTkLabel(tab, text="Output folder (portable per-user dir)").grid(row=row, column=0, sticky="w", padx=4, pady=8)
        self.out_entry = ctk.CTkEntry(tab, width=420)
        self.out_entry.insert(0, self.out_dir)
        self.out_entry.grid(row=row + 1, column=0, sticky="w", padx=4)
        ctk.CTkButton(tab, text="Browse", width=90, command=self._browse_out).grid(row=row + 1, column=1, padx=6)

        row = 3
        self.fmt_flags = {}
        for i, name in enumerate((".xlsx", ".csv", ".html", ".json", ".zip")):
            self.fmt_flags[name] = ctk.CTkCheckBox(tab, text=name)
            self.fmt_flags[name].grid(row=row, column=i, padx=8, pady=(12, 4))
            self.fmt_flags[name].select()

        row = 4
        self.sw_pw = ctk.CTkSwitch(tab, text="Protect ZIP bundle with passphrase (AES-256-GCM)")
        self.sw_pw.grid(row=row, column=0, columnspan=2, sticky="w", padx=8)
        self.pw_entry = ctk.CTkEntry(tab, show="\u2022", width=320, placeholder_text="passphrase")
        self.pw_entry.grid(row=row + 1, column=0, columnspan=2, sticky="w", padx=8, pady=(4, 10))
        if not vault.crypto_available():
            self.sw_pw.configure(state="disabled")
            self.pw_entry.configure(state="disabled")

        row = 6
        ctk.CTkButton(tab, text="Export Report Bundle", width=210, height=42,
                      font=ctk.CTkFont(weight="bold"), command=self._export).grid(row=row, column=0, sticky="w", padx=8)
        ctk.CTkButton(tab, text="Open folder", width=130, command=self._open_folder).grid(row=row, column=1, sticky="w", padx=8)
        self.export_status = ctk.CTkLabel(tab, text="runs are exported under out/<run_id>/", font=ctk.CTkFont(size=12),
                                          text_color="#8fa0c8")
        self.export_status.grid(row=row + 1, column=0, sticky="w", padx=8, pady=6)

    # ---------------------------------------------------------- actions
    def _collect_scenario(self) -> Scenario:
        raw: dict[str, Any] = {}
        for key, meta in self.fields.items():
            w = meta["widget"]
            val = w.get()
            if isinstance(w, ctk.CTkOptionMenu) or meta.get("menu"):
                raw[key] = val
            elif meta.get("int"):
                try:
                    raw[key] = int(float(val))
                except (TypeError, ValueError):
                    raise ValueError(f"{key} must be an integer, got {val!r}")
            else:
                try:
                    raw[key] = float(val)
                except (TypeError, ValueError):
                    raise ValueError(f"{key} must be a number, got {val!r}")
        raw["compare_baseline"] = bool(self.sw_compare.get())
        return scenario_from_dict(raw)

    def _start_study(self) -> None:
        if self.worker and self.worker.is_alive():
            self._toast("Study already running.")
            return
        try:
            scenario = self._collect_scenario()
        except Exception as exc:  # validation at boundary
            self.export_status.configure(text=f"validation error: {exc}", text_color="#fb7185")
            self._render_status(f"ERROR: {exc}")
            return
        self.cancel_event.clear()
        self.latest_scenario = scenario
        self.progress.set(0)
        self._render_status("launching simulation...")
        self.btn_run.configure(state="disabled")
        self.btn_cancel.configure(state="normal")
        self._set_tab_enabled(False)
        self.worker = threading.Thread(target=self._worker, args=(scenario,), daemon=True)
        self.worker.start()
        self.after(120, self._poll)

    def _worker(self, scenario: Scenario) -> None:
        try:
            def progress(f: float, msg: str) -> None:
                if self.cancel_event.is_set():
                    raise StudyCancelled()
                self.result_queue.put(("progress", f, msg))

            result = run_study(scenario, progress)
            self.audit.append("study.run", {
                "scenario_hash": scenario.config_hash(),
                "replicas": scenario.replicas,
                "compare_baseline": scenario.compare_baseline,
                "engine": scenario.engine,
            })
            self.result_queue.put(("done", result))
        except StudyCancelled:
            self.result_queue.put(("cancelled", None))
        except Exception as exc:  # surface anything to the UI
            self.result_queue.put(("error", f"{type(exc).__name__}: {exc}\n{traceback.format_exc()[-1200:]}"))

    def _poll(self) -> None:
        try:
            while True:
                msg = self.result_queue.get_nowait()
                kind = msg[0]
                if kind == "progress":
                    f, text = msg[1], msg[2]
                    self.progress.set(f)
                    self._render_status(f"{text}  ({f*100:.0f}%)")
                elif kind == "done":
                    self.result = msg[1]
                    self.model = build_report_model(self.result)
                    self.progress.set(1)
                    badge, text = study_verdict(self.result)
                    self.verdict.configure(text=f"{badge} - {text}", text_color="#34d399" if badge == "PASS" else "#fbbf24")
                    self._render_status("study complete. open Export tab to write .xlsx/.csv/.html/.json/.zip")
                    self._print_summary()
                    self._finish_run()
                elif kind == "cancelled":
                    self._render_status("cancelled by user")
                    self._finish_run()
                elif kind == "error":
                    self.verdict.configure(text="RUN FAILED", text_color="#fb7185")
                    self.outbox_append(msg[1])
                    self._render_status("run failed - see Results tab")
                    self._finish_run()
        except queue.Empty:
            pass
        if self.worker and self.worker.is_alive():
            self.after(120, self._poll)

    def _finish_run(self) -> None:
        self.btn_run.configure(state="normal")
        self.btn_cancel.configure(state="disabled")
        self._set_tab_enabled(True)

    def _cancel_study(self) -> None:
        self.cancel_event.set()
        self._render_status("cancelling...")

    def _print_summary(self) -> None:
        if not self.model:
            return
        self.outbox_clear()
        lines = [
            f"run_id         : {self.model['run_id']}",
            f"verdict        : {self.model['verdict_badge']} - {self.model['verdict_text']}",
            "",
            "KPI (candidate vs baseline):",
        ]
        for r in self.model["summary_rows"]:
            base = r.get("baseline", "-")
            lines.append(f"  {r['metric']:<32} {r['candidate']:<20} {base}")
        if self.model["comparison_rows"]:
            lines.append("")
            lines.append("Statistical comparisons:")
            for c in self.model["comparison_rows"]:
                lines.append(f"  {c['metric']:<26} g={c['hedges_g']:>7} p={c['u_p']:>8} verdict={c['verdict']}")
        self.outbox_append("\n".join(lines))

    def _export(self) -> None:
        if not self.model:
            self.export_status.configure(text="no study results yet - run a study first", text_color="#fb7185")
            return
        out = self.out_entry.get().strip() or out_dir()
        fmt_any = any(v.get() for v in self.fmt_flags.values())
        if not fmt_any:
            self.export_status.configure(text="select at least one format", text_color="#fb7185")
            return
        passphrase = self.pw_entry.get() if self.sw_pw.get() else None
        try:
            paths = write_full_bundle(self.model, out, self.audit, passphrase)
            ok = self._filter_paths(paths)
            self.export_status.configure(
                text=f"written {len(ok)} artifacts to {out}\\{self.model['run_id']}",
                text_color="#34d399",
            )
            self.outbox_append("exported:\n" + "\n".join(f"  {b}" for b in ok))
        except Exception as exc:
            self.export_status.configure(text=f"export failed: {exc}", text_color="#fb7185")

    def _filter_paths(self, paths: dict[str, str]) -> list[str]:
        wanted = self.fmt_flags
        m = {ext: wanted[ext].get() for ext in wanted}
        keep = []
        for name, path in paths.items():
            if any((ext in name) and active for ext, active in m.items()):
                keep.append(name)
        return keep

    def _browse_out(self) -> None:
        from tkinter import filedialog
        sel = filedialog.askdirectory(initialdir=self.out_dir)
        if sel:
            self.out_dir = sel
            self.out_entry.delete(0, "end")
            self.out_entry.insert(0, sel)

    def _open_folder(self) -> None:
        d = self.out_entry.get().strip() or out_dir()
        os.makedirs(d, exist_ok=True)
        os.startfile(d)  # Windows only

    def _save_scenario(self) -> None:
        from tkinter import filedialog
        try:
            sc = self._collect_scenario()
        except Exception as exc:
            self._render_status(f"cannot save: {exc}")
            return
        f = filedialog.asksaveasfilename(defaultextension=".json",
                                          initialfile="scenario.json")
        if f:
            with open(f, "w", encoding="utf-8") as fh:
                json.dump(sc.model_dump(), fh, indent=2, sort_keys=True)
            self._render_status(f"scenario saved -> {f}")

    def _load_scenario(self) -> None:
        from tkinter import filedialog
        f = filedialog.askopenfilename(filetypes=[("json","*.json"),("yaml","*.yml;*.yaml")])
        if not f:
            return
        try:
            if f.endswith((".yml", ".yaml")):
                import yaml
                with open(f, "r", encoding="utf-8") as fh:
                    raw = yaml.safe_load(fh)
            else:
                with open(f, "r", encoding="utf-8") as fh:
                    raw = json.load(fh)
            sc = scenario_from_dict(raw)
            self._apply_scenario(sc)
            self._render_status(f"scenario loaded -> {Path(f).name}")
        except Exception as exc:
            self.export_status.configure(text=f"load failed: {exc}", text_color="#fb7185")

    def _apply_scenario(self, sc: Scenario) -> None:
        d = sc.model_dump()
        for key, meta in self.fields.items():
            w = meta["widget"]
            w.configure(state="normal")
            if isinstance(w, ctk.CTkOptionMenu):
                w.set(str(d.get(key, "")))
            else:
                w.delete(0, "end")
                w.insert(0, str(d.get(key, "")))
        self.sw_compare.select() if d.get("compare_baseline") else self.sw_compare.deselect()

    def _set_tab_enabled(self, enabled: bool):
        # tabview internals are private; keep control surfaces in the bar only
        return

    # ---------------------------------------------------------- ui helpers
    def _render_status(self, text: str) -> None:
        self.status.configure(text=text[:90])

    def _toast(self, text: str) -> None:
        self._render_status(text)

    def outbox_append(self, text: str) -> None:
        self.out_text.configure(state="normal")
        self.out_text.insert("end", text + "\n")
        self.out_text.see("end")
        self.out_text.configure(state="disabled")

    def outbox_clear(self) -> None:
        self.out_text.configure(state="normal")
        self.out_text.delete("1.0", "end")
        self.out_text.configure(state="disabled")


def run_gui() -> None:
    app = App()
    app.mainloop()