"""Main window for the Log Anonymizer desktop application."""

from __future__ import annotations

import sys
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from ..gui.audit_viewer import AuditViewer
from ..gui.export_dialog import ExportDialog
from ..gui.memory_manager import Memory, MemoryError, MemoryManager
from ..gui.scanner import EngineBridge, LineScan, ScanSession
from ..gui.security_dashboard import SecurityDashboard
from ..gui.settings_dialog import SettingsDialog
from ..gui.state_manager import AppState, StateError, StateManager
from ..gui.text_view import LogText
from ..gui.theme import DARK, LIGHT

__all__ = ["AnonymizerApp", "run_app"]


class AnonymizerApp(tk.Tk):
    """Desktop front-end for the redaction engine."""

    def __init__(
        self,
        bridge: EngineBridge | None = None,
        state_dir: Path | str | None = None,
        memory_dir: Path | str | None = None,
    ) -> None:
        super().__init__()
        self.title("Log Anonymizer - Redactor for Safe Log Sharing")
        self.bridge = bridge or EngineBridge()

        self.state_manager = StateManager(state_dir)
        try:
            self.state: AppState = self.state_manager.load()
        except StateError as exc:
            self.state = AppState()
            messagebox.showwarning("State file ignored", f"{exc}\nDefaults were used.")

        self.memory = MemoryManager(memory_dir)
        try:
            self.memory.load()
        except MemoryError:
            self.memory.memory = Memory()

        self._theme = DARK if self.state.theme == "dark" else LIGHT
        self._lines: list[str] = []
        self._source_path: str = ""
        self._session: ScanSession | None = None
        self._running = False
        self._policy_ids = self.bridge.policies()

        self._build_ui()
        self._scale_window()
        self._apply_theme()

    # ---------------------------------------------------- UI construction

    def _build_ui(self) -> None:
        self.minsize(900, 560)
        self._build_menu()
        self._build_toolbar()
        self._build_controls()
        self._build_panes()
        self._build_legend()
        self._build_statusbar()
        if self.state.last_policy_id in self._policy_ids:
            self.policy_var.set(self.state.last_policy_id)

    def _build_menu(self) -> None:
        menubar = tk.Menu(self)
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="Open Log File...", command=self.open_file)
        file_menu.add_command(label="Open Recent", command=self.open_recent)
        file_menu.add_command(label="Load Sample Logs", command=self.load_samples)
        file_menu.add_separator()
        file_menu.add_command(label="Export Redacted...", command=self.export)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.destroy)
        menubar.add_cascade(label="File", menu=file_menu)

        action_menu = tk.Menu(menubar, tearoff=0)
        action_menu.add_command(label="Detect & Highlight", command=self.highlight)
        action_menu.add_command(label="Anonymize", command=self.anonymize)
        action_menu.add_separator()
        action_menu.add_command(label="Clear Input", command=self.clear_input)
        menubar.add_cascade(label="Actions", menu=action_menu)

        sec_menu = tk.Menu(menubar, tearoff=0)
        sec_menu.add_command(label="Security Framework Dashboard", command=self.show_dashboard)
        sec_menu.add_command(label="Audit Trail Viewer", command=self.show_audit)
        sec_menu.add_command(label="Verify Audit Chain", command=self.verify_chain)
        sec_menu.add_separator()
        sec_menu.add_command(label="Settings...", command=self.show_settings)
        menubar.add_cascade(label="Security", menu=sec_menu)

        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="Architecture Overview", command=self.show_help)
        help_menu.add_command(label="About", command=self.show_about)
        menubar.add_cascade(label="Help", menu=help_menu)
        self.config(menu=menubar)

    def _build_toolbar(self) -> None:
        bar = tk.Frame(self, bg=self._theme["panel"])
        bar.pack(side="top", fill="x")
        for text, cmd in (
            ("Open Log File...", self.open_file),
            ("Anonymize", self.anonymize),
            ("Export Redacted...", self.export),
            ("Verify Audit Chain", self.verify_chain),
            ("Security Dashboard", self.show_dashboard),
        ):
            btn = ttk.Button(bar, text=text, command=cmd)
            btn.pack(side="left", padx=3, pady=4)

    def _build_controls(self) -> None:
        row = tk.Frame(self, bg=self._theme["panel"], padx=8, pady=4)
        row.pack(side="top", fill="x")
        ttk.Label(row, text="Policy:").pack(side="left")
        self.policy_var = tk.StringVar()
        self.policy_combo = ttk.Combobox(
            row,
            textvariable=self.policy_var,
            values=self._policy_ids,
            state="readonly",
            width=22,
        )
        self.policy_combo.pack(side="left", padx=(4, 18))
        ttk.Label(row, text="Date shift (days):").pack(side="left")
        self.shift_var = tk.StringVar(value=str(self.state.default_date_shift_days))
        ttk.Spinbox(row, from_=-3650, to=3650, textvariable=self.shift_var, width=7).pack(
            side="left", padx=(4, 18)
        )
        ttk.Label(row, text="Token salt:").pack(side="left")
        self.salt_entry = ttk.Entry(row, width=24, show="*")
        self.salt_entry.pack(side="left", padx=4)
        if self.state.token_salt:
            self.salt_entry.insert(0, self.state.token_salt)
        ttk.Label(row, text="Lines:").pack(side="left")
        self.limit_var = tk.StringVar(value=str(self.state.preview_lines))
        ttk.Spinbox(row, from_=10, to=100_000, textvariable=self.limit_var, width=8).pack(
            side="left", padx=(4, 0)
        )

    def _build_panes(self) -> None:
        paned = ttk.Panedwindow(self, orient=tk.HORIZONTAL)
        paned.pack(side="top", fill="both", expand=True, padx=6, pady=2)

        left = ttk.Frame(paned)
        self.orig_label = ttk.Label(left, text="Original log (sensitive entities highlighted)")
        self.orig_label.pack(fill="x", padx=2)
        self.orig_text = LogText(left, theme=self._theme)
        self.orig_text.pack(fill="both", expand=True, padx=2, pady=(0, 4))
        paned.add(left, weight=1)

        right = ttk.Frame(paned)
        self.out_label = ttk.Label(right, text="Redacted output (safe to share)")
        self.out_label.pack(fill="x", padx=2)
        self.out_text = LogText(right, theme=self._theme)
        self.out_text.pack(fill="both", expand=True, padx=2, pady=(0, 4))
        paned.add(right, weight=1)

    def _build_legend(self) -> None:
        bar = tk.Frame(self, bg=self._theme["panel"], padx=8, pady=2)
        bar.pack(side="top", fill="x")
        ttk.Label(bar, text="Detected entities: ").pack(side="left")
        classes = [
            ("CRITICAL", "#e05555"),
            ("HIGH", "#f08c3a"),
            ("MEDIUM", "#e5c14a"),
            ("LOW", "#6ea8fe"),
        ]
        for cls, color in classes:
            chip = tk.Label(
                bar, text=f" {cls} ", bg=color, fg="#ffffff", font=("Segoe UI", 8, "bold")
            )
            chip.pack(side="left", padx=4, pady=2)

    def _build_statusbar(self) -> None:
        self.status_var = tk.StringVar(value="Ready.")
        bar = tk.Label(self, textvariable=self.status_var, anchor="w", padx=8, pady=3)
        bar.pack(side="bottom", fill="x")

    # ------------------------------------------------------------- theming

    def _apply_theme(self) -> None:
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        t = self._theme
        self.configure(bg=t["bg"])
        style.configure(".", background=t["bg"], foreground=t["fg"])
        style.configure("TButton", background=t["frame"], foreground=t["fg"])
        style.map(
            "TButton", background=[("active", t["accent"])], foreground=[("active", t["accent_fg"])]
        )
        style.configure(
            "TCombobox", fieldbackground=t["input"], background=t["frame"], foreground=t["fg"]
        )
        style.configure(
            "TEntry", fieldbackground=t["input"], background=t["frame"], foreground=t["fg"]
        )
        style.configure(
            "TSpinbox", fieldbackground=t["input"], background=t["frame"], foreground=t["fg"]
        )
        style.configure("TLabel", background=t["bg"], foreground=t["fg"])

    def _scale_window(self) -> None:
        st = self.state
        self.geometry(f"{st.window_width}x{st.window_height}")
        if st.window_x is not None and st.window_y is not None:
            self.geometry(f"+{st.window_x}+{st.window_y}")

    # -------------------------------------------------------------- actions

    def _policy_id(self) -> str:
        return self.policy_var.get() or "default"

    def _load_lines(self, path: Path) -> None:
        try:
            raw = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            messagebox.showerror("Open failed", str(exc))
            return
        self._lines = raw.splitlines()
        self._source_path = str(path)
        self.state_manager.update(**{"recent.last_open_dir": str(path.parent)})
        self.memory.remember_file(
            str(path),
            line_count=len(self._lines),
            sensitive_hits=self._sensitive_hits_for(self._lines),
        )
        self.memory.save()
        self._render_input()
        self.status_var.set(f"Loaded {len(self._lines)} lines from {path.name}")

    def _sensitive_hits_for(self, lines: list[str]) -> int:
        hits = 0
        for line in lines[:200]:
            hits += len(self.bridge.service.detection.detect(line))
        return hits

    def open_file(self) -> None:
        initial = self.state.last_open_dir or "."
        path = filedialog.askopenfilename(
            parent=self,
            title="Open log file",
            initialdir=initial,
            filetypes=[
                ("Log files", "*.log *.txt *.json *.csv"),
                ("All files", "*.*"),
            ],
        )
        if path:
            self._load_lines(Path(path))
            self.render_entity_check()

    def open_recent(self) -> None:
        recents = [r.path for r in self.memory.memory.recent_files if r.path]
        if not recents:
            messagebox.showinfo("Recent files", "No recently opened files yet.")
            return
        from .recent_dialog import RecentDialog

        chosen = RecentDialog(self, recents, self._theme).pick()
        if chosen:
            path = Path(chosen)
            if path.exists():
                self._load_lines(path)
            else:
                messagebox.showerror("Missing file", f"{chosen} no longer exists.")

    def load_samples(self) -> None:
        samples = [
            "ERROR [auth-service] user bob@example.com failed login from 203.0.113.7, ssn 555-66-7777",
            "INFO  [payments] card 4539-6651-3101-6828 authorized for 99.95 USD",
            "WARN  [api-gateway] suspect path /healthz from user anna@corp.dev",
            "DEBUG [db] slow query 312ms from ip 198.51.100.4 on table users",
            "INFO  [notification] sent SMS to +1 (555) 100-0000",
            "ERROR [ml] patient John A. Doe inference failed, dob 1975-08-14",
            "INFO  [ops] deployed release v2.4.1 scale replicas=6",
            "DEBUG [search] geolocation 37.7749,-122.4194 for query hotels",
        ]
        self._lines = samples
        self._source_path = "(sample)"
        self._render_input()
        self.render_entity_check()
        self.status_var.set("Samples loaded. Click Anonymize to redact.")

    def clear_input(self) -> None:
        self._lines = []
        self._source_path = ""
        self._session = None
        self.orig_text.delete("1.0", "end")
        self.out_text.delete("1.0", "end")
        self.status_var.set("Input cleared.")

    def _render_input(self) -> None:
        limit = int(self.limit_var.get() or 500)
        self.orig_text.render(self._lines, max_lines=limit)

    def highlight(self) -> None:
        """Menu alias for: detect entities and highlight them in the source."""
        if not self._lines:
            messagebox.showinfo("No input", "Open a log file or load sample logs first.")
            return
        self.render_entity_check()

    def render_entity_check(self) -> None:
        """Highlight detected entities in the original pane (no redaction)."""
        self.status_var.set("Detecting sensitive entities...")
        self.update_idletasks()
        scans = [
            LineScan(index=i, original=line, redacted=line, entities=[])
            for i, line in enumerate(self._lines)
        ]
        for i, line in enumerate(self._lines):
            scans[i].entities = self.bridge.service.detection.detect(line)
        limit = int(self.limit_var.get() or 500)
        self.orig_text.render(self._lines, scans, max_lines=limit)
        total = sum(len(s.entities) for s in scans[:limit])
        self.status_var.set(
            f"Highlighted {total} sensitive entities across {min(limit, len(self._lines))} lines."
        )

    def anonymize(self) -> None:
        if not self._lines:
            messagebox.showinfo("No input", "Open a log file or load sample logs first.")
            return
        if self._running:
            return
        self._running = True
        self._set_output("Anonymizing...")

        limit = int(self.limit_var.get() or 500)
        lines = self._lines[:limit]
        policy = self._policy_id()
        salt = self.salt_entry.get().strip()
        shift = int(self.shift_var.get() or 0)

        def work() -> ScanSession:
            return self.bridge.scan(lines, policy_id=policy, token_salt=salt, date_shift_days=shift)

        def done(session: ScanSession) -> None:
            self._running = False
            self._session = session
            self.out_text.delete("1.0", "end")
            self.out_text.render(session.redacted_lines)
            counts = session.entity_counts
            summary = ", ".join(f"{k}:{v}" for k, v in sorted(counts.items())) or "none"
            self.status_var.set(
                f"Policy={session.policy_id} | entities={summary} | "
                f"audit={session.audit_events} | {session.processing_ms:.0f} ms | chain {session.chain_root[:12]}..."
            )
            self.state_manager.update(**{"recent.last_policy_id": policy})
            self.memory.record_stats(session.entity_counts)
            self.memory.save()

        self._run_async(work, done)

    def export(self) -> None:
        if not self._session:
            messagebox.showinfo("Nothing to export", "Run Anonymize first.")
            return
        ExportDialog(
            self,
            bridge=self.bridge,
            session=self._session,
            state=self.state,
            theme=self._theme,
            on_export=lambda lines, path, meta: self._on_export_done(lines, path, meta),
        ).show()

    def _on_export_done(self, lines: list[str], path: Path, meta: dict) -> None:
        self.state_manager.update(**{"recent.last_export_dir": str(path.parent)})
        hint = " (encrypted)" if meta.get("encrypted") else ""
        self.status_var.set(f"Exported {len(lines)} redacted lines{hint} -> {path}")

    def verify_chain(self) -> None:
        valid, expected, count = self.bridge.verify_chain()
        self.status_var.set(
            f"Audit chain verify: {'INTACT' if valid else 'MISMATCH'} | "
            f"{count} records | root {expected[:12]}..."
        )
        if not valid:
            messagebox.showwarning(
                "Audit chain", f"Chain verification failed.\nExpected root: {expected[:16]}..."
            )
        else:
            messagebox.showinfo(
                "Audit chain", f"Chain intact. {count} records, root {expected[:16]}..."
            )

    def show_dashboard(self) -> None:
        SecurityDashboard(self, self._theme).show()

    def show_audit(self) -> None:
        AuditViewer(self, self.bridge, self._theme).show()

    def show_settings(self) -> None:
        before = self.state.theme
        SettingsDialog(
            self,
            state_manager=self.state_manager,
            theme=self._theme,
        ).show()
        if self.state.theme != before:
            self._theme = DARK if self.state.theme == "dark" else LIGHT
            self._apply_theme()

    def show_help(self) -> None:
        messagebox.showinfo(
            "Architecture overview",
            "See ARCHITECTURE.md in the project for the full design.\n\n"
            "Security frameworks maintained: OWASP Top 10 (2021), NIST CSF 2.0 /\n"
            "SP 800-53 R5, ISO 27001:2022 Annex A, GDPR, HIPAA, PCI-DSS.\n"
            "Open Security > Security Framework Dashboard to browse the mapping.",
        )

    def show_about(self) -> None:
        messagebox.showinfo(
            "About",
            "Log Anonymizer with Redactor - for safe log sharing.\n"
            "Redaction strategies: full redact, partial mask, tokenize,\n"
            "pseudonymize, generalize, date-shift, contextual.\n"
            "Audit trail: append-only and tamper-evident.",
        )

    # ------------------------------------------------------------- helpers

    def _run_async(self, work, done) -> None:
        def runner() -> None:
            try:
                result = work()
            except Exception as exc:  # noqa: BLE001 - UI boundary, surface any engine error
                message = str(exc)
                self.after(0, lambda: self._async_failed(message))
                return
            self.after(0, lambda: done(result))

        threading.Thread(target=runner, daemon=True).start()

    def _async_failed(self, message: str) -> None:
        self._running = False
        messagebox.showerror("Operation failed", message)

    def _set_output(self, text: str) -> None:
        self.out_text.configure(state="normal")
        self.out_text.delete("1.0", "end")
        self.out_text.insert("1.0", text)
        self.out_text.configure(state="disabled")

    def destroy(self) -> None:
        self.state.window_width = self.winfo_width()
        self.state.window_height = self.winfo_height()
        try:
            self.state.window_x = self.winfo_x()
            self.state.window_y = self.winfo_y()
        except tk.TclError:
            pass
        try:
            self.state_manager.save(self.state)
            self.memory.save()
        except Exception as exc:  # noqa: BLE001 - best effort on shutdown
            sys.stderr.write(f"failed to persist session state: {exc}\n")
        super().destroy()


def run_app(
    bridge: EngineBridge | None = None,
    state_dir: Path | str | None = None,
    memory_dir: Path | str | None = None,
) -> AnonymizerApp:
    app = AnonymizerApp(bridge, state_dir, memory_dir)
    app.mainloop()
    return app
