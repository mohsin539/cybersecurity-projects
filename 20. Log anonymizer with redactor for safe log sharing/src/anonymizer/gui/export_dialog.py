"""Secure export dialog: plaintext, JSON, or password-encrypted output."""

from __future__ import annotations

import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from ..gui.scanner import EncryptedExportError, EngineBridge, ScanSession
from ..gui.state_manager import AppState


class ExportDialog(tk.Toplevel):
    """Choose format, optional encryption, and an evidence report."""

    def __init__(
        self,
        master,
        *,
        bridge: EngineBridge,
        session: ScanSession,
        state: AppState,
        theme: dict,
        on_export,
    ) -> None:
        super().__init__(master)
        self.title("Export Redacted Log")
        self.bridge = bridge
        self.session = session
        self.state = state
        self._theme = theme
        self._on_export = on_export
        self.geometry("460x360")
        self.configure(bg=theme["bg"])
        self._build()
        self.transient(master)
        self.grab_set()

    def _build(self) -> None:
        form = ttk.Frame(self, padding=14)
        form.pack(fill="both", expand=True)

        self.format_var = tk.StringVar(value="plain")
        ttk.Label(form, text="Output format:").grid(sticky="w")
        fmt = ttk.Frame(form)
        fmt.grid(row=1, column=0, columnspan=2, sticky="w")
        for key, label in (
            ("plain", "Redacted text (.log)"),
            ("json", "Redacted JSON (.json)"),
            ("encrypted", "Encrypted (AES-GCM/Fernet, .enc)"),
        ):
            ttk.Radiobutton(fmt, text=label, variable=self.format_var, value=key).pack(
                side="left", padx=6
            )

        ttk.Label(form, text="Share with analytics report?").grid(sticky="w", pady=(10, 0))
        self.report_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            form,
            text="Also write a compliance evidence report (.md) with the chain root",
            variable=self.report_var,
        ).grid(row=4, column=0, columnspan=2, sticky="w")

        ttk.Label(form, text="Password (required for encrypted format):").grid(
            sticky="w", pady=(12, 0)
        )
        self.password_var = tk.StringVar()
        ttk.Entry(form, textvariable=self.password_var, show="*", width=30).grid(
            row=6, column=0, columnspan=2, sticky="w"
        )

        ttk.Label(form, text="File base name (do not include extension):").grid(
            sticky="w", pady=(12, 0)
        )
        self.base_var = tk.StringVar(value="redacted-output")
        ttk.Entry(form, textvariable=self.base_var, width=30).grid(
            row=8, column=0, columnspan=2, sticky="w"
        )

        btn = ttk.Frame(self, padding=12)
        btn.pack(side="bottom", fill="x")
        ttk.Button(btn, text="Export", command=self._export).pack(side="right")
        ttk.Button(btn, text="Cancel", command=self.destroy).pack(side="right", padx=4)

    def _export(self) -> None:
        fmt = self.format_var.get()
        initial = self.state.last_export_dir or "."
        ext = {"plain": ".log", "json": ".json", "encrypted": ".enc"}[fmt]
        path = filedialog.asksaveasfilename(
            parent=self,
            title="Export redacted log",
            initialdir=initial,
            defaultextension=ext,
            initialfile=self.base_var.get().strip() or "redacted-output",
            filetypes=[("Output files", f"*{ext}"), ("All files", "*.*")],
        )
        if not path:
            return
        target = Path(path)
        try:
            meta: dict = {}
            if fmt == "plain":
                self.bridge.export_plain(self.session.redacted_lines, target)
            elif fmt == "json":
                self.bridge.export_json(self.session.redacted_lines, target)
            else:
                password = self.password_var.get()
                if not password:
                    messagebox.showerror(
                        "Password required", "Encrypted export needs a password.", parent=self
                    )
                    return
                self.bridge.export_encrypted(self.session.redacted_lines, target, password)
                meta["encrypted"] = True
            if self.report_var.get():
                self._write_report(target.with_suffix(".evidence.md"))
        except (EncryptedExportError, OSError, ValueError) as exc:
            messagebox.showerror("Export failed", str(exc), parent=self)
            return
        self._on_export(self.session.redacted_lines, target, meta)
        self.destroy()

    def _write_report(self, path: Path) -> None:
        session = self.session
        ticket = self.bridge.verification_ticket()
        rows = "\n".join(f"| {key} | {value} |" for key, value in session.entity_counts.items())
        content = (
            "# Compliance Evidence Report\n\n"
            f"- Tool: Log Anonymizer with Redactor\n"
            f"- Request: `{session.request_id}`\n"
            f"- Policy applied: `{session.policy_id}`\n"
            f"- Lines processed: {len(session.redacted_lines)}\n"
            f"- Audit events appended: {session.audit_events}\n"
            f"- Audit chain root: `{session.chain_root}`\n"
            f"- Verification ticket: `{ticket.get('root', '')}`\n"
            f"- Processing time: {session.processing_ms:.0f} ms\n\n"
            f"## Entity statistics\n\n| type | count |\n|---|---|\n{rows}\n\n"
            "_This report contains no original sensitive values; all data was redacted._\n"
        )
        path.write_text(content, encoding="utf-8")
