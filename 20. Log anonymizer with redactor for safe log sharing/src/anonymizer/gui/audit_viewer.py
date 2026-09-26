"""Audit trail viewer with on-demand integrity verification."""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk

from ..gui.scanner import EngineBridge


class AuditViewer(tk.Toplevel):
    """Inspect recent audit records and verify the chain root."""

    def __init__(self, master, bridge: EngineBridge, theme: dict) -> None:
        super().__init__(master)
        self.title("Audit Trail Viewer")
        self.bridge = bridge
        self._theme = theme
        self.geometry("820x540")
        self.configure(bg=theme["bg"])
        self._build()

    def _build(self) -> None:
        toolbar = ttk.Frame(self)
        toolbar.pack(fill="x", padx=8, pady=6)
        ttk.Button(toolbar, text="Refresh", command=self.refresh).pack(side="left")
        ttk.Button(toolbar, text="Verify Chain", command=self.verify).pack(side="left", padx=6)

        self.info_var = tk.StringVar(value="")
        ttk.Label(self, textvariable=self.info_var).pack(fill="x", padx=8)

        cols = ("seq", "when", "action", "class", "type", "policy", "confidence")
        self.tree = ttk.Treeview(self, columns=cols, show="headings")
        for col, width in (
            ("seq", 60),
            ("when", 150),
            ("action", 90),
            ("class", 80),
            ("type", 110),
            ("policy", 130),
            ("confidence", 80),
        ):
            self.tree.heading(col, text=col.upper())
            self.tree.column(col, width=width, anchor="w")
        scroll = ttk.Scrollbar(self, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)
        self.tree.pack(side="left", fill="both", expand=True, padx=(8, 0), pady=4)
        scroll.pack(side="right", fill="y", padx=(0, 8), pady=4)
        self.refresh()

    def refresh(self) -> None:
        for item in self.tree.get_children():
            self.tree.delete(item)
        records = self.bridge.recent_records()
        for rec in records:
            self.tree.insert(
                "",
                "end",
                values=(
                    rec.get("seq", ""),
                    rec.get("timestamp", "")[:19],
                    rec.get("action", ""),
                    rec.get("data_class", ""),
                    rec.get("entity_type", ""),
                    rec.get("policy_applied", ""),
                    rec.get("confidence", ""),
                ),
            )
        self.info_var.set(
            f"Last {len(records)} records shown | total={self.bridge.service.audit.record_count}"
        )

    def verify(self) -> None:
        from tkinter import messagebox

        valid, expected, count = self.bridge.verify_chain()
        self.info_var.set(
            f"verify {'INTACT' if valid else 'MISMATCH'} | {count} records | root {expected[:16]}..."
        )
        messagebox.showinfo(
            "Audit chain verification",
            f"Status: {'INTACT' if valid else 'MISMATCH'}\n"
            f"records: {count}\n"
            f"expected root: {expected}",
            parent=self,
        )

    def show(self) -> None:
        self.transient(self.master)
        self.lift()
