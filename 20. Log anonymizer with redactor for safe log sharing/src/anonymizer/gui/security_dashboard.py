"""Security framework compliance dashboard (OWASP / NIST / ISO 27001)."""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk

from ..gui.framework import ALL_CONTROLS, status_summary


class SecurityDashboard(tk.Toplevel):
    """Read-only view of which control each feature implements."""

    def __init__(self, master, theme: dict) -> None:
        super().__init__(master)
        self.title("Security Framework Dashboard")
        self._theme = theme
        self.geometry("860x520")
        self.configure(bg=theme["bg"])
        self._build()

    def _build(self) -> None:
        summary = status_summary()
        header = "Implementation status across security frameworks: " + " | ".join(
            f"{k} {v}" for k, v in summary.items()
        )
        ttk.Label(self, text=header).pack(fill="x", padx=8, pady=(8, 4))

        notebook = ttk.Notebook(self)
        notebook.pack(fill="both", expand=True, padx=8, pady=4)

        for frame_name, controls in ALL_CONTROLS:
            tab = ttk.Frame(notebook)
            notebook.add(tab, text=frame_name)
            cols = ("id", "control", "status", "component")
            tree = ttk.Treeview(tab, columns=cols, show="headings")
            for col, width, anchor in (
                ("id", 70, "center"),
                ("control", 200, "w"),
                ("status", 150, "center"),
                ("component", 420, "w"),
            ):
                tree.heading(col, text=col.upper())
                tree.column(col, width=width, anchor=anchor, stretch=True)
            for control in controls:
                tree.insert(
                    "",
                    "end",
                    values=(
                        control["id"],
                        control["control"],
                        control["status"],
                        control["component"],
                    ),
                )
            scroll = ttk.Scrollbar(tab, orient="vertical", command=tree.yview)
            tree.configure(yscrollcommand=scroll.set)
            tree.pack(side="left", fill="both", expand=True)
            scroll.pack(side="right", fill="y")

        ttk.Button(self, text="Close", command=self.destroy).pack(pady=(0, 8))

    def show(self) -> None:
        self.transient(self.master)
        self.grab_set()
        self.lift()
