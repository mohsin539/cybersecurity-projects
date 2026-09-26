"""Simple picker dialog for recently opened files."""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk


class RecentDialog(tk.Toplevel):
    """List recalled file paths; let the user pick one to reopen."""

    def __init__(self, master, recents: list[str], theme: dict) -> None:
        super().__init__(master)
        self.title("Recent Files")
        self._theme = theme
        self._result = None
        self.geometry("560x340")
        self.configure(bg=theme["bg"])
        self._build(recents)
        self.transient(master)
        self.grab_set()

    def _build(self, recents: list[str]) -> None:
        ttk.Label(self, text="Select a file to reopen:").pack(anchor="w", padx=8, pady=6)
        self.listbox = tk.Listbox(
            self, font=("Consolas", 10), bg=self._theme["text_bg"], fg=self._theme["fg"]
        )
        for path in recents:
            self.listbox.insert("end", path)
        if recents:
            self.listbox.selection_set(0)
        self.listbox.pack(fill="both", expand=True, padx=8)
        btn = ttk.Frame(self, padding=8)
        btn.pack(fill="x")
        ttk.Button(btn, text="Open", command=self._pick).pack(side="right")
        ttk.Button(btn, text="Cancel", command=self.destroy).pack(side="right", padx=4)

    def _pick(self) -> None:
        sel = self.listbox.curselection()
        if sel:
            self._result = self.listbox.get(sel[0])
        self.destroy()

    def pick(self) -> str | None:
        self.wait_window()
        return self._result
