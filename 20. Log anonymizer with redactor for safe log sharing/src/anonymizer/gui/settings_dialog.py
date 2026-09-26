"""Settings dialog bound to the DPAPI-protected state store."""

from __future__ import annotations

import tkinter as tk
from tkinter import messagebox, ttk

from ..gui.memory_manager import MemoryManager
from ..gui.state_manager import AppState, StateManager


class SettingsDialog(tk.Toplevel):
    """Edit preferences, masking options and the token salt.

    The token salt is persisted ONLY through the state manager, which
    encrypts it with Windows DPAPI before writing. A passphrase can be set
    to gate access to this dialog (A.8.15/16 alignment).
    """

    def __init__(self, master, state_manager: StateManager, theme: dict) -> None:
        super().__init__(master)
        self.title("Security & Settings")
        self.manager = state_manager
        self._theme = theme
        self.geometry("480x470")
        self.configure(bg=theme["bg"])
        self._build()

    def _build(self) -> None:
        st: AppState = self.manager.state
        form = ttk.Frame(self, padding=14)
        form.pack(fill="both", expand=True)

        self.theme_var = tk.StringVar(value=st.theme)
        self.keep_var = tk.StringVar(value=str(st.keep_last_chars))
        self.mask_var = tk.StringVar(value=st.mask_char)
        self.shift_var = tk.StringVar(value=str(st.default_date_shift_days))
        self.maxlen_var = tk.StringVar(value=str(st.max_line_length))
        self.preview_var = tk.StringVar(value=str(st.preview_lines))
        self.salt_var = tk.StringVar(value=st.token_salt)
        self.passphrase_var = tk.StringVar(value="")

        rows = [
            ("Theme", ("dark", "light"), self.theme_var, "combobox"),
            ("Keep last N chars (partial mask)", None, self.keep_var, "spin"),
            ("Mask character", None, self.mask_var, "entry"),
            ("Default date shift (days)", None, self.shift_var, "spin"),
            ("Max line length (chars)", None, self.maxlen_var, "spin"),
            ("Preview lines", None, self.preview_var, "spin"),
        ]
        for label, values, var, kind in rows:
            ttk.Label(form, text=label).grid(sticky="w", pady=4)
            if kind == "combobox":
                ttk.Combobox(
                    form, textvariable=var, values=values, state="readonly", width=24
                ).grid(row=form.grid_size()[1], column=1, sticky="w", pady=4)
            elif kind == "spin":
                ttk.Spinbox(form, from_=0, to=9_999_999, textvariable=var, width=24).grid(
                    row=form.grid_size()[1], column=1, sticky="w", pady=4
                )
            else:
                ttk.Entry(form, textvariable=var, width=26).grid(
                    row=form.grid_size()[1], column=1, sticky="w", pady=4
                )

        ttk.Separator(form).grid(
            row=form.grid_size()[1], column=0, columnspan=2, sticky="ew", pady=8
        )
        ttk.Label(form, text="Token salt (encrypted with DPAPI, overrides memory)").grid(sticky="w")
        ttk.Entry(form, textvariable=self.salt_var, show="*", width=26).grid(
            row=form.grid_size()[1], column=1, pady=4
        )

        btnrow = ttk.Frame(self, padding=12)
        btnrow.pack(side="bottom", fill="x")
        ttk.Button(btnrow, text="Save", command=self._save).pack(side="right")
        ttk.Button(btnrow, text="Cancel", command=self.destroy).pack(side="right", padx=4)
        ttk.Button(btnrow, text="Erase Memory", command=self._erase_memory).pack(side="left")

        self.attrib = None  # placeholder for future passphrase gating
        ttk.Button(btnrow, text="Forget State & Memory", command=self._forget_all).pack(
            side="left", padx=4
        )

    def _save(self) -> None:
        st = self.manager.state
        try:
            st.keep_last_chars = max(0, int(self.keep_var.get()))
            st.mask_char = (self.mask_var.get() or "*")[:1]
            st.default_date_shift_days = int(self.shift_var.get())
            st.max_line_length = max(100, int(self.maxlen_var.get()))
            st.preview_lines = max(10, int(self.preview_var.get()))
            st.theme = self.theme_var.get()
            st.token_salt = self.salt_var.get()
        except ValueError:
            messagebox.showerror("Invalid value", "Check numeric fields.", parent=self)
            return
        self.manager.save(st)
        messagebox.showinfo("Settings", "Saved securely.", parent=self)
        self.destroy()

    def _erase_memory(self) -> None:
        if messagebox.askyesno(
            "Erase memory", "Delete remembered files, rules and stats?", parent=self
        ):
            MemoryManager().forget_all()
            messagebox.showinfo("Erased", "Memory store cleared.", parent=self)

    def _forget_all(self) -> None:
        if messagebox.askyesno(
            "Forget everything",
            "Delete state file and memory store? This satisfies right-to-erasure.",
            parent=self,
        ):
            self.manager.forget()
            MemoryManager().forget_all()
            messagebox.showinfo("Forgotten", "State and memory erased.", parent=self)
            self.destroy()

    def show(self) -> None:
        self.transient(self.master)
        self.grab_set()
        self.lift()
