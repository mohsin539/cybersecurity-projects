"""Password-protected gate dialog.

Controls: A07 (no default credentials), NIST IA-5 / AC-7 (PBKDF2 + lockout),
ISO A.9. Two modes:
  - create : first run - mandates a strong master password (the vault secret).
  - login  : successful AES-GCM/ PBKDF2 unlock unwraps the data key.
"""
from __future__ import annotations

import tkinter as tk
from tkinter import ttk, messagebox
from typing import Optional, Tuple

from ..sec import constants as C
from ..sec.identity import AuthError, IdentityStore

_STYLED = False


def _ensure_styles():
    global _STYLED
    if _STYLED:
        return
    s = ttk.Style()
    s.configure("App.TFrame", background="#101820")
    s.configure("App.TLabel", background="#101820", foreground="#e8eef2")
    s.configure("Err.TLabel", background="#101820", foreground="#ff8f8f")
    _STYLED = True


class GateDialog(tk.Toplevel):
    RESULT_CREATE = "create"
    RESULT_LOGIN = "login"

    def __init__(self, master=None, mode: str = "login"):
        super().__init__(master)
        self.mode = mode
        self.username = ""
        self.password = ""
        self.result = ""
        self.configure(bg="#101820")
        _ensure_styles()
        self.title("First-run setup" if mode == "create" else "Phishing Email Analyzer - Unlock")
        self.resizable(False, False)
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self.grab_set()
        self._build()
        self._center()
        self.bind("<Return>", lambda e: self._submit())
        self.focus_force()

    def _center(self):
        self.update_idletasks()
        w, h = self.winfo_reqwidth(), self.winfo_reqheight()
        x = (self.winfo_screenwidth() - w) // 2
        y = (self.winfo_screenheight() - h) // 3
        self.geometry(f"+{x}+{y}")

    def _build(self):
        pad = {"padx": 18, "pady": 8}
        ttk.Label(self, text=("Create vault profile" if self.mode == "create" else "Authenticate"),
                  font=("Segoe UI", 14, "bold"), foreground="#7fd4a0", background="#101820").pack(**pad)
        ttk.Label(self, text=(
            "First run: you must set the master password.\n"
            f"Policy: >= {C.MIN_PASSWORD_LEN} chars; PBKDF2-HMAC-SHA256 (600k) + AES-256-GCM."
            if self.mode == "create" else
            "Unlock encrypts/decrypts the local vault. Failed attempts trigger lockout."),
            background="#101820", foreground="#9fb4c7").pack(padx=18, pady=2)

        f = ttk.Frame(self, style="App.TFrame")
        f.pack(padx=18, pady=10)
        ttk.Label(f, text="Analyst:", style="App.TLabel").grid(row=0, column=0, sticky="e", padx=6, pady=3)
        self.e_user = ttk.Entry(f, width=28)
        self.e_user.grid(row=0, column=1, pady=3)

        ttk.Label(f, text="Password:", style="App.TLabel").grid(row=1, column=0, sticky="e", padx=6, pady=3)
        self.e_pass = ttk.Entry(f, width=28, show="*")
        self.e_pass.grid(row=1, column=1, pady=3)

        if self.mode == "create":
            ttk.Label(f, text="Confirm:", style="App.TLabel").grid(row=2, column=0, sticky="e", padx=6, pady=3)
            self.e_confirm = ttk.Entry(f, width=28, show="*")
            self.e_confirm.grid(row=2, column=1, pady=3)

        self.l_status = ttk.Label(self, text="", style="Err.TLabel", background="#101820")
        self.l_status.pack(pady=2)
        ttk.Button(self, text="Unlock" if self.mode == "login" else "Create profile",
                   command=self._submit).pack(pady=10)
        ttk.Button(self, text="Exit", command=self._on_close).pack(pady=(0, 12))

    def _submit(self):
        name = (self.e_user.get() or "").strip().lower()
        pw = self.e_pass.get()
        if self.mode == "create":
            cw = self.e_confirm.get()
            if not name:
                return self._err("enter an analyst name")
            if len(pw) < C.MIN_PASSWORD_LEN:
                return self._err(f"password must be >= {C.MIN_PASSWORD_LEN} chars")
            if pw != cw:
                return self._err("passwords do not match")
        elif not name or not pw:
            return self._err("name and password required")
        self.username, self.password = name, pw
        self.result = self.RESULT_CREATE if self.mode == "create" else self.RESULT_LOGIN
        self.destroy()

    def _err(self, msg: str):
        self.l_status.config(text=msg)
        self.bell()

    def _on_close(self):
        self.result = ""
        self.destroy()


class Gate:
    """Performs identity operations; returns a session payload."""

    def __init__(self, root: tk.Tk, store: IdentityStore):
        self.root = root
        self.store = store

    def run(self) -> Optional[Tuple[str, str, bytes, str]]:
        """Returns (username, role, data_key, password) or None (cancelled)."""
        while True:
            mode = "create" if self.store.is_empty() else "login"
            dlg = GateDialog(master=self.root, mode=mode)
            self.root.wait_window(dlg)
            if not dlg.result:
                return None
            try:
                if dlg.result == GateDialog.RESULT_CREATE:
                    pub = self.store.create_profile(dlg.username, dlg.password, role="admin")
                    return (pub["username"], pub["role"], bytes(self.store.data_key), dlg.password)
                pub, data_key = self.store.authenticate(dlg.username, dlg.password)
                return (pub["username"], pub["role"], bytes(data_key), dlg.password)
            except AuthError as exc:
                messagebox.showerror("Authentication", str(exc), parent=self.root)
        return None