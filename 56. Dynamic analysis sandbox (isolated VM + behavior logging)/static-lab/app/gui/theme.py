"""Dark "pro" theme for the StaticLab GUI using ttk styles."""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk

BG = "#0f1420"
PANEL = "#161d2d"
INPUT = "#0c101c"
LINE = "#243049"
FG = "#d7e0f2"
DIM = "#8fa0bd"
ACCENT = "#38bdf8"
ACCENT2 = "#818cf8"
GOOD = "#2ea043"
WARN = "#e08a00"
BAD = "#d1242f"
CHIP = "#31415e"
HEADER = "#1e2a44"


def apply(root: tk.Tk) -> ttk.Style:
    style = ttk.Style(root)
    try:
        style.theme_use("clam")
    except Exception:  # noqa: BLE001
        pass
    style.configure(".", background=BG, foreground=FG, fieldbackground=INPUT, bordercolor=LINE)
    style.configure("TFrame", background=BG)
    style.configure("Panel.TFrame", background=PANEL)
    style.configure("TLabel", background=BG, foreground=FG)
    style.configure("Panel.TLabel", background=PANEL, foreground=FG)
    style.configure("Dim.TLabel", background=BG, foreground=DIM)
    style.configure("Title.TLabel", background=BG, foreground=ACCENT, font=("Segoe UI", 16, "bold"))
    style.configure("H1.TLabel", background=BG, foreground=FG, font=("Segoe UI", 13, "bold"))

    style.configure("TButton", background=HEADER, foreground=FG, bordercolor=LINE, padding=(12, 6), focuscolor=HEADER)
    style.map("TButton", background=[("active", ACCENT), ("pressed", "#0ea5c2")], foreground=[("active", "#0b1020")])
    style.configure("Accent.TButton", background=ACCENT, foreground="#0b1020", bordercolor=ACCENT, padding=(12, 6))
    style.map("Accent.TButton", background=[("active", "#7dd3fc")], foreground=[("active", "#0b1020")])

    style.configure("TEntry", fieldbackground=INPUT, foreground=FG, bordercolor=LINE, insertcolor=FG)
    style.configure("TCombobox", fieldbackground=INPUT, foreground=FG, background=INPUT, arrowcolor=DIM)
    style.configure("TCheckbutton", background=BG, foreground=FG, focuscolor=BG)

    style.configure("Horizontal.TProgressbar", background=ACCENT, troughcolor=INPUT, bordercolor=LINE, lightcolor=ACCENT, darkcolor=ACCENT)

    style.configure("Treeview", background=PANEL, fieldbackground=PANEL, foreground=FG, bordercolor=LINE, rowheight=24)
    style.map("Treeview", background=[("selected", ACCENT)], foreground=[("selected", "#0b1020")])
    style.configure("Treeview.Heading", background=HEADER, foreground="#9db4dd", font=("Segoe UI", 9, "bold"))

    style.configure("flat.TNotebook", background=BG, borderwidth=0)
    style.configure("flat.TNotebook.Tab", background=PANEL, foreground=DIM, padding=(16, 7))
    style.map("flat.TNotebook.Tab", background=[("selected", ACCENT)], foreground=[("selected", "#0b1020")])

    for w in ("TText",):
        style.configure(w, background=PANEL, foreground=FG, bordercolor=LINE, insertcolor=FG)
    return style