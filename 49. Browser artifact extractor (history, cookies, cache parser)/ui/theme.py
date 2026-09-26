"""Colour palette and ttk theme configuration.

A single source of truth for the visual language: an indigo/cyan forensic
console with high-contrast, accessible text and category colour accents.
"""
from __future__ import annotations

import tkinter as tk
from tkinter import ttk

C = {
    "bg": "#0b1220",
    "sidebar": "#0f172a",
    "sidebar_alt": "#1e293b",
    "surface": "#ffffff",
    "surface_alt": "#f8fafc",
    "surface2": "#f1f5f9",
    "border": "#e2e8f0",
    "text": "#0f172a",
    "muted": "#64748b",
    "muted2": "#94a3b8",
    "accent": "#4f46e5",
    "accent_hover": "#4338ca",
    "accent_soft": "#eef2ff",
    "secondary": "#06b6d4",
    "secondary_hover": "#0891b2",
    "success": "#10b981",
    "success_hover": "#059669",
    "warning": "#f59e0b",
    "danger": "#ef4444",
    "danger_hover": "#dc2626",
    "purple": "#8b5cf6",
    "pink": "#ec4899",
    "teal": "#14b8a6",
    "white": "#ffffff",
}

# Colour accents for each artifact category (used by nav, tables, badges).
CATEGORY_COLORS = {
    "history": "#6366f1",
    "downloads": "#0ea5e9",
    "cookies": "#f59e0b",
    "bookmarks": "#10b981",
    "autofill": "#8b5cf6",
    "logins": "#ef4444",
    "search_terms": "#14b8a6",
    "cache": "#ec4899",
    "evidence": "#0f172a",
    "compliance": "#7c3aed",
    "audit": "#334155",
    "overview": "#4f46e5",
}

CATEGORY_ICONS = {
    "overview": "\u25a6",
    "history": "\u2318",
    "downloads": "\u21e9",
    "cookies": "\u25cf",
    "bookmarks": "\u2605",
    "autofill": "\u270e",
    "logins": "\u26bf",
    "search_terms": "\u2315",
    "cache": "\u25a3",
    "evidence": "\u26c1",
    "compliance": "\u2696",
    "audit": "\u2261",
}

FONT = "Segoe UI"
FONT_MONO = "Consolas"


def apply_theme(root: tk.Tk) -> ttk.Style:
    style = ttk.Style(root)
    try:
        style.theme_use("clam")
    except tk.TclError:
        pass

    root.configure(bg=C["surface2"])
    root.option_add("*Font", (FONT, 10))

    # Frames / labels
    style.configure("TFrame", background=C["surface2"])
    style.configure("Surface.TFrame", background=C["surface"])
    style.configure("Sidebar.TFrame", background=C["sidebar"])
    style.configure("TLabel", background=C["surface2"], foreground=C["text"], font=(FONT, 10))
    style.configure("Surface.TLabel", background=C["surface"], foreground=C["text"])
    style.configure("Muted.TLabel", background=C["surface"], foreground=C["muted"], font=(FONT, 9))
    style.configure("MutedBg.TLabel", background=C["surface2"], foreground=C["muted"], font=(FONT, 9))
    style.configure("H1.TLabel", background=C["surface2"], foreground=C["text"], font=(FONT, 16, "bold"))
    style.configure("H2.TLabel", background=C["surface"], foreground=C["text"], font=(FONT, 13, "bold"))
    style.configure("SidebarTitle.TLabel", background=C["sidebar"], foreground=C["white"], font=(FONT, 12, "bold"))
    style.configure("SidebarSub.TLabel", background=C["sidebar"], foreground=C["muted2"], font=(FONT, 8))

    # Buttons
    def _btn(name, bg, fg, hover):
        style.configure(name, background=bg, foreground=fg, borderwidth=0,
                        focusthickness=0, padding=(14, 9), font=(FONT, 10, "bold"))
        style.map(name,
                  background=[("active", hover), ("pressed", hover), ("disabled", C["border"])],
                  foreground=[("disabled", C["muted2"])])

    _btn("Accent.TButton", C["accent"], C["white"], C["accent_hover"])
    _btn("Secondary.TButton", C["secondary"], C["white"], C["secondary_hover"])
    _btn("Success.TButton", C["success"], C["white"], C["success_hover"])
    _btn("Danger.TButton", C["danger"], C["white"], C["danger_hover"])
    _btn("Ghost.TButton", C["surface"], C["text"], C["surface2"])
    style.configure("Ghost.TButton", borderwidth=1, relief="solid")
    _btn("Sidebar.TButton", C["sidebar_alt"], C["white"], C["accent"])

    style.configure("TCheckbutton", background=C["surface"], foreground=C["text"], font=(FONT, 10))
    style.map("TCheckbutton", background=[("active", C["surface"])])
    style.configure("Sidebar.TCheckbutton", background=C["sidebar"], foreground=C["white"])
    style.map("Sidebar.TCheckbutton", background=[("active", C["sidebar"])])

    # Inputs
    style.configure("TEntry", padding=6, fieldbackground=C["surface"],
                    bordercolor=C["border"], lightcolor=C["border"], darkcolor=C["border"])
    style.configure("TCombobox", padding=5)
    style.configure("TSpinbox", padding=5)

    # Notebook
    style.configure("TNotebook", background=C["surface2"], borderwidth=0, tabmargins=(6, 6, 6, 0))
    style.configure("TNotebook.Tab", background=C["surface2"], foreground=C["muted"],
                    padding=(18, 10), font=(FONT, 10, "bold"), borderwidth=0)
    style.map("TNotebook.Tab",
              background=[("selected", C["surface"])],
              foreground=[("selected", C["accent"])],
              expand=[("selected", (0, 0, 0, 0))])

    # Treeview
    style.configure("Treeview", background=C["surface"], fieldbackground=C["surface"],
                    foreground=C["text"], rowheight=26, borderwidth=0, font=(FONT, 9))
    style.configure("Treeview.Heading", background=C["sidebar"], foreground=C["white"],
                    font=(FONT, 9, "bold"), borderwidth=0, padding=(8, 8), relief="flat")
    style.map("Treeview.Heading", background=[("active", C["accent"])])
    style.map("Treeview", background=[("selected", C["accent"])],
              foreground=[("selected", C["white"])])

    # Progressbar
    style.configure("Horizontal.TProgressbar", background=C["accent"],
                    troughcolor=C["surface2"], borderwidth=0, thickness=16)
    style.configure("Success.Horizontal.TProgressbar", background=C["success"],
                    troughcolor=C["surface2"], borderwidth=0, thickness=16)

    # Scrollbars
    style.configure("Vertical.TScrollbar", background=C["border"], troughcolor=C["surface"],
                    borderwidth=0, arrowsize=14, gripcount=0)
    style.map("Vertical.TScrollbar", background=[("active", C["muted2"])])

    # Paned / Separator / Scale
    style.configure("TSeparator", background=C["border"])
    style.configure("TScale", background=C["surface"])
    return style
