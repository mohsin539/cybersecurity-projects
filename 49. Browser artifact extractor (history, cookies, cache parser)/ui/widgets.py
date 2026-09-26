"""Reusable, colourised Tkinter widgets."""
from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Callable, List, Optional, Sequence

from . import theme
from .theme import C


def _hex_shift(hex_color: str, factor: float) -> str:
    """Lighten (factor>0) or darken (factor<0) a hex colour."""
    hex_color = hex_color.lstrip("#")
    r, g, b = (int(hex_color[i:i + 2], 16) for i in (0, 2, 4))
    if factor >= 0:
        r = int(r + (255 - r) * factor)
        g = int(g + (255 - g) * factor)
        b = int(b + (255 - b) * factor)
    else:
        r, g, b = (int(v * (1 + factor)) for v in (r, g, b))
    return f"#{r:02x}{g:02x}{b:02x}"


class StatCard(tk.Frame):
    """A rounded-feeling KPI card with a coloured accent bar."""

    def __init__(self, master, label: str, value: str = "0",
                 color: str = C["accent"], width: int = 170, **kw):
        super().__init__(master, bg=C["surface"], highlightthickness=1,
                         highlightbackground=C["border"], **kw)
        bar = tk.Frame(self, bg=color, height=5)
        bar.pack(fill="x")
        inner = tk.Frame(self, bg=C["surface"])
        inner.pack(fill="both", expand=True, padx=14, pady=12)
        self._value = tk.Label(inner, text=value, bg=C["surface"], fg=color,
                               font=(theme.FONT, 20, "bold"))
        self._value.pack(anchor="w")
        tk.Label(inner, text=label.upper(), bg=C["surface"], fg=C["muted"],
                 font=(theme.FONT, 8, "bold")).pack(anchor="w")

    def set(self, value) -> None:
        self._value.configure(text=str(value))


class Badge(tk.Label):
    def __init__(self, master, text: str, color: str = C["accent"], **kw):
        super().__init__(master, text=f" {text} ", bg=color, fg=C["white"],
                         font=(theme.FONT, 8, "bold"), padx=6, pady=2, **kw)


class ArtifactTable(ttk.Frame):
    """Searchable, sortable Treeview bound to one artifact category."""

    def __init__(self, master, headers: Sequence[str], color: str = C["accent"],
                 on_select: Optional[Callable] = None, **kw):
        super().__init__(master, style="Surface.TFrame", **kw)
        self.color = color
        self.headers = list(headers)
        self._raw: List[List] = []
        self._sort_col: Optional[str] = None
        self._sort_desc = False
        self._on_select = on_select

        # Toolbar
        bar = tk.Frame(self, bg=C["surface"])
        bar.pack(fill="x", padx=10, pady=(10, 6))
        tk.Label(bar, text="\u2315", bg=C["surface"], fg=color,
                 font=(theme.FONT, 12, "bold")).pack(side="left")
        self.var_search = tk.StringVar()
        entry = ttk.Entry(bar, textvariable=self.var_search, width=34)
        entry.pack(side="left", padx=8)
        self.var_search.trace_add("write", lambda *_: self._apply_filter())
        ttk.Button(bar, text="Clear", style="Ghost.TButton",
                   command=self._clear).pack(side="left")
        self.lbl_count = tk.Label(bar, text="0 records", bg=C["surface"],
                                  fg=C["muted"], font=(theme.FONT, 9, "bold"))
        self.lbl_count.pack(side="right")
        tk.Label(bar, text="Filter:", bg=C["surface"], fg=C["muted"],
                 font=(theme.FONT, 9)).pack(side="left")

        # Table
        wrap = tk.Frame(self, bg=C["surface"])
        wrap.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        self.tree = ttk.Treeview(wrap, columns=self.headers, show="headings",
                                 selectmode="extended")
        vsb = ttk.Scrollbar(wrap, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(wrap, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        wrap.rowconfigure(0, weight=1)
        wrap.columnconfigure(0, weight=1)

        for h in self.headers:
            self.tree.heading(h, text=h, command=lambda c=h: self._sort_by(c))
        self.tree.tag_configure("odd", background=C["surface"])
        self.tree.tag_configure("even", background=C["surface_alt"])
        self.tree.tag_configure("accent", foreground=color)
        self.tree.bind("<<TreeviewSelect>>", self._selected)

        self.tree.tag_configure("secret_ok", foreground=C["success"])
        self.tree.tag_configure("secret_no", foreground=C["warning"])

    # -- data ---------------------------------------------------------------
    def load(self, rows: List[Sequence]) -> None:
        self._raw = [list(r) for r in rows]
        self._render(self._raw)

    def _render(self, rows: List[List]) -> None:
        self.tree.delete(*self.tree.get_children())
        for idx, row in enumerate(rows):
            tag = "even" if idx % 2 else "odd"
            vals = ["" if v is None else v for v in row]
            self.tree.insert("", "end", values=vals, tags=(tag,))
        self._autosize(rows)
        self.lbl_count.configure(text=f"{len(rows):,} of {len(self._raw):,} records")

    def _autosize(self, rows: List[List]) -> None:
        for i, header in enumerate(self.headers):
            width = max(len(str(header)) + 4, 12)
            for row in rows[:300]:
                if i < len(row):
                    width = max(width, min(len(str(row[i])) + 2, 60))
            self.tree.column(header, width=width * 7, minwidth=70, stretch=False)

    def _apply_filter(self) -> None:
        needle = self.var_search.get().lower().strip()
        if not needle:
            self._render(self._raw)
            return
        filtered = [r for r in self._raw if any(needle in str(v).lower() for v in r)]
        self._render(filtered)

    def _clear(self) -> None:
        self.var_search.set("")

    def _sort_by(self, col: str) -> None:
        try:
            idx = self.headers.index(col)
        except ValueError:
            return
        if self._sort_col == col:
            self._sort_desc = not self._sort_desc
        else:
            self._sort_col, self._sort_desc = col, False

        def key(row):
            v = row[idx] if idx < len(row) else ""
            if isinstance(v, (int, float)):
                return (0, v)
            return (1, str(v).lower())

        rows = sorted(self._raw, key=key, reverse=self._sort_desc)
        self._render(rows)
        arrow = " \u25bc" if self._sort_desc else " \u25b2"
        for h in self.headers:
            self.tree.heading(h, text=h + (arrow if h == col else ""))

    def _selected(self, _event=None) -> None:
        if self._on_select:
            sel = self.tree.selection()
            if sel:
                self._on_select(self.tree.item(sel[0], "values"))

    def rows(self) -> List[List]:
        return list(self._raw)


class SidebarNav(tk.Frame):
    """Vertical navigation with coloured active indicator."""

    def __init__(self, master, items, command: Callable[[str], None], **kw):
        super().__init__(master, bg=C["sidebar"], **kw)
        self.command = command
        self.buttons = {}
        self.active = None
        title = tk.Frame(self, bg=C["sidebar"])
        title.pack(fill="x", padx=16, pady=(18, 4))
        tk.Label(title, text="\U0001f6e1  BAE Console", bg=C["sidebar"], fg=C["white"],
                 font=(theme.FONT, 12, "bold")).pack(anchor="w")
        tk.Label(title, text="Browser Artifact Extractor", bg=C["sidebar"],
                 fg=C["muted2"], font=(theme.FONT, 8)).pack(anchor="w")
        tk.Frame(self, bg=C["sidebar_alt"], height=1).pack(fill="x", padx=12, pady=12)

        for key, label in items:
            color = theme.CATEGORY_COLORS.get(key, C["accent"])
            icon = theme.CATEGORY_ICONS.get(key, "\u2022")
            row = tk.Frame(self, bg=C["sidebar"], cursor="hand2")
            row.pack(fill="x", padx=10, pady=1)
            indicator = tk.Frame(row, bg=C["sidebar"], width=4)
            indicator.pack(side="left", fill="y")
            lbl = tk.Label(row, text=f"  {icon}  {label}", bg=C["sidebar"], fg=C["muted2"],
                           font=(theme.FONT, 10), anchor="w", padx=8, pady=8)
            lbl.pack(side="left", fill="x", expand=True)
            for widget in (row, lbl):
                widget.bind("<Button-1>", lambda e, k=key: self.command(k))
                widget.bind("<Enter>", lambda e, r=row, l=lbl, k=key: self._hover(r, l, k, True))
                widget.bind("<Leave>", lambda e, r=row, l=lbl, k=key: self._hover(r, l, k, False))
            self.buttons[key] = (row, indicator, lbl, color)

    def _hover(self, row, lbl, key, entering: bool) -> None:
        if self.active == key:
            return
        bg = C["sidebar_alt"] if entering else C["sidebar"]
        fg = C["white"] if entering else C["muted2"]
        row.configure(bg=bg)
        lbl.configure(bg=bg, fg=fg)

    def set_active(self, key: str) -> None:
        self.active = key
        for k, (row, indicator, lbl, color) in self.buttons.items():
            if k == key:
                row.configure(bg=C["sidebar_alt"])
                lbl.configure(bg=C["sidebar_alt"], fg=C["white"],
                              font=(theme.FONT, 10, "bold"))
                indicator.configure(bg=color)
            else:
                row.configure(bg=C["sidebar"])
                lbl.configure(bg=C["sidebar"], fg=C["muted2"], font=(theme.FONT, 10))
                indicator.configure(bg=C["sidebar"])
