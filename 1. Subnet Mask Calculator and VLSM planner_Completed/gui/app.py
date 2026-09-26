"""Tkinter GUI (architecture.md section 8).

Three tabs, mirroring the web architecture:
  1. Calculator — live subnet details as you type (no submit button).
  2. VLSM Planner — base network + editable requirement table + results.
  3. Visualizer — 32-bit mask grid + VLSM address-space bar.

Only this package imports tkinter; domain/ stays pure.
"""
from __future__ import annotations

import tkinter as tk
from tkinter import ttk

from domain import (VLSMRequirement, describe, parse_ipv4,
                    parse_prefix, plan_vlsm)
from domain import formatter as fmt
from state import load_state, save_state

BG = "#0f172a"        # slate-900
PANEL = "#1e293b"     # slate-800
PANEL_LIGHT = "#273449"
FG = "#e2e8f0"        # slate-200
MUTED = "#94a3b8"     # slate-400
ACCENT = "#38bdf8"    # sky-400
GREEN = "#4ade80"
RED = "#f87171"
AMBER = "#fbbf24"
NETWORK_BIT = "#38bdf8"
HOST_BIT = "#334155"

MONO = ("Consolas", 11)
MONO_SMALL = ("Consolas", 10)
LABEL = ("Segoe UI", 10)
LABEL_BOLD = ("Segoe UI", 10, "bold")
TITLE = ("Segoe UI", 15, "bold")
TABLE_ROW = ("Consolas", 10)


def _clear(widget: tk.Widget) -> None:
    for child in widget.winfo_children():
        child.destroy()


def _grid_rows(parent: tk.Widget, rows: list[tuple[str, str]],
               highlight_first: bool = True) -> None:
    """Render a definition-list of label/value rows inside `parent`."""
    _clear(parent)
    for i, (label, value) in enumerate(rows):
        lbl = tk.Label(parent, text=label, anchor="w", bg=PANEL, fg=MUTED,
                       font=LABEL)
        val = tk.Label(parent, text=value, anchor="w", bg=PANEL,
                       fg=ACCENT if (highlight_first and i == 0) else FG,
                       font=MONO)
        lbl.grid(row=i, column=0, sticky="ew", padx=(12, 6), pady=3)
        val.grid(row=i, column=1, sticky="ew", padx=(6, 12), pady=3)
    parent.grid_columnconfigure(1, weight=1)


class Tooltip:
    """Minimal hover tooltip for field explanations."""

    def __init__(self, widget: tk.Widget, text: str) -> None:
        self._widget = widget
        self._text = text
        self._tip: tk.Toplevel | None = None
        widget.bind("<Enter>", self._show)
        widget.bind("<Leave>", self._hide)

    def _show(self, _event: tk.Event) -> None:
        if self._tip is not None:
            return
        x = self._widget.winfo_rootx() + 20
        y = self._widget.winfo_rooty() + self._widget.winfo_height() + 4
        self._tip = tw = tk.Toplevel(self._widget)
        tw.wm_overrideredirect(True)
        tw.wm_geometry(f"+{x}+{y}")
        tk.Label(tw, text=self._text, bg="#0b1220", fg=MUTED,
                 font=LABEL, padx=8, pady=4,
                 relief="solid", bd=1).pack()

    def _hide(self, _event: tk.Event) -> None:
        if self._tip is not None:
            self._tip.destroy()
            self._tip = None


class App(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("Subnet Mask Calculator & VLSM Planner")
        self.geometry("980x760")
        self.minsize(880, 680)
        self.configure(bg=BG)

        self._state = load_state()
        self._requirements: list[VLSMRequirement] = self._read_requirements()

        header = tk.Label(self, text="Subnet Mask Calculator & VLSM Planner",
                          bg=BG, fg=FG, font=TITLE, anchor="w")
        header.pack(fill="x", padx=16, pady=(14, 4))

        self._tabs = ttk.Notebook(self)
        self._tabs.pack(fill="both", expand=True, padx=12, pady=(4, 10))
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("TNotebook.Tab", background=PANEL, foreground=MUTED,
                        padding=(16, 8))
        style.map("TNotebook.Tab", background=[("selected", ACCENT)],
                  foreground=[("selected", "#0b1220")])

        self._calc_tab = tk.Frame(self._tabs, bg=PANEL, bd=0)
        self._vlsm_tab = tk.Frame(self._tabs, bg=PANEL, bd=0)
        self._viz_tab = tk.Frame(self._tabs, bg=PANEL, bd=0)
        self._tabs.add(self._calc_tab, text="  Subnet Calculator  ")
        self._tabs.add(self._vlsm_tab, text="  VLSM Planner  ")
        self._tabs.add(self._viz_tab, text="  Visualizer  ")

        self._build_calc_tab()
        self._build_vlsm_tab()
        self._build_viz_tab()

        self._tabs.bind("<<NotebookTabChanged>>", self._on_tab_changed)
        self._restore_or_default()
        self._on_tab_changed()

    # ------------------------------------------------------------- state I/O
    def _read_requirements(self) -> list[VLSMRequirement]:
        raw = self._state.get("vlsm_requirements", [])
        result: list[VLSMRequirement] = []
        if isinstance(raw, list):
            for item in raw:
                if isinstance(item, dict):
                    result.append(VLSMRequirement(
                        name=str(item.get("name", "Subnet")),
                        hosts=_to_int(item.get("hosts"), 0)))
        return result or [VLSMRequirement("Sales", 50),
                          VLSMRequirement("Engineering", 25),
                          VLSMRequirement("Guest WiFi", 10)]

    def _collect_state(self) -> dict[str, object]:
        rows = getattr(self, "_req_rows", self._requirements)
        return {
            "calc_ip": self._calc_ip_var.get(),
            "calc_prefix": self._calc_prefix_var.get(),
            "vlsm_base_ip": self._vlsm_ip_var.get(),
            "vlsm_base_prefix": self._vlsm_prefix_var.get(),
            "vlsm_requirements": [
                {"name": row.name, "hosts": row.hosts} for row in rows
            ],
        }

    def save_now(self) -> None:
        try:
            save_state(self._collect_state())
        except tk.TclError:      # widgets already destroyed at shutdown
            pass

    # ---------------------------------------------------------- calculator tab
    def _build_calc_tab(self) -> None:
        tab = self._calc_tab

        form = tk.Frame(tab, bg=PANEL)
        form.pack(fill="x", padx=12, pady=(12, 6))

        ip_lbl = tk.Label(form, text="IPv4 address", bg=PANEL, fg=MUTED,
                          font=LABEL_BOLD)
        ip_lbl.grid(row=0, column=0, sticky="w", padx=(4, 6))
        self._calc_ip_var = tk.StringVar()
        self._calc_ip_entry = tk.Entry(form, textvariable=self._calc_ip_var,
                                       font=MONO, width=18, bg=PANEL_LIGHT,
                                       fg=FG, insertbackground=FG,
                                       relief="flat", highlightthickness=1,
                                       highlightbackground="#3b4a63",
                                       highlightcolor=ACCENT)
        self._calc_ip_entry.grid(row=0, column=1, sticky="w")
        Tooltip(self._calc_ip_entry,
                 "Any host address, e.g. 192.168.10.77 — the subnet is derived from it.")

        pre_lbl = tk.Label(form, text="Prefix / mask", bg=PANEL, fg=MUTED,
                           font=LABEL_BOLD)
        pre_lbl.grid(row=0, column=2, sticky="w", padx=(18, 6))
        self._calc_prefix_var = tk.StringVar()
        self._calc_prefix_entry = tk.Entry(form,
                                           textvariable=self._calc_prefix_var,
                                           font=MONO, width=14, bg=PANEL_LIGHT,
                                           fg=FG, insertbackground=FG,
                                           relief="flat", highlightthickness=1,
                                           highlightbackground="#3b4a63",
                                           highlightcolor=ACCENT)
        self._calc_prefix_entry.grid(row=0, column=3, sticky="w")
        Tooltip(self._calc_prefix_entry,
                 "CIDR like 26 or /26 — or a dotted mask like 255.255.255.192.")

        self._calc_error = tk.Label(tab, text="", bg=PANEL, fg=RED,
                                    font=LABEL, anchor="w")
        self._calc_error.pack(fill="x", padx=16)

        body = tk.Frame(tab, bg=PANEL)
        body.pack(fill="both", expand=True, padx=12, pady=(6, 12))

        left = tk.Frame(body, bg=PANEL)
        left.grid(row=0, column=0, sticky="nsew")
        right = tk.Frame(body, bg=PANEL)
        right.grid(row=0, column=1, sticky="nsew", padx=(12, 0))
        body.grid_columnconfigure(0, weight=3)
        body.grid_columnconfigure(1, weight=2)
        body.grid_rowconfigure(0, weight=1)

        self._calc_details = tk.Frame(left, bg=PANEL)
        self._calc_details.pack(fill="both", expand=True)

        self._calc_binary = tk.Label(right, text="", bg=PANEL, fg=MUTED,
                                     font=MONO_SMALL, anchor="nw",
                                     justify="left")
        self._calc_binary.pack(fill="x", pady=(2, 8))

        grid_holder = tk.Frame(right, bg=PANEL)
        grid_holder.pack(fill="x")
        self._mask_grid = MaskBitGrid(grid_holder, root=self)
        self._mask_grid.pack(fill="x")

        self._calc_meta = tk.Label(right, text="", bg=PANEL, fg=MUTED,
                                   font=LABEL, anchor="w", justify="left")
        self._calc_meta.pack(fill="x", pady=(10, 0))

        self._calc_ip_var.trace_add("write", lambda *_: self._recalc())
        self._calc_prefix_var.trace_add("write", lambda *_: self._recalc())

    def _recalc(self) -> None:
        ip_r = parse_ipv4(self._calc_ip_var.get())
        prefix_r = parse_prefix(self._calc_prefix_var.get())
        if ip_r.is_err():
            self._show_calc_error(ip_r.error)
            return
        if prefix_r.is_err():
            self._show_calc_error(prefix_r.error)
            return

        info = describe(ip_r.unwrap(), prefix_r.unwrap())
        self._calc_error.config(text="")
        _grid_rows(self._calc_details, [
            ("Network", info.network),
            ("Broadcast", info.broadcast),
            ("First host", info.first_host),
            ("Last host", info.last_host),
            ("Subnet mask", info.subnet_mask),
            ("Wildcard mask", info.wildcard_mask),
            ("Prefix", f"/{info.cidr}"),
            ("Total addresses", fmt.format_int(info.total_addresses)),
            ("Usable hosts", fmt.format_int(info.usable_hosts)),
            ("Class", info.ip_class),
            ("Scope", "Private" if info.is_private else "Public"),
            ("Hex IP", info.hex_ip),
        ])
        self._calc_binary.config(
            text="Mask bits:\n" + info.binary_mask)
        self._mask_grid.set_mask(info.cidr)
        self._calc_meta.config(
            text=f"Class {info.ip_class} · "
                 f"{'Private' if info.is_private else 'Public'} address · "
                 f"{fmt.format_int(info.usable_hosts)} usable hosts")

    def _show_calc_error(self, message: str) -> None:
        self._calc_error.config(text=f"⚠ {message}")

    # -------------------------------------------------------------- VLSM tab
    def _build_vlsm_tab(self) -> None:
        tab = self._vlsm_tab

        base = tk.Frame(tab, bg=PANEL)
        base.pack(fill="x", padx=12, pady=(12, 6))
        tk.Label(base, text="Base network", bg=PANEL, fg=MUTED,
                 font=LABEL_BOLD).grid(row=0, column=0, sticky="w", padx=(4, 6))
        self._vlsm_ip_var = tk.StringVar()
        tk.Entry(base, textvariable=self._vlsm_ip_var, font=MONO, width=18,
                 bg=PANEL_LIGHT, fg=FG, insertbackground=FG, relief="flat",
                 highlightthickness=1, highlightbackground="#3b4a63",
                 highlightcolor=ACCENT).grid(row=0, column=1, sticky="w")
        self._vlsm_prefix_var = tk.StringVar()
        tk.Entry(base, textvariable=self._vlsm_prefix_var, font=MONO, width=14,
                 bg=PANEL_LIGHT, fg=FG, insertbackground=FG, relief="flat",
                 highlightthickness=1, highlightbackground="#3b4a63",
                 highlightcolor=ACCENT).grid(row=0, column=2, sticky="w",
                                             padx=(10, 0))
        Tooltip(base.winfo_children()[1],
                 "Network you are dividing, e.g. 192.168.1.0 with prefix 24.")

        tk.Button(base, text="＋ Add subnet", font=LABEL, bd=0, bg=ACCENT,
                  fg="#0b1220", activebackground=ACCENT, cursor="hand2",
                  command=self._add_row).grid(row=0, column=3, sticky="e",
                                              padx=(18, 4))

        columns = ("name", "hosts", "cidr", "network", "mask", "broadcast",
                   "range", "util")
        self._req_tree = ttk.Treeview(tab, columns=columns, show="headings",
                                      height=6, selectmode="browse")
        headings = {"name": ("Requirement", 150, "w"),
                    "hosts": ("Hosts needed", 100, "e"),
                    "cidr": ("CIDR", 60, "center"),
                    "network": ("Network", 120, "w"),
                    "mask": ("Mask", 120, "w"),
                    "broadcast": ("Broadcast", 120, "w"),
                    "range": ("Host range", 210, "w"),
                    "util": ("Utilization", 90, "e")}
        for col, (text, width, anchor) in headings.items():
            self._req_tree.heading(col, text=text)
            self._req_tree.column(col, width=width, anchor=anchor)
        self._req_tree.pack(fill="both", expand=True, padx=12, pady=(4, 4))

        self._vlsm_error = tk.Label(tab, text="", bg=PANEL, fg=RED,
                                    font=LABEL, anchor="w")
        self._vlsm_error.pack(fill="x", padx=16)

        self._vlsm_summary = tk.Label(tab, text="", bg=PANEL, fg=MUTED,
                                      font=LABEL, anchor="w")
        self._vlsm_summary.pack(fill="x", padx=16, pady=(0, 8))

        actions = tk.Frame(tab, bg=PANEL)
        actions.pack(fill="x", padx=12, pady=(0, 12))
        tk.Button(actions, text="🗑 Remove selected", font=LABEL, bd=0,
                  bg=PANEL_LIGHT, fg=MUTED, activebackground=PANEL_LIGHT,
                  cursor="hand2",
                  command=self._remove_selected).pack(side="left")
        tk.Button(actions, text="Copy results", font=LABEL, bd=0,
                  bg=PANEL_LIGHT, fg=MUTED, cursor="hand2",
                  command=self._copy_results).pack(side="left", padx=8)
        tk.Button(actions, text="Save state", font=LABEL, bd=0,
                  bg=PANEL_LIGHT, fg=MUTED, cursor="hand2",
                  command=self.save_now).pack(side="left")

        self._vlsm_ip_var.trace_add("write", lambda *_: self._replan())
        self._vlsm_prefix_var.trace_add("write", lambda *_: self._replan())

    def _add_row(self) -> None:
        self._requirements.append(VLSMRequirement(f"Subnet {len(self._requirements) + 1}", 10))
        self._replan(save=False)

    def _remove_selected(self) -> None:
        sel = self._req_tree.selection()
        if not sel:
            return
        # Tree rows are in the sorted plan order; map back via the stored name.
        name = self._req_tree.item(sel[0], "values")[0]
        for i, req in enumerate(self._requirements):
            if req.name == name:
                del self._requirements[i]
                break
        self._replan(save=False)

    def _copy_results(self) -> None:
        lines: list[str] = []
        for item in self._req_tree.get_children():
            v = self._req_tree.item(item, "values")
            lines.append(",".join(str(x) for x in v))
        if lines:
            self.clipboard_clear()
            self.clipboard_append("\n".join(lines))

    def _replan(self, save: bool = True) -> None:
        ip_r = parse_ipv4(self._vlsm_ip_var.get())
        prefix_r = parse_prefix(self._vlsm_prefix_var.get())

        self._req_tree.delete(*self._req_tree.get_children())
        if ip_r.is_err() or prefix_r.is_err():
            for req in self._requirements:
                self._req_tree.insert("", "end", values=(
                    req.name, req.hosts, "—", "fix the base network above",
                    "", "", "", ""))
            self._vlsm_error.config(
                text=f"⚠ {ip_r.error if ip_r.is_err() else prefix_r.error}")
            self._vlsm_summary.config(text="")
            self._viz_empty = True
            return

        plan_r = plan_vlsm(ip_r.unwrap(), prefix_r.unwrap(), self._requirements)
        if plan_r.is_err():
            self._vlsm_error.config(text=f"⚠ {plan_r.error}")
            self._vlsm_summary.config(text="")
            self._viz_empty = True
            return

        plan = plan_r.unwrap()
        self._vlsm_error.config(text="")

        for s in plan.subnets:
            self._req_tree.insert("", "end", values=(
                s.name, fmt.format_int(s.hosts_needed), f"/{s.cidr}",
                s.network, s.mask, s.broadcast,
                fmt.format_range(s.first_host, s.last_host),
                f"{s.utilization:.0f}%"))

        notes: list[str] = []
        if plan.failures:
            failed = "; ".join(f"{f.name} ({f.reason})" for f in plan.failures)
            notes.append("Not allocated: " + failed)
        if plan.gaps:
            gap_txt = ", ".join(
                f"{ip_core_str(g.start)}–{ip_core_str(g.end)}" for g in plan.gaps)
            notes.append("Alignment gaps: " + gap_txt)
        if plan.leftover_start is not None:
            notes.append("Leftover: "
                         f"{ip_core_str(plan.leftover_start)}–{ip_core_str(plan.leftover_end)}")

        if notes:
            self._vlsm_error.config(text="⚠ " + "  ·  ".join(notes), fg=AMBER)
        self._vlsm_summary.config(
            text=f"{len(plan.subnets)} subnet(s) allocated from "
                 f"{ip_core_str(plan.base_network)}/{plan.base_cidr} · "
                 f"{plan.used_percent:.1f}% used · "
                 f"{fmt.format_int(plan.wasted_addresses)} addresses unused")

        self._last_plan = plan
        self._viz_empty = False
        self._render_plan_on_viz()
        if save:
            self.save_now()

    # --------------------------------------------------------- visualizer tab
    def _build_viz_tab(self) -> None:
        tab = self._viz_tab

        tk.Label(tab, text="Mask bit grid (calculator input)",
                 bg=PANEL, fg=MUTED, font=LABEL_BOLD).pack(anchor="w",
                                                           padx=16, pady=(14, 4))
        holder = tk.Frame(tab, bg=PANEL)
        holder.pack(fill="x", padx=16)
        self._viz_mask_grid = MaskBitGrid(holder, root=self)
        self._viz_mask_grid.pack(fill="x")

        tk.Label(tab, text="VLSM address space (proportional)",
                 bg=PANEL, fg=MUTED, font=LABEL_BOLD).pack(anchor="w",
                                                           padx=16, pady=(16, 4))
        self._viz_holder = tk.Frame(tab, bg=PANEL)
        self._viz_holder.pack(fill="x", padx=16)
        self._viz_bar_holder = tk.Frame(self._viz_holder, bg=PANEL)
        self._viz_bar_holder.pack(fill="x")
        self._viz_legend = tk.Label(tab, text="", bg=PANEL, fg=MUTED,
                                    font=LABEL, anchor="w", justify="left")
        self._viz_legend.pack(fill="x", padx=16, pady=(6, 0))

        self._on_tab_changed()

    def _render_plan_on_viz(self) -> None:
        if getattr(self, "_viz_bar_holder", None) is None:
            return
        _clear(self._viz_bar_holder)
        plan = getattr(self, "_last_plan", None)
        if plan is None or not plan.subnets:
            return
        palette = ["#38bdf8", "#4ade80", "#fbbf24", "#f472b6", "#a78bfa",
                   "#fb923c", "#34d399", "#f87171", "#60a5fa", "#e879f9"]
        total = plan.total_addresses
        canvas = tk.Canvas(self._viz_bar_holder, height=120, bg=PANEL,
                           highlightthickness=0)
        canvas.pack(fill="x")

        x = 0.0
        for i, s in enumerate(plan.subnets):
            frac = (s.end - s.start + 1) / total
            w = frac * 1000
            color = palette[i % len(palette)]
            canvas.create_rectangle(x, 10, x + w, 74, fill=color, width=0)
            if w > 34:
                canvas.create_text(x + w / 2, 36, text=f"/{s.cidr}",
                                   fill="#0b1220", font=LABEL_BOLD)
                canvas.create_text(x + w / 2, 56, text=s.name[:12],
                                   fill="#0b1220", font=LABEL)
            x += w
        if plan.leftover_start is not None:
            frac = (plan.leftover_end - plan.leftover_start + 1) / total
            canvas.create_rectangle(x, 10, x + frac * 1000, 74,
                                    fill=HOST_BIT, width=0)
            if frac * 1000 > 34:
                canvas.create_text(x + frac * 500, 42, text="free",
                                   fill=MUTED, font=LABEL)
        for g in plan.gaps:
            frac = (g.end - g.start + 1) / total
            gx = g.start / total * 1000
            canvas.create_rectangle(gx, 10, gx + frac * 1000, 74,
                                    fill="#1f2937", outline=AMBER)
            if frac * 1000 > 30:
                canvas.create_text(gx + frac * 500, 42, text="gap",
                                   fill=AMBER, font=LABEL)

        legend_bits = [f"Base /{plan.base_cidr} = "
                       f"{fmt.format_int(plan.total_addresses)} addresses",
                       "█ subnet   █ leftover   █ alignment gap"]
        self._viz_legend.config(text="\n".join(legend_bits))

    def _on_tab_changed(self, _event: object = None) -> None:
        current = self._tabs.index(self._tabs.select()) if self._tabs.tabs() else 0
        if current == 2:
            self._viz_mask_grid.set_mask(self._last_mask_cidr())
            self._render_plan_on_viz()
        if current == 0:
            self._recalc()

    def _last_mask_cidr(self) -> int:
        prefix_r = parse_prefix(self._calc_prefix_var.get())
        if prefix_r.is_ok():
            return prefix_r.unwrap()
        return 24

    # ------------------------------------------------------------- lifecycle
    def _restore_or_default(self) -> None:
        s = self._state
        self._calc_ip_var.set(str(s.get("calc_ip", "192.168.10.77")))
        self._calc_prefix_var.set(str(s.get("calc_prefix", "26")))
        self._vlsm_ip_var.set(str(s.get("vlsm_base_ip", "192.168.1.0")))
        self._vlsm_prefix_var.set(str(s.get("vlsm_base_prefix", "24")))
        self._replan(save=False)

    def on_close(self) -> None:
        self.save_now()
        self.destroy()


def ip_core_str(ip: int) -> str:
    """Local helper so GUI imports stay lean."""
    from domain import ip_core
    return ip_core.ip_to_string(ip)


def _to_int(value: object, default: int) -> int:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return default


class MaskBitGrid(tk.Frame):
    """32 squares: network bits vs host bits (the main teaching aid)."""

    CELL = 18
    GAP = 3

    def __init__(self, master: tk.Widget, root: tk.Tk) -> None:
        super().__init__(master, bg=PANEL)
        self._cidr = 24
        self._built_for: int | None = None
        self._label = tk.Label(self, text="", bg=PANEL, fg=MUTED, font=LABEL,
                               anchor="w")
        self._label.pack(fill="x")
        self._canvas = tk.Canvas(self, width=2 + 18 * (self.CELL + self.GAP),
                                 height=2 * self.CELL + self.GAP + 10,
                                 bg=PANEL, highlightthickness=0)
        self._canvas.pack(fill="x")

    def set_mask(self, cidr: int) -> None:
        cidr = max(0, min(32, cidr))
        if self._built_for == cidr and self._canvas.find_all():
            return
        self._built_for = cidr
        self._cidr = cidr
        canvas = self._canvas
        canvas.delete("all")
        size, gap = self.CELL, self.GAP
        for i in range(32):
            x = 2 + (i % 18) * (size + gap)
            y = 4 + (i // 18) * (size + gap)
            is_network = i < cidr
            color = NETWORK_BIT if is_network else HOST_BIT
            canvas.create_rectangle(x, y, x + size, y + size,
                                    fill=color, width=0)
            canvas.create_text(x + size / 2, y + size / 2,
                               text="1" if is_network else "0",
                               fill="#0b1220", font=LABEL)
        canvas.create_text(4, 2 * (size + gap) + 6, anchor="w",
                           fill=NETWORK_BIT,
                           text=f"network bits: {cidr}", font=LABEL)
        canvas.create_text(150, 2 * (size + gap) + 6, anchor="w",
                           fill=MUTED,
                           text=f"host bits: {32 - cidr}", font=LABEL)


def main() -> None:
    app = App()
    app.protocol("WM_DELETE_WINDOW", app.on_close)
    app.mainloop()


if __name__ == "__main__":
    main()
