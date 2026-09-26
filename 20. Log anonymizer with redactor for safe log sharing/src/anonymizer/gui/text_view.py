"""Read-only, entity-highlighted log text widget."""

from __future__ import annotations

import tkinter as tk
from dataclasses import dataclass

from ..gui.scanner import LineScan
from ..gui.theme import entity_color

__all__ = ["HighlightSpec", "LogText"]


@dataclass(frozen=True)
class HighlightSpec:
    """Highlight a span [start, end) of one line with a tag colour."""

    line: int
    start: int
    end: int
    tag: str


class LogText(tk.Text):
    """Monospace read-only pane that highlights sensitive entities."""

    def __init__(self, master=None, *, theme: dict, **kwargs):
        kwargs.setdefault("wrap", "none")
        kwargs.setdefault("font", ("Consolas", 10))
        kwargs.setdefault("bg", theme["text_bg"])
        kwargs.setdefault("fg", theme["fg"])
        kwargs.setdefault("insertbackground", theme["fg"])
        kwargs.setdefault("relief", "flat")
        super().__init__(master, **kwargs)
        self.configure(state="disabled")
        self._theme = theme

    def render(
        self,
        lines: list[str],
        scans: list[LineScan] | None = None,
        *,
        max_lines: int = 0,
    ) -> int:
        """Stream lines into the pane applying entity highlights."""
        self.configure(state="normal")
        self.delete("1.0", "end")
        view_lines = lines[:max_lines] if max_lines else lines
        # Pre-compute per-line base offsets inside the widget (lines joined with \n)
        base = 0
        scanned = {s.index: s for s in (scans or [])}
        for i, line in enumerate(view_lines):
            line = str(line).replace("\t", "    ")
            self.insert("end", line + "\n")
            scan = scanned.get(i)
            if scan:
                for ent in scan.entities:
                    start = min(max(ent.start, 0), len(line))
                    end = min(max(ent.end, start), len(line))
                    if end > start:
                        tag = f"HL-{ent.entity_type}"
                        self._tag(tag, entity_color(ent.entity_type))
                        self.tag_add(tag, f"1.0+{base + start}c", f"1.0+{base + end}c")
            base += len(line) + 1
        # Reset cursor + bookkeeping so detection in the same pane keeps indices.
        self._base_ofs = [0] * len(view_lines)
        offset = 0
        for i, line in enumerate(view_lines):
            self._base_ofs[i] = offset
            offset += len(str(line)) + 1
        self.configure(state="disabled")
        return len(view_lines)

    def _tag(self, name: str, color: str) -> None:
        if name not in self.tag_names():
            self.tag_configure(name, background=color, foreground="#ffffff")
            self.tag_raise(name)

    @property
    def line_offsets(self) -> list[int]:
        return list(getattr(self, "_base_ofs", []))
