"""Theme + misc constants for the GUI."""
from __future__ import annotations

# Cross-platform fonts (Segoe UI on Windows, fallbacks elsewhere)
FONT_FAMILY = "Segoe UI"

PROTO_COLORS = {
    "TCP":       "#1f6feb",
    "UDP":       "#8250df",
    "DNS":       "#8250df",
    "HTTP":      "#1a7f37",
    "ICMP":      "#bf8700",
    "ARP":       "#d29922",
    "IPv6":      "#57606a",
    "IPv4-frag": "#57606a",
    "TLS":       "#0969da",
}

SEV_COLORS = {
    "low":      "#57606a",
    "medium":   "#bf8700",
    "high":     "#cf222e",
    "critical": "#a40e26",
}

PROTO_TAG_COLORS = {
    "TCP": "#1f6feb", "UDP": "#8250df", "ICMP": "#bf8700", "ARP": "#d29922",
    "IPv6": "#57606a", "IPv4-frag": "#57606a", "DNS": "#8250df",
}

ROW_STRIPE = "#f6f8fa"

DISPLAY_MAX_ROWS = 25000   # treeview FIFO cap — keeps Tk responsive


def apply_theme(root):
    """ttk theme configuration — called once at startup."""
    import tkinter.ttk as ttk
    style = ttk.Style(root)
    try:
        if "vista" in style.theme_names():
            style.theme_use("vista")
        elif "clam" in style.theme_names():
            style.theme_use("clam")
    except Exception:  # noqa: BLE001
        pass
    style.configure("Toolbar.TFrame", background="#f6f8fa")
    style.configure("Toolbar.TLabel", background="#f6f8fa")
    style.configure("Toolbar.TButton", padding=(10, 4))
    style.configure("Filter.TCheckbutton", background="#f6f8fa")
    style.configure("Status.TLabel", padding=(6, 2))
    style.configure("Card.TLabelframe", padding=6)
