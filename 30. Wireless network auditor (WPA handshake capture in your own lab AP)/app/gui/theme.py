"""Color palette & ttk theme for the auditor GUI."""
from app import config

C = {
    "bg": "#0d1117",
    "panel": "#161b22",
    "panel2": "#1c2333",
    "border": "#30363d",
    "text": "#e6edf3",
    "muted": "#8b949e",
    "cyan": "#39d5ff",
    "green": "#3fb950",
    "amber": "#f0b429",
    "red": "#f85149",
    "purple": "#bc8cff",
    "pink": "#ff7bc7",
    "blue": "#58a6ff",
    "teal": "#56d4dd",
}

SEV_COLORS = {
    "Critical": C["red"],
    "High": "#f0883e",
    "Medium": "#93d50a",
    "Low": C["amber"],
    "Info": C["muted"],
}


def setup_ttk(root):
    from tkinter import ttk
    style = ttk.Style(root)
    style.theme_use("clam")
    style.configure("App.TFrame", background=C["bg"])
    style.configure("Panel.TFrame", background=C["panel"])
    style.configure("App.TLabel", background=C["bg"], foreground=C["text"])
    style.configure("Panel.TLabel", background=C["panel"], foreground=C["text"])
    style.configure("Muted.TLabel", background=C["bg"], foreground=C["muted"])
    style.configure("MutedPanel.TLabel", background=C["panel"], foreground=C["muted"])
    style.configure("Title.TLabel", background=C["bg"], foreground=C["cyan"], font=("Segoe UI", 17, "bold"))
    style.configure("Card.TLabel", background=C["panel"], foreground=C["text"], font=("Segoe UI", 10, "bold"))
    style.configure("CardNum.TLabel", background=C["panel"], foreground=C["green"], font=("Segoe UI", 24, "bold"))
    style.configure("CardSub.TLabel", background=C["panel"], foreground=C["muted"], font=("Segoe UI", 8))
    style.configure("Acc.TButton", background=C["cyan"], foreground="#0d1117", font=("Segoe UI", 10, "bold"),
                    borderwidth=0, focusthickness=0, padding=(14, 8))
    style.map("Acc.TButton", background=[("active", "#2fb8d8")])
    style.configure("Danger.TButton", background=C["red"], foreground="#0d1117", font=("Segoe UI", 10, "bold"),
                    borderwidth=0, focusthickness=0, padding=(14, 8))
    style.map("Danger.TButton", background=[("active", "#d6373e")])
    style.configure("Ghost.TButton", background=C["panel2"], foreground=C["text"], font=("Segoe UI", 9),
                    borderwidth=1, focusthickness=0, padding=(8, 5))
    style.map("Ghost.TButton", background=[("active", C["border"])])
    style.configure("Treeview", background=C["panel"], fieldbackground=C["panel"], foreground=C["text"],
                    borderwidth=0, rowheight=26, font=("Segoe UI", 9))
    style.configure("Treeview.Heading", background=C["panel2"], foreground=C["cyan"], font=("Segoe UI", 9, "bold"),
                    relief="flat")
    style.map("Treeview", background=[("selected", "#1f6feb")])
    style.configure("App.Horizontal.TProgressbar", background=C["cyan"], troughcolor=C["panel2"], borderwidth=0)
    style.configure("Status.TLabel", background=C["panel2"], foreground=C["teal"], font=("Consolas", 9))
    return style