"""Main Tkinter application window.
"""
import tkinter as tk
from tkinter import ttk

from app import config
from app.core.events import BUS
from app.core.scope import ScopeGuard
from app.core.engine import AuditEngine
from app.data.vault import EvidenceVault
from app.gui.theme import C, setup_ttk
from app.gui.views import DashboardView, CaptureView, HandshakeView, ReportView

NAV = [
    ("▦  Dashboard", "cyan"),
    ("📡  Capture", "green"),
    ("🔐  Handshakes", "purple"),
    ("📄  Reports", "amber"),
]


class AuditorApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(f"{config.APP_NAME} v{config.APP_VERSION}")
        self.configure(bg=C["bg"])
        self.geometry("1180x720")
        self.minsize(980, 620)

        setup_ttk(self)

        # engine + vault are created here (single instance shared by views)
        self.vault = EvidenceVault()
        self.engine = AuditEngine(self.vault)
        self._poll_after = None

        self._build_shell()
        self.register_demo_lab()
        self.show(0)
        self.set_status("READY · authorized lab use only")
        self.after(260, self._poll)

    # ---------------- shell ----------------
    def _build_shell(self):
        self.sidebar = tk.Frame(self, bg=C["panel"], width=190)
        self.sidebar.pack(side="left", fill="y")
        self.sidebar.pack_propagate(False)

        tk.Label(self.sidebar, text="📡 WNA", font=("Segoe UI", 15, "bold"),
                 fg=C["cyan"], bg=C["panel"]).pack(anchor="w", padx=18, pady=(18, 2))
        tk.Label(self.sidebar, text=config.APP_TAGLINE, font=("Segoe UI", 8), fg=C["muted"],
                 bg=C["panel"], wraplength=150, justify="left").pack(anchor="w", padx=18, pady=(0, 14))

        self.nav_btns = {}
        for i, (label, color) in enumerate(NAV):
            btn = tk.Label(self.sidebar, text=label, font=("Segoe UI", 10, "bold"),
                           fg=C[color], bg=C["panel"], padx=14, pady=9, anchor="w", cursor="hand2")
            btn.pack(fill="x", padx=10, pady=2)
            btn.bind("<Button-1>", lambda e, idx=i: self.show(idx))
            btn.bind("<Enter>", lambda e, b=btn: b.config(bg=C["panel2"]))
            btn.bind("<Leave>", lambda e, b=btn: b.config(bg=C["panel"]))
            self.nav_btns[i] = btn

        tk.Label(self.sidebar, text="", bg=C["panel"]).pack(fill="both", expand=True)

        self.status = ttk.Label(self.sidebar, text="READY", style="Status.TLabel")
        self.status.pack(fill="x", padx=10, pady=(0, 10))

        self.content = tk.Frame(self, bg=C["bg"])
        self.content.pack(side="left", fill="both", expand=True)

        self.views = [
            DashboardView(self.content, self.engine, self),
            CaptureView(self.content, self.engine, self),
            HandshakeView(self.content, self.engine, self),
            ReportView(self.content, self.engine, self),
        ]
        for v in self.views:
            v_place = v
            v_place.place_forget()
        for v in self.views:
            v.place_forget()

    def show(self, idx: int):
        self.content.tkraise()
        for i, v in enumerate(self.views):
            if i == idx:
                v.pack(fill="both", expand=True)
            else:
                v.pack_forget()
        for i, btn in self.nav_btns.items():
            btn.config(bg=C["panel"] if i != idx else C["panel2"])

    # ---------------- helpers ----------------
    def register_demo_lab(self):
        if not self.engine.scope.authorized_list():
            self.engine.register_lab_ap("00:1A:2B:3C:4D:5E", "MY-LAB-AP", 6, "WPA2/AES")

    def set_status(self, text: str):
        self.status.config(text=text)

    def feed_event(self, kind: str, detail: str):
        self.views[0].feed_event(kind, detail)

    def refresh_all(self):
        for v in self.views:
            try:
                v.refresh()
            except Exception:
                pass

    # ---------------- event pump ----------------
    def _poll(self):
        for ev in BUS.drain():
            kind = ev[0]
            if kind == "scope":
                self.feed_event("scope", ev[1] if len(ev) > 1 else "")
            elif kind == "scope_drop":
                self.set_status("SCOPE GUARD DROPPED FRAME")
                self.feed_event("scope", ev[1] if len(ev) > 1 else "blocked")
            elif kind == "eapol":
                st = ev[1]
                status = f"HANDSHAKE {st['client']} {len(st['seen'])}/4"
                if st.get("complete"):
                    status = f"4-WAY COMPLETE · {st['client']}"
                self.set_status(status)
                self.feed_event("eapol", f"{st['client']} on {st['bssid']} → {len(st['seen'])}/4")
            elif kind == "finding":
                f = ev[1]
                self.feed_event("finding", f"{f['title']} [{f['severity']}]")
            elif kind == "status":
                self.set_status(str(ev[1]))
            elif kind == "error":
                self.set_status("ERROR")
                self.feed_event("error", str(ev[1]))
        self.refresh_all()
        self._poll_after = self.after(260, self._poll)

    def destroy(self):
        self.engine.stop()
        try:
            self.vault.close()
        except Exception:
            pass
        try:
            if self._poll_after:
                self.after_cancel(self._poll_after)
        except Exception:
            pass
        super().destroy()


def run():
    app = AuditorApp()
    app.mainloop()


if __name__ == "__main__":
    run()