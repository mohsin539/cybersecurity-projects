"""Honeypot GUI console — SSH + HTTP deceptions with live attacker fingerprinting.

Portable build entrypoint: `py -m PyInstaller --onefile --windowed honeypot_gui.py`.
Reuses the honeypot door/engine/export layers; adds a dark terminal-style console,
start/stop controls, a built-in simulated attacker, and live attribution feed.
"""
from __future__ import annotations

import json
import os
import queue
import sys
import threading
import time
import tkinter as tk
from pathlib import Path
from tkinter import messagebox, scrolledtext

from honeypot.doors.http import HttpDoor, HttpSimulator
from honeypot.doors.ssh import SshDoor, SshSimulator
from honeypot.engine.fingerprint import attribute
from honeypot.export.events import EventExporter

HONEYTOKENS = ["admin", "root-hun"]
DEFAULT_SSH_PORT = 2222
DEFAULT_HTTP_PORT = 8080

BG = "#10141c"
PANEL = "#161b26"
FG = "#d8dee9"
LOG_BG = "#0b0e14"
AMBER = "#f5a623"


def _dpi_aware() -> None:
    if os.name != "nt":
        return
    try:
        import ctypes
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        pass


def _app_base() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


def _app_dir() -> Path:
    base = _app_base()
    try:
        probe = base / "data"
        probe.mkdir(parents=True, exist_ok=True)
        test = probe / ".write_test"
        test.write_text("ok", encoding="utf-8")
        test.unlink()
        return base
    except OSError:
        fallback = Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "Honeypot"
        fallback.mkdir(parents=True, exist_ok=True)
        return fallback


def _excepthook(exc_type, exc, tb) -> None:
    import traceback
    detail = "".join(traceback.format_exception(exc_type, exc, tb))
    try:
        log = _app_dir() / "data" / "errors.log"
        log.parent.mkdir(parents=True, exist_ok=True)
        with log.open("a", encoding="utf-8") as fh:
            fh.write(f"{time.strftime('%Y-%m-%dT%H:%M:%S')}\n{detail}\n")
    except Exception:
        pass
    try:
        messagebox.showerror("Honeypot error", detail[-1200:])
    except Exception:
        pass


def _fmt_http(session, attr: dict) -> tuple[str, str]:
    paths = []
    for sig in session.signals:
        if sig["kind"] != "request":
            continue
        try:
            paths.append(json.loads(str(sig["value"])))
        except json.JSONDecodeError:
            continue
    if paths:
        last = paths[-1]
        path, method = last.get("path", "?"), last.get("method", "?")
    else:
        path, method = "?", "?"
    conf = attr["tool_scores"][0] if attr["tool_scores"] else None
    top = f"{conf['tool']} {conf['confidence']:.2f}" if conf else "unclassified"
    text = f"[HTTP] {session.peer_ip}:{session.peer_port}  {method} {path}  -> {top}"
    tag = "high" if attr["tool_scores"] else "medium"
    return text, tag


def _fmt_ssh(session, attr: dict, honeytokens: set[str]) -> tuple[str, str]:
    auths = [str(sig["value"]) for sig in session.signals if sig["kind"] == "auth-attempt"]
    cmds = [str(sig["value"]) for sig in session.signals if sig["kind"] == "cmd"]
    hit = [u for u in auths if u in honeytokens]
    conf = attr["tool_scores"][0] if attr["tool_scores"] else None
    top = f"{conf['tool']} {conf['confidence']:.2f}" if conf else "unclassified"
    inter = " honeytoken-hit" if hit else ""
    text = (f"[SSH]  {session.peer_ip}:{session.peer_port}  "
            f"{len(auths)} auth{inter} · {len(cmds)} cmd  -> {top}  os={attr['os_guess']}")
    if cmds and conf and conf["confidence"] >= 0.8:
        tag = "critical"
    elif cmds or inter:
        tag = "high"
    else:
        tag = "medium"
    return text, tag


def _think(session) -> tuple[str, str]:
    attr = attribute(session)
    if session.protocol == "http":
        return _fmt_http(session, attr)
    return _fmt_ssh(session, attr, set(HONEYTOKENS))


class DoorController:
    def __init__(self, ssh_port: int, http_port: int, exporter: EventExporter,
                 on_event) -> None:
        self.ssh_port = ssh_port
        self.http_port = http_port
        self.exporter = exporter
        self.on_event = on_event
        self.ssh_door: SshDoor | None = None
        self.http_door: HttpDoor | None = None
        self._running = False
        self._ssh_seen = 0
        self._http_seen = 0
        self._monitor: threading.Thread | None = None

    def running(self) -> bool:
        return self._running

    def start(self) -> str | None:
        ssh = SshDoor(self.ssh_port, honeytokens=list(HONEYTOKENS))
        http = HttpDoor(self.http_port)
        try:
            ssh.start()
        except OSError as exc:
            return f"cannot bind SSH :{self.ssh_port} — {exc}"
        try:
            http.start()
        except OSError as exc:
            try:
                ssh._sock.close()
            except Exception:
                pass
            return f"cannot bind HTTP :{self.http_port} — {exc}"
        self.ssh_door, self.http_door = ssh, http
        self._running = True
        self._ssh_seen = 0
        self._http_seen = 0
        self._monitor = threading.Thread(target=self._monitor_loop, daemon=True)
        self._monitor.start()
        self.on_event(f"[ok] doors listening  ssh=:{self.ssh_port}  http=:{self.http_port}",
                      "ok")
        return None

    def stop(self) -> None:
        if not self._running:
            return
        self._running = False
        ssh, http = self.ssh_door, self.http_door
        self.ssh_door = self.http_door = None
        try:
            ssh._sock.close()
        except Exception:
            pass
        try:
            http._srv.shutdown()
            http._srv.server_close()
        except Exception:
            pass
        if self._monitor and self._monitor.is_alive():
            self._monitor.join(timeout=2.0)
        self._drain()
        self.on_event("[sys] doors stopped", "info")

    def _monitor_loop(self) -> None:
        while self._running:
            time.sleep(0.25)
            self._drain()

    def _drain(self) -> None:
        if not self.ssh_door or not self.http_door:
            return
        new_ssh = self.ssh_door.sessions[self._ssh_seen:]
        self._ssh_seen = len(self.ssh_door.sessions)
        new_http = self.http_door.sessions[self._http_seen:]
        self._http_seen = len(self.http_door.sessions)
        for session in list(new_ssh) + list(new_http):
            try:
                text, tag = _think(session)
                self.exporter.export(session)
                self.on_event(text, tag)
            except Exception as exc:
                self.on_event(f"[err] {exc}", "error")


def _run_demo(ssh_port: int, http_port: int, host: str = "127.0.0.1") -> None:
    SshSimulator(host, ssh_port).attempt(
        ["root", "admin", "postgres", "ubuntu", "demo", "admin"])
    HttpSimulator(host, http_port).probe(["/", "/.env", "/.git/config", "/admin"])


class GuiApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.app_dir = _app_dir()
        self.data_dir = self.app_dir / "data"
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.exporter = EventExporter(self.data_dir)
        self.events: queue.Queue = queue.Queue()
        self.counters = {"sessions": 0, "critical": 0, "high": 0, "medium": 0}
        self.controller = DoorController(DEFAULT_SSH_PORT, DEFAULT_HTTP_PORT,
                                         self.exporter, self.events.put)

        root.title("Honeypot Console — SSH + HTTP attacker fingerprinting")
        root.geometry("980x620")
        root.minsize(760, 460)
        root.configure(bg=BG)
        self._build()
        self._refresh_state()
        self.root.after(120, self._poll_events)
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    def _build(self) -> None:
        head = tk.Frame(self.root, bg=BG)
        head.pack(fill="x", padx=14, pady=(12, 6))

        tk.Label(head, text="HONEYPOT  \u2022  SSH + HTTP deception host",
                 font=("Segoe UI", 15, "bold"), bg=BG, fg=AMBER).pack(anchor="w")
        tk.Label(head,
                 text="Fake services lure scanners; every touch is fingerprinted "
                      "(tool, campaign, OS) and archived to data\\sessions.jsonl.",
                 font=("Segoe UI", 9), bg=BG, fg="#8b9bb4").pack(anchor="w", pady=(2, 0))

        ctl = tk.Frame(self.root, bg=PANEL, padx=12, pady=10)
        ctl.pack(fill="x", padx=14, pady=(0, 8))

        tk.Label(ctl, text="SSH port", bg=PANEL, fg=FG, font=("Segoe UI", 9)).grid(
            row=0, column=0, sticky="e", padx=(0, 4))
        self.ssh_var = tk.StringVar(value=str(DEFAULT_SSH_PORT))
        self.ssh_entry = tk.Entry(ctl, textvariable=self.ssh_var, width=7,
                                  font=("Consolas", 10), bg=LOG_BG, fg=FG,
                                  insertbackground=FG, relief="flat")
        self.ssh_entry.grid(row=0, column=1, sticky="w", padx=(0, 16))

        tk.Label(ctl, text="HTTP port", bg=PANEL, fg=FG, font=("Segoe UI", 9)).grid(
            row=0, column=2, sticky="e", padx=(0, 4))
        self.http_var = tk.StringVar(value=str(DEFAULT_HTTP_PORT))
        self.http_entry = tk.Entry(ctl, textvariable=self.http_var, width=7,
                                   font=("Consolas", 10), bg=LOG_BG, fg=FG,
                                   insertbackground=FG, relief="flat")
        self.http_entry.grid(row=0, column=3, sticky="w", padx=(0, 24))

        self.start_btn = self._button(ctl, "Start", self._on_start, "#2f81f7")
        self.start_btn.grid(row=0, column=4, padx=3)
        self.stop_btn = self._button(ctl, "Stop", self._on_stop, "#da3633")
        self.stop_btn.grid(row=0, column=5, padx=3)
        self.demo_btn = self._button(ctl, "Demo attack", self._on_demo, "#d29922")
        self.demo_btn.grid(row=0, column=6, padx=3)
        tk.Button(ctl, text="Open data folder", command=self._open_data, bg=PANEL,
                  fg=FG, activebackground="#243044", activeforeground=FG,
                  relief="flat", font=("Segoe UI", 9), padx=8, cursor="hand2").grid(
            row=0, column=7, padx=3)
        tk.Button(ctl, text="Clear log", command=self._clear_log, bg=PANEL,
                  fg=FG, activebackground="#243044", activeforeground=FG,
                  relief="flat", font=("Segoe UI", 9), padx=8, cursor="hand2").grid(
            row=0, column=8, padx=3)

        for col in range(9):
            ctl.grid_columnconfigure(col, weight=0)

        tk.Label(self.root, text="Live capture & attribution",
                 font=("Segoe UI", 10, "bold"), bg=BG, fg=AMBER).pack(
            anchor="w", padx=14, pady=(4, 2))

        self.log = scrolledtext.ScrolledText(
            self.root, bg=LOG_BG, fg=FG, insertbackground=FG, relief="flat",
            font=("Consolas", 10), state="disabled", wrap="char", padx=10, pady=8)
        self.log.pack(fill="both", expand=True, padx=14, pady=(0, 8))

        for name, color in {
            "critical": "#ff6b6b", "high": "#ffa94d", "medium": "#ffd43b",
            "info": "#4dabf7", "ok": "#69db7c", "error": "#ff6b6b",
        }.items():
            self.log.tag_configure(name, foreground=color)
        self.log.tag_configure("dim", foreground="#5d6f8f")

        self.status = tk.Label(self.root, text="", bg=BG, fg="#8b9bb4",
                               font=("Segoe UI", 9), anchor="w")
        self.status.pack(fill="x", padx=14, pady=(0, 10))

    def _button(self, parent, text, cmd, color) -> tk.Button:
        return tk.Button(parent, text=text, command=cmd, bg=color, fg="white",
                         activebackground=color, activeforeground="white",
                         relief="flat", font=("Segoe UI", 9, "bold"), padx=14,
                         cursor="hand2")

    def _write(self, text: str, tag: str = "dim") -> None:
        ts = time.strftime("%H:%M:%S")
        self.log.config(state="normal")
        self.log.insert("end", f"{ts}  {text}\n", tag)
        self.log.see("end")
        self.log.config(state="disabled")
        if tag in self.counters:
            self.counters[tag] += 1
            self.counters["sessions"] += 1
        self._refresh_status()

    def _clear_log(self) -> None:
        self.log.config(state="normal")
        self.log.delete("1.0", "end")
        self.log.config(state="disabled")

    def _open_data(self) -> None:
        os.startfile(str(self.data_dir))

    def _severity_of(self, tag: str) -> str:
        return tag if tag in ("critical", "high", "medium") else ""

    def _refresh_status(self) -> None:
        if self.controller.running():
            state = f"RUNNING  ssh=:{self.ssh_var.get()}  http=:{self.http_var.get()}"
        else:
            state = "stopped"
        counts = "  \u00b7  ".join(
            f"{k}={v}" for k, v in self.counters.items())
        self.status.config(text=f"{state}   sessions={self.counters['sessions']}   {counts}"
                               f"   data={self.data_dir}")

    def _refresh_state(self) -> None:
        running = self.controller.running()
        self.start_btn.config(state="disabled" if running else "normal")
        self.stop_btn.config(state="normal" if running else "disabled")
        self.demo_btn.config(state="normal" if running else "disabled")
        self.ssh_entry.config(state="disabled" if running else "normal")
        self.http_entry.config(state="disabled" if running else "normal")
        self._refresh_status()

    def _parse_ports(self) -> tuple[int, int] | None:
        try:
            ssh_port = int(self.ssh_var.get())
            http_port = int(self.http_var.get())
        except ValueError:
            messagebox.showwarning("Ports", "Ports must be integers.")
            return None
        if not (1 <= ssh_port <= 65535 and 1 <= http_port <= 65535):
            messagebox.showwarning("Ports", "Ports must be 1..65535.")
            return None
        return ssh_port, http_port

    def _on_start(self) -> None:
        ports = self._parse_ports()
        if not ports:
            return
        ssh_port, http_port = ports
        self.controller.ssh_port, self.controller.http_port = ssh_port, http_port
        self._write(f"[sys] starting doors  ssh=:{ssh_port}  http=:{http_port} ...", "info")
        self._refresh_state()
        err = self.controller.start()
        if err:
            messagebox.showerror("Start failed", err)
            self._write(f"[err] {err}", "error")
        self._refresh_state()
        self._write("[sys] try it: browser -> http://127.0.0.1:{0}   or run "
                    "`py scripts/attacker_sim.py 127.0.0.1 {1}`".format(
                        http_port, ssh_port), "dim")

    def _on_stop(self) -> None:
        self.controller.stop()
        self._refresh_state()

    def _on_demo(self) -> None:
        if not self.controller.running():
            return
        self._write("[demo] firing simulated hydra + sqlmap-ish attacker ...", "info")
        threading.Thread(target=_run_demo,
                         args=(self.controller.ssh_port, self.controller.http_port),
                         daemon=True).start()

    def _poll_events(self) -> None:
        try:
            while True:
                text, tag = self.events.get_nowait()
                self._write(text, tag)
        except queue.Empty:
            pass
        else:
            self._refresh_state()
        if not self.root.winfo_exists():
            return
        self.root.after(120, self._poll_events)

    def _on_close(self) -> None:
        try:
            self.controller.stop()
        except Exception:
            pass
        try:
            self.exporter.close()
        except Exception:
            pass
        self.root.destroy()


def main() -> int:
    _dpi_aware()
    sys.excepthook = _excepthook
    root = tk.Tk()
    app = GuiApp(root)
    if os.environ.get("HONEYPOT_AUTOSTART") in ("1", "true", "yes"):
        app._on_start()
    root.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())