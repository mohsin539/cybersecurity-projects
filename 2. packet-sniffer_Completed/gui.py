"""Main GUI — Tkinter packet sniffer front-end.

Threading contract:
  * GUI thread ONLY touches tkinter widgets.
  * Capture/parse threads push (seq_no, Packet) onto ui_queue.
  * A 33 ms root.after loop drains ui_queue in batch, so Tk never sees
    more than ~30 render passes per second regardless of packet rate.
  * Display is rendered incrementally (append-only) unless filters change.
"""
from __future__ import annotations

import queue
import threading
import time
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

from parsers import Packet
from capture import CaptureEngine, CaptureStats, list_interfaces, make_processor, processor_stop
from storage import Storage, Exporter
from pcap_writer import PcapWriter
from threat import ThreatAnalyzer, ThreatEvent
import gui_theme as theme

VIEW_WINDOW = 2000   # max rows rendered in the treeview at once


class SnifferGUI(tk.Tk):
    UI_FLUSH_MS = 33

    def __init__(self):
        super().__init__()
        self.title("Packet Sniffer — Raw Socket Edition (Authorized Use Only)")
        self.geometry("1500x880")
        self.minsize(1100, 620)

        # ---- state -------------------------------------------------------
        self.engine: CaptureEngine | None = None
        self.proc_threads: list = []
        self.proc_stop: threading.Event | None = None
        self.storage: Storage | None = None
        self.analyzer = ThreatAnalyzer(emit=self._on_threat_event)
        self.raw_q: "queue.Queue" = queue.Queue(maxsize=25000)
        self.ui_q: "queue.Queue" = queue.Queue(maxsize=50000)
        self.threat_q: "queue.Queue" = queue.Queue(maxsize=5000)
        self.stats = CaptureStats()
        self.pcap: PcapWriter | None = None
        self.pcap_lock = threading.Lock()
        self._ifaces: list = []

        self.seq = 0
        self.rows: dict[int, Packet] = {}
        self.row_order: list[int] = []
        self._view: list[int] = []          # seqs currently passing filters
        self._last_rendered: set[int] = set()

        # filters
        self.f_tcp = tk.BooleanVar(value=True)
        self.f_udp = tk.BooleanVar(value=True)
        self.f_icmp = tk.BooleanVar(value=True)
        self.f_arp = tk.BooleanVar(value=True)
        self.f_other = tk.BooleanVar(value=True)
        self.f_text = tk.StringVar()
        self.f_text.trace_add("write", lambda *_: self._rebuild_view())
        for v in (self.f_tcp, self.f_udp, self.f_icmp, self.f_arp, self.f_other):
            v.trace_add("write", lambda *_: self._rebuild_view())

        self._build_menu()
        self._build_ui()
        self._refresh_ifaces()
        self.after(self.UI_FLUSH_MS, self._ui_tick)
        self.after(1000, self._stats_tick)
        self.after(500, self._drain_threats)
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    # ==================================================================
    # UI construction
    # ==================================================================
    def _build_menu(self):
        m = tk.Menu(self)
        fm = tk.Menu(m, tearoff=0)
        fm.add_command(label="Export CSV…", command=self._export_csv)
        fm.add_command(label="Export JSON…", command=self._export_json)
        fm.add_separator()
        fm.add_command(label="Clear display", command=self._clear)
        fm.add_separator()
        fm.add_command(label="Exit", command=self._on_close)
        m.add_cascade(label="File", menu=fm)
        hm = tk.Menu(m, tearoff=0)
        hm.add_command(label="About / Legal", command=self._about)
        m.add_cascade(label="Help", menu=hm)
        self.config(menu=m)

    def _build_ui(self):
        # ---------- control bar ----------
        bar = ttk.Frame(self, style="Toolbar.TFrame")
        bar.pack(side="top", fill="x")

        ttk.Label(bar, text="Interface:", style="Toolbar.TLabel").pack(
            side="left", padx=(8, 2), pady=6)
        self.iface_cb = ttk.Combobox(bar, state="readonly", width=32)
        self.iface_cb.pack(side="left", padx=2)

        self.btn_start = ttk.Button(bar, text="▶ Start", command=self._start)
        self.btn_start.pack(side="left", padx=(10, 2))
        self.btn_stop = ttk.Button(bar, text="■ Stop", command=self._stop,
                                   state="disabled")
        self.btn_stop.pack(side="left", padx=2)

        self.authorized = tk.BooleanVar(value=False)
        ttk.Checkbutton(bar, text="I am authorized to monitor this network",
                        variable=self.authorized,
                        style="Filter.TCheckbutton").pack(side="left", padx=(16, 4))

        self.pcap_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(bar, text="Record PCAP", variable=self.pcap_var,
                        style="Filter.TCheckbutton").pack(side="left", padx=8)

        # ---------- filter bar ----------
        fbar = ttk.Frame(self, style="Toolbar.TFrame")
        fbar.pack(side="top", fill="x")
        ttk.Label(fbar, text="Protocols:", style="Toolbar.TLabel").pack(
            side="left", padx=(8, 2))
        for lbl, var in (("TCP", self.f_tcp), ("UDP", self.f_udp),
                         ("ICMP", self.f_icmp), ("ARP", self.f_arp),
                         ("Other", self.f_other)):
            ttk.Checkbutton(fbar, text=lbl, variable=var,
                            style="Filter.TCheckbutton").pack(side="left", padx=2)
        ttk.Label(fbar, text="   Filter (ip / port / text):",
                  style="Toolbar.TLabel").pack(side="left")
        self.ent_filter = ttk.Entry(fbar, textvariable=self.f_text, width=28)
        self.ent_filter.pack(side="left", padx=4, pady=4)
        ttk.Button(fbar, text="✕", width=2,
                   command=lambda: self.f_text.set("")).pack(side="left")

        # ---------- main paned layout ----------
        pane = ttk.PanedWindow(self, orient="horizontal")
        pane.pack(side="top", fill="both", expand=True)

        left = ttk.Frame(pane)
        pane.add(left, weight=4)

        cols = ("no", "time", "src", "dst", "proto", "len", "info")
        self.tree = ttk.Treeview(left, columns=cols, show="headings",
                                 selectmode="browse")
        headers = {"no": ("No.", 60), "time": ("Time", 96),
                   "src": ("Source", 170), "dst": ("Destination", 170),
                   "proto": ("Proto", 70), "len": ("Len", 60),
                   "info": ("Info", 560)}
        for c, (txt, w) in headers.items():
            self.tree.heading(c, text=txt)
            self.tree.column(c, width=w, anchor="w", stretch=(c == "info"))
        ysb = ttk.Scrollbar(left, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=ysb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        ysb.pack(side="left", fill="y")
        for proto, color in theme.PROTO_TAG_COLORS.items():
            self.tree.tag_configure(proto, foreground=color)
        self.tree.tag_configure("stripe", background=theme.ROW_STRIPE)
        self.tree.bind("<<TreeviewSelect>>", self._on_select)
        self.tree.bind("<Double-1>", lambda e: self._on_select())
        self.tree.bind("<Button-3>", self._popup_menu)

        # right sidebar: stats + threats
        right = ttk.Frame(pane)
        pane.add(right, weight=1)
        nb = ttk.Notebook(right)
        nb.pack(fill="both", expand=True)

        st = ttk.Frame(nb)
        nb.add(st, text=" Statistics ")
        self.lbl_pps = tk.Label(st, text="0 pps",
                                font=(theme.FONT_FAMILY, 16, "bold"),
                                fg="#1f6feb")
        self.lbl_pps.pack(anchor="w", padx=10, pady=(10, 0))
        self.lbl_totals = tk.Label(st, text="", font=(theme.FONT_FAMILY, 9),
                                   justify="left", anchor="w")
        self.lbl_totals.pack(anchor="w", padx=10, pady=4)
        self.proto_bars = tk.Label(st, text="", font=(theme.FONT_FAMILY, 9),
                                   justify="left", anchor="w")
        self.proto_bars.pack(anchor="w", padx=10, pady=4)
        self.canvas_pps = tk.Canvas(st, height=90, bg="white",
                                    highlightthickness=0)
        self.canvas_pps.pack(fill="x", padx=10, pady=8)

        th = ttk.Frame(nb)
        nb.add(th, text=" Threats ")
        tcols = ("time", "sev", "kind", "desc")
        self.threat_tree = ttk.Treeview(th, columns=tcols, show="headings")
        for c, txt, w in (("time", "Time", 70), ("sev", "Sev", 64),
                          ("kind", "Type", 110), ("desc", "Description", 330)):
            self.threat_tree.heading(c, text=txt)
            self.threat_tree.column(c, width=w, anchor="w",
                                    stretch=(c == "desc"))
        tsb = ttk.Scrollbar(th, orient="vertical",
                            command=self.threat_tree.yview)
        self.threat_tree.configure(yscrollcommand=tsb.set)
        self.threat_tree.pack(side="left", fill="both", expand=True)
        tsb.pack(side="left", fill="y")
        for sev, color in theme.SEV_COLORS.items():
            self.threat_tree.tag_configure(sev, foreground=color)

        # ---------- detail pane (bottom) ----------
        dpane = ttk.PanedWindow(self, orient="vertical")
        dpane.pack(side="top", fill="both", expand=True)
        detail_lf = ttk.Labelframe(dpane,
                                   text="Packet Detail — click a row")
        dpane.add(detail_lf, weight=3)
        self.txt_detail = tk.Text(detail_lf, height=10, font=("Consolas", 9),
                                  bg="#0d1117", fg="#c9d1d9",
                                  insertbackground="#c9d1d9",
                                  state="disabled", wrap="none")
        dsb = ttk.Scrollbar(detail_lf, orient="vertical",
                            command=self.txt_detail.yview)
        self.txt_detail.configure(yscrollcommand=dsb.set)
        self.txt_detail.pack(side="left", fill="both", expand=True)
        dsb.pack(side="left", fill="y")

        hex_lf = ttk.Labelframe(dpane, text="Hex Dump")
        dpane.add(hex_lf, weight=2)
        self.txt_hex = tk.Text(hex_lf, height=8, font=("Consolas", 9),
                               bg="#0d1117", fg="#7ee787",
                               insertbackground="#7ee787",
                               state="disabled", wrap="none")
        hsb = ttk.Scrollbar(hex_lf, orient="vertical",
                            command=self.txt_hex.yview)
        self.txt_hex.configure(yscrollcommand=hsb.set)
        self.txt_hex.pack(side="left", fill="both", expand=True)
        hsb.pack(side="left", fill="y")

        # ---------- status bar ----------
        sb = ttk.Frame(self, relief="sunken")
        sb.pack(side="bottom", fill="x")
        self.lbl_status = ttk.Label(
            sb, text="Idle — pick an interface, check authorization, Start.",
            style="Status.TLabel")
        self.lbl_status.pack(side="left")
        self.lbl_caps = ttk.Label(sb, text="", style="Status.TLabel")
        self.lbl_caps.pack(side="right")

        # context menu
        self.ctx = tk.Menu(self, tearoff=0)
        self.ctx.add_command(label="Copy summary", command=self._copy_summary)
        self.ctx.add_command(label="Copy raw hex", command=self._copy_hex)

    # ==================================================================
    # Capture lifecycle
    # ==================================================================
    def _refresh_ifaces(self):
        try:
            self._ifaces = list_interfaces()
        except Exception as e:  # noqa: BLE001
            self._ifaces = []
            messagebox.showerror("Interface discovery failed", str(e))
        self.iface_cb["values"] = [f.name for f in self._ifaces]
        if self._ifaces:
            self.iface_cb.current(0)

    def _start(self):
        if not self.authorized.get():
            messagebox.showwarning(
                "Authorization required",
                "Packet capture without authorization is illegal in most "
                "jurisdictions.\n\nCheck the authorization box only if you "
                "own this network or have written permission.")
            return
        idx = self.iface_cb.current()
        if idx < 0 or not self._ifaces:
            messagebox.showerror("No interface", "Select a network interface.")
            return
        ip = self._ifaces[idx].ip

        self.storage = Storage("packets.db")
        self.storage.log_consent(True)

        if self.pcap_var.get():
            path = filedialog.asksaveasfilename(
                defaultextension=".pcap",
                filetypes=[("PCAP files", "*.pcap")],
                initialfile=f"capture_{int(time.time())}.pcap")
            if path:
                self.pcap = PcapWriter(path)

        self.engine = CaptureEngine(
            ip, self.raw_q, self.stats,
            on_error=lambda m: self.after(0, messagebox.showerror,
                                          "Capture error", m))
        if not self.engine.start():
            self.engine = None
            return

        self.proc_threads, self.proc_stop = make_processor(
            self.raw_q, self.stats, self._on_packet)

        self.btn_start.config(state="disabled")
        self.btn_stop.config(state="normal")
        self.lbl_status.config(text=f"Capturing on {ip} … (admin/raw-socket)")
        self.stats.started_at = time.time()

    def _stop(self):
        if self.engine:
            self.engine.stop()
            self.engine = None
        if self.proc_stop:
            processor_stop(self.proc_stop)
            for t in self.proc_threads:
                t.join(timeout=1.5)
            self.proc_threads, self.proc_stop = [], None
        with self.pcap_lock:
            if self.pcap:
                self.pcap.close()
                self.pcap = None
        if self.storage:
            self.storage.stop()
            self.storage = None
        self.btn_start.config(state="normal")
        self.btn_stop.config(state="disabled")
        self.lbl_status.config(text="Stopped.")

    def _on_close(self):
        try:
            self._stop()
        finally:
            self.destroy()

    # ==================================================================
    # Packet ingestion (processor thread → UI thread)
    # ==================================================================
    def _on_packet(self, pkt: Packet):
        """Runs on PacketProcessor thread. Fan-out: UI queue, DB, PCAP, threat."""
        self.analyzer.analyze(pkt)
        self.seq += 1
        try:
            self.ui_q.put_nowait((self.seq, pkt))
        except queue.Full:
            pass
        if self.storage:
            self.storage.add_packet(
                (pkt.timestamp, pkt.src_ip, pkt.dst_ip, pkt.src_port,
                 pkt.dst_port, pkt.protocol, pkt.length,
                 pkt.info[:180], 0, pkt.raw_hex[:256]))
        if self.pcap:
            with self.pcap_lock:
                if self.pcap:
                    self.pcap.write_packet(pkt.timestamp, pkt.raw)

    # ==================================================================
    # UI drain + rendering
    # ==================================================================
    def _ui_tick(self):
        """Drain ui_q into the row store (GUI thread, every 33 ms)."""
        dirty = False
        try:
            for _ in range(5000):                    # bounded per tick
                seq, pkt = self.ui_q.get_nowait()
                self.rows[seq] = pkt
                self.row_order.append(seq)
                dirty = True
                if len(self.row_order) > theme.DISPLAY_MAX_ROWS:
                    old = self.row_order.pop(0)
                    self.rows.pop(old, None)
                    self._last_rendered.discard(old)
        except queue.Empty:
            pass
        if dirty:
            self._append_new_rows()
        self.after(self.UI_FLUSH_MS, self._ui_tick)

    def _passes_filter(self, pkt: Packet) -> bool:
        pm = pkt.protocol
        if pm == "TCP" and not self.f_tcp.get():
            return False
        if pm in ("UDP", "DNS") and not self.f_udp.get():
            return False
        if pm == "ICMP" and not self.f_icmp.get():
            return False
        if pm == "ARP" and not self.f_arp.get():
            return False
        if pm not in ("TCP", "UDP", "DNS", "ICMP", "ARP") \
                and not self.f_other.get():
            return False
        t = self.f_text.get().strip().lower()
        if t:
            hay = (f"{pkt.src_ip} {pkt.dst_ip} {pkt.src_port} {pkt.dst_port} "
                   f"{pkt.protocol} {pkt.info} "
                   f"{pkt.payload_ascii}").lower()
            if t not in hay:
                return False
        return True

    def _append_new_rows(self):
        """Incrementally append rows not yet rendered (append-only fast path)."""
        start = len(self._view)
        appended = False
        for seq in self.row_order[start:]:
            if self._passes_filter(self.rows[seq]):
                self._view.append(seq)
                appended = True
        if not appended and len(self._view) == start:
            return
        self._render_window()

    def _rebuild_view(self):
        """Full re-filter (called on any filter change)."""
        self._view = [s for s in self.row_order
                      if self._passes_filter(self.rows[s])]
        self._last_rendered.clear()
        self.tree.delete(*self.tree.get_children())
        self._render_window()

    def _render_window(self):
        """Render the tail of _view (last VIEW_WINDOW rows) incrementally."""
        window = self._view[-VIEW_WINDOW:]
        existing = set(self.tree.get_children())
        # evict rows that scrolled out of the window
        if len(existing) > len(window):
            self.tree.delete(*self.tree.get_children())
            existing.clear()
        # grow window at front if it shrank (e.g. after filter change)
        if not existing and window:
            pass
        for seq in window:
            key = str(seq)
            if key in existing:
                continue
            p = self.rows[seq]
            ts = p.timestamp
            tstr = (time.strftime("%H:%M:%S", time.localtime(ts))
                    + f".{int(ts * 1000) % 1000:03d}")
            tags = [p.protocol if p.protocol in theme.PROTO_TAG_COLORS
                    else "other"]
            if int(key) % 2 == 0:
                tags.append("stripe")
            self.tree.insert("", "end", iid=key,
                             values=(seq, tstr, p.src_ip, p.dst_ip,
                                     p.protocol, p.length, p.info),
                             tags=tags)
        # auto-scroll if user is at the bottom
        try:
            if self.tree.yview()[1] > 0.98 or not existing:
                self.tree.see(self.tree.get_children()[-1])
        except (tk.TclError, IndexError):
            pass

    def _on_select(self, _e=None):
        sel = self.tree.selection()
        if sel:
            self._render_detail(self.rows.get(int(sel[0])))

    # ==================================================================
    # Detail rendering
    # ==================================================================
    def _render_detail(self, p: Packet | None):
        self.txt_detail.config(state="normal")
        self.txt_detail.delete("1.0", "end")
        self.txt_hex.config(state="normal")
        self.txt_hex.delete("1.0", "end")
        if not p:
            self.txt_detail.config(state="disabled")
            self.txt_hex.config(state="disabled")
            return
        ind = "    "
        lines: list[tuple[str, str]] = []
        for i, layer in enumerate(p.layers):
            pad = ind * i
            lines.append(("hdr", f"{pad}▸ {layer}"))
            sub = ind * (i + 1)
            if layer == "ETH":
                lines.append(("kv", f"{sub}Destination: {p.dst_mac}   "
                                    f"Source: {p.src_mac}   "
                                    f"EtherType: 0x{p.ethertype:04x}"))
            elif layer == "IPv4":
                lines.append(("kv", f"{sub}{p.src_ip} → {p.dst_ip}   "
                                    f"TTL: {p.ttl}   ID: 0x{p.ip_id:04x}   "
                                    f"ToS: 0x{p.tos:02x}"))
            elif layer == "TCP":
                lines.append(("kv", f"{sub}Src Port: {p.src_port}   "
                                    f"Dst Port: {p.dst_port}   "
                                    f"Seq: {p.seq}   Ack: {p.ack}   "
                                    f"Win: {p.window}"))
                lines.append(("kv", f"{sub}Flags: {p.flags}   "
                                    f"Options: {p.tcp_options or '—'}"))
            elif layer == "UDP":
                lines.append(("kv", f"{sub}Src Port: {p.src_port}   "
                                    f"Dst Port: {p.dst_port}"))
            elif layer == "ICMP":
                lines.append(("kv", f"{sub}Type: {p.icmp_type}   "
                                    f"Code: {p.icmp_code}"))
            elif layer == "DNS" and p.dns:
                d = p.dns
                lines.append(("kv", f"{sub}TxID: 0x{d['id']:04x}   "
                                    f"{'Response' if d['response'] else 'Query'}"
                                    f"   RCODE: {d['rcode']}"))
                for q in d["queries"]:
                    lines.append(("kv", f"{sub}Q  {q['name']} "
                                        f"(type {q['type']})"))
                for a in d["answers"]:
                    lines.append(("kv", f"{sub}A  {a['name']} → {a['value']}"))
        if p.payload_ascii:
            lines.append(("hdr", "▸ Payload (ASCII preview)"))
            lines.append(("kv", f"{ind}{p.payload_ascii}"))
        for kind, text in lines:
            self.txt_detail.insert("end", text + "\n", kind)
        self.txt_detail.tag_config("hdr", foreground="#79c0ff",
                                   font=("Consolas", 9, "bold"))
        self.txt_detail.tag_config("kv", foreground="#c9d1d9")
        self.txt_detail.config(state="disabled")

        raw = p.raw if p.raw else (bytes.fromhex(p.raw_hex) if p.raw_hex else b"")
        for off in range(0, len(raw), 16):
            chunk = raw[off:off + 16]
            hexs = " ".join(f"{b:02x}" for b in chunk)
            asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            self.txt_hex.insert("end",
                                f"{off:08x}  {hexs:<47}  |{asc}|\n")
        self.txt_hex.config(state="disabled")

    # ==================================================================
    # Threats tab
    # ==================================================================
    def _on_threat_event(self, ev: ThreatEvent):
        # Persist per ARCHITECTURE.md §3.6 (events table = analyzer audit trail)
        if self.storage:
            self.storage.add_event(
                (ev.ts, ev.kind, ev.src_ip, ev.description, ev.severity))
        try:
            self.threat_q.put_nowait(ev)
        except queue.Full:
            pass

    def _drain_threats(self):
        try:
            while True:
                ev = self.threat_q.get_nowait()
                tstr = time.strftime("%H:%M:%S", time.localtime(ev.ts))
                self.threat_tree.insert(
                    "", 0,
                    values=(tstr, ev.severity.upper(), ev.kind,
                            ev.description),
                    tags=(ev.severity,))
                kids = self.threat_tree.get_children()
                if len(kids) > 500:
                    self.threat_tree.delete(kids[-1])
        except queue.Empty:
            pass
        self.after(500, self._drain_threats)

    # ==================================================================
    # Stats
    # ==================================================================
    def _stats_tick(self):
        s = self.stats.snapshot()
        self.lbl_pps.config(text=f"{s['pps']:.0f} pps")
        mins, secs = int(s["elapsed"] // 60), int(s["elapsed"] % 60)
        self.lbl_totals.config(text=(
            f"Captured : {s['captured']:,}\n"
            f"Parsed   : {s['parsed']:,}\n"
            f"Errors   : {s['parse_errors']:,}\n"
            f"Dropped  : {s['dropped']:,}\n"
            f"Uptime   : {mins:02d}:{secs:02d}"))
        counts: dict[str, int] = {}
        for p in list(self.rows.values())[-4000:]:
            counts[p.protocol] = counts.get(p.protocol, 0) + 1
        total = sum(counts.values()) or 1
        lines = [f"{proto:<10}{cnt:>7,}  " + "█" * max(1, int(20 * cnt / total))
                 for proto, cnt in sorted(counts.items(),
                                          key=lambda kv: -kv[1])[:8]]
        self.proto_bars.config(text="\n".join(lines) or "—")
        # pps sparkline
        c = self.canvas_pps
        c.delete("all")
        hist = self.stats.pps_history[-60:]
        if hist:
            w = c.winfo_width() or 200
            h = 90
            mx = max(hist) or 1
            pts = []
            for i, v in enumerate(hist):
                x = i * w / max(1, len(hist) - 1)
                y = h - (v / mx) * (h - 8) - 4
                pts += [x, y]
            if len(pts) >= 4:
                c.create_line(*pts, fill="#1f6feb", width=2)
            c.create_text(4, 4, anchor="nw", text=f"peak {mx:.0f} pps",
                          fill="#57606a", font=(theme.FONT_FAMILY, 8))
        self.after(1000, self._stats_tick)

    # ==================================================================
    # Exports / utils
    # ==================================================================
    def _export_csv(self):
        path = filedialog.asksaveasfilename(defaultextension=".csv",
                                            filetypes=[("CSV", "*.csv")])
        if not path:
            return
        rows = [(p.timestamp, p.src_ip, p.dst_ip, p.src_port, p.dst_port,
                 p.protocol, p.length, p.info)
                for p in (self.rows[s] for s in self.row_order if s in self.rows)]
        Exporter.to_csv(path, rows)
        messagebox.showinfo("Exported", f"CSV written: {path}")

    def _export_json(self):
        path = filedialog.asksaveasfilename(defaultextension=".json",
                                            filetypes=[("JSON", "*.json")])
        if not path:
            return
        rows = [(p.timestamp, p.src_ip, p.dst_ip, p.src_port, p.dst_port,
                 p.protocol, p.length, p.info)
                for p in (self.rows[s] for s in self.row_order if s in self.rows)]
        Exporter.to_json(path, rows)
        messagebox.showinfo("Exported", f"JSON written: {path}")

    def _clear(self):
        self.tree.delete(*self.tree.get_children())
        self.rows.clear()
        self.row_order.clear()
        self._view.clear()
        self._last_rendered.clear()

    def _copy_summary(self):
        sel = self.tree.selection()
        if not sel:
            return
        p = self.rows.get(int(sel[0]))
        if p:
            self.clipboard_clear()
            self.clipboard_append(
                f"{p.timestamp:.3f} {p.src_ip}:{p.src_port} → "
                f"{p.dst_ip}:{p.dst_port} {p.protocol} len={p.length} "
                f"{p.info}")

    def _copy_hex(self):
        sel = self.tree.selection()
        if not sel:
            return
        p = self.rows.get(int(sel[0]))
        if p:
            self.clipboard_clear()
            self.clipboard_append((p.raw or b"").hex())

    def _popup_menu(self, event):
        try:
            self.ctx.tk_popup(event.x_root, event.y_root)
        finally:
            self.ctx.grab_release()

    def _about(self):
        messagebox.showinfo(
            "About",
            "Raw-socket packet sniffer — defensive security tooling.\n\n"
            "Authorized monitoring only. Capture without consent is a crime "
            "in most jurisdictions.\n\nStack: Python stdlib "
            "(socket/struct/tkinter/sqlite3).")


def run():
    app = SnifferGUI()
    theme.apply_theme(app)
    app.mainloop()


if __name__ == "__main__":
    run()
