import os
import queue
import sys
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from forensics import (
    analysis,
    android,
    audit,
    compliance,
    config,
    evidence,
    extractor,
    reporter,
)

BG = "#0d1b2a"
PANEL = "#1b263b"
PANEL2 = "#12233b"
FG = "#e0e1dd"
DIM = "#778da9"
ACCENT = "#ffb703"
BLUE = "#4ea8de"
GREEN = "#2dcb8b"
ORANGE = "#e76f51"
PURPLE = "#9a7bd4"
RED = "#e05d5d"
ZONE_COLORS = {"intake": ORANGE, "acquisition": BLUE, "extraction": GREEN,
               "analysis": PURPLE, "reporting": ORANGE, "audit": DIM}


def fmt_bytes(n: int) -> str:
    n = int(n or 0)
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.2f} TB"


def apply_theme(root: tk.Tk) -> None:
    style = ttk.Style(root)
    try:
        style.theme_use("clam")
    except tk.TclError:
        pass
    style.configure(".", background=BG, foreground=FG, fieldbackground=PANEL2, font=("Segoe UI", 10))
    style.configure("TFrame", background=BG)
    style.configure("Panel.TFrame", background=PANEL)
    style.configure("Header.TLabel", background=BG, foreground=ACCENT, font=("Segoe UI", 15, "bold"))
    style.configure("Sub.TLabel", background=BG, foreground=DIM)
    style.configure("TLabel", background=BG, foreground=FG)
    style.configure("Panel.TLabel", background=PANEL, foreground=FG)
    style.configure("TLabelFrame", background=BG, foreground=BLUE, font=("Segoe UI", 10, "bold"))
    style.configure("TLabelframe.Label", background=BG, foreground=BLUE)
    style.configure("TButton", background=PANEL2, foreground=FG, bordercolor="#2b3a55", padding=6)
    style.map("TButton", background=[("active", "#1f3a5f"), ("disabled", "#16233b")],
              foreground=[("disabled", "#4a5a6f")])
    style.configure("Accent.TButton", background=ORANGE, foreground="#0d1b2a", font=("Segoe UI", 10, "bold"))
    style.map("Accent.TButton", background=[("active", ACCENT)])
    style.configure("TCheckbutton", background=BG, foreground=FG)
    style.map("TCheckbutton", background=[("active", BG)])
    style.configure("TRadiobutton", background=BG, foreground=FG)
    style.map("TRadiobutton", background=[("active", BG)])
    style.configure("TEntry", fieldbackground=PANEL2, foreground=FG, bordercolor="#2b3a55")
    style.configure("TCombobox", fieldbackground=PANEL2, foreground=FG)
    style.map("TCombobox", selectbackground=[("readonly", PANEL2)], selectforeground=[("readonly", FG)],
              fieldbackground=[("readonly", PANEL2)], foreground=[("readonly", FG)])
    style.configure("TNotebook", background=BG, borderwidth=0)
    style.configure("TNotebook.Tab", background=PANEL, foreground=DIM, padding=(14, 8),
                    font=("Segoe UI", 10, "bold"))
    style.map("TNotebook.Tab", background=[("selected", "#1f3a5f")], foreground=[("selected", FG)])
    style.configure("Treeview", background=PANEL2, fieldbackground=PANEL2, foreground=FG,
                    bordercolor="#2b3a55", rowheight=22)
    style.map("Treeview", background=[("selected", "#1f3a5f")], foreground=[("selected", FG)])
    style.configure("Treeview.Heading", background="#1f3a5f", foreground=ACCENT, font=("Segoe UI", 9, "bold"))
    style.configure("Horizontal.TProgressbar", background=GREEN, troughcolor=PANEL2, borderwidth=0)
    style.configure("Status.TLabel", background="#0a1522", foreground=DIM)


def run_async(root, fn, on_done, on_error=None):
    q = queue.Queue()

    def poll():
        try:
            kind, payload = q.get_nowait()
        except queue.Empty:
            root.after(60, poll)
            return
        if kind == "ok":
            on_done(payload)
        else:
            if on_error:
                on_error(payload)

    def runner():
        try:
            q.put(("ok", fn()))
        except Exception as exc:
            q.put(("err", exc))

    threading.Thread(target=runner, daemon=True).start()
    root.after(60, poll)


def setup_tree(parent, columns: dict[str, int]) -> ttk.Treeview:
    cols = list(columns.keys())
    tree = ttk.Treeview(parent, columns=cols, show="headings", height=10)
    for name, width in columns.items():
        tree.heading(name, text=name.replace("_", " ").title())
        tree.column(name, width=width, anchor="w")
    return tree


class DashboardTab(ttk.Frame):
    def __init__(self, app, nb):
        super().__init__(app.root)
        self.app = app
        self._build_ui()

    def _build_ui(self):
        row = ttk.Frame(self)
        row.pack(fill="x", padx=16, pady=(16, 6))
        ttk.Label(row, text="MOBILE DEVICE FORENSICS LAB", style="Header.TLabel").pack(side="left")
        ttk.Label(row, text="portable workstation · ISO 27001 · NIST · OWASP", style="Sub.TLabel").pack(side="right")

        main = tk.Frame(self, bg=BG)
        main.pack(fill="both", expand=True, padx=16, pady=6)

        left = ttk.Frame(main)
        left.pack(side="left", fill="both", expand=True)
        right = ttk.Frame(main)
        right.pack(side="right", fill="both", expand=True, padx=(12, 0))

        self.case_frame = ttk.LabelFrame(left, text="Active Case")
        self.case_frame.pack(fill="x")
        self.case_lbl = ttk.Label(self.case_frame, text="No case open — use File → New Case")
        self.case_lbl.pack(anchor="w", padx=10, pady=8)

        self.zone_frame = ttk.LabelFrame(left, text="Zone Status (NIST SP 800-101 pipeline)")
        self.zone_frame.pack(fill="x", pady=(12, 0))
        self.zone_rows = {}
        for zone, desc in [
            ("intake", "ZONE0 · Evidence intake & custody"), ("acquisition", "ZONE1 · Android backup"),
            ("extraction", "ZONE2 · Logical extraction"), ("analysis", "ZONE3 · Correlation"),
            ("reporting", "ZONE4 · Signed report export"), ("audit", "ZONE5 · WORM audit journal")]:
            fr = ttk.Frame(self.zone_frame)
            fr.pack(fill="x", padx=10, pady=4)
            dot = tk.Label(fr, text="  ●", fg=DIM, bg=PANEL, font=("Segoe UI", 12))
            dot.pack(side="left")
            ttk.Label(fr, text=desc, width=38).pack(side="left", padx=(8, 0))
            st = ttk.Label(fr, text="—", width=12)
            st.pack(side="right")
            self.zone_rows[zone] = (dot, st)

        comp = ttk.LabelFrame(right, text="Compliance Snapshot")
        comp.pack(fill="x")
        self.comp_txt = tk.Text(comp, height=6, bg=PANEL2, fg=FG, bd=0, insertbackground=FG,
                                font=("Consolas", 9), highlightthickness=1, highlightbackground="#2b3a55")
        self.comp_txt.pack(fill="both", expand=True, padx=8, pady=8)
        self.comp_txt.tag_configure("green", foreground=GREEN)
        self.comp_txt.insert("end", "ISO 27001:2022  Annex A controls  — assessed\n")
        self.comp_txt.insert("end", "NIST SP 800-101/124 — workflow aligned\n")
        self.comp_txt.insert("end", "OWASP Top 10      — portal/tooling secured\n", )

        btf = ttk.Frame(right)
        btf.pack(fill="x", pady=(10, 0))
        ttk.Button(btf, text="✚ New Case", style="Accent.TButton", command=self.app.new_case).pack(side="left", fill="x", expand=True)
        ttk.Button(btf, text="\u2b73 Open Case", command=self.app.open_case).pack(side="left", fill="x", expand=True, padx=(8, 0))

        logf = ttk.LabelFrame(main, text="Activity Log · tamper-evident journal")
        logf.pack(side="bottom", fill="both", expand=True, pady=(12, 0))
        self.log = tk.Text(logf, height=12, bg="#0a1522", fg=FG, bd=0, wrap="word",
                           insertbackground=FG, font=("Consolas", 9),
                           highlightthickness=1, highlightbackground="#2b3a55")
        sb = ttk.Scrollbar(logf, command=self.log.yview)
        self.log.configure(yscrollcommand=sb.set)
        self.log.pack(side="left", fill="both", expand=True, padx=(8, 0), pady=8)
        sb.pack(side="right", fill="y", padx=(0, 8), pady=8)
        for tag, color in (("ok", GREEN), ("warn", ORANGE), ("err", RED), ("act", BLUE), ("aud", PURPLE)):
            self.log.tag_configure(tag, foreground=color)

    def update(self):
        case = self.app.case
        if case is None:
            self.case_lbl.configure(text="No case open — use File → New Case")
            for zone, (dot, st) in self.zone_rows.items():
                dot.configure(fg=DIM)
                st.configure(text="—")
            return
        self.case_lbl.configure(
            text=f"{case.id}  ·  {case.title or '(untitled)'}\n"
                 f"Exhibits: {len(case.evidence)}   ·   {fmt_bytes(case.summary['total_bytes'])}"
                 f"   ·   opened {case.opened_at}")
        for zone, (dot, st) in self.zone_rows.items():
            state = case.zones.get(zone, "pending")
            dot.configure(fg=ZONE_COLORS.get(zone, DIM) if state in ("done", "acquired", "complete") else DIM)
            st.configure(text=state.upper())

    def logr(self, text, tag="act"):
        self.log.insert("end", text + "\n", tag)
        self.log.see("end")


class IntakeTab(ttk.Frame):
    def __init__(self, app):
        super().__init__(app.root)
        self.app = app
        self._build()

    def _build(self):
        box = ttk.LabelFrame(self, text="Register Evidence Exhibit (ISO 27037 intake)")
        box.pack(fill="x", padx=14, pady=(14, 0))
        g = ttk.Frame(box)
        g.pack(fill="x", padx=10, pady=8)
        ttk.Label(g, text="Exhibit ID").grid(row=0, column=0, sticky="w", padx=4, pady=3)
        ttk.Label(g, text="Source").grid(row=1, column=0, sticky="w", padx=4, pady=3)
        ttk.Label(g, text="Description").grid(row=2, column=0, sticky="w", padx=4, pady=3)
        self.ex_id = ttk.Entry(g, width=38)
        self.ex_id.grid(row=0, column=1, sticky="ew", padx=4, pady=3)
        self.ex_src = ttk.Combobox(g, width=36, values=["Android ADB backup (.ab)", "Logical extraction (USB)",
                                                        "Manual exhibit / documented artifact", "OEM cloud / API export"])
        self.ex_src.grid(row=1, column=1, sticky="ew", padx=4, pady=3)
        self.ex_src.set("Manual exhibit / documented artifact")
        self.ex_desc = ttk.Entry(g, width=38)
        self.ex_desc.grid(row=2, column=1, sticky="ew", padx=4, pady=3)
        ttk.Label(g, text="Reference file").grid(row=3, column=0, sticky="w", padx=4, pady=3)
        self.ex_path = ttk.Entry(g, width=38)
        self.ex_path.grid(row=3, column=1, sticky="ew", padx=4, pady=3)
        ttk.Button(g, text="Browse", command=self._browse).grid(row=3, column=2, padx=4)
        bt = ttk.Frame(box)
        bt.pack(fill="x", padx=10, pady=(0, 10))
        ttk.Button(bt, text="Register & Hash", style="Accent.TButton", command=self.register).pack(side="left")
        ttk.Button(bt, text="Create Sample Artifact (demo)", command=self.sample).pack(side="left", padx=8)
        ttk.Button(bt, text="Save Case", command=self.app.save_case).pack(side="left", padx=8)

        ttl = ttk.LabelFrame(self, text="Exhibits & Chain of Custody")
        ttl.pack(fill="both", expand=True, padx=14, pady=(12, 0))
        self.tree = setup_tree(ttl, {"exhibit": 90, "source": 170, "description": 220, "size": 90, "sha256": 340, "status": 80})
        self.tree.pack(fill="both", expand=True, padx=8, pady=8)

    def _browse(self):
        p = filedialog.askopenfilename(title="Select exhibit reference file")
        if p:
            self.ex_path.delete(0, "end")
            self.ex_path.insert(0, p)

    def _case_or_warn(self) -> bool:
        if self.app.case is None:
            messagebox.showwarning("No case", "Open or create a case first.")
            return False
        return True

    def register(self):
        if not self._case_or_warn():
            return
        case = self.app.case
        ex_id = self.ex_id.get().strip() or f"EXH-{len(case.evidence)+1:03d}"
        rec = evidence.EvidenceRecord(ex_id, self.ex_src.get(), self.ex_desc.get().strip() or ex_id)
        path = self.ex_path.get().strip()
        if path and Path(path).exists():
            dest = case.sub("acquired_files") / Path(path).name
            import shutil
            shutil.copy2(path, dest)
            rec.path = str(dest.relative_to(case.root))
            rec.source = rec.source
        if rec.path:
            rec.hash_if_missing(case.root)
        case.add_evidence(rec)
        case.set_zone("intake", "done")
        case.save()
        self.app.journal.append("examiner", "ZONE0", "exhibit.registered", f"{case.id} :: {ex_id}")
        self.refresh()
        self.app.log(f"Registered exhibit {ex_id} (sha256 {rec.sha256[:16]}…)", "ok")

    def sample(self):
        if not self._case_or_warn():
            return
        case = self.app.case
        d = case.sub("acquired_files", "demo")
        texts = [
            ("demo_chat_history.txt", "2026-09-21 14:02 meet at Pier 7, code word HELIOTROPE\n2026-09-20 09:15 transfer completed"),
            ("demo_note.txt", "stash location: QZ-44 coordinate 51.5074,-0.1278\ncontact: +1 555 013 449"),
        ]
        for name, content in texts:
            (d / name).write_text(content, encoding="utf-8")
        import sqlite3
        db = d / "app_messages.db"
        con = sqlite3.connect(db)
        con.execute("CREATE TABLE messages(msg_id INTEGER, sender TEXT, body TEXT, ts TEXT)")
        con.executemany("INSERT INTO messages VALUES (?,?,?,?)", [
            (1, "alice", "sending the HELIOTROPE file now", "2026-09-20T21:10:00Z"),
            (2, "bob", "confirmed", "2026-09-20T21:11:00Z"),
        ])
        con.commit()
        con.close()
        for f in ("demo_chat_history.txt", "demo_note.txt", "app_messages.db"):
            p = d / f
            rec = evidence.EvidenceRecord("EXH-DEMO-" + os.urandom(2).hex().upper(), "Manual exhibit / documented artifact", f)
            rec.path = str(p.relative_to(case.root))
            rec.hash_if_missing(case.root)
            case.add_evidence(rec)
        case.set_zone("intake", "done")
        case.save()
        self.app.journal.append("examiner", "ZONE0", "demo.artifacts", f"{case.id} :: sample exhibits created")
        self.refresh()
        self.app.log("Demo artifacts created + registered", "ok")

    def refresh(self):
        for i in self.tree.get_children():
            self.tree.delete(i)
        if self.app.case:
            for e in self.app.case.evidence:
                self.tree.insert("", "end", values=(
                    e.exhibit_id, e.source, e.description, fmt_bytes(e.size),
                    e.sha256[:40] + "…" if e.sha256 else "(not hashed)", e.status))
        self.app.dashboard.update()


class AcquisitionTab(ttk.Frame):
    def __init__(self, app):
        super().__init__(app.root)
        self.app = app
        self._build()

    def _build(self):
        top = ttk.LabelFrame(self, text="ZONE1 · Acquisition — Android device via ADB (write-blocked)")
        top.pack(fill="x", padx=14, pady=(14, 0))
        row = ttk.Frame(top)
        row.pack(fill="x", padx=10, pady=8)
        ttk.Button(row, text="🔍 Detect ADB", command=self.detect).pack(side="left")
        self.adb_lbl = ttk.Label(row, text="", width=46)
        self.adb_lbl.pack(side="left", padx=10)
        ttk.Button(row, text="↻ Re-scan", command=self.detect).pack(side="left")
        ttk.Label(row, text="Device:").pack(side="left", padx=(14, 0))
        self.dev_combo = ttk.Combobox(row, width=24, state="readonly")
        self.dev_combo.pack(side="left", padx=6)

        opts = ttk.Frame(top)
        opts.pack(fill="x", padx=10, pady=(0, 4))
        self.c_apk = tk.BooleanVar(value=True)
        self.c_shared = tk.BooleanVar(value=True)
        ttk.Checkbutton(opts, text="Include APK packages", variable=self.c_apk).pack(side="left", padx=4)
        ttk.Checkbutton(opts, text="Include shared storage", variable=self.c_shared).pack(side="left", padx=14)
        ttk.Label(opts, text="⚠ Full adb backup restricted on Android 12+; fallback = logical pull",
                  foreground=ORANGE).pack(side="right")

        acts = ttk.Frame(top)
        acts.pack(fill="x", padx=10, pady=(0, 10))
        ttk.Button(acts, text="▸ Run Android Backup (.ab)", style="Accent.TButton", command=self.backup).pack(side="left")
        ttk.Button(acts, text="▸ Logical Pull (fallback / no root)", command=self.logical).pack(side="left", padx=8)
        ttk.Button(acts, text="Open acquired files", command=self.open_dir).pack(side="left", padx=8)
        self.prog = ttk.Progressbar(acts, mode="indeterminate", length=160)
        self.prog.pack(side="right")

        box = ttk.LabelFrame(self, text="Acquisition Result")
        box.pack(fill="both", expand=True, padx=14, pady=(12, 0))
        self.log = tk.Text(box, bg="#0a1522", fg=FG, bd=0, wrap="word",
                           insertbackground=FG, font=("Consolas", 9),
                           highlightthickness=1, highlightbackground="#2b3a55")
        sb = ttk.Scrollbar(box, command=self.log.yview)
        self.log.configure(yscrollcommand=sb.set)
        self.log.pack(side="left", fill="both", expand=True, padx=8, pady=8)
        sb.pack(side="right", fill="y", padx=(0, 8), pady=8)
        for tag, color in (("ok", GREEN), ("warn", ORANGE), ("err", RED), ("info", BLUE)):
            self.log.tag_configure(tag, foreground=color)

    def _require(self):
        if self.app.case is None:
            messagebox.showwarning("No case", "Open or create a case first.")
            return False
        return True

    def detect(self):
        self.app.log("Scanning for adb…", "act")
        run_async(self.app, android.list_devices, self._on_detect,
                  on_error=lambda e: self._log(f"adb error: {e}", "err"))

    def _on_detect(self, devs):
        self.dev_combo["values"] = devs
        if devs:
            self.dev_combo.set(devs[0])
            self.adb_lbl.configure(text=f"{len(devs)} device(s) · {', '.join(devs[:3])}")
            self.app.log(f"adb present -> {len(devs)} device(s) found", "ok")
        else:
            self.adb_lbl.configure(text="no device / adb not found")
            self.app.log("No ADB devices detected (portable tool runs paper-mode fine)", "warn")

    def _busy(self, on):
        if on:
            self.prog.start(10)
        else:
            self.prog.stop()

    def backup(self):
        if not self._require():
            return
        case = self.app.case
        target = case.sub("acquisition") / f"{case.id}.ab"
        self._busy(True)
        self._log("Starting adb backup…", "info")

        def work():
            out = android.acquire_backup(target, self.c_apk.get(), self.c_shared.get())
            return out, target

        def done(res):
            _, t = res
            rec = evidence.EvidenceRecord(f"EXH-BU-{len(case.evidence)+1:03d}",
                                          "Android ADB backup (.ab)", f"full backup {t.name}")
            rec.path = str(t.relative_to(case.root))
            rec.hash_if_missing(case.root)
            case.add_evidence(rec)
            case.set_zone("acquisition", "done")
            case.save()
            self.app.journal.append("examiner", "ZONE1", "backup.acquired", f"{case.id} :: {t.name} :: {rec.sha256[:16]}…")
            self._busy(False)
            self._log(f"Backup stored: {t} ({fmt_bytes(rec.size)})", "ok")
            self._log(f"SHA-256: {rec.sha256}", "ok")
            self.app.log(f"Android backup captured: {t.name}", "ok")
            self.app.intake.refresh()
            self.app.dashboard.update()

        def fail(e):
            self._busy(False)
            self._log(f"Backup failed: {e}", "err")
            self.app.log(f"Backup failed: {e}", "err")

        run_async(self.app, work, done, fail)

    def logical(self):
        if not self._require():
            return
        case = self.app.case
        serial = self.dev_combo.get().strip()
        self._busy(True)
        self._log("Logical pull over USB debug bridge…", "info")

        def work():
            return android.logical_pull(serial, case.logical_dir)

        def done(result):
            ok = [k for k, v in result.items() if v == "ok"]
            self._busy(False)
            pulled = [p for p in case.logical_dir.rglob("*") if p.is_file()]
            n = len(pulled)
            total = sum(p.stat().st_size for p in pulled)
            self._log(f"Pulled dirs: {', '.join(ok)}", "ok")
            self._log(f"{n} files · {fmt_bytes(total)} staged in logical/", "ok")
            for name in ok[:2]:
                p = case.logical_dir / name
                files = [f for f in p.rglob("*") if f.is_file()][:3]
                for f in files:
                    self._log(f"   - {f.relative_to(case.root)}", "info")
            rec = evidence.EvidenceRecord(f"EXH-LG-{len(case.evidence)+1:03d}",
                                          "Logical extraction (USB)", f"logical pull {n} files")
            rec.path = "logical"
            rec.sha256 = "tree-hash on inventory"
            rec.size = total
            case.add_evidence(rec)
            if n:
                case.set_zone("acquisition", "done")
            case.save()
            self.app.journal.append("examiner", "ZONE1", "logical.pull", f"{case.id} :: {n} files, {fmt_bytes(total)}")
            self.app.log(f"Logical extraction complete: {n} files", "ok")
            self.app.intake.refresh()
            self.app.dashboard.update()

        def fail(e):
            self._busy(False)
            self._log(f"Logical pull failed: {e}", "err")

        run_async(self.app, work, done, fail)

    def open_dir(self):
        if self.app.case:
            os.startfile(str(self.app.case.logical_dir))

    def _log(self, text, tag="info"):
        self.log.insert("end", text + "\n", tag)
        self.log.see("end")


class ExtractionTab(ttk.Frame):
    def __init__(self, app):
        super().__init__(app.root)
        self.app = app
        self._build()

    def _build(self):
        top = ttk.Frame(self)
        top.pack(fill="x", padx=14, pady=(14, 6))
        ttk.Label(top, text="ZONE2 · Examination", style="Header.TLabel").pack(side="left")
        ttk.Button(top, text="▶ Run Inventory (hash + catalog)", style="Accent.TButton",
                   command=self.run).pack(side="right")

        self.summary = ttk.Label(self, text="", foreground=BLUE)
        self.summary.pack(anchor="w", padx=14)

        self.sq = ttk.LabelFrame(self, text="SQLite Databases (live phone metadata)")
        self.sq.pack(fill="both", expand=False, padx=14, pady=(8, 0))
        self.sq_tree = setup_tree(self.sq, {"path": 380, "tables": 90, "detail": 340})
        self.sq_tree.pack(fill="x", padx=8, pady=8)

        inv = ttk.LabelFrame(self, text="File Inventory (given /sdcard surface)")
        inv.pack(fill="both", expand=True, padx=14, pady=8)
        ctrl = ttk.Frame(inv)
        ctrl.pack(fill="x", padx=8, pady=(8, 0))
        ttk.Button(ctrl, text="Export inventory CSV", command=self.export_csv).pack(side="left")
        self.kind_lbl = ttk.Label(ctrl, text="", foreground=DIM)
        self.kind_lbl.pack(side="right")
        self.inv_tree = setup_tree(inv, {"path": 380, "size": 90, "ext": 60, "kind": 100, "sha256": 300})
        self.inv_tree.pack(fill="both", expand=True, padx=8, pady=8)

    def run(self):
        if self.app.case is None:
            messagebox.showwarning("No case", "Open or create a case first.")
            return
        case = self.app.case
        run_async(self.app,
                  lambda: extractor.run_inventory(case, case.logical_dir),
                  self._done, on_error=lambda e: messagebox.showerror("Inventory", str(e)))

    def _done(self, inv):
        case = self.app.case
        self.app.inventory = inv
        self.summary.configure(
            text=f"{inv['file_count']} files · {fmt_bytes(inv['total_size'])} · "
                 f"{len(inv['sqlite_databases'])} sqlite db(s) · sha256 per file")
        self.kind_lbl.configure(text=" | ".join(f"{k}={v}" for k, v in inv["categories"]["by_kind"].items()))
        for row in self.sq_tree.get_children():
            self.sq_tree.delete(row)
        for d in inv["sqlite_databases"]:
            meta = d["meta"]
            self.sq_tree.insert("", "end", values=(
                d["path"], meta["tables"], ", ".join(f"{t}:{n}" for t, n in list(meta["table_rows"].items())[:6])))
        n = 0
        for row in self.inv_tree.get_children():
            self.inv_tree.delete(row)
        for f in inv["files"]:
            if n >= 2000:
                break
            self.inv_tree.insert("", "end", values=(f["path"], fmt_bytes(f["size"]),
                                                    f["ext"], f["kind"], f["sha256"][:32] + "…"))
            n += 1
        case.set_zone("extraction", "done")
        case.save()
        self.app.journal.append("examiner", "ZONE2", "inventory.run", f"{case.id} :: {inv['file_count']} files")
        self.app.log(f"Inventory complete: {inv['file_count']} files, {len(inv['sqlite_databases'])} dbs", "ok")
        self.app.dashboard.update()

    def export_csv(self):
        if not self.app.inventory:
            messagebox.showwarning("No inventory", "Run inventory first.")
            return
        p = extractor.inventory_csv(self.app.case, self.app.inventory)
        self.app.log(f"CSV exported -> {p}", "ok")
        messagebox.showinfo("Exported", f"Inventory CSV written to:\n{p}")


class AnalysisTab(ttk.Frame):
    def __init__(self, app):
        super().__init__(app.root)
        self.app = app
        self._build()

    def _build(self):
        top = ttk.LabelFrame(self, text="ZONE3 · Keyword Search & Timeline")
        top.pack(fill="x", padx=14, pady=(14, 0))
        g = ttk.Frame(top)
        g.pack(fill="x", padx=10, pady=8)
        ttk.Label(g, text="Keyword:").pack(side="left")
        self.kw = ttk.Entry(g, width=30)
        self.kw.pack(side="left", padx=8)
        self.scope = tk.StringVar(value="all")
        for val, lbl in (("all", "All files"), ("text", "Text-ish"), ("media", "Media")):
            ttk.Radiobutton(g, text=lbl, value=val, variable=self.scope).pack(side="left", padx=6)
        ttk.Button(g, text="Search", style="Accent.TButton", command=self.search).pack(side="left", padx=10)
        ttk.Button(g, text="Build Timeline", command=self.timeline).pack(side="left")

        hits = ttk.LabelFrame(self, text="Keyword Hits")
        hits.pack(fill="both", expand=True, padx=14, pady=(10, 0))
        self.hit_tree = setup_tree(hits, {"path": 460, "size": 90, "keyword": 120})
        self.hit_tree.pack(fill="both", expand=True, padx=8, pady=8)

        tl = ttk.LabelFrame(self, text="Timeline (artifact mtimes)")
        tl.pack(fill="both", expand=True, padx=14, pady=8)
        self.tl_tree = setup_tree(tl, {"timestamp": 180, "path": 520, "size": 90})
        self.tl_tree.pack(fill="both", expand=True, padx=8, pady=8)

    def search(self):
        if self.app.case is None:
            messagebox.showwarning("No case", "Open or create a case first.")
            return
        kw = self.kw.get().strip()
        if not kw:
            return
        root = self.app.case.logical_dir
        run_async(self.app, lambda: analysis.search_in_dir(root, kw, self.scope.get()), self._hits)

    def _hits(self, hits):
        self.app.keyword_hits = hits
        for row in self.hit_tree.get_children():
            self.hit_tree.delete(row)
        for h in hits:
            self.hit_tree.insert("", "end", values=(h["path"], fmt_bytes(h["size"]), h["needle"]))
        self.app.log(f"Search found {len(hits)} hit(s)", "ok")
        messagebox.showinfo("Search", f"{len(hits)} file(s) matched.")

    def timeline(self):
        if self.app.case is None:
            messagebox.showwarning("No case", "Open or create a case first.")
            return
        root = self.app.case.logical_dir
        run_async(self.app, lambda: analysis.build_timeline(root), self._tl)

    def _tl(self, rows):
        self.app.timeline_rows = rows
        for r in self.tl_tree.get_children():
            self.tl_tree.delete(r)
        for r in rows:
            self.tl_tree.insert("", "end", values=(r["ts"], r["path"], fmt_bytes(r["size"])))
        self.app.log(f"Timeline built: {len(rows)} events", "ok")


class ReportTab(ttk.Frame):
    def __init__(self, app):
        super().__init__(app.root)
        self.app = app
        self._build()

    def _build(self):
        left = ttk.LabelFrame(self, text="ZONE4 · Export Formats (SDF-style, signed)")
        left.pack(side="left", fill="y", padx=14, pady=(14, 0))
        self.fmts = {}
        for f, lbl in (("pdf", "PDF — court-ready"), ("docx", "DOCX — editable/redactable"),
                       ("xml", "XML (SDF) — machine ingest"), ("json", "JSON — tooling pipeline"),
                       ("csv", "CSV — tables"), ("html", "HTML — interactive viewer")):
            v = tk.BooleanVar(value=f == "pdf")
            self.fmts[f] = v
            ttk.Checkbutton(left, text=lbl, variable=v).pack(anchor="w", padx=14, pady=3)
        ttk.Label(left, text="\nIncludes: exhibits · inventory · keywords ·\ntimeline · audit trail · zone status.\n",
                  style="Sub.TLabel").pack(anchor="w", padx=14, pady=6)
        ttk.Button(left, text="⚡ Generate Signed Reports", style="Accent.TButton",
                   command=self.generate).pack(fill="x", padx=14, pady=4)
        ttk.Button(left, text="Open Reports Folder", command=self.open_dir).pack(fill="x", padx=14, pady=4)

        right = ttk.LabelFrame(self, text="Produced & Signed Deliverables (HMAC-SHA256 manifest)")
        right.pack(side="right", fill="both", expand=True, padx=(0, 14), pady=(14, 0))
        self.tree = setup_tree(right, {"format": 80, "file": 280, "signature": 360})
        self.tree.pack(fill="both", expand=True, padx=8, pady=8)
        self.info = ttk.Label(self, text="", foreground=GREEN)
        self.info.pack(side="bottom", anchor="w", padx=14, pady=8)

    def generate(self):
        if self.app.case is None:
            messagebox.showwarning("No case", "Open or create a case first.")
            return
        case = self.app.case
        formats = [f for f, v in self.fmts.items() if v.get()]
        if not formats:
            messagebox.showwarning("Nothing selected", "Pick at least one format.")
            return
        data = reporter.build_report_data(case, self.app.inventory, self.app.keyword_hits,
                                          self.app.timeline_rows)
        made = reporter.generate_all(case, data, formats)
        for row in self.tree.get_children():
            self.tree.delete(row)
        for m in made:
            self.tree.insert("", "end", values=(m["format"].upper(), m["path"], m["hmac_sha256"][:40] + "…"))
        case.set_zone("reporting", "done")
        case.save()
        self.app.journal.append("examiner", "ZONE4", "report.generated",
                                f"{case.id} :: {', '.join(m['format'] for m in made)}")
        self.info.configure(text=f"Generated {len(made)} signed deliverable(s) in {case.reports_dir}")
        self.app.log(f"Reports generated: {', '.join(m['format'] for m in made)}", "ok")
        self.app.dashboard.update()

    def open_dir(self):
        if self.app.case:
            os.startfile(str(self.app.case.reports_dir))


class AuditTab(ttk.Frame):
    def __init__(self, app):
        super().__init__(app.root)
        self.app = app
        self._build()

    def _build(self):
        top = ttk.Frame(self)
        top.pack(fill="x", padx=14, pady=(14, 6))
        ttk.Label(top, text="ZONE5 · WORM Audit Journal", style="Header.TLabel").pack(side="left")
        ttk.Button(top, text="Refresh", command=self.refresh).pack(side="right")
        ttk.Button(top, text="Verify Hash Chain", style="Accent.TButton", command=self.verify).pack(side="right", padx=6)
        ttk.Button(top, text="Export Audit JSON", command=self.export).pack(side="right")

        box = ttk.LabelFrame(self, text="Journal entries (append-only, hash-linked)")
        box.pack(fill="both", expand=True, padx=14, pady=(6, 0))
        self.tree = setup_tree(box, {"n": 40, "ts": 180, "actor": 90, "zone": 80, "action": 200, "detail": 300})
        self.tree.pack(fill="both", expand=True, padx=8, pady=8)

        vf = ttk.LabelFrame(self, text="Verification Result")
        vf.pack(fill="both", expand=True, padx=14, pady=8)
        self.vlog = tk.Text(vf, height=7, bg="#0a1522", fg=FG, bd=0, wrap="word",
                            insertbackground=FG, font=("Consolas", 9),
                            highlightthickness=1, highlightbackground="#2b3a55")
        sb = ttk.Scrollbar(vf, command=self.vlog.yview)
        self.vlog.configure(yscrollcommand=sb.set)
        self.vlog.pack(side="left", fill="both", expand=True, padx=8, pady=8)
        sb.pack(side="right", fill="y", padx=(0, 8), pady=8)
        self.vlog.tag_configure("ok", foreground=GREEN)
        self.vlog.tag_configure("err", foreground=RED)

    def refresh(self):
        for r in self.tree.get_children():
            self.tree.delete(r)
        for e in self.app.journal.read():
            self.tree.insert("", "end", values=(e["n"], e["ts"], e["actor"], e["zone"], e["action"], e["detail"]))

    def verify(self):
        results = self.app.journal.verify()
        self.vlog.delete("1.0", "end")
        bad = 0
        for idx, ok, msg in results:
            self.vlog.insert("end", f"entry #{idx}: {msg}\n", "ok" if ok else "err")
            if not ok:
                bad += 1
        if not results:
            self.vlog.insert("end", "Journal empty — no entries to verify.\n")
        else:
            self.vlog.insert("end", f"\n{len(results) - bad}/{len(results)} entries intact.\n",
                             "ok" if bad == 0 else "err")

    def export(self):
        if not self.app.journal.read():
            messagebox.showinfo("Journal", "Journal is empty.")
            return
        p = self.app.vault / "exports" / "audit_export.json"
        self.app.journal.export(p)
        self.app.log(f"Audit journal exported -> {p}", "ok")
        messagebox.showinfo("Exported", f"Audit JSON written to:\n{p}")


class ComplianceTab(ttk.Frame):
    def __init__(self, app):
        super().__init__(app.root)
        self.app = app
        self._build()

    def _build(self):
        top = ttk.Frame(self)
        top.pack(fill="x", padx=14, pady=(14, 6))
        ttk.Label(top, text="Governance · ISO 27001 / NIST / OWASP", style="Header.TLabel").pack(side="left")
        self.score = ttk.Label(top, text="", foreground=GREEN)
        self.score.pack(side="right")

        frame = ttk.LabelFrame(self, text="Control Mapping Matrix")
        frame.pack(fill="both", expand=True, padx=14, pady=(6, 0))
        tree = setup_tree(frame, {"id": 50, "domain": 170, "ISO": 130, "NIST": 130, "OWASP": 90, "zone": 80, "note": 260})
        tree.pack(fill="both", expand=True, padx=8, pady=8)
        for c in compliance.CONTROL_MATRIX:
            tree.insert("", "end", values=(c["id"], c["domain"], c["iso"], c["nist"], c["owasp"], c["zone"], c["note"]))
        self.tree = tree

        o = ttk.LabelFrame(self, text="OWASP Top 10 · mapped posture")
        o.pack(fill="x", padx=14, pady=(0, 8))
        txt = tk.Text(o, height=6, bg=PANEL2, fg=FG, bd=0, wrap="word", font=("Consolas", 9),
                      highlightthickness=1, highlightbackground="#2b3a55")
        txt.pack(fill="x", padx=8, pady=8)
        txt.insert("end", "\n".join(f"  {k}  {v}" for k, v in compliance.OWASP.items()))
        txt.configure(state="disabled")

    def refresh(self):
        met = set()
        for z, st in (self.app.case.zones.items() if self.app.case else {}).items():
            if st in ("done", "complete", "acquired"):
                met.update([c["id"] for c in compliance.CONTROL_MATRIX if c["zone"].startswith("ZONE")])
        self.score.configure(text=f"Evidence-driven posture scoring")


def main():
    def _except_hook(etype, value, tb):
        import traceback
        crash_log = config.app_base_dir() / "crash.log"
        try:
            crash_log.write_text(
                "".join(traceback.format_exception(etype, value, tb)), encoding="utf-8")
        except OSError:
            pass
        import tkinter.messagebox as mbox
        try:
            mbox.showerror("Mobile Device Forensics Lab — Unhandled Exception",
                           f"{etype.__name__}: {value}\n\nDetails written to:\n{crash_log}")
        except Exception:
            pass

    sys.excepthook = _except_hook

    root = tk.Tk()
    root.title("Mobile Device Forensics Lab — Portable Workstation (ISO 27001 · NIST · OWASP)")
    root.geometry("1320x800")
    root.minsize(1120, 700)
    apply_theme(root)

    vault = config.default_vault()
    config.ensure_vault(vault)

    app = App(root, vault)
    root.mainloop()


class App:
    def __init__(self, root, vault):
        self.root = root
        self.vault = Path(vault)
        self.case = None
        self.journal = audit.AuditJournal(self.vault / "journal" / "audit.jsonl")
        self.inventory = None
        self.keyword_hits = []
        self.timeline_rows = []

        self.menu = tk.Menu(root)
        fmenu = tk.Menu(self.menu, tearoff=0, bg="#1b263b", fg="#e0e1dd")
        fmenu.add_command(label="✚ New Case", command=self.new_case)
        fmenu.add_command(label="⭮ Open Case…", command=self.open_case)
        fmenu.add_command(label="Save Case", command=self.save_case)
        fmenu.add_separator()
        fmenu.add_command(label="Exit", command=root.destroy)
        self.menu.add_cascade(label="File", menu=fmenu)
        hmenu = tk.Menu(self.menu, tearoff=0, bg="#1b263b", fg="#e0e1dd")
        hmenu.add_command(label="Open Evidence Vault", command=lambda: os.startfile(str(self.vault)))
        hmenu.add_command(label="About", command=self.about)
        self.menu.add_cascade(label="Help", menu=hmenu)
        root.configure(menu=self.menu)

        nb = ttk.Notebook(root)
        nb.pack(fill="both", expand=True, padx=8, pady=(8, 2))

        self.dashboard = DashboardTab(self, nb)
        self.intake = IntakeTab(self)
        self.acquisition = AcquisitionTab(self)
        self.extraction = ExtractionTab(self)
        self.analysis = AnalysisTab(self)
        self.report = ReportTab(self)
        self.audit = AuditTab(self)
        self.compliance = ComplianceTab(self)

        nb.add(self.dashboard, text="  📊 Dashboard ")
        nb.add(self.intake, text="  📦 Intake ")
        nb.add(self.acquisition, text="  🔌 Acquisition ")
        nb.add(self.extraction, text="  🧪 Extraction ")
        nb.add(self.analysis, text="  🔎 Analysis ")
        nb.add(self.report, text="  📤 Report ")
        nb.add(self.audit, text="  🔐 Audit ")
        nb.add(self.compliance, text="  🏛️ Compliance ")

        self.status = ttk.Label(root, text="Ready · vault: <vault>", style="Status.TLabel", anchor="w")
        self.status.pack(fill="x", side="bottom", padx=8, pady=(0, 6))
        self.journal.append("examiner", "ZONE5", "app.started", "workstation launched")
        self.log("Workstation ready · evidence vault initialized", "ok")
        self.dashboard.update()

    def log(self, text, tag="act"):
        self.dashboard.logr(text, tag)
        self.status.configure(text=f"{self.case.id if self.case else 'no case'} · {text[:60]}")

    def new_case(self):
        case_id = config.next_case_id(self.vault)
        root = config.case_root(self.vault, case_id)
        case = evidence.Case(case_id, root, title="", description="", examiner="examiner")
        case.save()
        self.case = case
        self.inventory = None
        self.keyword_hits = []
        self.timeline_rows = []
        for tab in (self.intake, self.acquisition, self.extraction, self.analysis,
                    self.report, self.audit):
            if hasattr(tab, "refresh"):
                tab.refresh()
        self.journal.append("examiner", "ZONE0", "case.created", f"{case_id} :: new case")
        self.log(f"New case {case_id} created", "ok")
        messagebox.showinfo("New Case", f"Created {case_id}\nEvidence vault: {root}")

    def open_case(self):
        p = filedialog.askopenfilename(title="Open case manifest",
                                       filetypes=[("Case manifest", "manifest.json")])
        if not p:
            return
        try:
            case = evidence.Case.open_existing(Path(p).parent)
        except Exception as exc:
            messagebox.showerror("Open Case", str(exc))
            return
        self.case = case
        self.inventory = None
        self.keyword_hits = []
        self.timeline_rows = []
        if case.inventory_path.exists():
            import json as _json
            self.inventory = _json.loads(case.inventory_path.read_text(encoding="utf-8"))
        for tab in (self.intake, self.acquisition, self.extraction, self.analysis,
                    self.report, self.audit):
            if hasattr(tab, "refresh"):
                tab.refresh()
        self.journal.append("examiner", "ZONE5", "case.opened", f"{case.id} :: reopened from manifest")
        self.log(f"Case {case.id} opened", "ok")
        self.dashboard.update()

    def save_case(self):
        if self.case:
            self.case.save()
            self.log(f"Case {self.case.id} saved", "ok")
            messagebox.showinfo("Saved", f"Case {self.case.id} manifest updated.")

    def about(self):
        messagebox.showinfo(
            "About",
            "Mobile Device Forensics Lab — Portable\n\n"
            "Implements ZONE0-5 workflow from architecture.md:\n"
            "  ZONE0 Intake · ZONE1 ADB backup/logical · ZONE2 Extraction\n"
            "  ZONE3 Analysis · ZONE4 Signed reports · ZONE5 WORM audit\n\n"
            "Governance: ISO 27001:2022 · NIST SP 800-101/124 · OWASP Top 10\n"
            "           ISO 27037 · SWGDE · ACPO\n\n"
            "All data stays beside the executable (portable / air-gapped).")


if __name__ == "__main__":
    main()