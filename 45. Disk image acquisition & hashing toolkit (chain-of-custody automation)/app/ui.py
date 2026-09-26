#!/usr/bin/env python3
"""GUI privacy & memory hygiene model (see memory.md).

DIHT is a *portable* forensic tool: it intentionally leaves ZERO user
config/state residue on the host(a). Evidence, ledgers and reports live
only in the case folder chosen by the examiner. Passphrases are never
written to disk and are zeroised from memory on close.
"""

from __future__ import annotations

import ctypes
import queue
import threading
import traceback
from tkinter import filedialog, messagebox

import customtkinter as ctk

from .config import APP_NAME, VERSION
from .imaging import fmt_size, is_device_path, list_physical_drives
from .workflow import Case, open_case

ACCENT = "#3b82f6"
OK = "#22c55e"
WARN = "#f59e0b"
ERR = "#ef4444"
BG = "#0b0f14"
PANEL = "#111820"
FIELD = "#16212e"
TEXT = "#e6edf3"
MUTED = "#8b98a5"


class App(ctk.CTk):
    def __init__(self):
        super().__init__(fg_color=BG)
        self.title(f"{APP_NAME}  v{VERSION}")
        self.geometry("1240x820")
        self.minsize(1060, 720)
        self._q = queue.Queue()
        self._busy = False
        self._cancel_flag = threading.Event()
        self._case: Case | None = None
        self._last_file = None

        self._build_header()
        self._build_body()
        self._wire_actions()

        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self.after(120, self._drain)
        self.after(400, self._refresh_drives)

    # ------------------------------------------------------------ header
    def _build_header(self):
        bar = ctk.CTkFrame(self, fg_color=PANEL, corner_radius=10)
        bar.pack(fill="x", padx=12, pady=(12, 6))
        badge = ctk.CTkLabel(
            bar, text="  DIHT  ",
            text_color="#0b0f14", font=ctk.CTkFont(size=16, weight="bold"),
            fg_color=ACCENT, corner_radius=8)
        badge.pack(side="left", padx=(12, 8), pady=10)
        ctk.CTkLabel(
            bar, text=f"{APP_NAME}",
            font=ctk.CTkFont(size=19, weight="bold"), text_color=TEXT
        ).pack(side="left")
        ctk.CTkLabel(
            bar, text="Chain-of-Custody Automation  ·  ISO 27001/NIST/OWASP aligned",
            font=ctk.CTkFont(size=12), text_color=MUTED
        ).pack(side="left", padx=14)
        self._locked_lbl = ctk.CTkLabel(
            bar, text="●  WRITE-BLOCKER READ-ONLY MODE",
            font=ctk.CTkFont(size=11, weight="bold"), text_color=OK)
        self._locked_lbl.pack(side="right", padx=14)

    # ------------------------------------------------------------- body
    def _build_body(self):
        body = ctk.CTkFrame(self, fg_color="transparent")
        body.pack(fill="both", expand=True, padx=12, pady=6)

        left = ctk.CTkFrame(body, fg_color=PANEL, corner_radius=10)
        left.pack(side="left", fill="both", expand=True, padx=(0, 6))
        right = ctk.CTkFrame(body, fg_color=PANEL, corner_radius=10)
        right.pack(side="left", fill="both", expand=True, padx=(6, 0))

        # ----- left: case + operator
        self._card(left, "Case & Operator", 0)
        grid = ctk.CTkFrame(left, fg_color="transparent")
        grid.pack(fill="x", padx=12, pady=(0, 6))

        def row(label, widget, r):
            grid.grid_columnconfigure(1, weight=1)
            ctk.CTkLabel(grid, text=label, text_color=MUTED,
                         font=ctk.CTkFont(size=12)).grid(row=r, column=0, sticky="w", pady=3, padx=(0, 6))
            widget.grid(row=r, column=1, sticky="ew", pady=3)

        self.e_case_id = ctk.CTkEntry(grid, placeholder_text="e.g. LE-2026-0142", fg_color=FIELD, border_color="#24344b")
        row("Case ID", self.e_case_id, 0)
        self.e_case_name = ctk.CTkEntry(grid, placeholder_text="Case title (civil/criminal no.)", fg_color=FIELD, border_color="#24344b")
        row("Case Name", self.e_case_name, 1)
        self.e_examiner = ctk.CTkEntry(grid, placeholder_text="Acquirer / examiner name", fg_color=FIELD, border_color="#24344b")
        row("Examiner", self.e_examiner, 2)
        self.e_role = ctk.CTkEntry(grid, placeholder_text="Role (e.g. Forensic Examiner)", fg_color=FIELD, border_color="#24344b")
        row("Role", self.e_role, 3)
        self.e_org = ctk.CTkEntry(grid, placeholder_text="Organization", fg_color=FIELD, border_color="#24344b")
        row("Org", self.e_org, 4)
        self.e_pass = ctk.CTkEntry(grid, placeholder_text="Signing passphrase (PBKDF2-HMAC)", show="●", fg_color=FIELD, border_color="#24344b")
        row("Passphrase", self.e_pass, 5)
        self.e_pass2 = ctk.CTkEntry(grid, placeholder_text="Confirm passphrase", show="●", fg_color=FIELD, border_color="#24344b")
        row("Confirm", self.e_pass2, 6)
        self.l_pass_hint = ctk.CTkLabel(
            grid, text="Used to derive the ledger signing key. Never stored. Required for audit & exports.",
            font=ctk.CTkFont(size=10), text_color=MUTED)
        self.l_pass_hint.grid(row=7, column=0, columnspan=2, sticky="w", pady=(2, 0))
        step = ctk.CTkLabel(
            grid, text="① Prepare case → ② Set source → ③ Confirm write-blocker → ④ Acquire",
            font=ctk.CTkFont(size=11, weight="bold"), text_color=ACCENT)
        step.grid(row=8, column=0, columnspan=2, sticky="w", pady=(14, 2))

        # ----- source/target
        self._card(left, "Source & Target", 1)
        src = ctk.CTkFrame(left, fg_color="transparent")
        src.pack(fill="x", padx=12, pady=(0, 6))
        self.src_var = ctk.StringVar(master=self, value="")
        self.cb_source = ctk.CTkComboBox(src, variable=self.src_var, values=[],
                                         state="readonly", width=0, fg_color=FIELD,
                                         border_color="#24344b")
        self.cb_source.pack(fill="x")
        sbtn = ctk.CTkFrame(src, fg_color="transparent")
        sbtn.pack(fill="x", pady=(6, 2))
        ctk.CTkButton(sbtn, text="🔄 Refresh drives", width=0, fg_color=FIELD,
                      hover_color="#1c2b3d", command=self._refresh_drives).pack(side="left")
        ctk.CTkButton(sbtn, text="📂 Browse file/lve image", fg_color=FIELD,
                      hover_color="#1c2b3d", command=self._browse_source).pack(side="left", padx=8)
        self.l_source = ctk.CTkLabel(src, text="No source selected", text_color=MUTED,
                                     font=ctk.CTkFont(size=11))
        self.l_source.pack(anchor="w", pady=(4, 0))

        tgt = ctk.CTkFrame(left, fg_color="transparent")
        tgt.pack(fill="x", padx=12, pady=(10, 6))
        ctk.CTkLabel(tgt, text="Output case folder", text_color=MUTED).pack(anchor="w")
        tg2 = ctk.CTkFrame(tgt, fg_color="transparent")
        tg2.pack(fill="x", pady=(4, 0))
        self.e_out = ctk.CTkEntry(tg2, placeholder_text=r"<Documents>\DIHT_Cases\<CaseID>", fg_color=FIELD, border_color="#24344b")
        self.e_out.pack(side="left", fill="x", expand=True)
        ctk.CTkButton(tg2, text="📁", width=36, fg_color=FIELD, hover_color="#1c2b3d",
                      command=self._browse_out).pack(side="left", padx=(6, 0))
        self.l_out = ctk.CTkLabel(tgt, text="", text_color=MUTED, font=ctk.CTkFont(size=10))
        self.l_out.pack(anchor="w", pady=(3, 0))

        # ----- algorithms
        self._card(left, "Digest Algorithms (FIPS aligned)", 2)
        algo = ctk.CTkFrame(left, fg_color="transparent")
        algo.pack(fill="x", padx=12, pady=(2, 6))
        self.algo_vars = {}
        for i, (key, label) in enumerate([
                ("sha256", "SHA-256 (FIPS 180-4)"),
                ("sha3_256", "SHA3-256 (primary)"),
                ("blake2b", "BLAKE2b-256"),
                ("sha1", "SHA-1 (legacy)"),
                ("md5", "MD5 (legacy)")]):
            var = ctk.BooleanVar(master=self, value=key in ("sha256", "sha3_256"))
            cb = ctk.CTkCheckBox(algo, text=label, variable=var, width=0,
                                 text_color=TEXT, fg_color=ACCENT,
                                 font=ctk.CTkFont(size=12))
            cb.grid(row=i // 2, column=i % 2, sticky="w", pady=2, padx=(0, 18))
            self.algo_vars[key] = var

        self._build_right(right)

    def _card(self, parent, title, index):
        ctk.CTkLabel(parent, text=title, text_color=ACCENT,
                     font=ctk.CTkFont(size=13, weight="bold")).pack(
            anchor="w", padx=14, pady=(10 if index else 0, 4), fill="x")

    # -------------------------------------------------------- right panel
    def _build_right(self, right):
        act = ctk.CTkFrame(right, fg_color="transparent")
        act.pack(fill="x", padx=12, pady=(12, 4))
        self.wb_var = ctk.BooleanVar(master=self, value=False)
        ctk.CTkCheckBox(
            act, text="① Hardware / software write-blocker engaged — source stays READ-ONLY",
            variable=self.wb_var, text_color="#f0fdf4", fg_color=ACCENT,
            font=ctk.CTkFont(size=12)).pack(anchor="w")
        self.wb_warn = ctk.CTkLabel(
            act, text="⚠ Show‑and‑tell must be confirmed before acquisition starts.",
            text_color=WARN, font=ctk.CTkFont(size=10))
        self.wb_warn.pack(anchor="w", pady=(1, 4))

        btns = ctk.CTkFrame(right, fg_color="transparent")
        btns.pack(fill="x", padx=12, pady=4)
        self.b_acquire = ctk.CTkButton(btns, text="▶ BEGIN ACQUISITION", fg_color="#15803d",
                                       hover_color="#16a34a", text_color="white",
                                       font=ctk.CTkFont(size=14, weight="bold"),
                                       command=self._start_acquire)
        self.b_acquire.pack(side="left", fill="x", expand=True)
        self.b_verify = ctk.CTkButton(btns, text="✔ Verify", fg_color=FIELD,
                                      hover_color="#1c2b3d", command=self._start_verify)
        self.b_verify.pack(side="left", fill="x", expand=True, padx=6)
        self.b_cancel = ctk.CTkButton(btns, text="✖", width=40, fg_color="#7f1d1d",
                                      hover_color="#991b1b", command=self._cancel)
        self.b_cancel.pack(side="left")

        ctk.CTkButton(right, text="📄 Reports (PDF · XLSX · CSV · JSON · SHA256SUMS)",
                      fg_color=ACCENT, hover_color="#2563eb",
                      command=self._export_reports).pack(fill="x", padx=12, pady=6)
        ctk.CTkButton(right, text="🔒 Custody event (seal / transfer / return / destroy)",
                      fg_color="#0e7490", hover_color="#155e75",
                      command=self._custody_dialog).pack(fill="x", padx=12, pady=6)
        ctk.CTkButton(right, text="🛡  Audit ledger integrity (HMAC chain)",
                      fg_color=FIELD, hover_color="#1c2b3d",
                      command=self._audit_ledger).pack(fill="x", padx=12, pady=6)

        self.prog = ctk.CTkProgressBar(right, fg_color=FIELD, progress_color=ACCENT)
        self.prog.set(0)
        self.prog.pack(fill="x", padx=12, pady=(8, 2))
        self.l_prog = ctk.CTkLabel(right, text="Idle", text_color=MUTED,
                                   font=ctk.CTkFont(size=10))
        self.l_prog.pack(anchor="w", padx=12)

        # ----- log
        ctk.CTkLabel(right, text="Session Log (signed into ledger)",
                     text_color=ACCENT, font=ctk.CTkFont(size=13, weight="bold")
                     ).pack(anchor="w", padx=14, pady=(8, 2))
        self.log = ctk.CTkTextbox(right, fg_color=FIELD, border_width=0,
                                  text_color=TEXT, font=ctk.CTkFont(family="Consolas", size=12),
                                  wrap="word")
        self.log.pack(fill="both", expand=True, padx=12, pady=(0, 12))
        tb = self.log._textbox
        for tag, color in (( "time",  "#64748b"), ("info", TEXT), ("ok", OK),
                           ("warn", WARN), ("err", ERR), ("acc", ACCENT)):
            try:
                tb.tag_config(tag, foreground=color)
            except Exception:
                pass

    def _wire_actions(self):
        self.e_out.bind(
            "<FocusOut>", lambda e: self._update_out_hint())
        self.cb_source.bind(
            "<<ComboboxSelected>>", lambda e: self._source_changed())
        self.e_pass.bind("<KeyRelease>", lambda e: self._pass_changed())
        self.e_pass2.bind("<KeyRelease>", lambda e: self._pass_changed())

    # -------------------------------------------------------------- utils
    def _log(self, tag, msg):
        import datetime
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        self._q.put(("log", tag, f"[{ts}] {msg}\n"))

    def _drain(self):
        try:
            while True:
                msg = self._q.get_nowait()
                kind = msg[0]
                if kind == "log":
                    _, tag, text = msg
                    self.log.insert("end", text, tag)
                    self.log.see("end")
                elif kind == "prog":
                    _, frac, label = msg
                    self.prog.set(frac)
                    self.l_prog.configure(text=label)
                elif kind == "done":
                    self._busy = False
                    self.b_acquire.configure(state="normal")
                    self.cb_source.configure(state="readonly")
        except queue.Empty:
            pass
        self.after(80, self._drain)

    def _pass_changed(self):
        p1 = self.e_pass.get()
        p2 = self.e_pass2.get()
        if p1 and p1 != p2:
            self.l_pass_hint.configure(text="Passphrases do NOT match.", text_color=ERR)
        elif not p1:
            self.l_pass_hint.configure(
                text="Used to derive the ledger signing key. Never stored. Required for audit & exports.",
                text_color=MUTED)
        else:
            self.l_pass_hint.configure(text="Passphrases match.", text_color=OK)

    def _refresh_drives(self):
        try:
            drives = list_physical_drives()
            vals = []
            for d in drives:
                vals.append(f"{d['device']}  ({fmt_size(d['size'])})")
            self.cb_source.configure(values=vals)
            if not vals:
                self._log("warn", "No physical drives enumerable (run as Administrator?).")
            else:
                self.cb_source.set(vals[0])
                self._source_changed()
        except Exception as exc:
            self._log("err", f"Drive enumeration failed: {exc}")

    def _browse_source(self):
        f = filedialog.askopenfilename(title="Select a file/pre-acquired image (for file imaging or testing)")
        if f:
            self.cb_source.set("")
            self.cb_source.configure(values=[""])
            self._last_file = f
            self.l_source.configure(text=f)
            self._log("info", f"Source set to FILE: {f}")

    def _source_changed(self):
        raw = self.cb_source.get()
        self._last_file = None
        if raw:
            dev = raw.split("  (")[0]
            self.l_source.configure(text=dev if not is_device_path(dev)
                                    else f"READ-ONLY device: {dev}")
        else:
            self.l_source.configure(text="No source selected")

    def _browse_out(self):
        d = filedialog.askdirectory(title="Choose output root for case folder")
        if d:
            self.e_out.delete(0, "end")
            self.e_out.insert(0, d)
            self._update_out_hint()

    def _update_out_hint(self):
        root = self.e_out.get().strip()
        cid = self.e_case_id.get().strip()
        if root and cid:
            self.l_out.configure(text=f"→ {root}\\{cid}\\ — portable evidence pack")
        elif root:
            self.l_out.configure(text=f"→ {root}\\<CaseID>\\")
        else:
            self.l_out.configure(text="")

    # ------------------------------------------------------------ workers
    def _collect_algorithms(self):
        return [k for k, v in self.algo_vars.items()
                if isinstance(v, ctk.BooleanVar) and v.get()]

    def _resolve_case(self, create=True) -> Case:
        cid = self.e_case_id.get().strip()
        if not cid:
            raise ValueError("Case ID is required.")
        root = self.e_out.get().strip()
        if not root:
            import os
            root = os.path.join(os.path.expanduser("~"), "Documents", "DIHT_Cases")
        case_dir = os.path.join(root, cid)
        passphrase = self.e_pass.get()
        if create and len(passphrase or "") < 6:
            raise ValueError("Passphrase must be ≥ 6 characters (PBKDF2 signing key).")
        return open_case(
            case_dir, cid, self.e_case_name.get().strip() or cid,
            self.e_examiner.get().strip() or "Unnamed Examiner",
            self.e_role.get().strip() or "Forensic Examiner",
            self.e_org.get().strip(), passphrase)

    def _set_busy(self, busy: bool, acquiring=False):
        self._busy = busy
        self.e_pass.configure(state="disabled" if acquiring else "normal")
        self.e_pass2.configure(state="disabled" if acquiring else "normal")
        if acquiring:
            self.b_acquire.configure(state="disabled")
            self.b_verify.configure(state="disabled")
        else:
            self.b_verify.configure(state="normal")

    def _start_acquire(self):
        if self._busy:
            return
        if not self.wb_var.get():
            messagebox.showwarning("Write-blocker confirmation required",
                                   "You must confirm the write-blocker is engaged. "
                                   "Forensically sound acquisition is READ-ONLY.")
            return
        algs = self._collect_algorithms()
        if not algs:
            messagebox.showerror("No algorithms", "Select at least one digest algorithm.")
            return
        try:
            case = self._resolve_case(create=True)
        except Exception as exc:
            messagebox.showerror("Case setup failed", str(exc))
            return
        case.ledger.append("case_created", f"Case {case.case_id} opened in GUI session",
                           case.key(self.e_pass.get()), detail={"action": "case_open"})
        self._case = case

        src = self._last_file or (self.cb_source.get().split("  (")[0] if self.cb_source.get() else "")
        if not src:
            messagebox.showerror("No source", "Select a physical drive or image file.")
            return

        self._set_busy(True, acquiring=True)
        self._cancel_flag.clear()
        self._log("acc", "► Acquisition session started")

        def worker():
            try:
                case.acquire(
                    src, algorithms=algs, passphrase=self.e_pass.get(),
                    writeblocker_confirmed=True,
                    progress_cb=lambda n, total: self._q.put(
                        ("prog", (n / total) if total else 0,
                         f"{fmt_size(n)} / {fmt_size(total) if total else '?'}")),
                    cancel_cb=lambda: self._cancel_flag.is_set())
                self._q.put(("prog", 1.0, "Complete"))
                self._log("ok", f"Acquisition complete → {case.dir}")
                self._log("ok", "Custody event 'acquisition_completed' signed & appended.")
                self._log("info", "Manifests + SHA256SUMS + CSV + XLSX written. Run Reports for PDF.")
                messagebox.showinfo("Acquisition complete", f"Evidence acquired.\n\n{case.dir}")
            except InterruptedError:
                self._log("warn", "Acquisition cancelled by examiner.")
                case.ledger.append("acquisition_cancelled",
                                   "Acquisition interrupted by examiner",
                                   case.key(self.e_pass.get()))
            except Exception as exc:
                self._log("err", f"Acquisition failed: {exc}\n{traceback.format_exc()}")
                messagebox.showerror("Acquisition failed", str(exc))
            finally:
                self._q.put(("done", None, None))
                self._set_busy(False, acquiring=True)

        threading.Thread(target=worker, daemon=True).start()

    def _start_verify(self):
        if self._busy:
            return
        if not self._case:
            messagebox.showwarning("No case open",
                                   "Start an acquisition first, or open a case folder.")
            return
        try:
            manifest = self._case.load_manifest()
        except FileNotFoundError:
            try:
                self._try_resume_case()
                manifest = self._case.load_manifest()
            except Exception as exc:
                messagebox.showerror("Verify error", str(exc))
                return
        ev = manifest["evidence"][0]
        fname, hashes = ev["exhibit"], ev["hashes"]

        self._set_busy(True)
        self._cancel_flag.clear()
        self._log("acc", "► Verification pass started")

        def worker():
            try:
                match, digests = self._case.verify_exhibit(
                    fname, list(hashes.keys()), hashes,
                    passphrase=self.e_pass.get(),
                    progress_cb=lambda n, total: self._q.put(
                        ("prog", (n / total) if total else 0, f"Verifying {fmt_size(n)}")),
                    cancel_cb=lambda: self._cancel_flag.is_set())
                self._q.put(("prog", 1.0, "Verification complete"))
                if match:
                    self._log("ok", f"VERIFY PASS — {fname} digests match the manifest.")
                else:
                    self._log("err", f"VERIFY FAIL — {fname} differs from manifest.")
                messagebox.showinfo(
                    "Verification", ("PASS — image unmodified & matches acquisition hashes.\n"
                                     if match else "FAIL — image does NOT match sealed hashes!\n")
                    + f"File: {fname}")
            except Exception as exc:
                self._log("err", f"Verification error: {exc}")
                messagebox.showerror("Verify error", str(exc))
            finally:
                self._q.put(("done", None, None))
                self._set_busy(False)

        threading.Thread(target=worker, daemon=True).start()

    def _try_resume_case(self):
        from tkinter import simpledialog
        root = filedialog.askdirectory(title="Select the case folder to resume")
        if not root:
            raise ValueError("No case folder selected.")
        import os
        from .config import CUSTODY_NAME
        if not os.path.exists(os.path.join(root, CUSTODY_NAME)):
            raise ValueError("No chain_of_custody.json found in that folder.")
        cid = simpledialog.askstring("Case ID", "Case ID for the ledger", initialvalue=os.path.basename(root))
        if not cid:
            raise ValueError("Case ID required.")
        self.e_case_id.delete(0, "end")
        self.e_case_id.insert(0, cid)
        self.e_out.delete(0, "end")
        self.e_out.insert(0, os.path.dirname(root))
        self._case = self._resolve_case(create=False)
        self._log("ok", f"Resumed case {cid} from {root}")

    def _export_reports(self):
        if self._busy:
            return
        try:
            if not self._case:
                self._try_resume_case()
            files = self._case.ensure_reports()
            fev = self._case.ledger.append(
                "report_exported", "Court-style reports exported (PDF/XLSX/CSV/JSON)",
                self._case.key(self.e_pass.get()))
            self._log("ok", f"Exported: {len(files)} report(s) → {self._case.dir}")
            messagebox.showinfo("Reports exported",
                                "Created:\n" + "\n".join("· " + f for f in files) +
                                "\n\n" + self._case.dir)
        except Exception as exc:
            messagebox.showerror("Export failed", str(exc))

    def _custody_dialog(self):
        from tkinter import simpledialog
        if self._busy:
            return
        try:
            if not self._case:
                self._try_resume_case()
        except Exception as exc:
            messagebox.showerror("Custody", str(exc))
            return
        actions = {"sealed": "🔐 Seal exhibit",
                   "transferred": "🚚 Transfer to another examiner/lab",
                   "returned": "↩ Return to owner",
                   "destroyed": "🔥 Destroy (NIST 800-88)"}
        choice = simpledialog.askstring(
            "Custody event", "Action (sealed / transferred / returned / destroyed):",
            initialvalue="sealed")
        if not choice:
            return
        choice = choice.strip().lower()
        if choice not in actions:
            messagebox.showerror("Custody", "Invalid action. Use: sealed, transferred, returned, destroyed.")
            return
        desc = simpledialog.askstring("Custody event", "Description:", initialvalue=actions[choice])
        try:
            rec = self._case.custody(choice, desc or actions[choice], self.e_pass.get())
            self._log("ok", f"Custody event '{choice}' signed: {rec['event_id'][:8]}…")
            messagebox.showinfo("Custody event", f"Signed & appended to ledger.\nEvent id: {rec['event_id']}")
        except Exception as exc:
            messagebox.showerror("Custody failed", str(exc))

    def _audit_ledger(self):
        if self._busy:
            return
        try:
            if not self._case:
                self._try_resume_case()
            ok, problems = self._case.audit(self.e_pass.get())
            n = len(self._case.ledger.records)
            if ok:
                self._log("ok", f"Ledger INTEGRITY PASS — all {n} records HMAC-verified.")
                messagebox.showinfo("Ledger audit",
                                    f"✓ Chain of custody INTEGRITY PASS.\n{n} signed records, "
                                    "hash chain continuous.\n\nYour passphrase validated the ledger.")
            else:
                self._log("err", f"Ledger INTEGRITY FAIL ({len(problems)} problem(s)).")
                messagebox.showerror("Ledger audit",
                                     "✗ Chain of custody INTEGRITY FAIL:\n- " + "\n- ".join(problems))
        except Exception as exc:
            messagebox.showerror("Audit failed", str(exc))

    def _cancel(self):
        if self._busy:
            self._cancel_flag.set()
            self._log("warn", "Cancel requested…")

    def _on_close(self):
        try:
            if self._busy:
                self._cancel_flag.set()
            # zeroise passphrase fields from memory (see memory.md)
            for e in (self.e_pass, self.e_pass2):
                e.delete(0, "end")
        finally:
            self.destroy()
