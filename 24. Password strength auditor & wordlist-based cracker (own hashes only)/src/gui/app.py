import os
import queue
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from .. import compat
from ..compat import paths, workspace, win
from ..core import auditor, cracker, hashes, report, wordlists


class AppState:
    def __init__(self, ws):
        self.ws = ws
        self.targets = []
        self.results = {}
        self.words = []
        self.words_path = ""
        self.words_fp = ""
        self.mode_32 = ""
        self.worker = None
        self.cracker = None
        self.msgq = queue.Queue()


class App:
    VERSION = "1.0.0"

    def __init__(self, root, ws_dir):
        self.root = root
        self.state = AppState(workspace.Workspace(ws_dir))
        self.running = True
        self._build_ui()
        self._startup()

    def _startup(self):
        dialog = AttestationDialog(self.root, self.state.ws)
        dialog.transient(self.root)
        self.root.deiconify()
        dialog.grab_set()
        dialog.lift()
        dialog.focus_force()
        self.root.update_idletasks()
        self.root.update()
        self.root.wait_window(dialog)
        if not dialog.accepted:
            self.running = False
            self.root.destroy()
            return
        self.state.ws.audit("session_start", detail="GUI session started")
        self.operator_var.set(self.state.ws.operator())
        self._refresh_log()
        self.root.after(120, self._poll)

    def _build_ui(self):
        self.root.title("PasswordGuardian - Password Strength Auditor & Wordlist Cracker (own hashes only)")
        self.root.geometry("980x700")
        self.operator_var = tk.StringVar()
        self.nb = ttk.Notebook(self.root)
        self.nb.pack(fill="both", expand=True)
        self._tab_load = self._build_tab_load()
        self._tab_attack = self._build_tab_attack()
        self._tab_auditor = self._build_tab_auditor()
        self._tab_report = self._build_tab_report()
        self._tab_log = self._build_tab_log()
        self._build_menu()
        self.root.protocol("WM_DELETE_WINDOW", self.quit_and_lock)

    def _build_menu(self):
        menubar = tk.Menu(self.root)
        filemenu = tk.Menu(menubar, tearoff=0)
        filemenu.add_command(label="Quit and Lock", command=self.quit_and_lock)
        menubar.add_cascade(label="File", menu=filemenu)
        helpmenu = tk.Menu(menubar, tearoff=0)
        helpmenu.add_command(label="About / Legal", command=self._show_about)
        menubar.add_cascade(label="Help", menu=helpmenu)
        self.root.config(menu=menubar)

    def _show_about(self):
        messagebox.showinfo(
            "About PasswordGuardian",
            "PasswordGuardian v{}\n\n"
            "Password strength auditor and wordlist-based cracker.\n"
            "Strictly for hashes and passwords that you own or are\n"
            "explicitly authorized to assess (own hashes only).\n\n"
            "Offline tool. No data leaves this machine.\n"
            "Compliance: NIST SP 800-63B, ISO 27001 controls, OWASP Top 10.",
        )

    def _build_tab_load(self):
        tab = ttk.Frame(self.nb, padding=10)
        self.nb.add(tab, text="1. Load & Identify")
        top = ttk.Frame(tab)
        top.pack(fill="x")
        self.load_path_var = tk.StringVar()
        ttk.Button(top, text="Load hash file...", command=self._pick_hash_file).pack(side="left", padx=2)
        ttk.Entry(top, textvariable=self.load_path_var, width=42).pack(side="left", padx=2)
        ttk.Label(top, text="32-hex:").pack(side="left", padx=(10, 0))
        self.mode32_var = tk.StringVar(value="Auto")
        ttk.Combobox(top, textvariable=self.mode32_var, values=("Auto", "Force MD5", "Force NTLM"),
                      width=12, state="readonly").pack(side="left", padx=2)
        ttk.Button(top, text="Parse", command=self._parse).pack(side="left", padx=6)
        ttk.Button(top, text="Clear", command=self._clear_load).pack(side="left", padx=2)
        paste = ttk.LabelFrame(tab, text="Paste hashes (one per line; supports hash:salt)")

        paste.pack(fill="both", expand=True, pady=(10, 0))
        self.text_area = tk.Text(paste, height=8, width=40)
        self.text_area.pack(fill="both", expand=True, padx=6, pady=6)
        sbar = ttk.Scrollbar(paste, command=self.text_area.yview)
        sbar.pack(side="right", fill="y")
        self.text_area.config(yscrollcommand=sbar.set)
        self.load_summary = ttk.Label(tab, text="No hashes loaded.")
        self.load_summary.pack(anchor="w", pady=(8, 2))
        self.load_tree = ttk.Treeview(tab, columns=("p", "h", "a", "s"), show="headings", height=10)
        for cid, title, w in (("p", "#", 40), ("h", "Hash", 300), ("a", "Algorithm", 110), ("s", "Salt", 120)):
            self.load_tree.heading(cid, text=title)
            self.load_tree.column(cid, width=w, anchor="w")
        self.load_tree.pack(fill="both", expand=False)
        return tab

    def _pick_hash_file(self):
        path = filedialog.askopenfilename(title="Select hash file (own data)")
        if path:
            self.load_path_var.set(path)
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as fh:
                    content = fh.read()
            except OSError as exc:
                messagebox.showerror("Open failed", str(exc))
                return
            self.text_area.delete("1.0", "end")
            self.text_area.insert("1.0", content)
            self._parse()

    def _clear_load(self):
        self.text_area.delete("1.0", "end")
        self.load_path_var.set("")
        self.state.targets = []
        self.state.results = {}
        self._refresh_load_ui({})

    def _parse(self):
        mode_map = {"Force MD5": "MD5", "Force NTLM": "NTLM", "Auto": None}
        force = mode_map.get(self.mode32_var.get())
        self.state.mode_32 = force or ""
        lines = self.text_area.get("1.0", "end").splitlines()
        targets = []
        seen = set()
        pos = 0
        for line in lines:
            t = hashes.identify_line(line, force32=force)
            if not t:
                continue
            key = (t["token"], tuple(t["algos"]), t.get("salt"))
            if key in seen:
                continue
            seen.add(key)
            pos += 1
            t["pos"] = pos
            targets.append(t)
        self.state.targets = targets
        self._refresh_load_ui({})
        total = len(targets)
        unsupported = sum(1 for t in targets if not set(t["algos"]) & {"MD5", "NTLM", "SHA1", "SHA224", "SHA256", "SHA384", "SHA512"})
        self.load_summary.config(
            text="{} target(s) loaded | {} offline-crackable | ambiguous 32-hex: {}".format(
                total, total - unsupported,
                sum(1 for t in targets if len(t["token"]) == 32 and self.state.mode_32 == ""),
            )
        )

    def _refresh_load_ui(self, results):
        self.load_tree.delete(*self.load_tree.get_children())
        for t in self.state.targets:
            self.load_tree.insert(
                "", "end",
                values=(t["pos"], t["token"], hashes.description(t["algos"]), t.get("salt") or ""),
            )

    def _build_tab_attack(self):
        tab = ttk.Frame(self.nb, padding=10)
        self.nb.add(tab, text="2. Attack")
        self.mode_var = tk.StringVar(value="wordlist")
        mode_frame = ttk.LabelFrame(tab, text="Attack method")
        mode_frame.pack(fill="x")
        ttk.Radiobutton(mode_frame, text="Wordlist", value="wordlist", variable=self.mode_var,
                        command=self._sync_mode_widgets).pack(side="left", padx=6)
        ttk.Radiobutton(mode_frame, text="Wordlist + rules (mangling)", value="rules", variable=self.mode_var,
                        command=self._sync_mode_widgets).pack(side="left", padx=6)
        ttk.Radiobutton(mode_frame, text="Mask (bounded brute-force)", value="mask", variable=self.mode_var,
                        command=self._sync_mode_widgets).pack(side="left", padx=6)
        wl_frame = ttk.LabelFrame(tab, text="Wordlist (own-/licensed data only)")
        wl_frame.pack(fill="x", pady=(8, 0))
        self.wl_var = tk.StringVar()
        ttk.Entry(wl_frame, textvariable=self.wl_var, width=52).pack(side="left", padx=4, pady=4)
        ttk.Button(wl_frame, text="Browse", command=self._pick_wordlist).pack(side="left", padx=2)
        ttk.Button(wl_frame, text="Load", command=self._load_wordlist).pack(side="left", padx=2)
        self.wl_label = ttk.Label(wl_frame, text="Not loaded.")
        self.wl_label.pack(side="left", padx=10)
        mask_frame = ttk.LabelFrame(tab, text="Mask options")
        mask_frame.pack(fill="x", pady=(8, 0))
        ttk.Label(mask_frame, text="Charset:").pack(side="left", padx=(8, 2))
        self.charset_var = tk.StringVar(value="abcdefghijklmnopqrstuvwxyz0123456789")
        ttk.Entry(mask_frame, textvariable=self.charset_var, width=40).pack(side="left", padx=2)
        ttk.Label(mask_frame, text="min:").pack(side="left", padx=(10, 2))
        self.min_len_var = tk.IntVar(value=4)
        ttk.Spinbox(mask_frame, from_=1, to=12, textvariable=self.min_len_var, width=4).pack(side="left")
        ttk.Label(mask_frame, text="max:").pack(side="left", padx=(6, 2))
        self.max_len_var = tk.IntVar(value=4)
        ttk.Spinbox(mask_frame, from_=1, to=12, textvariable=self.max_len_var, width=4).pack(side="left")
        ttk.Label(mask_frame, text="(keyspace guarded, max 1e12)").pack(side="left", padx=6)
        opt_frame = ttk.Frame(tab)
        opt_frame.pack(fill="x", pady=(8, 0))
        ttk.Label(opt_frame, text="Workers:").pack(side="left")
        self.workers_var = tk.IntVar(value=4)
        ttk.Spinbox(opt_frame, from_=1, to=16, textvariable=self.workers_var, width=4).pack(side="left", padx=(2, 10))
        self.run_btn = ttk.Button(opt_frame, text="Run", command=self._run_attack)
        self.run_btn.pack(side="left")
        self.stop_btn = ttk.Button(opt_frame, text="Stop", state="disabled", command=self._stop_attack)
        self.stop_btn.pack(side="left", padx=6)
        self.progress = ttk.Progressbar(tab, maximum=100)
        self.progress.pack(fill="x", pady=(8, 4))
        self.status_var = tk.StringVar(value="Idle.")
        self.status_lbl = ttk.Label(tab, textvariable=self.status_var)
        self.status_lbl.pack(anchor="w")
        res_frame = ttk.LabelFrame(tab, text="Cracked results (displayed in memory only; not persisted)")

        res_frame.pack(fill="both", expand=True, pady=(8, 0))
        self.res_tree = ttk.Treeview(res_frame, columns=("h", "a", "c"), show="headings", height=9)
        for cid, title, w in (("h", "Hash", 260), ("a", "Algorithm", 110), ("c", "Plaintext", 140)):
            self.res_tree.heading(cid, text=title)
            self.res_tree.column(cid, width=w, anchor="w")
        self.res_tree.pack(fill="both", expand=True, padx=4, pady=4)
        self.found_label = ttk.Label(tab, text="found: 0")
        self.found_label.pack(anchor="w")
        return tab

    def _sync_mode_widgets(self):
        mode = self.mode_var.get()

    def _pick_wordlist(self):
        path = filedialog.askopenfilename(title="Select wordlist file")
        if path:
            self.wl_var.set(path)

    def _load_wordlist(self):
        path = self.wl_var.get().strip()
        if not path:
            messagebox.showwarning("No path", "Choose a wordlist file first.")
            return
        try:
            words = wordlists.load_wordlist(path)
        except (OSError, ValueError) as exc:
            messagebox.showerror("Load failed", str(exc))
            return
        self.state.words = words
        self.state.words_path = path
        self.state.words_fp = wordlists.fingerprint(path)
        self.wl_label.config(text="{} unique words | sha256: {}".format(len(words), self.state.words_fp[:16]))
        self.state.ws.audit("wordlist_loaded", detail=path, fingerprint=self.state.words_fp, words=len(words))

    def _run_attack(self):
        if not self.state.targets:
            messagebox.showwarning("No targets", "Load hashes first (tab 1).")
            return
        if not self.state.ws.attested():
            messagebox.showwarning("Not attested", "Complete the ownership attestation (exit and relaunch).")
            return
        mode = self.mode_var.get()
        if mode in ("wordlist", "rules") and not self.state.words:
            messagebox.showwarning("No wordlist", "Load a wordlist first.")
            return
        if mode == "mask":
            charset = self.charset_var.get()
            if not charset:
                messagebox.showwarning("Charset", "Mask charset is empty.")
                return
            try:
                keyspace = cracker.mask_keyspace(charset, self.min_len_var.get(), self.max_len_var.get())
            except Exception:
                keyspace = 0
            if keyspace > cracker.MAX_MASK_GUARD:
                messagebox.showwarning(
                    "Too large",
                    "Mask keyspace {:,} exceeds the 1e12 safety guard. Reduce length/charset.".format(keyspace),
                )
                return
        targets = [dict(t) for t in self.state.targets]
        crk = cracker.Cracker(targets, workers=self.workers_var.get())
        self.state.cracker = crk
        self.state.worker = threading.Thread(
            target=self._worker_run, args=(mode,), daemon=True
        )
        self.state.worker.start()
        self.run_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        self.status_var.set("Running {}...".format(mode))

    def _worker_run(self, mode):
        crk = self.state.cracker
        try:
            stats = crk.run(
                mode,
                words=self.state.words,
                charset=self.charset_var.get(),
                min_len=self.min_len_var.get(),
                max_len=self.max_len_var.get(),
                progress=lambda d: self.state.msgq.put(("progress", d)),
            )
            self.state.msgq.put(("done", stats))
        except Exception as exc:
            self.state.msgq.put(("error", str(exc)))

    def _stop_attack(self):
        if self.state.cracker:
            self.state.cracker.stop()
        self.status_var.set("Stopping...")

    def _poll(self):
        try:
            while True:
                kind, payload = self.state.msgq.get_nowait()
                self._handle_msg(kind, payload)
        except queue.Empty:
            pass
        self.root.after(120, self._poll)

    def _handle_msg(self, kind, payload):
        if kind == "progress":
            pct = min(100, (payload.get("tried") / 200000.0) * 100)
            self.progress["value"] = pct
            self.found_label.config(text="found: {}".format(payload.get("found", 0)))
            found_map = payload.get("found_map") or {}
            if len(found_map) > len(self.state.results):
                self.state.results = found_map
                self._refresh_results()
            tried = payload.get("tried", 0)
            rate = payload.get("rate", 0) or 0
            self.status_var.set(
                "candidates: {:,} | rate: {:.0f}/s | found: {} | remaining: {} | elapsed: {:.1f}s".format(
                    tried, rate, payload.get("found"), payload.get("remaining"), payload.get("elapsed_s")
                )
            )
        elif kind == "done":
            self.progress["value"] = 100
            matches = payload.get("found_map") or {}
            self.state.results.update(matches)
            self._refresh_results()
            self.found_label.config(text="found: {}/{} targets".format(len(self.state.results), len(self.state.targets)))
            self.status_var.set(
                "Done. {:,} candidates tried in {:.1f}s ({:.0f}/s). {} cracked.".format(
                    payload.get("attempted", 0), payload.get("elapsed_s", 0), payload.get("rate", 0),
                    len(self.state.results),
                )
            )
            self.run_btn.config(state="normal")
            self.stop_btn.config(state="disabled")
            detail = {
                "mode": payload.get("mode"),
                "attempted": payload.get("attempted"),
                "found": payload.get("found"),
                "remaining": payload.get("remaining"),
                "elapsed_s": round(payload.get("elapsed_s", 0), 2),
            }
            self.state.ws.audit("attack_completed", detail=detail, fingerprint=self.state.words_fp or None)
        elif kind == "error":
            self.status_var.set("Error: " + payload)
            self.run_btn.config(state="normal")
            self.stop_btn.config(state="disabled")
            self.state.ws.audit("attack_error", detail=payload)

    def _refresh_results(self):
        self.res_tree.delete(*self.res_tree.get_children())
        for token, info in self.state.results.items():
            self.res_tree.insert("", "end", values=(token, info.get("algo", ""), info.get("candidate", "")))

    def _build_tab_auditor(self):
        tab = ttk.Frame(self.nb, padding=10)
        self.nb.add(tab, text="3. Strength Auditor")
        entry_frame = ttk.LabelFrame(tab, text="Analyze a password you own (NIST SP 800-63B)")
        entry_frame.pack(fill="x")
        self.pw_var = tk.StringVar()
        ttk.Entry(entry_frame, textvariable=self.pw_var, width=42).pack(side="left", padx=4, pady=4)
        self.block_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(entry_frame, text="Screen against common/breach blocklist", variable=self.block_var).pack(side="left", padx=6)
        ttk.Button(entry_frame, text="Analyze", command=self._analyze_pw).pack(side="left", padx=4)
        self.audit_score = ttk.Label(tab, text="score: -")
        self.audit_score.pack(anchor="w", pady=(8, 2))
        self.audit_bits = ttk.Label(tab, text="entropy: -")
        self.audit_bits.pack(anchor="w")
        self.audit_estimate = ttk.Label(tab, text="crack time: -")
        self.audit_estimate.pack(anchor="w")
        self.audit_checks = tk.Text(tab, height=8, width=60, state="disabled")
        self.audit_checks.pack(fill="x", pady=(8, 0))
        table_frame = ttk.LabelFrame(tab, text="Found candidates from attacks (in-memory)")
        table_frame.pack(fill="both", expand=True, pady=(8, 0))
        self.aud_tree = ttk.Treeview(table_frame, columns=("p", "a", "b", "s"), show="headings", height=6)
        for cid, title, w in (("p", "Password", 180), ("a", "Algo", 120), ("b", "Bits", 70), ("s", "Strength", 120)):
            self.aud_tree.heading(cid, text=title)
            self.aud_tree.column(cid, width=w, anchor="w")
        self.aud_tree.pack(fill="both", expand=True, padx=4, pady=4)
        ttk.Button(table_frame, text="Analyze all found candidates", command=self._analyze_found).pack(anchor="w", padx=4, pady=4)
        return tab

    def _blocklist(self):
        if not self.block_var.get():
            return None
        block = set(wordlists.common_blocklist())
        block.update(w.lower() for w in self.state.words)
        return block

    def _analyze_pw(self):
        pw = self.pw_var.get()
        if not pw:
            messagebox.showwarning("Empty", "Enter a password to analyze.")
            return
        result = auditor.analyze(pw, blocklist=self._blocklist())
        self._show_audit(result)

    def _show_audit(self, result):
        self.audit_score.config(
            text="score: {}/100  ({})  {}".format(result["score"], result["label"], "BLOCKLISTED - do not use" if result["blocked"] else "")
        )
        self.audit_bits.config(
            text="entropy: {} bits (raw {} - penalty {}) | length {} | {} char classes".format(
                result["bits"], result["raw_bits"], result["penalty"], result["length"], result["classes"]
            )
        )
        estimates = ", ".join("{}: {}".format(k, v) for k, v in result["estimates"].items())
        self.audit_estimate.config(text="estimated crack time: " + estimates)
        self.audit_checks.config(state="normal")
        self.audit_checks.delete("1.0", "end")
        for label, ok in result["checks"]:
            self.audit_checks.insert("end", "[{}] {}\n".format("PASS" if ok else "FAIL", label))
        self.audit_checks.insert(
            "end",
            "\n{} of {} NIST SP 800-63B checks passed.\n".format(result["passes"], result["total_checks"]),
        )
        self.audit_checks.config(state="disabled")

    def _analyze_found(self):
        if not self.state.results:
            messagebox.showinfo("No results", "Nothing to analyze yet.")
            return
        self.aud_tree.delete(*self.aud_tree.get_children())
        for token, info in self.state.results.items():
            pw = info.get("candidate", "")
            if not pw:
                continue
            r = auditor.analyze(pw, blocklist=self._blocklist())
            self.aud_tree.insert("", "end", values=(pw, info.get("algo", ""), r["bits"], r["label"]))

    def _build_tab_report(self):
        tab = ttk.Frame(self.nb, padding=10)
        self.nb.add(tab, text="4. Report")
        meta = ttk.LabelFrame(tab, text="Report metadata (bound to operator identity)")
        meta.pack(fill="x")
        ttk.Label(meta, text="Operator:").pack(side="left", padx=(6, 2), pady=4)
        ttk.Entry(meta, textvariable=self.operator_var, width=24).pack(side="left", padx=2)
        self.report_dir_var = tk.StringVar(value=paths.resource_path("reports"))
        ttk.Entry(meta, textvariable=self.report_dir_var, width=44).pack(side="left", padx=2)
        ttk.Button(meta, text="Browse", command=self._pick_report_dir).pack(side="left", padx=2)
        fmt = ttk.LabelFrame(tab, text="Output formats")
        fmt.pack(fill="x", pady=(8, 0))
        self.fmt_html = tk.BooleanVar(value=True)
        self.fmt_csv = tk.BooleanVar(value=True)
        self.fmt_json = tk.BooleanVar(value=False)
        self.fmt_bundle = tk.BooleanVar(value=True)
        for var, label in (
            (self.fmt_html, "Self-contained HTML"),
            (self.fmt_csv, "CSV"),
            (self.fmt_json, "JSON"),
            (self.fmt_bundle, "Encrypted bundle (.pwg, Windows DPAPI)"),
        ):
            ttk.Checkbutton(fmt, text=label, variable=var).pack(side="left", padx=8, pady=4)
        ttk.Button(tab, text="Generate report", command=self._generate_report).pack(anchor="w", pady=(10, 2))
        ttk.Button(tab, text="Open report folder", command=self._open_report_dir).pack(anchor="w")
        self.report_label = ttk.Label(tab, text="")
        self.report_label.pack(anchor="w", pady=(6, 0))
        self.report_wm = ttk.Label(tab, text="", foreground="#555")
        self.report_wm.pack(anchor="w")
        self.report_preview = ttk.LabelFrame(tab, text="Summary preview")
        self.report_preview.pack(fill="both", expand=True, pady=(8, 0))
        self.report_sum = tk.Text(self.report_preview, height=10, width=60, state="disabled")
        self.report_sum.pack(fill="both", expand=True, padx=4, pady=4)
        return tab

    def _pick_report_dir(self):
        path = filedialog.askdirectory(title="Report output folder")
        if path:
            self.report_dir_var.set(path)

    def _open_report_dir(self):
        outdir = self.report_dir_var.get().strip() or "."
        os.makedirs(outdir, exist_ok=True)
        os.startfile(outdir)

    def _report_data(self, operator):
        items = []
        for t in self.state.targets:
            info = self.state.results.get(t["token"].lower())
            items.append(
                {
                    "pos": t["pos"],
                    "token": t["token"],
                    "algos": t["algos"],
                    "salt": t.get("salt") or "",
                    "candidate": (info or {}).get("candidate", ""),
                    "algo_matched": (info or {}).get("algo", ""),
                }
            )
        cracked = sum(1 for i in items if i["candidate"])
        summary = {
            "targets": len(items),
            "cracked": cracked,
            "unresolved": len(items) - cracked,
            "scope": "OWN / AUTHORIZED DATA ONLY",
        }
        meta = {
            "tool": "PasswordGuardian",
            "version": self.VERSION,
            "operator": operator,
            "session_id": self.state.ws.session_id(),
            "workspace": self.state.ws.dir,
            "generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        return {"meta": meta, "summary": summary, "items": items}

    def _generate_report(self):
        operator = self.operator_var.get().strip() or self.state.ws.operator()
        if not operator:
            messagebox.showwarning("Operator", "Set the operator identity for the report.")
            return
        if not self.state.targets:
            messagebox.showwarning("No data", "Load hashes first (tab 1).")
            return
        data = self._report_data(operator)
        outdir = self.report_dir_var.get().strip() or "."
        os.makedirs(outdir, exist_ok=True)
        base = os.path.join(outdir, "report_{}_{}".format(self.state.ws.session_id(), int(time.time())))
        written = []
        if self.fmt_html.get():
            html_doc = report.build_html(data["meta"], data["summary"], data["items"])
            with open(base + ".html", "w", encoding="utf-8") as fh:
                fh.write(html_doc)
            written.append(base + ".html")
        if self.fmt_csv.get():
            report.write_csv(base + ".csv", data["items"])
            written.append(base + ".csv")
        if self.fmt_json.get():
            report.write_json(base + ".json", data)
            written.append(base + ".json")
        if self.fmt_bundle.get():
            if win.dpapi_capable():
                bpath = base + ".pwg"
                report.save_encrypted_bundle(bpath, data)
                written.append(bpath)
            else:
                messagebox.showwarning("DPAPI unavailable", "Encrypted bundle requires Windows. Skipped.")
        self.report_label.config(text="Wrote:\n" + "\n".join(written))
        self.report_wm.config(text=report.watermark(operator, self.state.ws.session_id()))
        self.state.ws.audit("report_generated", detail=outdir, files=written, operator=operator)
        self.report_sum.config(state="normal")
        self.report_sum.delete("1.0", "end")
        self.report_sum.insert(
            "1.0",
            "Targets: {}\nCracked: {}\nUnresolved: {}\nScope: {}\nOperator: {}\nSession: {}\n".format(
                data["summary"]["targets"],
                data["summary"]["cracked"],
                data["summary"]["unresolved"],
                data["summary"]["scope"],
                operator,
                self.state.ws.session_id(),
            ),
        )
        self.report_sum.config(state="disabled")

    def _build_tab_log(self):
        tab = ttk.Frame(self.nb, padding=10)
        self.nb.add(tab, text="5. Security Log & Settings")
        info = ttk.LabelFrame(tab, text="Workspace")
        info.pack(fill="x")
        ttk.Label(info, text="Path: " + self.state.ws.dir).pack(anchor="w", padx=6, pady=2)
        ttk.Label(info, text="Session: " + self.state.ws.session_id()).pack(anchor="w", padx=6)
        ttk.Label(info, text="DPAPI (encrypted reports): " + ("available" if win.dpapi_capable() else "not on this OS")).pack(anchor="w", padx=6, pady=2)
        chain = ttk.LabelFrame(tab, text="Audit log integrity (ISO A.12.4 / NIST AU)")
        chain.pack(fill="x", pady=(8, 0))
        self.chain_btn = ttk.Button(chain, text="Verify hash chain", command=self._verify_chain)
        self.chain_btn.pack(side="left", padx=6, pady=4)
        self.chain_label = ttk.Label(chain, text="")
        self.chain_label.pack(side="left", padx=8)
        events = ttk.LabelFrame(tab, text="Recent events")
        events.pack(fill="both", expand=True, pady=(8, 0))
        self.log_text = tk.Text(events, height=10, width=50, state="disabled")
        self.log_text.pack(fill="both", expand=True, padx=4, pady=4)
        danger = ttk.LabelFrame(tab, text="Data clearing (data minimization / DLP)")
        danger.pack(fill="x", pady=(8, 0))
        ttk.Button(danger, text="Wipe workspace (clear audit + config)", command=self._wipe_workspace).pack(side="left", padx=6, pady=4)
        ttk.Button(danger, text="Quit and Lock", command=self.quit_and_lock).pack(side="left", padx=6)
        return tab

    def _verify_chain(self):
        ok, count = self.state.ws.verify_chain()
        self.chain_label.config(
            text="{} entries | chain {}".format(count, "INTACT" if ok else "TAMPERED/DAMAGED")
        )
        if ok:
            self.security_banner("chain verified: {} entries".format(count))
        else:
            messagebox.showerror("Integrity", "Audit log chain verification failed. Possible tampering.")
        self._refresh_log()

    def _wipe_workspace(self):
        if not messagebox.askyesno("Wipe workspace", "Clear audit log, config and in-memory results? In-memory plaintext will be discarded."):
            return
        self.state.ws.wipe()
        self.state.targets = []
        self.state.results = {}
        self.text_area.delete("1.0", "end")
        self.log_text.config(state="normal")
        self.log_text.delete("1.0", "end")
        self.log_text.config(state="disabled")
        messagebox.showinfo("Wiped", "Workspace cleared.")

    def security_banner(self, msg):
        self.root.title("PasswordGuardian - " + msg)

    def _refresh_log(self):
        self.log_text.config(state="normal")
        self.log_text.delete("1.0", "end")
        for e in self.state.ws.events(limit=40):
            self.log_text.insert("end", "[{}] {} {}\n".format(e.get("ts"), e.get("event"), e.get("detail") or ""))
        self.log_text.config(state="disabled")

    def quit_and_lock(self):
        self.state.ws.audit("session_end", detail="GUI exit / lock requested")
        self.root.destroy()


class AttestationDialog(tk.Toplevel):
    def __init__(self, master, ws):
        super().__init__(master)
        self.ws = ws
        self.accepted = False
        self.title("Own-hashes-only attestation (required)")
        self.resizable(False, False)
        body = ttk.Frame(self, padding=14)
        body.pack(fill="both", expand=True)
        ttk.Label(
            body,
            text=(
                "PasswordGuardian is for assessing passwords and hashes that are\n"
                "YOUR OWN or that you are explicitly authorized to test.\n\n"
                "By proceeding you confirm that all data loaded into this tool:\n"
                "  * belongs to you or your organization, and\n"
                "  * is being assessed with full authorization.\n\n"
                "Unauthorized use or attempting to recover others' passwords is illegal\n"
                "and is outside this tool's scope."
            ),
            justify="left",
        ).grid(row=0, column=0, columnspan=2, sticky="w", padx=4, pady=4)
        ttk.Label(body, text="Operator name:").grid(row=1, column=0, sticky="w", padx=4, pady=6)
        self.operator_var = tk.StringVar(value=ws.operator())
        ttk.Entry(body, textvariable=self.operator_var, width=30).grid(row=1, column=1, padx=4)
        self.confirm_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            body,
            text="I confirm the data I will load is my own / authorized for assessment.",
            variable=self.confirm_var,
        ).grid(row=2, column=0, columnspan=2, sticky="w", padx=4, pady=8)
        btns = ttk.Frame(body)
        btns.grid(row=3, column=0, columnspan=2, sticky="e")
        self.ok_btn = ttk.Button(btns, text="Continue", state="disabled", command=self._accept)
        self.ok_btn.pack(side="left", padx=4)
        ttk.Button(btns, text="Exit", command=self._decline).pack(side="left")
        self.confirm_var.trace_add("write", lambda *_: self._sync_ok())
        self.operator_var.trace_add("write", lambda *_: self._sync_ok())
        self.protocol("WM_DELETE_WINDOW", self._decline)
        self.update_idletasks()
        w = self.winfo_reqwidth()
        h = self.winfo_reqheight()
        x = max(0, (self.winfo_screenwidth() - w) // 2)
        y = max(0, (self.winfo_screenheight() - h) // 3)
        self.geometry("+{}+{}".format(x, y))

    def _sync_ok(self):
        self.ok_btn.config(state="normal" if self.confirm_var.get() else "disabled")

    def _accept(self):
        operator = self.operator_var.get().strip()
        if not operator:
            tk.messagebox.showwarning("Operator", "Operator name is required for audit traceability.", parent=self)
            return
        self.ws.attest(operator)
        self.accepted = True
        self.destroy()

    def _decline(self):
        self.destroy()


def main():
    root = tk.Tk()
    app = App(root, paths.default_workspace_dir())
    if app.running:
        root.mainloop()


if __name__ == "__main__":
    main()