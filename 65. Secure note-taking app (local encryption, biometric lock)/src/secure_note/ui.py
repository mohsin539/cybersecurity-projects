"""Tkinter GUI for SecureNote Pro (architecture.md §3 Presentation Layer).

Tabs: Unlock/Setup · Notes · Reports · Audit · Settings.
All cryptographic operations run on the main thread; the Windows Hello
dialog runs in a worker thread so the UI stays responsive.
"""

from __future__ import annotations

import os
import subprocess
import sys
import threading
import time
import traceback

import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from . import auth
from . import audit
from .app import SecureNoteApp, resolve_data_dir

ACCENT = "#1f6feb"
BG = "#f5f7fa"
PANEL = "#ffffff"
DARK = "#182a4d"
BADGE_OK = "#2ea44f"
BADGE_WARN = "#9a6700"
BADGE_FAIL = "#d73a49"


class SecureNoteUI:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.app = SecureNoteApp()
        self._busy = False
        self._current_note_id: str | None = None
        root.title(f"SecureNote Pro — {self.app.data_dir}")
        root.geometry("1120x760")
        root.configure(bg=BG)

        self._build_style()
        self._build_ui()

    # ------------------------------------------------------------- styling
    def _build_style(self) -> None:
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("TNotebook", background=BG, borderwidth=0)
        style.configure("TNotebook.Tab", padding=(16, 8), font=("Segoe UI", 10))
        style.map("TNotebook.Tab", background=[("selected", PANEL)])
        style.configure("Accent.TButton", foreground="white", background=ACCENT,
                        font=("Segoe UI", 10, "bold"), padding=(14, 8))
        style.map("Accent.TButton", background=[("active", "#1a5cc8"), ("disabled", "#a8c4ef")])
        style.configure("Danger.TButton", foreground="white", background=BADGE_FAIL,
                        font=("Segoe UI", 9, "bold"), padding=(10, 6))
        style.map("Danger.TButton", background=[("active", "#b02a3d")])
        style.configure("Panel.TFrame", background=PANEL)
        style.configure("TLabel", background=BG, font=("Segoe UI", 10))
        style.configure("Panel.TLabel", background=PANEL, font=("Segoe UI", 10))
        style.configure("Title.TLabel", background=BG, foreground=DARK,
                        font=("Segoe UI", 18, "bold"))
        style.configure("Muted.TLabel", background=PANEL, foreground="#57606a",
                        font=("Segoe UI", 9))
        style.configure("Status.TLabel", background=BG, foreground="#57606a",
                        font=("Segoe UI", 9))

    # ------------------------------------------------------------- layout
    def _build_ui(self) -> None:
        self.statusbar = ttk.Label(self.root, text="", style="Status.TLabel", padding=(10, 4))
        self.statusbar.pack(side="bottom", fill="x")

        self.nb = ttk.Notebook(self.root)
        self.nb.pack(fill="both", expand=True, padx=8, pady=(8, 4))

        self.tab_auth = ttk.Frame(self.nb, style="Panel.TFrame", padding=20)
        self.tab_notes = ttk.Frame(self.nb, style="Panel.TFrame", padding=12)
        self.tab_reports = ttk.Frame(self.nb, style="Panel.TFrame", padding=12)
        self.tab_audit = ttk.Frame(self.nb, style="Panel.TFrame", padding=12)
        self.tab_settings = ttk.Frame(self.nb, style="Panel.TFrame", padding=12)

        self.nb.add(self.tab_auth, text="  Key / Unlock  ")
        self.nb.add(self.tab_notes, text="  Notes  ")
        self.nb.add(self.tab_reports, text="  Reports & Downloads  ")
        self.nb.add(self.tab_audit, text="  Audit Trail  ")
        self.nb.add(self.tab_settings, text="  Settings  ")

        self._build_auth_tab()
        self._build_notes_tab()
        self._build_reports_tab()
        self._build_audit_tab()
        self._build_settings_tab()

        self.refresh_all()
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    # ---------------------------------------------------------- auth tab
    def _build_auth_tab(self) -> None:
        f = self.tab_auth
        ttk.Label(f, text="🔐  SecureNote Pro — Vault Access",
                  style="Title.TLabel").pack(anchor="w", pady=(0, 4))
        ttk.Label(f, text="AES-256-GCM  ·  Argon2id  ·  Biometric 2FA  ·  Offline-First",
                  style="Muted.TLabel").pack(anchor="w", pady=(0, 16))

        self.auth_status = ttk.Label(f, style="Muted.TLabel", wraplength=720)
        self.auth_status.pack(anchor="w", pady=(0, 8))

        row = ttk.Frame(f, style="Panel.TFrame")
        row.pack(fill="x", pady=6)
        ttk.Label(row, text="Master passphrase:", style="Panel.TLabel").pack(side="left")
        self.entry_pass = ttk.Entry(row, show="•", width=34, font=("Segoe UI", 11))
        self.entry_pass.pack(side="left", padx=10)
        self.entry_pass.bind("<Return>", lambda e: self._unlock_passphrase())
        self.btn_unlock = ttk.Button(row, text="Unlock", style="Accent.TButton",
                                     command=self._unlock_passphrase)
        self.btn_unlock.pack(side="left", padx=4)

        row2 = ttk.Frame(f, style="Panel.TFrame")
        row2.pack(fill="x", pady=6)
        self.btn_bio = ttk.Button(row2, text="🫵  Unlock with Biometric (Windows Hello)",
                                  command=self._unlock_biometric)
        self.btn_bio.pack(side="left", padx=4)

        sep = ttk.Separator(f)
        sep.pack(fill="x", pady=18)

        ttk.Label(f, text="First time here?  Create your vault", style="Title.TLabel").pack(
            anchor="w", pady=(0, 8))
        row3 = ttk.Frame(f, style="Panel.TFrame")
        row3.pack(fill="x", pady=4)
        ttk.Label(row3, text="New passphrase:", style="Panel.TLabel").pack(side="left")
        self.entry_new = ttk.Entry(row3, show="•", width=28, font=("Segoe UI", 11))
        self.entry_new.pack(side="left", padx=10)
        row4 = ttk.Frame(f, style="Panel.TFrame")
        row4.pack(fill="x", pady=4)
        ttk.Label(row4, text="Confirm:", style="Panel.TLabel").pack(side="left")
        self.entry_confirm = ttk.Entry(row4, show="•", width=28, font=("Segoe UI", 11))
        self.entry_confirm.pack(side="left", padx=10)
        row5 = ttk.Frame(f, style="Panel.TFrame")
        row5.pack(fill="x", pady=10)
        self.var_bio_setup = tk.BooleanVar(value=True)
        ttk.Checkbutton(row5, text="Enable biometric unlock after creation (recommended)",
                        variable=self.var_bio_setup, style="Panel.TLabel").pack(side="left")
        row6 = ttk.Frame(f, style="Panel.TFrame")
        row6.pack(fill="x", pady=4)
        ttk.Button(row6, text="Create Vault", style="Accent.TButton",
                   command=self._setup).pack(side="left")

    # --------------------------------------------------------- notes tab
    def _build_notes_tab(self) -> None:
        f = self.tab_notes
        top = ttk.Frame(f)
        top.pack(fill="x", pady=(0, 8))
        ttk.Label(top, text="Your notes (all encrypted at rest)", style="Title.TLabel").pack(
            side="left")
        self.lock_btn = ttk.Button(top, text="Lock now", command=self._lock)
        self.lock_btn.pack(side="right")

        grid = ttk.PanedWindow(f, orient="horizontal")
        grid.pack(fill="both", expand=True)

        left = ttk.Frame(grid, padding=(0, 0, 8, 0))
        right = ttk.Frame(grid, padding=(8, 0, 0, 0))
        grid.add(left, weight=2)
        grid.add(right, weight=3)

        ttk.Button(left, text="+  New note", command=self._new_note,
                   style="Accent.TButton").pack(fill="x", pady=(0, 6))
        self.entry_search = ttk.Entry(left)
        self.entry_search.pack(fill="x", pady=(0, 6))
        self.entry_search.bind("<KeyRelease>", lambda e: self._refresh_list())

        cols = ("title", "updated", "pin")
        self.tree = ttk.Treeview(left, columns=cols, show="headings", height=26)
        self.tree.heading("title", text="Title")
        self.tree.heading("updated", text="Updated")
        self.tree.heading("pin", text="PIN")
        self.tree.column("title", width=240, anchor="w")
        self.tree.column("updated", width=140, anchor="w")
        self.tree.column("pin", width=40, anchor="center")
        self.tree.pack(fill="both", expand=True)
        self.tree.bind("<<TreeviewSelect>>", self._on_select)

        ttk.Label(right, text="Title", style="Panel.TLabel").pack(anchor="w")
        self.v_title = tk.StringVar()
        ttk.Entry(right, textvariable=self.v_title, font=("Segoe UI", 11)).pack(
            fill="x", pady=(0, 4))
        ttk.Label(right, text="Tags (comma separated)", style="Panel.TLabel").pack(anchor="w")
        self.v_tags = tk.StringVar()
        ttk.Entry(right, textvariable=self.v_tags).pack(fill="x", pady=(0, 4))
        ttk.Label(right, text="Body (encrypted with AES-256-GCM per note)", style="Panel.TLabel").pack(
            anchor="w")
        self.txt_body = tk.Text(right, height=16, font=("Consolas 10" if sys.platform == "win32" else "Mono 10",))
        self.txt_body.pack(fill="both", expand=True, pady=(0, 6))

        acts = ttk.Frame(right)
        acts.pack(fill="x")
        ttk.Button(acts, text="Save", style="Accent.TButton", command=self._save_note).pack(
            side="left", padx=2)
        ttk.Button(acts, text="Delete", style="Danger.TButton", command=self._delete_note).pack(
            side="left", padx=2)
        ttk.Button(acts, text="Pin / Unpin", command=self._toggle_pin).pack(side="left", padx=2)

    # ------------------------------------------------------- reports tab
    def _build_reports_tab(self) -> None:
        f = self.tab_reports
        ttk.Label(f, text="📥  Report Download Center", style="Title.TLabel").pack(anchor="w")
        ttk.Label(f, text="Reports are generated locally, signed (ECDSA P-256) and never uploaded.",
                  style="Muted.TLabel").pack(anchor="w", pady=(0, 12))

        row = ttk.Frame(f)
        row.pack(fill="x", pady=4)
        self.var_dest = tk.StringVar(value=self.app.reports_path)
        ttk.Label(row, text="Export to:").pack(side="left")
        ttk.Entry(row, textvariable=self.var_dest, width=56).pack(side="left", padx=6)
        ttk.Button(row, text="Browse…", command=self._browse_dest).pack(side="left")

        box = ttk.Frame(f, padding=(10, 10), relief="groove")
        box.pack(fill="x", pady=12)
        ttk.Button(box, text="Generate Compliance Report  (PDF + JSON)",
                   style="Accent.TButton", command=lambda: self._gen(("compliance", "audit"))).pack(
            fill="x", pady=2)
        ttk.Button(box, text="Generate Audit Report  (CSV + verify JSON)",
                   command=lambda: self._gen(("audit",))).pack(fill="x", pady=2)
        ttk.Button(box, text="Generate Full Attestation Package  (signed ZIP)",
                   command=lambda: self._gen(("compliance", "audit", "attestation"))).pack(
            fill="x", pady=2)

        self.report_out = tk.Text(f, height=12, state="disabled", font=("Consolas", 9))
        self.report_out.pack(fill="both", expand=True, pady=6)
        ttk.Button(f, text="Open export folder", command=self._open_folder).pack(anchor="w")

    # --------------------------------------------------------- audit tab
    def _build_audit_tab(self) -> None:
        f = self.tab_audit
        ttk.Label(f, text="🕵️  Hash-Chained Audit Ledger", style="Title.TLabel").pack(anchor="w")
        ttk.Label(f, text="Tamper-evident: every entry links to the previous hash and is HMAC-signed.",
                  style="Muted.TLabel").pack(anchor="w", pady=(0, 8))
        row = ttk.Frame(f)
        row.pack(fill="x", pady=(0, 6))
        ttk.Button(row, text="Verify chain integrity", style="Accent.TButton",
                   command=self._verify_chain).pack(side="left")
        ttk.Button(row, text="Refresh", command=self._refresh_audit).pack(side="left", padx=6)
        self.chain_label = ttk.Label(row, text="")
        self.chain_label.pack(side="left", padx=12)

        self.audit_text = tk.Text(f, height=26, state="disabled", font=("Consolas", 9))
        self.audit_text.pack(fill="both", expand=True)

    # ------------------------------------------------------ settings tab
    def _build_settings_tab(self) -> None:
        f = self.tab_settings
        ttk.Label(f, text="⚙️  Security Settings", style="Title.TLabel").pack(anchor="w")

        grp1 = ttk.LabelFrame(f, text="Authentication", padding=10)
        grp1.pack(fill="x", pady=8)
        row = ttk.Frame(grp1)
        row.pack(fill="x")
        self.var_bio = tk.BooleanVar()
        self.cb_bio = ttk.Checkbutton(row, text="Biometric unlock enabled (Windows Hello)",
                                      variable=self.var_bio, command=self._toggle_bio)
        self.cb_bio.pack(side="left")
        ttk.Label(row, text=f"[device: {self.app.bio_state}]").pack(side="left", padx=8)

        grp2 = ttk.LabelFrame(f, text="Auto-lock (idle timeout)", padding=10)
        grp2.pack(fill="x", pady=8)
        row = ttk.Frame(grp2)
        row.pack(fill="x")
        self.var_autolock = tk.IntVar(value=60)
        ttk.Spinbox(row, from_=10, to=3600, increment=10, textvariable=self.var_autolock,
                    width=8, command=self._set_autolock).pack(side="left")
        ttk.Label(row, text="  seconds  ").pack(side="left")
        ttk.Button(row, text="Apply", command=self._set_autolock).pack(side="left", padx=8)

        grp3 = ttk.LabelFrame(f, text="Credentials", padding=10)
        grp3.pack(fill="x", pady=8)
        row = ttk.Frame(grp3)
        row.pack(fill="x", pady=2)
        ttk.Label(row, text="Current passphrase:").pack(side="left")
        self.e_old = ttk.Entry(row, show="•", width=22)
        self.e_old.pack(side="left", padx=8)
        row = ttk.Frame(grp3)
        row.pack(fill="x", pady=2)
        ttk.Label(row, text="New passphrase:     ").pack(side="left")
        self.e_new = ttk.Entry(row, show="•", width=22)
        self.e_new.pack(side="left", padx=8)
        ttk.Button(row, text="Change passphrase", style="Accent.TButton",
                   command=self._change_pass).pack(side="left", padx=8)

        grp4 = ttk.LabelFrame(f, text="Danger zone", padding=10)
        grp4.pack(fill="x", pady=8)
        ttk.Label(grp4, text="Lockout threshold or manual reset triggers secure wipe (arch §8.10).",
                  foreground="#57606a").pack(anchor="w")
        ttk.Button(grp4, text="Securely wipe vault & keys", style="Danger.TButton",
                   command=self._wipe).pack(anchor="w", pady=4)

        self.settings_status = ttk.Label(f, style="Muted.TLabel")
        self.settings_status.pack(anchor="w", pady=8)

    # ------------------------------------------------------------- actions
    def set_busy(self, busy: bool) -> None:
        self._busy = busy
        state = "disabled" if busy else "normal"
        for w in (self.btn_unlock, self.btn_bio):
            w.configure(state=state)

    def _status(self, text: str) -> None:
        self.statusbar.configure(text=text)

    def refresh_all(self) -> None:
        st = self.app.status()
        self._refresh_auth_tab(st)
        self._refresh_notes_tab()
        self._refresh_audit()
        self._refresh_settings(st)

    def _refresh_auth_tab(self, st: dict) -> None:
        lines = [
            f"Data directory : {self.app.data_dir}",
            f"Vault exists    : {'yes' if st['vault_exists'] else 'no'}",
            f"State           : {'UNLOCKED' if st['unlocked'] else 'LOCKED'}",
            f"Biometric HW    : {st['biometric']}",
            f"Biometric cfg   : {'configured' if st['biometric_configured'] else 'not configured'}",
        ]
        self.auth_status.configure(text="\n".join(lines))
        self.btn_bio.configure(state="normal" if st["vault_exists"] and
                               st["biometric"] in ("available", "unknown") else "disabled")

    def _refresh_notes_tab(self) -> None:
        notes = self.app.note_list()
        for item in self.tree.get_children():
            self.tree.delete(item)
        needle = self.entry_search.get().strip().lower() if self.entry_search.winfo_exists() else ""
        for n in notes:
            if needle and needle not in n["title"].lower():
                continue
            self.tree.insert("", "end", iid=n["id"], values=(
                n["title"], n["updated"][:19], "📌" if n["pinned"] else ""))
        if not self.app.unlocked:
            try:
                self.txt_body.delete("1.0", "end")
            except tk.TclError:
                pass
            self.txt_body.configure(state="disabled")
            self.v_title.set("")
            self.v_tags.set("")
        else:
            self.txt_body.configure(state="normal")

    def _refresh_audit(self) -> None:
        rows = self.app.audit_events(300)
        self.audit_text.configure(state="normal")
        self.audit_text.delete("1.0", "end")
        if rows:
            for r in rows[::-1]:
                line = (f"[{r.get('seq', ''):>5}] {r.get('ts', '')[:19]}  "
                        f"{r.get('category','')[:10]:<11} {r.get('action',''):<22} "
                        f"{r.get('result',''):<8} {r.get('details','')}")
                self.audit_text.insert("end", line + "\n")
        else:
            self.audit_text.insert("end", "No audit events yet.\n")
        self.audit_text.configure(state="disabled")

    def _refresh_settings(self, st: dict) -> None:
        self.var_bio.set(bool(self.app.vault.settings.get("biometric_enabled", False)))
        self.var_autolock.set(int(self.app.vault.settings.get("autolock_seconds", 60)) or 60)

    # ------------------------------- unlock / setup ----------------------
    def _unlock_passphrase(self) -> None:
        if self._busy:
            return
        pw = self.entry_pass.get()
        if not pw:
            return
        self.set_busy(True)
        threading.Thread(target=self._do_unlock, args=(pw, False), daemon=True).start()

    def _unlock_biometric(self) -> None:
        if self._busy:
            return
        self.set_busy(True)
        threading.Thread(target=self._do_unlock, args=(None, True), daemon=True).start()

    def _do_unlock(self, pw, bio: bool) -> None:
        try:
            if self.app.is_locked_out():
                self._flash(f"Locked out — retry in {self.app.lockout_remaining()}s",
                            BADGE_WARN)
                return
            res = self.app.unlock(passphrase=pw or None, use_biometric=bio)
            self.root.after(0, lambda: self._unlock_done(res))
        except Exception as e:
            traceback.print_exc()
            self.root.after(0, lambda: self._unlock_done({"ok": False, "msg": repr(e)}))

    def _unlock_done(self, res: dict) -> None:
        self.set_busy(False)
        if res.get("ok"):
            self.entry_pass.delete(0, "end")
            messagebox.showinfo("Unlocked", res.get("msg", "Vault opened."))
            self.refresh_all()
            self.nb.select(self.tab_notes)
        else:
            if res.get("locked"):
                self._flash(res.get("msg", ""), BADGE_FAIL)
            self._flash(res.get("msg", "Unlock failed"), BADGE_FAIL)

    def _setup(self) -> None:
        if self.app.vault.exists:
            messagebox.showerror("Error", "Vault already exists — wipe or delete it first.")
            return
        pw, confirm = self.entry_new.get(), self.entry_confirm.get()
        if pw != confirm:
            self._flash("Passphrases do not match.", BADGE_FAIL)
            return
        res = self.app.setup(pw, enable_biometric=self.var_bio_setup.get())
        if res["ok"]:
            messagebox.showinfo("Vault created", res["msg"])
            self.entry_new.delete(0, "end")
            self.entry_confirm.delete(0, "end")
            self._audit_print("VAULT_INIT", "OK", "created from UI")
            self.refresh_all()
            if self.app.unlocked:
                self.nb.select(self.tab_notes)
        else:
            self._flash(res["msg"], BADGE_FAIL)

    def _audit_print(self, action, result, details) -> None:
        self.app._audit(action, result, details, audit.CAT_ADMIN)
        self._refresh_audit()

    # --------------------------------------------------------- notes ops
    def _new_note(self) -> None:
        if not self.app.unlocked:
            return
        self._current_note_id = None
        self.v_title.set("")
        self.v_tags.set("")
        self.txt_body.delete("1.0", "end")
        self.txt_body.focus_set()

    def _on_select(self, _evt) -> None:
        sel = self.tree.selection()
        if not sel:
            return
        note_id = sel[0]
        note = self.app.get_note(note_id)
        if not note:
            return
        self._current_note_id = note_id
        self.v_title.set(note["title"])
        self.v_tags.set(note["tags"])
        self.txt_body.delete("1.0", "end")
        self.txt_body.insert("1.0", note["body"])

    def _save_note(self) -> None:
        if not self.app.unlocked:
            return
        title = self.v_title.get()
        tags = self.v_tags.get()
        body = self.txt_body.get("1.0", "end-1c")
        if self._current_note_id:
            res = self.app.update_note(self._current_note_id, title, body, tags)
        else:
            res = self.app.add_note(title, body, tags)
            if res.get("ok"):
                self._current_note_id = res["id"]
        if res.get("ok"):
            self._status("Note saved ✓")
            self._refresh_list()
        else:
            self._flash(res.get("msg", "Save failed"), BADGE_FAIL)

    def _delete_note(self) -> None:
        if not self._current_note_id:
            return
        if not messagebox.askyesno("Delete note", "Permanently delete this encrypted note?"):
            return
        res = self.app.delete_note(self._current_note_id)
        if res.get("ok"):
            self._current_note_id = None
            self._clear_editor()
            self._refresh_list()
        else:
            self._flash(res.get("msg", "Delete failed"), BADGE_FAIL)

    def _toggle_pin(self) -> None:
        if self._current_note_id:
            self.app.toggle_pin(self._current_note_id)
            self._refresh_list()

    def _clear_editor(self) -> None:
        self.v_title.set("")
        self.v_tags.set("")
        self.txt_body.delete("1.0", "end")

    def _refresh_list(self) -> None:
        self._refresh_notes_tab()

    def _lock(self) -> None:
        self.app.lock()
        self._status("Vault locked — keys zeroized.")
        self.refresh_all()

    # -------------------------------------------------------- reports
    def _browse_dest(self) -> None:
        d = filedialog.askdirectory(initialdir=self.app.reports_path, title="Report export folder")
        if d:
            self.var_dest.set(d)

    def _gen(self, kinds) -> None:
        if self._busy:
            return
        self.set_busy(True)
        dest = self.var_dest.get() or self.app.reports_path

        def work():
            res = self.app.generate_reports(kinds, dest_dir=dest)
            self.root.after(0, lambda: self._gen_done(res))

        threading.Thread(target=work, daemon=True).start()

    def _gen_done(self, res: dict) -> None:
        self.set_busy(False)
        self.report_out.configure(state="normal")
        if res.get("ok"):
            msg = f"✔ Report {res['report_id']} exported to:\n  {res['dir']}\n\n"
            for label, path in res["artifacts"].items():
                if path:
                    msg += f"  • {label:>12}:  {os.path.basename(path)}\n"
            for s in res.get("summaries", []):
                msg += f"\n  {s['framework']:<22} {s['passed']:>2}/{s['total']:<2} controls  ->  {s['score']:.1f}%\n"
            self.report_out.insert("end", msg)
            self._status("Reports generated ✓")
        else:
            self.report_out.insert("end", "✘ " + res.get("msg", "unknown error") + "\n")
            self._status("Report failed")
        self.report_out.configure(state="disabled")

    def _open_folder(self) -> None:
        dest = self.var_dest.get() or self.app.reports_path
        os.makedirs(dest, exist_ok=True)
        try:
            if sys.platform == "win32":
                os.startfile(dest)  # type: ignore[attr-defined]
            else:
                subprocess.Popen(["xdg-open", dest])
        except OSError:
            pass

    # ------------------------------------------------------------- audit
    def _verify_chain(self) -> None:
        res = self.app.audit_verify()
        if res.get("ok"):
            txt = f"✔ Chain verified — {res['count']} events, no tampering."
            color = BADGE_OK
        else:
            txt = f"✘ CHAIN VIOLATION: {'; '.join(res['errors'][:4])}"
            color = BADGE_FAIL
        self.chain_label.configure(text=txt, foreground=color)
        self._refresh_audit()

    # ----------------------------------------------------------- settings
    def _toggle_bio(self) -> None:
        enabled = self.var_bio.get()
        if enabled and not self.app.unlocked:
            self._flash("Unlock the vault before enabling biometric.", BADGE_WARN)
            self.var_bio.set(False)
            return
        if enabled:
            self.app.enable_biometric()
        else:
            self.app.set_biometric_enabled(False)
        self._status(f"Biometric unlock {'enabled' if enabled else 'disabled'}.")
        self._audit_print("BIOMETRIC_UPDATE", "OK" if enabled else "OFF",
                          f"biometric_enabled={enabled}")

    def _set_autolock(self) -> None:
        try:
            v = int(self.var_autolock.get())
        except (tk.TclError, ValueError):
            v = 60
        self.app.set_autolock(max(10, v))
        self._status(f"Auto-lock set to {max(10, v)}s.")

    def _change_pass(self) -> None:
        old, new = self.e_old.get(), self.e_new.get()
        res = self.app.change_passphrase(old, new)
        if res.get("ok"):
            self._status("Passphrase changed ✓")
            self.e_old.delete(0, "end")
            self.e_new.delete(0, "end")
            self.settings_status.configure(text="Passphrase changed. Old keys re-wrapped.",
                                           foreground=BADGE_OK)
        else:
            self._flash(res.get("msg", "Change failed"), BADGE_FAIL)

    def _wipe(self) -> None:
        if not messagebox.askyesno(
                "Secure wipe",
                "This OVERWRITES and deletes ALL vault data and device keys on this "
                "machine. It cannot be undone. Continue?"):
            return
        if not messagebox.askyesno("Final confirmation", "Are you absolutely sure?"):
            return
        self.app.wipe()
        self._clear_editor()
        self.refresh_all()
        self._status("Vault securely wiped.")

    # -------------------------------------------------------------- misc
    def _flash(self, text: str, color: str = None) -> None:
        self.audit_text.configure(state="normal")
        self.audit_text.insert("end", f"   >>> {text}\n")
        self.audit_text.configure(state="disabled")
        self._status(text)
        self._refresh_auth_tab(self.app.status())

    def _on_close(self) -> None:
        if self.app.unlocked:
            self.app.lock()
        self.root.destroy()


def run_ui() -> int:
    root = tk.Tk()
    SecureNoteUI(root)
    root.mainloop()
    return 0