"""Application Controller / Use-Case Orchestrator (architecture.md §4).

Binds Vault + Audit Ledger + Rate Limiter + Report engine into the
high-level operations the UI and CLI call. Every security-relevant action
writes an audit event (arch §10).
"""

from __future__ import annotations

import json
import os
import sys
import threading
import time

from . import auth
from . import audit
from . import crypto_core as cc
from . import policy
from . import report
from .vault import Vault

MIN_PASSPHRASE = 8


def resolve_data_dir() -> str:
    """Portable layout: data next to the .exe when writable, else user profile."""
    override = os.environ.get("SECURENOTE_HOME")
    if override:
        d = os.path.abspath(override)
    else:
        exe_dir = os.path.dirname(os.path.abspath(sys.argv[0]))
        probe = exe_dir
        try:
            if os.access(probe, os.W_OK):
                d = os.path.join(exe_dir, "data")
            else:
                d = os.path.join(os.path.expanduser("~"), ".secure_note")
        except OSError:
            d = os.path.join(os.path.expanduser("~"), ".secure_note")
    os.makedirs(d, exist_ok=True)
    return d


class SecureNoteApp:
    def __init__(self, data_dir: str | None = None):
        self.data_dir = data_dir or resolve_data_dir()
        self.vault_path = os.path.join(self.data_dir, "vault.bin")
        self.dk_path = os.path.join(self.data_dir, "dk.bin")
        self.audit_path = os.path.join(self.data_dir, "audit.bin")
        self.ak_path = os.path.join(self.data_dir, "audit.key")
        self.state_path = os.path.join(self.data_dir, "authstate.json")
        self.reports_path = os.path.join(self.data_dir, "reports")
        self.signer_path = os.path.join(self.data_dir, "signer.key")

        self.vault = Vault(self.vault_path, self.dk_path)
        self.ledger = audit.AuditLedger(self.audit_path, self.ak_path)
        self.limiter = auth.RateLimiter(self.state_path)
        self._lock_guard = threading.Lock()

        now = time.strftime("%Y-%m-%dT%H:%M:%S%z")
        self.app_started = now
        self.bio_state = auth.biometric_available()
        self._audit("APP_START", "OK", f"data_dir={self.data_dir}; bio_state={self.bio_state}")
        if self.vault.exists:
            self.vault.load()
            self.vault.settings["biometric_available"] = self.bio_state

    # ---- audit helper ---------------------------------------------------------
    def _audit(self, action: str, result: str, details: str = "", category: str = audit.CAT_AUTH) -> int:
        try:
            return self.ledger.log(action, result, details, category)
        except Exception:
            return -1

    # ---- status ------------------------------------------------------------------
    @property
    def unlocked(self) -> bool:
        return self.vault.dek is not None

    def status(self) -> dict:
        return {
            "vault_exists": self.vault.exists,
            "unlocked": self.unlocked,
            "biometric": self.bio_state,
            "biometric_configured": bool(self.vault.settings.get("biometric_enabled")),
            "notes_count": len(self.vault.notes) if self.unlocked else 0,
            "autolock_seconds": self.vault.settings.get("autolock_seconds", 60),
            "data_dir": self.data_dir,
            "started": self.app_started,
        }

    # ---- setup ------------------------------------------------------------------
    def setup(self, passphrase: str, enable_biometric: bool) -> dict:
        if self.vault.exists:
            return {"ok": False, "msg": "Vault already exists — create in a new profile."}
        if len(passphrase) < MIN_PASSPHRASE:
            return {"ok": False, "msg": f"Passphrase must be ≥ {MIN_PASSPHRASE} characters."}
        settings = {
            "biometric_enabled": bool(enable_biometric and self.bio_state in ("available", "unknown")),
            "autolock_seconds": 60,
            "min_passphrase_len": MIN_PASSPHRASE,
            "wipe_on_lockout": True,
        }
        self.vault.initialize(passphrase, settings)
        self.vault.settings["biometric_available"] = self.bio_state
        self._audit("VAULT_INIT", "OK", "new vault created (AES-256-GCM key hierarchy)", audit.CAT_ADMIN)
        if self.vault.settings.get("biometric_enabled"):
            self.vault.enable_biometric()
            self._audit("BIOMETRIC_ENABLE", "OK", "biometric unlock configured", audit.CAT_AUTH)
        return {"ok": True, "msg": "Vault created"}

    # ---- unlock -------------------------------------------------------------------
    def is_locked_out(self) -> bool:
        try:
            self.limiter.check("unlock")
            return False
        except auth.LockoutError:
            return True

    def lockout_remaining(self) -> int:
        until = self.limiter._state.get("lockout_until", 0)
        return max(0, int(until - time.time()) + 1)

    def unlock(self, passphrase: str | None = None, use_biometric: bool = False) -> dict:
        with self._lock_guard:
            if not self.vault.exists:
                return {"ok": False, "msg": "No vault. Create one in Setup first."}
            try:
                self.limiter.check("unlock")
            except auth.LockoutError as e:
                self._audit("UNLOCK_BLOCKED", "LOCKED_OUT", str(e))
                return {"ok": False, "locked": True, "msg": str(e)}

            if use_biometric:
                self._audit("UNLOCK_ATTEMPT", "BIOMETRIC", "Windows Hello requested")
                verified = auth.request_biometric("Unlock SecureNote Pro")
                if not verified:
                    self._record_failure("biometric denied/error")
                    return {"ok": False, "msg": "Biometric not verified."}
                ok = self.vault.unlock_with_biometric()
                if ok:
                    self.limiter.record_success()
                    self._audit("UNLOCK_SUCCESS", "BIOMETRIC", "vault opened (biometric factor)")
                    return {"ok": True, "msg": "Unlocked (biometric)"}
                self._record_failure("biometric key release failed")
                return {"ok": False, "msg": "Biometric key release failed (device binding mismatch?)."}
            else:
                if not passphrase:
                    return {"ok": False, "msg": "Passphrase required."}
                ok = self.vault.unlock_with_passphrase(passphrase)
                if ok:
                    self.limiter.record_success()
                    self._audit("UNLOCK_SUCCESS", "PASSPHRASE", "vault opened (knowledge factor)")
                    return {"ok": True, "msg": "Unlocked"}
                self._record_failure("wrong passphrase")
                return {"ok": False, "msg": "Incorrect passphrase.", "attempts": self.limiter._state["failures"].get("unlock", 0)}

    def _record_failure(self, why: str) -> None:
        info = self.limiter.record_failure("unlock")
        self._audit("UNLOCK_FAIL", "DENIED", f"{why}; attempt {info['attempts']}")
        if info["attempts"] >= auth.MAX_FAILURES:
            self._audit("LOCKOUT_WIPE", "WIPED", "lockout threshold reached; secure wipe executed")
            # Hard lockout -> destroy key material (arch §6.2 / §12 "zerow")
            self.vault.wipe()
            self.ledger.log("VAULT_WIPED", "OK", "key material destroyed after lockout", audit.CAT_CRYPTO)
        else:
            self.limiter.trigger_lockout("unlock")

    def lock(self) -> None:
        if self.vault.dek is not None:
            self._audit("VAULT_LOCK", "OK", "keys zeroized", audit.CAT_AUTH)
        self.vault.lock()

    # ---- notes ---------------------------------------------------------------------
    def add_note(self, title: str, body: str, tags: str = "") -> dict:
        if not self.unlocked:
            return {"ok": False, "msg": "Vault locked."}
        if not title.strip():
            return {"ok": False, "msg": "Title is required."}
        nid = self.vault.add_note(title.strip(), body, tags.strip())
        self._audit("NOTE_CREATE", "OK", f"note={nid}", audit.CAT_DATA)
        return {"ok": True, "id": nid}

    def update_note(self, note_id: str, title: str, body: str, tags: str = "") -> dict:
        if not self.unlocked:
            return {"ok": False, "msg": "Vault locked."}
        try:
            self.vault.update_note(note_id, title, body, tags)
        except KeyError:
            return {"ok": False, "msg": "Note not found."}
        self._audit("NOTE_UPDATE", "OK", f"note={note_id}", audit.CAT_DATA)
        return {"ok": True}

    def delete_note(self, note_id: str) -> dict:
        if not self.unlocked:
            return {"ok": False, "msg": "Vault locked."}
        try:
            self.vault.delete_note(note_id)
        except KeyError:
            return {"ok": False, "msg": "Note not found."}
        self._audit("NOTE_DELETE", "OK", f"note={note_id}", audit.CAT_DATA)
        return {"ok": True}

    def toggle_pin(self, note_id: str) -> dict:
        if self.unlocked:
            self.vault.toggle_pin(note_id)
        return {"ok": True}

    def note_list(self) -> list[dict]:
        if not self.unlocked:
            return []
        out = []
        for n in self.vault.notes:
            try:
                plain = self.vault.get_note_plain(n)
                out.append({
                    "id": plain["id"], "title": plain["title"], "tags": plain["tags"],
                    "updated": plain["updated"], "pinned": plain["pinned"],
                })
            except Exception:
                continue
        return sorted(out, key=lambda x: (not x["pinned"], x["updated"]), reverse=True)

    def get_note(self, note_id: str) -> dict:
        if not self.unlocked:
            return {}
        for n in self.vault.notes:
            if n["id"] == note_id:
                return self.vault.get_note_plain(n)
        return {}

    # ---- biometric on/off --------------------------------------------------------------
    def enable_biometric(self) -> dict:
        if not self.unlocked:
            return {"ok": False, "msg": "Unlock first to configure."}
        if self.bio_state not in ("available", "unknown"):
            return {"ok": False, "msg": f"Biometric unavailable on this device ({self.bio_state})."}
        self.vault.enable_biometric()
        self._audit("BIOMETRIC_ENABLE", "OK", "biometric unlock configured", audit.CAT_AUTH)
        return {"ok": True}

    def set_biometric_enabled(self, enabled: bool) -> dict:
        if not self.unlocked:
            return {"ok": False, "msg": "Unlock first."}
        self.vault.settings["biometric_enabled"] = bool(enabled)
        self.vault.set_setting("biometric_enabled", bool(enabled))
        self._audit("BIOMETRIC_UPDATE", "OK", f"biometric_enabled={bool(enabled)}", audit.CAT_AUTH)
        return {"ok": True}

    # ---- passphrase/settings -----------------------------------------------------------------
    def change_passphrase(self, old: str, new: str) -> dict:
        if len(new) < MIN_PASSPHRASE:
            return {"ok": False, "msg": f"New passphrase must be ≥ {MIN_PASSPHRASE} chars."}
        ok = self.vault.change_passphrase(old, new)
        if ok:
            self._audit("PASSPHRASE_CHANGE", "OK", "verifier + wrapped keys rotated", audit.CAT_AUTH)
            return {"ok": True}
        return {"ok": False, "msg": "Old passphrase incorrect."}

    def set_autolock(self, seconds: int) -> None:
        self.vault.set_setting("autolock_seconds", int(seconds))
        self._audit("AUTOLOCK_SET", "OK", f"autolock={seconds}s", audit.CAT_ADMIN)

    # ---- reports & audit ---------------------------------------------------------------------
    def audit_events(self, limit: int = 200) -> list[dict]:
        return self.ledger.export_rows(limit)

    def audit_verify(self) -> dict:
        res = self.ledger.verify_chain()
        if res["ok"]:
            self._audit("AUDIT_VERIFY", "PASS", f"chain recomputed, {res['count']} events", audit.CAT_COMPLIANCE)
        else:
            self._audit("AUDIT_VERIFY", "FAIL", "; ".join(res["errors"][:3]), audit.CAT_COMPLIANCE)
        return res

    def generate_reports(self, kinds: tuple[str, ...] = ("compliance", "audit", "attestation"),
                         dest_dir: str | None = None) -> dict:
        d = dest_dir or self.reports_path
        try:
            out = report.generate_reports(self.vault, self.ledger, d, self.signer_path, kinds)
        except Exception as e:
            return {"ok": False, "msg": f"Report generation failed: {e}"}
        self._audit(
            "REPORT_EXPORT", "OK",
            f"report {out['report_id']} -> {d} ({kinds})", audit.CAT_COMPLIANCE)
        return {"ok": True, **out}

    def wipe(self) -> dict:
        self._audit("SECURE_WIPE", "OK", "all local key material and vault erased", audit.CAT_ADMIN)
        self.vault.wipe()
        return {"ok": True, "msg": "Vault and device keys securely wiped."}

    def compliance_summary(self) -> list[dict]:
        ev = policy.collect_evidence(self.vault, self.ledger)
        return policy.summarize(policy.score(ev))