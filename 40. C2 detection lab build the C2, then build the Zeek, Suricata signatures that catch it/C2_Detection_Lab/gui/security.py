"""PIN-lock + RBAC helper - OWASP A01/A07, ISO A.9, NIST AC-2.

PIN is stored hashed (SHA-256 + salt) in <outdir>/security.json. The GUI shows
the lock dialog once per session; 5 wrong attempts triggers a lockout window.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from pathlib import Path

_MAX_ATTEMPTS = 5
_LOCKOUT_S = 60
_SEC_FILE = "security.json"
_DEFAULT_PIN = "1234"


class PinVault:
    def __init__(self, base_dir: str | Path):
        self.path = Path(base_dir) / "state" / _SEC_FILE
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        if self.path.exists():
            self.data = json.loads(self.path.read_text(encoding="utf-8"))
        else:
            self.data = self._new_store(_DEFAULT_PIN)
            self._persist()

    @staticmethod
    def _hash(pin: str, salt: str) -> str:
        return hashlib.sha256((salt + ":" + pin).encode()).hexdigest()

    @staticmethod
    def _new_store(pin: str) -> dict:
        salt = os.urandom(16).hex()
        return {
            "pin_salt": salt,
            "pin_hash": PinVault._hash(pin, salt),
            "attempts": 0,
            "locked_until": 0.0,
            "last_unlock": None,
        }

    def check(self, pin: str) -> bool:
        with self._lock:
            now = time.time()
            if now < self.data.get("locked_until", 0):
                return False
            ok = self._hash(pin, self.data["pin_salt"]) == self.data["pin_hash"]
            if ok:
                self.data["attempts"] = 0
                self.data["last_unlock"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            else:
                self.data["attempts"] = self.data.get("attempts", 0) + 1
                if self.data["attempts"] >= _MAX_ATTEMPTS:
                    self.data["locked_until"] = now + _LOCKOUT_S
                    self.data["attempts"] = 0
            self._persist()
            return ok

    def change(self, old_pin: str, new_pin: str) -> bool:
        if not self.check(old_pin) or len(new_pin) < 4:
            return False
        self.path.write_text(json.dumps(self._new_store(new_pin), indent=2),
                            encoding="utf-8")
        self.data = self._new_store(new_pin)
        self._persist()
        return True

    def _persist(self) -> None:
        self.path.write_text(json.dumps(self.data, indent=2), encoding="utf-8")