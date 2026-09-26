"""Encrypted Vault — key hierarchy & note storage (architecture.md §5 & §7).

Storage layout (JSON vault.bin, every envelope AES-256-GCM):
  salt         -> Argon2id -> KEK
  verifier     = HKDF(KEK, "passphrase-verifier")
  kek_verifier = HKDF(KEK, "kek-verifier")           # biometric path check
  kek_blob     = AEAD(BK, KEK)                        # biometric-releasable copy
  bio_blob     = AEAD(DK, BK)                          # device-bound BK
  dek_wrapped  = AEAD(KEK, DEK)
  body         = AEAD(DEK, { notes: [ ... ] })        # per-note AEAD inside

DK (device key) lives in `dk.bin`, sealed with Windows DPAPI (device+user
bound) — the portable hardware-root-of-trust analog (arch §5.2/§12).
"""

from __future__ import annotations

import json
import os
import time
import uuid

from . import crypto_core as cc
from . import dpapi_binding as dpapi

SCHEMA = 1
PASS_VER = "passphrase-verifier"
KEK_VER = "kek-verifier"


def _json_dump(obj) -> str:
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False)


def _json_load(raw: bytes) -> dict:
    return json.loads(raw.decode("utf-8"))


class Vault:
    def __init__(self, path: str, dk_path: str):
        self.path = path
        self.dk_path = dk_path
        self.dk: bytes | None = None          # device key (DPAPI-sealed)
        self.bk: bytes | None = None          # biometric key
        self.kek: bytes | None = None         # key-encryption key
        self.dek: bytes | None = None         # data key (short-lived)
        self.salt: bytes | None = None
        self._verifier: bytes | None = None
        self._kek_verifier: bytes | None = None
        self.settings: dict = {}
        self.notes: list[dict] = []
        self.header: dict = {}
        self.exists = os.path.exists(self.path)

    # ---------------------------------------------------------------- setup
    def initialize(self, passphrase: str, settings: dict | None = None) -> None:
        """First-run vault creation (arch §12 key generation)."""
        if self.exists:
            raise ValueError("Vault already exists")
        self.salt = cc.generate_salt()
        self.kek = cc.derive_kek(passphrase, self.salt)
        self.dk = cc.random_bytes(32)
        self.bk = cc.random_bytes(32)
        self.dek = cc.random_bytes(32)
        self.settings = settings or {"biometric_enabled": False, "autolock_seconds": 60}
        self._verifier = cc.expand_subkey(self.kek, PASS_VER)
        self._kek_verifier = cc.expand_subkey(self.kek, KEK_VER)
        self.notes = []
        self._persist_dk()
        self._rebuild_header_entries()
        self._persist_header()

    # ------------------------------------------------------------- unlocking
    def unlock_with_passphrase(self, passphrase: str) -> bool:
        kek = cc.derive_kek(passphrase, self.salt)
        if not cc.constant_time_eq(
            cc.expand_subkey(kek, PASS_VER), self._verifier
        ):
            return False
        self.kek = kek
        self._open_keks()
        return True

    def unlock_with_biometric(self) -> bool:
        """Post-biometric-success key release (arch §6.1 Step VERIFY_BIO)."""
        try:
            dk = dpapi.dpapi_unprotect(open(self.dk_path, "rb").read())
        except (OSError, FileNotFoundError):
            return False
        self.dk = dk
        try:
            bk = cc.aead_load(dk, self.header["bio_blob"])
        except Exception:
            return False
        self.bk = bk
        try:
            self.kek = cc.aead_load(bk, self.header["kek_blob"])
        except Exception:
            return False
        if not cc.constant_time_eq(
            cc.expand_subkey(self.kek, KEK_VER), self._kek_verifier
        ):
            return False
        self._open_keks()
        return True

    # ------------------------------------------------------------- internals
    def _persist_dk(self) -> None:
        os.makedirs(os.path.dirname(self.dk_path), exist_ok=True)
        with open(self.dk_path, "wb") as f:
            f.write(dpapi.dpapi_protect(self.dk))

    def _open_keks(self) -> None:
        bundle = _json_load(cc.aead_load(self.kek, self.header["dek_wrapped"]))
        self.dek = bytes.fromhex(bundle["dek"])
        self._load_body()

    def _load_body(self) -> None:
        payload = cc.aead_load(self.dek, self.header["body"])
        self.notes = _json_load(payload).get("notes", [])

    def _rebuild_header_entries(self) -> None:
        self.header["kek_blob"] = cc.aead_dump(self.bk, self.kek)
        self.header["bio_blob"] = cc.aead_dump(self.dk, self.bk)
        self.header["dek_wrapped"] = cc.aead_dump(
            self.kek, _json_dump({"dek": self.dek.hex()}).encode("utf-8"))
        self.header["body"] = cc.aead_dump(
            self.dek, _json_dump({"notes": self.notes}).encode("utf-8"))

    def _persist_header(self) -> None:
        doc = {
            "schema": SCHEMA,
            "salt": self.salt.hex(),
            "verifier": self._verifier.hex(),
            "kek_verifier": self._kek_verifier.hex(),
            "kek_blob": self.header["kek_blob"],
            "bio_blob": self.header["bio_blob"],
            "dek_wrapped": self.header["dek_wrapped"],
            "body": self.header["body"],
            "settings": self.settings,
            "created": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        }
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(doc, f, indent=1)
        os.replace(tmp, self.path)
        self.exists = True

    def load(self) -> None:
        with open(self.path, encoding="utf-8") as f:
            doc = json.load(f)
        self.header = doc
        self.salt = bytes.fromhex(doc["salt"])
        self._verifier = bytes.fromhex(doc["verifier"])
        self._kek_verifier = bytes.fromhex(doc["kek_verifier"])
        self.settings = doc.get("settings", {})

    # ------------------------------------------------------------- lifecycle
    def enable_biometric(self) -> None:
        if not self.kek or not self.dek:
            raise RuntimeError("vault must be unlocked first")
        if self.dk is None:
            self.dk = cc.random_bytes(32)
            self._persist_dk()
        if self.bk is None:
            self.bk = cc.random_bytes(32)
        self._rebuild_header_entries()
        self.settings["biometric_enabled"] = True
        self._persist_header()

    def change_passphrase(self, old: str, new: str) -> bool:
        if not self.unlock_with_passphrase(old):
            return False
        self.kek = cc.derive_kek(new, self.salt)
        self._verifier = cc.expand_subkey(self.kek, PASS_VER)
        self._kek_verifier = cc.expand_subkey(self.kek, KEK_VER)
        if self.bk:  # re-wrap biometric path under new KEK
            self._rebuild_header_entries()
        else:
            self.header["dek_wrapped"] = cc.aead_dump(
                self.kek, _json_dump({"dek": self.dek.hex()}).encode("utf-8"))
        self._persist_header()
        return True

    def set_setting(self, key: str, value) -> None:
        self.settings[key] = value
        self._persist_header()

    def lock(self) -> None:
        self.kek = None
        self.dek = None
        self.bk = None
        self.notes = []

    def wipe(self) -> None:
        """Secure wipe: overwrite vault + device key with noise, then delete."""
        for p in (self.path, self.dk_path):
            if os.path.exists(p):
                with open(p, "r+b") as f:
                    size = os.path.getsize(p)
                    if size:
                        f.seek(0)
                        f.write(cc.random_bytes(size))
                        f.flush()
                        os.fsync(f.fileno())
                os.remove(p)
        self.exists = False
        self.lock()

    # ------------------------------------------------------------- note CRUD
    def _wrap_note(self, title: str, body: str, tags: str) -> dict:
        doc = {"title": title, "body": body, "tags": tags.split(",") if tags else [],
               "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z")}
        return {
            "id": str(uuid.uuid4()),
            "enc": cc.aead_dump(self.dek, _json_dump(doc).encode("utf-8")),
            "created": doc["ts"],
            "updated": doc["ts"],
            "pinned": False,
        }

    def add_note(self, title: str, body: str, tags: str = "") -> str:
        note = self._wrap_note(title, body, tags)
        self.notes.append(note)
        self._save_body()
        return note["id"]

    def update_note(self, note_id: str, title: str, body: str, tags: str = "") -> None:
        for i, note in enumerate(self.notes):
            if note["id"] == note_id:
                updated = self._wrap_note(title, body, tags)
                updated["id"] = note_id
                updated["created"] = note["created"]
                updated["pinned"] = note.get("pinned", False)
                self.notes[i] = updated
                self._save_body()
                return
        raise KeyError("note not found")

    def delete_note(self, note_id: str) -> None:
        before = len(self.notes)
        self.notes = [n for n in self.notes if n["id"] != note_id]
        if len(self.notes) == before:
            raise KeyError("note not found")
        self._save_body()

    def toggle_pin(self, note_id: str) -> None:
        for note in self.notes:
            if note["id"] == note_id:
                note["pinned"] = not note.get("pinned", False)
                self._save_body()
                return

    def _save_body(self) -> None:
        self.header["body"] = cc.aead_dump(
            self.dek, _json_dump({"notes": self.notes}).encode("utf-8"))
        self._persist_header()

    def get_note_plain(self, note: dict) -> dict:
        doc = _json_load(cc.aead_load(self.dek, note["enc"]))
        return {
            "id": note["id"], "title": doc["title"], "body": doc["body"],
            "tags": ", ".join(doc.get("tags", [])),
            "created": note["created"], "updated": note["updated"],
            "pinned": note.get("pinned", False),
        }

    def decrypt_title(self, note: dict) -> str:
        try:
            return self.get_note_plain(note)["title"]
        except Exception:
            return "[unreadable]"