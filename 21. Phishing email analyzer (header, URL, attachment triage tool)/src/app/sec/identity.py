"""Local identity & role-based access control (RBA) with key wrapping.

Controls: OWASP A07 (no default creds, strong auth), NIST AC-7/IA-5,
ISO A.9, AC-2/3/6 (roles, least privilege).

Security model (portable single-credential tool):
  - profile.dat = plaintext header {magic, salt, pbkdf2 iterations}
                  + AES-256-GCM encrypted body {users meta, data_key}
  - The body is encrypted under K = PBKDF2(password). Successful GCM
    decryption IS authentication (tamper + possession of the secret); this
    avoids any cleartext verifier and equalizes "bad user / bad password".
  - data_key (random AES-256) is stored INSIDE the body and stays constant,
    so changing the password only re-encrypts the body under the new K.
    Stored cases/audit/settings remain decryptable across password rotations.
  - Brute-force lockout state lives in a non-secret lockout file (AC-7);
    a failed unlock therefore never re-encrypts the body with a wrong key.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import secrets
import time
from typing import Dict, Optional, Tuple

from .crypto import SecurityError, decrypt_bytes, encrypt_bytes
from .validation import sanitize_text
from . import constants as C

_PROFILE_MAGIC = b"PEAP1"
_ID_MAGIC = b"PEAI1"
_PROFILE_AAD = b"pea-profile.v1"


class AuthError(Exception):
    pass


def _kdf(password: str, salt: bytes, iterations: int) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt,
                               iterations, dklen=32)


class IdentityStore:
    def __init__(self, path: str):
        self.path = path
        self.key_path = os.path.join(os.path.dirname(path), "lockout.dat")
        self.salt = b""
        self.iterations = C.PBKDF2_ITERATIONS
        self.users: Dict[str, dict] = {}
        self.data_key: bytes = b""
        self.role = ""
        self.username = ""
        self._body_enc = b""
        self.load()

    # ------------------------------------------------------------------ header
    def load(self) -> None:
        if not os.path.exists(self.path):
            return
        try:
            raw = open(self.path, "rb").read()
            if raw[: len(_PROFILE_MAGIC)] != _PROFILE_MAGIC:
                raise AuthError("profile magic mismatch [tampering suspected]")
            off = len(_PROFILE_MAGIC)
            salt_len = raw[off]; off += 1
            self.salt = raw[off:off + salt_len]; off += salt_len
            self.iterations = int.from_bytes(raw[off:off + 4], "big"); off += 4
            body = raw[off:]
            if body[: len(_ID_MAGIC)] != _ID_MAGIC:
                raise AuthError("profile body magic mismatch")
            self._body_enc = body[len(_ID_MAGIC):]
        except Exception as exc:  # noqa: BLE001
            raise AuthError(f"profile unreadable: {exc}") from exc

    def _decrypt_body(self, password: str) -> dict:
        k = _kdf(password, self.salt, self.iterations)
        try:
            payload = decrypt_bytes(self._body_enc, k, _PROFILE_AAD)
        except SecurityError as exc:
            raise AuthError("invalid credentials [GCM authentication failed]") from exc
        doc = json.loads(payload.decode("utf-8"))
        self.users = doc.get("users", {})
        self.data_key = base64.b64decode(doc["data_key"])
        self.role = self.users.get(self.username, {}).get("role", "")
        return doc

    def _encode(self, users: Dict, data_key: bytes, password: str, salt: bytes,
                iterations: int) -> bytes:
        k = _kdf(password, salt, iterations)
        doc = {"users": users, "data_key": base64.b64encode(data_key).decode("ascii")}
        return _PROFILE_MAGIC + bytes([len(salt)]) + salt + iterations.to_bytes(4, "big") \
            + _ID_MAGIC + encrypt_bytes(json.dumps(doc, ensure_ascii=False).encode("utf-8"),
                                        k, _PROFILE_AAD)

    def _save_blob(self, blob: bytes) -> None:
        tmp = self.path + ".tmp"
        with open(tmp, "wb") as fh:
            fh.write(blob)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, self.path)

    # ------------------------------------------------------------------ create
    def create_profile(self, username: str, password: str, role: str = "admin") -> Dict:
        username = self._validate_username(username)
        if role not in C.ROLES:
            raise AuthError("invalid role")
        if os.path.exists(self.path):
            raise AuthError("profile already exists; delete the vault to re-create")
        self._assert_password_policy(password)
        salt = secrets.token_bytes(C.SALT_BYTES)
        data_key = secrets.token_bytes(C.AES_KEY_BYTES)
        users = {username: self._new_user(role, time.time(), salt)}
        blob = self._encode(users, data_key, password, salt, C.PBKDF2_ITERATIONS)
        self._save_blob(blob)
        self.load()   # sync salt/iterations/_body_enc so authenticate works in-process
        self.username = username
        self.role = role
        self.data_key = data_key
        return {"username": username, "role": role}

    @staticmethod
    def _new_user(role: str, created: float, salt: bytes) -> dict:
        return {"role": role, "created": created, "password_changed": created,
                "iterations": C.PBKDF2_ITERATIONS}

    # ------------------------------------------------------------------ auth
    def authenticate(self, username: str, password: str) -> Tuple[Dict, bytes]:
        username = self._validate_username(username)
        if not self.users and not os.path.exists(self.path):
            raise AuthError("no profile found - fresh setup required")
        self._enforce_lockout(username)
        try:
            doc = self._decrypt_body(password)     # possession of password == auth
        except AuthError:
            self._bump(username)
            time.sleep(0.3)
            raise
        if username not in doc["users"]:
            self._bump(username)
            time.sleep(0.3)
            raise AuthError("invalid credentials")
        self._clear_lockout(username)
        self.username = username
        self.role = doc["users"][username]["role"]
        self.users = doc["users"]
        self.data_key = base64.b64decode(doc["data_key"])
        return {"username": username, "role": self.role}, bytes(self.data_key)

    # ------------------------------------------------------------------ change
    def change_password(self, username: str, old_password: str, new_password: str) -> None:
        username = self._validate_username(username)
        doc = self._decrypt_body(old_password)      # old password proves ownership
        if username not in doc["users"]:
            raise AuthError("no such user")
        self._assert_password_policy(new_password)
        new_salt = secrets.token_bytes(C.SALT_BYTES)
        users = doc["users"]
        users[username]["password_changed"] = time.time()
        users[username]["iterations"] = C.PBKDF2_ITERATIONS
        blob = self._encode(users, self.data_key or base64.b64decode(doc["data_key"]),
                            new_password, new_salt, C.PBKDF2_ITERATIONS)
        self._save_blob(blob)
        self.load()   # sync _body_enc/iterations so the same process can decrypt
        self.salt = new_salt
        self._clear_lockout(username)

    def set_role(self, username: str, role: str, vault_password: str) -> None:
        if role not in C.ROLES:
            raise AuthError("invalid role")
        username = self._validate_username(username)
        doc = self._decrypt_body(vault_password)
        if username not in doc["users"]:
            raise AuthError("no such user")
        doc["users"][username]["role"] = role
        blob = self._encode(doc["users"], base64.b64decode(doc["data_key"]),
                            vault_password, self.salt, self.iterations)
        self._save_blob(blob)
        if username == self.username:
            self.role = role

    # ------------------------------------------------------------------ lockout
    def _lock_file(self) -> dict:
        if not os.path.exists(self.key_path):
            return {}
        try:
            return json.load(open(self.key_path, encoding="utf-8"))
        except Exception:  # noqa: BLE001
            return {}

    def _write_lock_file(self, data: dict) -> None:
        tmp = self.key_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(data, fh)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, self.key_path)

    def _enforce_lockout(self, username: str) -> None:
        rec = self._lock_file().get(username)
        if rec and rec.get("locked_until", 0) > time.time():
            raise AuthError("account locked due to repeated failures [AC-7]")

    def _bump(self, username: str) -> None:
        data = self._lock_file()
        rec = data.get(username, {"fails": 0, "locked_until": 0})
        rec["fails"] = int(rec.get("fails", 0)) + 1
        if rec["fails"] >= C.LOGIN_MAX_ATTEMPTS:
            rec["locked_until"] = time.time() + C.LOGIN_LOCKOUT_SECONDS
            rec["fails"] = 0
        data[username] = rec
        self._write_lock_file(data)

    def _clear_lockout(self, username: str) -> None:
        data = self._lock_file()
        if username in data:
            del data[username]
            self._write_lock_file(data)

    # ------------------------------------------------------------------ misc
    @staticmethod
    def _validate_username(username: str) -> str:
        username = sanitize_text(username.strip().lower(), 64)
        if not re.match(r"^[a-z0-9_.-]{3,64}$", username):
            raise AuthError("invalid username (3-64 lowercase alnum) [SI-10]")
        return username

    @staticmethod
    def _assert_password_policy(password: str) -> None:
        if len(password) < C.MIN_PASSWORD_LEN:
            raise AuthError(f"password must be >= {C.MIN_PASSWORD_LEN} chars [IA-5]")

    def is_empty(self) -> bool:
        return not os.path.exists(self.path)

    def profile_exists(self) -> bool:
        return os.path.exists(self.path)


class Session:
    def __init__(self, username: str, role: str, data_key: bytes, password: str):
        self.username = username
        self.role = role
        self.data_key = data_key
        self._password = password
        self.started = time.time()

    def can(self, action: str) -> bool:
        return self.role in C.ALLOWED_ROLE_BY_ACTION.get(action, set())

    @property
    def password(self) -> str:
        return self._password

    def update_password(self, password: str) -> None:
        self._password = password

    def wipe(self) -> None:
        self.data_key = b""
        self._password = ""
        self.username = ""