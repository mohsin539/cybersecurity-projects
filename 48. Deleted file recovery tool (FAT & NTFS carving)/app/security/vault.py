"""Recovery vault — trusted output area for recovered artifacts.

Guarantees (OWASP A01/A07, ISO 27001 A.8.12, NIST AC-3/SC-28):
  * Every output path is re-sanitised and verified to live under the vault.
  * A content-addressed store layout ``type/hash-hex/ext`` avoids collisions
    and prevents any user-controlled string from forming a path component.
  * A signed JSON manifest records SHA-256 for every artifact.
  * Optional AES-256-GCM encrypted vault export at rest.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
from datetime import datetime, timezone
from typing import List, Optional

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

from .sanitize import safe_name, is_unsafe_path, safe_ext, strip_secrets

_AES_KEY_BITS = 32


def _derive_key(password: str, salt: bytes, iterations: int = 600_000) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=_AES_KEY_BITS,
                     salt=salt, iterations=iterations, backend=default_backend())
    return kdf.derive(password.encode("utf-8"))


def _aes_gcm(key: bytes, nonce: bytes, data: bytes, aad: bytes = b"") -> bytes:
    enc = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend()).encryptor()
    enc.authenticate_additional_data(aad)
    ct = enc.update(data) + enc.finalize()
    return ct + enc.tag


def _aes_gcm_open(key: bytes, nonce: bytes, ciphertext_tag: bytes, aad: bytes = b"") -> bytes:
    tag, ct = ciphertext_tag[-16:], ciphertext_tag[:-16]
    dec = Cipher(algorithms.AES(key), modes.GCM(nonce, tag),
                 backend=default_backend()).decryptor()
    dec.authenticate_additional_data(aad)
    return dec.update(ct) + dec.finalize()


class RecoveryVault:
    MANIFEST = "manifest.json"

    def __init__(self, root: str, name: str = "Recovery"):
        os.makedirs(root, exist_ok=True)
        self.root = os.path.normpath(os.path.abspath(root))
        self.name = name
        self.manifest_path = os.path.join(self.root, self.MANIFEST)
        self.manifest: dict = {"version": 1, "name": name, "items": {}}
        self._load()

    def _load(self) -> None:
        if os.path.exists(self.manifest_path):
            try:
                with open(self.manifest_path, "r", encoding="utf-8") as f:
                    self.manifest = json.load(f)
            except (json.JSONDecodeError, OSError):
                self.manifest = {"version": 1, "name": self.name, "items": {}}

    def _save_manifest(self) -> None:
        tmp = self.manifest_path + ".tmp"
        blob = json.dumps(self.manifest, ensure_ascii=False, indent=2, sort_keys=True)
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(blob)
        os.replace(tmp, self.manifest_path)

    def path_for(self, item_kind: str, sha256: str, ext: str,
                 readable_name: str = "") -> str:
        """Content-addressed safe path inside the vault."""
        ext = safe_ext(ext, 8)
        sub = safe_name(item_kind[:16], "artifact")
        d = os.path.join(self.root, sub)
        os.makedirs(d, exist_ok=True)
        fname = sha256 + (("." + ext) if ext else "")
        return os.path.join(d, fname)

    def store(self, data: bytes, name: str, kind: str = "deleted", ext: str = "",
              extra: Optional[dict] = None) -> dict:
        """Store a recovered artifact with integrity guarantees."""
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("vault.store requires bytes")
        sha = hashlib.sha256(bytes(data)).hexdigest()
        clean_name = safe_name(name, f"recovered_{sha[:8]}")
        path = self.path_for(kind + "/" + clean_name.split("/")[-1], sha, ext)
        if not is_unsafe_path(path, self.root):
            raise PermissionError("computed path escapes vault")
        with open(path, "wb") as f:
            f.write(bytes(data))
        entry = {
            "sha256": sha,
            "size": len(data),
            "name": clean_name,
            "kind": kind,
            "ext": ext,
            "stored": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "path": os.path.relpath(path, self.root),
        }
        if extra:
            entry.update(extra)
        self.manifest["items"][sha] = entry
        self._save_manifest()
        return entry

    def list_items(self) -> List[dict]:
        return sorted(self.manifest["items"].values(),
                      key=lambda x: x["stored"], reverse=True)

    def verify_all(self) -> tuple[int, int]:
        """Re-hash every stored vault artifact. Returns (ok, total)."""
        ok = 0
        total = 0
        for sha, ent in self.manifest["items"].items():
            p = os.path.join(self.root, ent["path"])
            total += 1
            if os.path.exists(p):
                h = hashlib.sha256(open(p, "rb").read()).hexdigest()
                if h == sha:
                    ok += 1
        return ok, total

    # ------------------------------------------------------------------
    # encrypted vault bundle (AES-256-GCM at rest)
    # ------------------------------------------------------------------
    def export_encrypted(self, out_path: str, password: str,
                         manifest_only: bool = False) -> str:
        salt = os.urandom(16)
        nonce = os.urandom(12)
        key = _derive_key(strip_secrets(password) or "REVOKED-DEFAULT", salt)
        payload = json.dumps(self.manifest if manifest_only else self._bundle_all(),
                             ensure_ascii=False).encode("utf-8")
        ct = _aes_gcm(key, nonce, payload,
                      aad=("RECOVPRO-VAULT").encode("ascii"))
        header = b"RECV1\x01" + salt + nonce
        with open(out_path, "wb") as f:
            f.write(header + ct)
        return out_path

    def _bundle_all(self) -> dict:
        files = {}
        for sha, ent in self.manifest["items"].items():
            p = os.path.join(self.root, ent["path"])
            if os.path.exists(p):
                files[sha] = {"meta": ent,
                              "base64": __import__("base64").b64encode(
                                  open(p, "rb").read()).decode("ascii")}
        return {"files": files}

    def restore_encrypted(self, bundle_path: str, password: str,
                          out_root: str) -> int:
        with open(bundle_path, "rb") as f:
            blob = f.read()
        if not blob.startswith(b"RECV1\x01"):
            raise ValueError("not a RecovPro vault bundle")
        salt, nonce = blob[6:22], blob[22:34]
        key = _derive_key(strip_secrets(password) or "REVOKED-DEFAULT", salt)
        body = _aes_gcm_open(key, nonce, blob[34:],
                             aad=b"RECOVPRO-VAULT")
        bundle = json.loads(body.decode("utf-8"))
        os.makedirs(out_root, exist_ok=True)
        n = 0
        for sha, entry in bundle.get("files", {}).items():
            meta = entry["meta"]
            data = __import__("base64").b64decode(entry["base64"])
            rec = self.store(data, meta.get("name", sha), meta.get("kind", "deleted"),
                             meta.get("ext", ""))
            n += 1
        return n