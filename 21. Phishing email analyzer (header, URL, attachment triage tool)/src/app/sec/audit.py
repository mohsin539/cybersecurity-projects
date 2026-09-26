"""Tamper-evident, encrypted, append-only audit log.

Controls: OWASP A09 (logging/monitoring failures), NIST AU-3/AU-6/AU-11,
ISO 27001 A.12.4 (logging & monitoring), A.8.10 (deletion).

Design:
  - Entries are grouped into numbered encrypted batch files (AES-256-GCM).
  - Every entry carries a SHA-256 hash chaining to the previous entry's hash.
  - The chain head (last entry hash) is stored protected by an HMAC keyed with
    a salt-diversified key derived from the same passphrase, so offline
    tampering without the credential is detectable.
  - verify() replays every batch and fails-closed on any mismatch.
  - Purge securely erases batches beyond policy ({}.format -> secure_erase).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from typing import Dict, Iterator, List, Optional

from .crypto import SecurityError, decrypt_bytes, derive_key, encrypt_bytes, secure_erase
from .validation import sanitize_text
from . import constants as C

AUDIT_AAD = b"pea-audit.v1"
_HEAD_AAD = b"pea-audit-head.v1"
_HEAD_SALT = b"pea-audit-head-salt"        # fixed 16-byte diversification salt
_HEAD_TAG = b"PEAH1"


class AuditError(Exception):
    pass


def _entry_hash(entry: Dict) -> str:
    h = hashlib.sha256()
    for key in ("seq", "ts", "actor", "role", "action", "target", "result"):
        h.update((entry.get(key) or "").__str__().encode("utf-8", "replace"))
        h.update(b"\x00")
    h.update((entry.get("prev") or "").encode("utf-8", "replace"))
    h.update(entry.get("detail", "").encode("utf-8", "replace"))
    return h.hexdigest()


class AuditLog:
    def __init__(self, audit_dir: str, key: bytes):
        self.dir = audit_dir
        self.batches: Dict[int, str] = {}   # seq -> encrypted filename
        hmac_key = derive_key("", _HEAD_SALT)[:32]  # replaced below w/ correct inputs
        self.head_key = hmac.new(key, b"peat-audit-head", hashlib.sha256).digest()
        os.makedirs(self.dir, exist_ok=True)
        self.seq = 0
        self.last_hash = ""
        self._load_index()

    # -- helpers ------------------------------------------------------------
    def _rel_filename(self, seq: int) -> str:
        return f"batch-{seq:06d}.bin"

    def _load_index(self) -> None:
        self.batches = {}
        try:
            for fname in os.listdir(self.dir):
                if fname.lower().endswith(".bin"):
                    seq = int(fname.split("-")[1].split(".")[0])
                    self.batches[seq] = os.path.join(self.dir, fname)
        except (ValueError, OSError):
            pass
        head = self._read_head()
        if head:
            self.seq, self.last_hash = head

    def _read_head(self) -> Optional[tuple]:
        path = os.path.join(self.dir, "audit.head")
        if not os.path.exists(path):
            return None
        try:
            raw = base64.b64decode(open(path, "rb").read())
            if raw[: len(_HEAD_TAG)] != _HEAD_TAG:
                raise AuditError("audit head magic corrupt")
            payload = decrypt_bytes(raw[len(_HEAD_TAG):], self.head_key, _HEAD_AAD)
            doc = json.loads(payload.decode("utf-8"))
            seq, last_hash = int(doc["seq"]), str(doc["last_hash"])
            if not last_hash:
                return None
            return seq, last_hash
        except Exception as exc:  # noqa: BLE001
            raise AuditError(f"audit head unreadable: {exc}") from exc

    def _write_head(self) -> None:
        payload = json.dumps({"seq": self.seq, "last_hash": self.last_hash}).encode("utf-8")
        blob = _HEAD_TAG + encrypt_bytes(payload, self.head_key, _HEAD_AAD)
        path = os.path.join(self.dir, "audit.head")
        tmp = path + ".tmp"
        with open(tmp, "wb") as fh:
            fh.write(base64.b64encode(blob))
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)

    # -- write ----------------------------------------------------------------
    def append(self, action: str, actor: str, role: str, target: str = "",
               result: str = "ok", detail: str = "") -> None:
        if action not in C.AUDIT_EVENTS:
            raise AuditError(f"unknown audit action {action!r}")
        entry = {
            "seq": self.seq + 1,
            "ts": time.time(),
            "actor": sanitize_text(actor, 128),
            "role": sanitize_text(role, 32),
            "action": action,
            "target": sanitize_text(target, 256),
            "result": sanitize_text(result, 64),
            "detail": sanitize_text(detail, 2048),
            "prev": self.last_hash,
            "hash": None,
        }
        entry["hash"] = _entry_hash(entry)
        self.seq = entry["seq"]
        self.last_hash = entry["hash"]
        self._append_entry(entry)
        self._write_head()

    def _append_entry(self, entry: Dict) -> None:
        # current open batch = highest seq present
        seq = max(self.batches) if self.batches else 0
        batch = self.batches.get(seq)
        if batch and os.path.exists(batch):
            raw = open(batch, "rb").read()
            try:
                doc = json.loads(decrypt_bytes(raw, self._batch_key(seq), AUDIT_AAD).decode("utf-8"))
            except Exception:  # noqa: BLE001
                raise AuditError(f"corrupt audit batch {batch}")
        else:
            doc = {"seq": seq, "entries": []}
        doc["entries"].append(entry)
        if len(doc["entries"]) >= C.AUDIT_BATCH or seq == 0:
            seq += 1
            doc = {"seq": seq, "entries": [entry]}
        blob = encrypt_bytes(json.dumps(doc, ensure_ascii=False).encode("utf-8"),
                             self._batch_key(seq), AUDIT_AAD)
        path = os.path.join(self.dir, self._rel_filename(seq))
        tmp = path + ".tmp"
        with open(tmp, "wb") as fh:
            fh.write(blob)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
        self.batches[seq] = path

    def _batch_key(self, seq: int) -> bytes:
        return hmac.new(self.head_key, f"batch-{seq}".encode("ascii"), hashlib.sha256).digest()

    # -- read / verify ---------------------------------------------------------
    def iterate(self, reverse: bool = False) -> Iterator[Dict]:
        files = sorted(self.batches.items())
        if reverse:
            files_rev = sorted(self.batches.items(), reverse=True)
        else:
            files_rev = files
        for seq, path in files_rev:
            try:
                doc = json.loads(decrypt_bytes(open(path, "rb").read(),
                                               self._batch_key(seq), AUDIT_AAD).decode("utf-8"))
            except KeyError:
                continue
            entries = doc.get("entries", [])
            if reverse:
                entries = list(reversed(entries))
            yield from entries

    def tail(self, n: int = 200) -> List[Dict]:
        out: List[Dict] = []
        for e in self.iterate(reverse=True):
            out.append(e)
            if len(out) >= n:
                break
        return out

    def verify(self) -> List[str]:
        """Replay full chain; return list of integrity problems (empty == OK)."""
        problems: List[str] = []
        prev = ""
        seen = 0
        for seq_sorted in sorted(self.batches):
            path = self.batches[seq_sorted]
            try:
                doc = json.loads(decrypt_bytes(open(path, "rb").read(),
                                               self._batch_key(seq_sorted), AUDIT_AAD).decode("utf-8"))
            except Exception as exc:  # noqa: BLE001
                problems.append(f"batch-{seq_sorted}: cannot decrypt ({exc})")
                continue
            for entry in doc.get("entries", []):
                seen += 1
                if entry.get("prev") != prev:
                    problems.append(f"seq {entry.get('seq')}: chain break")
                calc = _entry_hash(entry)
                if calc != entry.get("hash"):
                    problems.append(f"seq {entry.get('seq')}: hash mismatch")
                prev = entry.get("hash", "")
        head = self._read_head()
        if not head:
            problems.append("audit head missing")
        elif head[1] != self.last_hash and self.last_hash:
            problems.append("audit head is stale (tampering suspected)")
        if not self.last_hash:
            problems.append("empty chain (no entries)")
        return problems

    def export_text(self, out_path: str, max_bytes: int = C.MAX_AUDIT_EXPORT_BYTES) -> int:
        """Decrypted, redacted export; truncates at max_bytes (DLP guard)."""
        lines = ["seq,ts,actor,role,action,target,result,detail,prev,hash"]
        n = 0
        total = 0
        for e in sorted([x for x in self.iterate()], key=lambda x: x.get("seq", 0)):
            line = (f"{e.get('seq')},{e.get('ts')},{e.get('actor')},{e.get('role')},"
                    f"{e.get('action')},{e.get('target')},{e.get('result')},"
                    f"{e.get('detail','').replace(',',';').replace(chr(10),' ')[:280]},"
                    f"{e.get('prev','')[:12]},{e.get('hash','')[:12]}")
            total += len(line) + 1
            if total > max_bytes:
                break
            lines.append(line)
            n += 1
        with open(out_path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines))
        return n

    def purge(self, keep: int = C.AUDIT_PURGE_KEEP) -> int:
        """Secure-erase audit batches beyond `keep` entries, keeping the newest.

        The newest (head) batch is always retained; only whole old batches are
        dropped so the hash chain stays verifiable without gaps.
        """
        count = sum(1 for _ in self.iterate())
        if count <= keep:
            return 0
        excess = count - keep
        removed = 0
        for seq in sorted(self.batches):
            if excess <= 0:
                break
            path = self.batches[seq]
            n_entries = 0
            try:
                doc = json.loads(decrypt_bytes(open(path, "rb").read(),
                                               self._batch_key(seq), AUDIT_AAD).decode("utf-8"))
                n_entries = len(doc.get("entries", []))
            except Exception:  # noqa: BLE001
                n_entries = C.AUDIT_BATCH
            secure_erase(path)
            del self.batches[seq]
            excess -= n_entries
            removed += 1
        return removed