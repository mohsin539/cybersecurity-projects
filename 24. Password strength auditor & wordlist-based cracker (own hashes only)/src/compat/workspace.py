import hashlib
import json
import os
import sys
import time
import uuid

from ..compat import win


def _utcnow():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


class Workspace:
    def __init__(self, base_dir):
        self.dir = os.path.abspath(base_dir)
        os.makedirs(self.dir, exist_ok=True)
        self.config_path = os.path.join(self.dir, "config.json")
        self.audit_path = os.path.join(self.dir, "audit.jsonl")
        self._cfg = self._load_config()

    def _load_config(self):
        if os.path.exists(self.config_path):
            with open(self.config_path, "r", encoding="utf-8") as fh:
                return json.load(fh)
        cfg = {
            "created_utc": _utcnow(),
            "session_id": "ws-" + uuid.uuid4().hex[:12],
            "operator": "",
            "attested": False,
            "attested_at": None,
            "tool": "PasswordGuardian",
            "version": "1.0.0",
        }
        self._write_config(cfg)
        return cfg

    def _write_config(self, cfg):
        with open(self.config_path, "w", encoding="utf-8") as fh:
            json.dump(cfg, fh, indent=2)

    def session_id(self):
        return self._cfg.get("session_id")

    def operator(self):
        return self._cfg.get("operator", "")

    def attested(self):
        return bool(self._cfg.get("attested"))

    def attest(self, operator):
        self._cfg["operator"] = operator
        self._cfg["attested"] = True
        self._cfg["attested_at"] = _utcnow()
        self._write_config(self._cfg)
        self.audit("attestation", detail="own-hashes-only attestation accepted", operator=operator)

    def audit(self, event, detail=None, **extra):
        prev = None
        last = _last_line(self.audit_path)
        if last:
            try:
                prev = json.loads(last).get("entry_hash")
            except ValueError:
                prev = None
        seq = self._next_seq()
        payload = {
            "seq": seq,
            "ts": _utcnow(),
            "event": event,
            "detail": detail,
            "prev_hash": prev,
            **{k: v for k, v in extra.items()},
        }
        entry = {
            "seq": seq,
            "ts": payload["ts"],
            "event": event,
            "detail": detail,
            "prev_hash": prev,
            "extra": {k: v for k, v in extra.items()},
            "entry_hash": hashlib.sha256(
                json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
            ).hexdigest(),
        }
        with open(self.audit_path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry) + "\n")
        return entry

    def _next_seq(self):
        seq = 0
        if os.path.exists(self.audit_path):
            with open(self.audit_path, "r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    if line.strip():
                        try:
                            seq = int(json.loads(line).get("seq", 0))
                        except ValueError:
                            pass
        return seq + 1

    def events(self, limit=100):
        rows = []
        if not os.path.exists(self.audit_path):
            return rows
        with open(self.audit_path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if line.strip():
                    try:
                        rows.append(json.loads(line))
                    except ValueError:
                        continue
        return rows[-limit:]

    def verify_chain(self):
        if not os.path.exists(self.audit_path):
            return True, 0
        prev = None
        count = 0
        with open(self.audit_path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if not line.strip():
                    continue
                try:
                    entry = json.loads(line)
                except ValueError:
                    return (False, count)
                if entry.get("prev_hash") != prev:
                    return (False, count)
                payload = {
                    "seq": entry["seq"],
                    "ts": entry["ts"],
                    "event": entry["event"],
                    "detail": entry["detail"],
                    "prev_hash": entry.get("prev_hash"),
                    **entry.get("extra", {}),
                }
                recomputed = hashlib.sha256(
                    json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
                ).hexdigest()
                if recomputed != entry.get("entry_hash"):
                    return (False, count)
                prev = entry.get("entry_hash")
                count += 1
        return (True, count)

    def wipe(self):
        for name in ("config.json", "audit.jsonl"):
            path = os.path.join(self.dir, name)
            if os.path.exists(path):
                try:
                    os.remove(path)
                except PermissionError:
                    pass
        self._cfg = self._load_config()

    def destroy(self):
        self.wipe()
        try:
            os.rmdir(self.dir)
        except OSError:
            pass


BUNDLE_MAGIC = b"PWG1"


def bundle_available():
    return win.dpapi_capable()


def save_bundle(path, payload, local_machine=False):
    encrypted = win.dpapi_protect(payload, local_machine=local_machine)
    with open(path, "wb") as fh:
        fh.write(BUNDLE_MAGIC + encrypted)


def load_bundle(path):
    with open(path, "rb") as fh:
        data = fh.read()
    if not data.startswith(BUNDLE_MAGIC):
        raise ValueError("not a PasswordGuardian bundle")
    return win.dpapi_unprotect(data[len(BUNDLE_MAGIC):])


def _last_line(path):
    if not os.path.exists(path) or os.path.getsize(path) == 0:
        return None
    with open(path, "rb") as fh:
        fh.seek(0, os.SEEK_END)
        data = b""
        pos = fh.tell()
        while pos > 0 and len(data) < 65536:
            pos = max(0, pos - 1024)
            fh.seek(pos)
            data = fh.read(1024) + data
        return data.strip().split(b"\n")[-1].decode("utf-8", errors="replace")