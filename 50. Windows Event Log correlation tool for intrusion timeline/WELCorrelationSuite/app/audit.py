"""Audit sub-system: tamper-evident, append-only activity log and
artefact integrity (SHA-256) for generated reports.
"""
import hashlib
import json
import os
from datetime import datetime, timezone

from .events import sha256_of  # reuse canonical hasher


def utc_now():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


class AuditTrail:
    """Append-only JSONL audit trail with per-line chained integrity."""

    def __init__(self, directory):
        self.directory = directory
        self.path = os.path.join(directory, "audit_trail.jsonl")
        self.last_hash = None
        os.makedirs(directory, exist_ok=True)
        if os.path.exists(self.path):
            with open(self.path, "r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if line.startswith("{"):
                        try:
                            self.last_hash = json.loads(line).get("integrity.hash")
                        except json.JSONDecodeError:
                            continue
        if self.last_hash is None:
            self.last_hash = sha256_of("GENESIS")

    def append(self, actor, action, detail="", level="info"):
        entry = {
            "ts": utc_now(),
            "actor": actor,
            "action": action,
            "detail": detail,
            "level": level,
            "integrity.prev_hash": self.last_hash,
        }
        checksum = sha256_of({k: v for k, v in entry.items()})
        entry["integrity.hash"] = checksum
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
        self.last_hash = checksum
        return entry

    def entries(self, limit=None, level=None, action=None):
        rows = []
        if os.path.exists(self.path):
            with open(self.path, "r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line.startswith("{"):
                        continue
                    try:
                        row = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if level and row.get("level") != level:
                        continue
                    if action and row.get("action") != action:
                        continue
                    rows.append(row)
        return rows[-limit:] if limit else rows

    def verify(self):
        """Re-play the chain and return (valid, broken_entry)."""
        valid, prev = True, sha256_of("GENESIS")
        if not os.path.exists(self.path):
            return False, None
        with open(self.path, "r", encoding="utf-8") as fh:
            for n, line in enumerate(fh, 1):
                line = line.strip()
                if not line.startswith("{"):
                    continue
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    return False, "line %d not JSON" % n
                calc = sha256_of({k: v for k, v in row.items() if k != "integrity.hash"})
                if row.get("integrity.prev_hash") != prev or row.get("integrity.hash") != calc:
                    return False, {"line": n, "entry": row}
                prev = row["integrity.hash"]
        return valid, None

    def stats(self):
        rows = self.entries()
        return {"entries": len(rows), "last_hash": self.last_hash,
                "valid": self.verify()[0], "path": self.path}


def artefact_hash(data_bytes):
    """SHA-256 of an exported artefact (report bytes stored next to it)."""
    return hashlib.sha256(data_bytes or b"").hexdigest()


def write_artefact_hash(base_path, data_bytes):
    with open(base_path + ".sha256", "w", encoding="utf-8") as fh:
        fh.write(artefact_hash(data_bytes) + "\n")


def verify_artefact(base_path, data_bytes):
    try:
        with open(base_path + ".sha256", "r", encoding="utf-8") as fh:
            expected = fh.read().strip().splitlines()[0]
    except (OSError, IndexError):
        return False
    return expected == artefact_hash(data_bytes)