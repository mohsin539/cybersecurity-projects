"""Immutable audit trail writer (ISO 27001 A.8.15 Logging, NIST AU-2/12).

Records are NEVER updated or deleted. Only append. The chain is
tamper-evident via MerkleAnchor linking hashes.
"""

import hashlib
import json
import secrets
from datetime import datetime, timezone
from pathlib import Path

from ..core.models import AuditRecord
from .hashing import MerkleAnchor, hash_original, hash_redacted, hmac_chain_step


class AuditTrail:
    """Append-only audit store with hash-chain verification."""

    def __init__(self, output_dir: Path | None = None):
        self._dir = Path(output_dir) if output_dir else Path("data/audit")
        self._chain = MerkleAnchor()
        self._dir.mkdir(parents=True, exist_ok=True)
        self._recover_chain_from_disk()

    def _recover_chain_from_disk(self) -> None:
        """Replay persisted records so the in-memory chain matches disk.

        A process that starts against an existing audit store must learn
        the current chain root before appending new records. This makes
        the store single-writer but restart-safe (ISO A.8.13).
        """
        for f in sorted(self._dir.glob("*.json")):
            try:
                data = json.loads(f.read_text(encoding="utf-8"))
            except (ValueError, OSError):
                continue
            chain_input = data.get("chain_input")
            if chain_input:
                self._chain.append(chain_input)

    def record_redaction(
        self,
        original_value: str,
        redacted_value: str,
        action: str,
        data_class: str,
        entity_type: str,
        policy_applied: str = "default",
        confidence: float = 1.0,
        search_salt: str | None = None,
    ) -> AuditRecord:
        """Append a tamper-evident audit record for a redaction action."""
        event_id = secrets.token_hex(16)
        timestamp = datetime.now(timezone.utc).isoformat(timespec="microseconds")

        record = AuditRecord(
            event_id=event_id,
            timestamp=timestamp,
            action=action,
            data_class=data_class,
            entity_type=entity_type,
            original_hash=hash_original(original_value, search_salt),
            redacted_hash=hash_redacted(redacted_value),
            policy_applied=policy_applied,
            confidence=confidence,
        )

        # Link into the tamper-evident chain.
        # The chain input is a deterministic hash of record contents so
        # the root can be independently recomputed from persisted records
        # (tamper detection without retaining the original values).
        record.seq = self._chain.count
        chain_input = self._record_chain_input(record)
        record.chain_input = chain_input
        record.merkle_proof = self._chain.append(chain_input)

        # Persist alongside audit JSON file
        self._write_record(record)
        return record

    @staticmethod
    def _record_chain_input(record: AuditRecord) -> str:
        """Deterministic hash binding all record fields together."""
        payload = f"{record.seq}|{record.event_id}|{record.timestamp}|{record.action}|{record.original_hash}|{record.redacted_hash}|{record.policy_applied}".encode()
        return hashlib.sha256(payload).hexdigest()

    def _write_record(self, record: AuditRecord) -> None:
        # Sequence-prefixed filename preserves insertion order for
        # independent chain recomputation from disk.
        filename = self._dir / f"{record.seq:08d}-{record.event_id}.json"
        filename.write_text(json.dumps(record.to_dict(), indent=2), encoding="utf-8")

    @property
    def chain_root(self) -> str:
        return self._chain.root

    @property
    def record_count(self) -> int:
        return self._chain.count

    def verification_ticket(self) -> dict:
        """Ticket for external anchoring (audit evidence)."""
        return self._chain.audit_ticket()

    def rebuild_root_from_disk(self) -> str:
        """Recompute the exact chain this process has seen.

        Recomputation is limited to seq 0..(count-1) via the
        sequence-prefixed filenames, so records written by OTHER
        processes/instances after this one started do not invalidate
        verification of this instance's chain.
        """
        root = "0" * 64
        for seq in range(self._chain.count):
            matches = list(self._dir.glob(f"{seq:08d}-*.json"))
            if not matches:
                return "-"  # missing record, chain cannot be verified
            data = json.loads(matches[0].read_text(encoding="utf-8"))
            chain_input = data.get("chain_input")
            if not chain_input:
                return "-"
            root = hmac_chain_step(root, chain_input)
        return root
