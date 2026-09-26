"""Headless engine bridge used by the GUI (fully unit-testable).

Performs detection, policy-driven redaction, secure export and audit
verification. Kept free of any tkinter import so logic can be tested
and reused by the CLI/API with identical behaviour.
"""

from __future__ import annotations

import json
import secrets
import time
from dataclasses import dataclass, field
from pathlib import Path

from ..core.models import SensitiveEntity
from ..security import AuditTrail
from ..services.anonymizer_service import AnonymizationRequest, AnonymizerService

__all__ = [
    "EncryptedExportError",
    "EngineBridge",
    "ScanSession",
]

ENCRYPT_HEADER = b"LAC1-ENC\x01"


@dataclass
class LineScan:
    """Result for a single log line: original + redacted + entities."""

    index: int
    original: str
    redacted: str
    entities: list[SensitiveEntity] = field(default_factory=list)


@dataclass
class ScanSession:
    """Aggregate result over all scanned lines."""

    lines: list[LineScan] = field(default_factory=list)
    entity_counts: dict[str, int] = field(default_factory=dict)
    redacted_lines: list[str] = field(default_factory=list)
    processing_ms: float = 0.0
    request_id: str = ""
    policy_id: str = "default"
    chain_root: str = ""
    audit_events: int = 0


class EncryptedExportError(RuntimeError):
    """Raised when encrypted export fails."""


class EngineBridge:
    """Thin wrapper around AnonymizerService for the GUI/CLI front-ends."""

    def __init__(
        self,
        service: AnonymizerService | None = None,
        *,
        default_policy_id: str = "default",
        audit_dir: Path | str | None = None,
    ):
        self.service = service or AnonymizerService(audit_trail=AuditTrail(audit_dir))
        self.default_policy_id = default_policy_id or "default"

    # -- core pipeline -----------------------------------------------------

    def policies(self) -> list[str]:
        try:
            return sorted(self.service.policies.list_ids())
        except AttributeError:
            return [self.default_policy_id]

    def scan(
        self,
        lines: list[str],
        *,
        policy_id: str | None = None,
        token_salt: str = "",
        date_shift_days: int = 0,
        max_entities: int = 0,
    ) -> ScanSession:
        """Validate, detect and redact a batch of log lines."""
        request = AnonymizationRequest(
            lines=lines,
            policy_id=policy_id or self.default_policy_id,
            date_shift_days=date_shift_days,
            token_salt=token_salt or None,
        )
        start = time.perf_counter()
        result = self.service.anonymize(request)
        elapsed = (time.perf_counter() - start) * 1000

        session = ScanSession(
            entity_counts=dict(result.entity_stats),
            redacted_lines=list(result.redacted_lines),
            processing_ms=round(elapsed, 2),
            request_id=result.request_id,
            policy_id=result.policy_id,
            chain_root=result.chain_root,
            audit_events=result.audit_events,
        )
        detected = self._collect_entities(lines)
        for i, (orig, red) in enumerate(zip(lines, result.redacted_lines)):
            session.lines.append(
                LineScan(index=i, original=orig, redacted=red, entities=detected.get(i, []))
            )
        return session

    def _collect_entities(self, lines: list[str]) -> dict[int, list[SensitiveEntity]]:
        out: dict[int, list[SensitiveEntity]] = {}
        for idx, line in enumerate(lines):
            out[idx] = self.service.detection.detect(line)
        return out

    # -- audit -------------------------------------------------------------

    def verify_chain(self) -> tuple[bool, str, int]:
        """Recompute chain from disk; return (valid, expected_root, count)."""
        try:
            expected = self.service.audit.rebuild_root_from_disk()
        except Exception:  # noqa: BLE001 - a broken store must never crash verification
            return False, "-", 0
        actual = self.service.audit.chain_root
        count = self.service.audit.record_count
        return (expected == actual and expected != "-"), expected, count

    def recent_records(self, limit: int = 25) -> list[dict]:
        """Last N audit records (safe fields only, no raw values)."""
        records: list[dict] = []
        for seq in range(
            max(0, self.service.audit.record_count - limit), self.service.audit.record_count
        ):
            matches = list(self.service.audit._dir.glob(f"{seq:08d}-*.json"))
            if not matches:
                continue
            try:
                records.append(json.loads(matches[0].read_text(encoding="utf-8")))
            except (OSError, ValueError):
                continue
        return records

    def verification_ticket(self) -> dict:
        return self.service.audit.verification_ticket()

    # -- export ------------------------------------------------------------

    @staticmethod
    def export_plain(lines: list[str], path: Path | str) -> Path:
        path = Path(path)
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return path

    @staticmethod
    def export_json(lines: list[str], path: Path | str) -> Path:
        path = Path(path)
        path.write_text(
            json.dumps(
                {
                    "format": "anonymized-log-v1",
                    "sensitive": [],  # redacted, so none contained
                    "lines": lines,
                },
                indent=2,
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )
        return path

    @staticmethod
    def export_encrypted(
        lines: list[str],
        path: Path | str,
        password: str,
    ) -> Path:
        """Encrypt redacted output with an scrypt-derived Fernet key.

        Format: `LAC1-ENC\\x01` + salt(16) + Fernet token (AES-128-CBC +
        HMAC-SHA256). The 16-byte random salt enables independent keys per
        export and defeats rainbow tables (ISO A.8.24, NIST PR.DS).
        """
        if not password:
            raise EncryptedExportError("an export password is required")
        from cryptography.fernet import Fernet
        from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

        try:
            salt = secrets.token_bytes(16)
            kdf = Scrypt(salt=salt, length=32, n=2**17, r=8, p=1)
            fernet = Fernet(base64_urlsafe(kdf.derive(password.encode("utf-8"))))
            payload = json.dumps(
                {"format": "anonymized-log-encrypted-v1", "lines": lines},
                ensure_ascii=False,
            ).encode("utf-8")
            token = fernet.encrypt(payload)
        except Exception as exc:
            raise EncryptedExportError(f"encryption failed: {exc}") from exc
        path = Path(path)
        path.write_bytes(ENCRYPT_HEADER + salt + token)
        return path


def base64_urlsafe(data: bytes) -> str:
    import base64

    return base64.urlsafe_b64encode(data).decode("ascii")
