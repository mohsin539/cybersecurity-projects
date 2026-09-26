"""Application-layer payload encryption (OWASP A02, ISO 27001 A.10).

Fernet provides authenticated symmetric encryption (AES-128-CBC + HMAC-SHA256)
via the `cryptography` library. For real deployments, transport should also be
TLS (HTTPS) terminated at the listener - see COMPLIANCE.md / README notes.
"""
import base64
import hashlib

from cryptography.fernet import Fernet, InvalidToken

from .config import derive_fernet_key


def _cipher(key_b64: str | None = None):
    key = key_b64 if key_b64 else derive_fernet_key()
    return Fernet(key.encode("ascii") if isinstance(key, str) else key)


class PayloadCrypto:
    """Encrypt / decrypt JSON payloads exchanged between beacon and listener."""

    def __init__(self, key_b64: str | None = None):
        self._f = _cipher(key_b64)

    def encrypt(self, data: str) -> str:
        return self._f.encrypt(data.encode("utf-8")).decode("ascii")

    def decrypt(self, token: str) -> str:
        try:
            return self._f.decrypt(token.encode("ascii")).decode("utf-8")
        except InvalidToken as exc:  # tampered or wrong key
            raise ValueError("payload decrypt failed: invalid token or key") from exc


def b64_sha256(value: str) -> str:
    """Non-cryptographic collision-safe fingerprint used for secret-less IDs."""
    return base64.urlsafe_b64encode(hashlib.sha256(value.encode("utf-8")).digest()).decode("ascii")[:24]