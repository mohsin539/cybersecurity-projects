import base64
import hashlib
import os
import secrets

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY_BYTES = 32
NONCE_BYTES = 12


def new_aes_key() -> bytes:
    return secrets.token_bytes(KEY_BYTES)


def aes_encrypt(key: bytes, plaintext: bytes, aad: bytes = b"") -> str:
    nonce = secrets.token_bytes(NONCE_BYTES)
    ct = AESGCM(key).encrypt(nonce, plaintext, aad)
    return base64.b64encode(nonce + ct).decode()


def aes_decrypt(key: bytes, token: str, aad: bytes = b"") -> bytes:
    raw = base64.b64decode(token)
    nonce, ct = raw[:NONCE_BYTES], raw[NONCE_BYTES:]
    return AESGCM(key).decrypt(nonce, ct, aad)


def fingerprint(fields: "list[str]") -> str:
    h = hashlib.sha256()
    for f in fields:
        h.update(f.encode())
    return h.hexdigest()[:32]


def short_ja3(seed: str) -> str:
    parts = []
    acc = 0
    for ch in seed:
        acc = (acc + ord(ch)) & 0xFFFFFFFF
        parts.append(str((acc >> 8) & 0xFF))
    return ",".join(parts[:12])


def random_hex(nbytes: int = 16) -> str:
    return secrets.token_hex(nbytes)