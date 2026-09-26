"""Cryptographic core for SecureNote Pro.

Implements the architecture.md crypto blueprint:
  - AES-256-GCM (NIST SP 800-38D) AEAD for all data at rest
  - Argon2id (RFC 9106) memory-hard KDF for passphrase -> KEK
  - HKDF-SHA256 (RFC 5869) domain-separated sub-key expansion
  - HMAC-SHA256 integrity, SHA-256 hash-chain support
  - CSPRNG randomness (os.urandom)
"""

from __future__ import annotations

import hashlib
import hmac
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from argon2 import PasswordHasher
from argon2.exceptions import VerificationError, VerifyMismatchError, InvalidHashError

# ---------------------------------------------------------------------------
# Tuning (matches architecture.md section 5.2)
# ---------------------------------------------------------------------------
ARGON2_MEM_KIB = 64 * 1024   # 64 MiB memory  (m=65536 KiB)
ARGON2_ITER = 3              # t=3
ARGON2_PARALLEL = 4          # p=4
ARGON2_HASH_LEN = 32

GCM_NONCE_LEN = 12           # 96-bit IV
GCM_TAG_LEN = 16             # 128-bit auth tag

PEPPER = b"SecureNotePro::v1::domain-separated-pepper"  # app secret (enclave-bound in prod)

_argon2 = PasswordHasher(
    time_cost=ARGON2_ITER,
    memory_cost=ARGON2_MEM_KIB,
    parallelism=ARGON2_PARALLEL,
    hash_len=ARGON2_HASH_LEN,
)


# ---------------------------------------------------------------------------
# Randomness (NIST SP 800-90A/B CSPRNG via OS entropy)
# ---------------------------------------------------------------------------
def random_bytes(n: int) -> bytes:
    return os.urandom(n)


def generate_salt() -> bytes:
    return random_bytes(16)


def generate_nonce() -> bytes:
    return random_bytes(GCM_NONCE_LEN)


def generate_key256() -> bytes:
    return random_bytes(32)


# ---------------------------------------------------------------------------
# Key derivation
# ---------------------------------------------------------------------------
def derive_kek(passphrase: str, salt: bytes) -> bytes:
    """KEK = Argon2id(passphrase, salt||pepper) -> 32 bytes."""
    return _argon2_derive(passphrase, salt + PEPPER)


def _argon2_derive(passphrase: str, raw_salt: bytes) -> bytes:
    """Pure-Argon2id derivation returning raw 32-byte key (no PHC encoding)."""
    from argon2.low_level import hash_secret_raw, Type
    return hash_secret_raw(
        secret=passphrase.encode("utf-8"),
        salt=raw_salt,
        time_cost=ARGON2_ITER,
        memory_cost=ARGON2_MEM_KIB,
        parallelism=ARGON2_PARALLEL,
        hash_len=ARGON2_HASH_LEN,
        type=Type.ID,
    )


def expand_subkey(ikm: bytes, info: str) -> bytes:
    """HKDF-SHA256 expand into domain-separated sub-key."""
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info.encode("utf-8"))
    return hkdf.derive(ikm)


# ---------------------------------------------------------------------------
# AEAD
# ---------------------------------------------------------------------------
def aead_encrypt(key: bytes, plaintext: bytes) -> tuple[bytes, bytes, bytes]:
    """Returns (ciphertext, nonce, tag). Nonce fresh per call (never reused)."""
    nonce = generate_nonce()
    out = AESGCM(key).encrypt(nonce, plaintext, None)
    return out[:-GCM_TAG_LEN], nonce, out[-GCM_TAG_LEN:]


def aead_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes) -> bytes:
    return AESGCM(key).decrypt(nonce, ciphertext + tag, None)


def aead_dump(key: bytes, plaintext: bytes) -> dict:
    """Serialize an AEAD envelope as a JSON-safe dict."""
    ct, nonce, tag = aead_encrypt(key, plaintext)
    return {
        "iv": nonce.hex(),
        "ct": ct.hex(),
        "tag": tag.hex(),
    }


def aead_load(key: bytes, envelope: dict) -> bytes:
    return aead_decrypt(
        key, bytes.fromhex(envelope["iv"]),
        bytes.fromhex(envelope["ct"]), bytes.fromhex(envelope["tag"]),
    )


# ---------------------------------------------------------------------------
# Integrity
# ---------------------------------------------------------------------------
def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def hmac_sha256(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()


# ---------------------------------------------------------------------------
# Passphrase verification helper (side-channel-aware timing-minimized check)
# ---------------------------------------------------------------------------
def constant_time_eq(a: bytes, b: bytes) -> bool:
    return hmac.compare_digest(a, b)


def verify_passphrase(verifier: bytes, passphrase: str, salt: bytes) -> bool:
    kek = derive_kek(passphrase, salt)
    expect = expand_subkey(kek, "passphrase-verifier")
    return constant_time_eq(expect, verifier)