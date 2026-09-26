from __future__ import annotations

import collections
import re
import struct
from typing import Optional

from .models import StaticFindings

# architecture.md section 6.4: Static Analyzer — pure, read-only analysis.
# No platform calls to execute anything; input treated as inert bytes.

_LOG2 = __import__("math").log2


def file_entropy(data: bytes) -> float:
    """Shannon entropy over the whole buffer, 0..8 bits/byte."""
    if not data:
        return 0.0
    counts = collections.Counter(data)
    n = len(data)
    return -sum((c / n) * _LOG2(c / n) for c in counts.values())


def block_entropies(data: bytes, block: int = 8192) -> list[float]:
    out = []
    for i in range(0, len(data), block):
        out.append(file_entropy(data[i:i + block]))
    return out


def high_entropy_ratio(blocks: list[float], threshold: float = 7.5) -> float:
    if not blocks:
        return 0.0
    high = sum(1 for b in blocks if b >= threshold)
    return high / len(blocks)


def printable_prefix(data: bytes, n: int = 8) -> bool:
    if len(data) < 4:
        return False
    chunk = data[:n]
    return all((32 <= b < 127) or b in (9, 10, 13) for b in chunk)


_ASCII_RE = re.compile(rb"[\x20-\x7e]{6,}")
_UTF16_RE = re.compile((b"(?:[\x20-\x7e]\x00){6,}"))


def extract_strings(data: bytes, min_len: int = 6, cap: int = 4000) -> list[str]:
    found: dict[str, None] = {}
    for m in _ASCII_RE.finditer(data):
        s = m.group().decode("ascii", "ignore")
        if len(s) >= min_len:
            found[s] = None
    for m in _UTF16_RE.finditer(data):
        s = m.group().decode("utf-16le", "ignore")
        if len(s) >= min_len:
            found[s] = None
        if len(found) >= cap:
            break
    return list(found)[:cap]


_CRYPTO_HINTS = (
    "cryptencrypt", "cryptdecrypt", "cryptimportkey", "cryptgenkey",
    "bcryptencrypt", "bcryptdecrypt", "ncrypt", "rsa", "rsacrypt",
    "cryptserviceprovider", "rsacryptoserviceprovider", "aesmanaged",
    "rijndael", "symmetricalgorithm", "cryptoapi", "openssl", "cryptopp",
    "chacha", "salsa", "evp_aes", "aes_set_encrypt", "wolfcrypt",
    "crypto", "generatekey", "publickey", "privatekey", "exportkey", "importkey",
)

_RANSOM_KEYWORDS = (
    "ransom", "bitcoin", "btc address", "wallet", "recover your files",
    "your files", "encrypted", "decrypt", "unlock", "payment", "ransomware",
    ".lock", ".enc", ".crypt", ".locked", "_readme", "readme_", "wanna",
    "petya", "notpetya", "badcrypt", "how to decrypt", "restore files",
)

_NOTE_KEYWORDS = (
    "ransom", "bitcoin", "recover your files", "decrypt", "unlock", "wallet",
    "how to decrypt", "restore files",
)


def _lower_hints(hints: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(h.lower() for h in hints)


def crypto_imports_from(strings: list[str]) -> list[str]:
    hits: dict[str, None] = {}
    low = [s.lower() for s in strings]
    for kind in _lower_hints(_CRYPTO_HINTS):
        if any(kind in s for s in low):
            # normalise display only if it is a meaningful token
            hits[kind.upper()] = None
    return list(hits)


def ransom_indicators_from(strings: list[str], filename: str) -> list[str]:
    hits: dict[str, None] = {}
    low = [s.lower() for s in strings]
    lower_name = filename.lower()
    for kw in _lower_hints(_RANSOM_KEYWORDS):
        if any(kw in s for s in low) or kw in lower_name:
            hits[kw] = None
    return list(hits)


def is_ransom_note_style(strings: list[str]) -> bool:
    low = " ".join(s.lower() for s in strings[:2000])
    return any(kw in low for kw in _lower_hints(_NOTE_KEYWORDS))


def parse_pe_info(data: bytes) -> dict:
    info: dict = {"is_pe": False}
    if not data.startswith(b"MZ") or len(data) < 0x40:
        return info
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if e_lfanew + 4 > len(data) or data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        return info
    machine = struct.unpack_from("<H", data, e_lfanew + 4)[0]
    nsec = struct.unpack_from("<H", data, e_lfanew + 6)[0]
    magic = struct.unpack_from("<H", data, e_lfanew + 24)[0] if e_lfanew + 26 <= len(data) else 0
    opt = "PE32" if magic == 0x10B else ("PE32+" if magic == 0x20B else hex(magic))
    image = "MZ/PE"
    info.update(is_pe=True, machine=hex(machine), sections=nsec,
                optional_header=opt, magic_hint=image, module=image)
    return info


def static_analyze(data: bytes, filename: str) -> StaticFindings:
    ent = file_entropy(data)
    blocks = block_entropies(data)
    hr = high_entropy_ratio(blocks)
    strings = extract_strings(data)
    pe = parse_pe_info(data)
    crypto = crypto_imports_from(strings) if pe.get("is_pe") else (
        crypto_imports_from(strings)
    )
    frags = ransom_indicators_from(strings, filename)

    # cap stored strings to keep DB/report lean but informative
    kept = [s for s in strings if len(s) <= 200][:240]
    return StaticFindings(
        entropy=round(ent, 4),
        block_high_entropy_ratio=round(hr, 4),
        strings=kept,
        pe_info=pe,
        crypto_imports=crypto[:20],
        ransom_indicators=frags[:20],
    )