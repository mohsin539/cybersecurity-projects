"""Translation / evasion encoders.

These are **test fixtures for your own lab app** — they produce character
encodings that browsers normalize, which is exactly what real filter
bypasses look for (OWASP XSS Filter Evasion Cheat Sheet). They are never
applied to code the tool itself renders.
"""

from __future__ import annotations

_CHAR_TO_HEX = {ord(c): f"&#x{ord(c):02x};" for c in '<>"&\'()/'}
_CHAR_HTML_DEC = {ord(c): f"&#{ord(c)};" for c in '<>"&\'`'}


def html_hex_encode(s: str) -> str:
    return "".join(_CHAR_TO_HEX.get(ord(ch), ch) for ch in s)


def html_dec_encode(s: str) -> str:
    return "".join(_CHAR_HTML_DEC.get(ord(ch), ch) for ch in s)


def js_hex_escape(s: str) -> str:
    return "".join(f"\\x{ord(ch):x}" if 32 <= ord(ch) < 127 else ch for ch in s)


def js_unicode_escape(s: str) -> str:
    return "".join(f"\\u{ord(ch):04x}" if 32 <= ord(ch) < 127 else ch for ch in s)


def url_encode(s: str) -> str:
    from urllib.parse import quote

    return quote(s, safe="")


def double_url_encode(s: str) -> str:
    return url_encode(url_encode(s))


def case_mix(s: str, *tags: str) -> str:
    """Return s with each tag/word from `tags` internal-cased randomly."""
    import random

    rng = random.Random(hash(s + "|".join(tags)) & 0xFFFFFFFF)
    out = s
    for t in tags:
        mixed = "".join(ch.upper() if rng.random() < 0.5 else ch.lower() for ch in t)
        out = out.replace(t, mixed)
    return out


def js_string_mutation(s: str) -> str:
    """Encode the character class *inside* a JS string, e.g. 'al\u0065rt'.
    Used to defeat naive keyword blacklists in WAF/`script` contexts."""
    chars = []
    for ch in s:
        o = ord(ch)
        if o < 128 and ch.isalpha() and (o % 3 == 0):
            chars.append(f"\\u{o:04x}")
        elif o < 128 and ch.isalpha() and (o % 3 == 1):
            chars.append(f"\\x{o:x}")
        else:
            chars.append(ch)
    return "".join(chars)


def hex_number_escape(n: int) -> str:
    return f"0x{n:x}"


def overlong_utf8_encode(s: str) -> str:
    """Overlong UTF-8 for non-ASCII only (rarely relevant; kept for parity)."""
    return s


ALL_ENCODERS = {
    "html_hex": html_hex_encode,
    "html_dec": html_dec_encode,
    "js_hex": js_hex_escape,
    "js_unicode": js_unicode_escape,
    "url": url_encode,
    "double_url": double_url_encode,
    "js_string": js_string_mutation,
    "none": lambda s: s,
}