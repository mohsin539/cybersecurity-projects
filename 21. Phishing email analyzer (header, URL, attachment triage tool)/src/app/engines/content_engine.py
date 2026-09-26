"""Content / NLP engine: plain-text linguistic analysis with zero execution.

Controls: SI-4 (detection). Body text is decoded and analyzed as plain text
only; the rendered GUI uses this text, never the raw HTML (A03 XSS control).
"""
from __future__ import annotations

import email
import re
from typing import Dict, List

from ..sec import constants as C
from ..sec.validation import sanitize_text
from .model import EngineResult, Severity

_KEYWORD_RE = re.compile(r"(?i)\b(?:%s)\b" % "|".join(re.escape(k) for k in C.PHISHING_KEYWORDS))
_HTML_RE = re.compile(r"<[^>]+>")


class ContentEngine:
    def __init__(self, msg):
        self.msg = msg

    def _body_parts(self) -> List[str]:
        parts: List[str] = []
        for part in self.msg.walk():
            if part.is_multipart():
                continue
            try:
                ctype = part.get_content_type().lower()
            except Exception:  # noqa: BLE001
                continue
            if ctype not in ("text/plain", "text/html"):
                continue
            try:
                payload = part.get_payload(decode=True)
                charset = part.get_content_charset() or "utf-8"
                text = payload.decode(charset, errors="replace")
            except Exception:  # noqa: BLE001
                continue
            parts.append(text)
        return parts

    def analyze(self) -> EngineResult:
        res = EngineResult("content")
        parts = self._body_parts()
        if not parts:
            res.add("NO_BODY", Severity.INFO, "No readable body content", category="info")
            return res

        plain = "\n".join(p for p in parts if _plain_part(self.msg, p) or True)
        plain = _HTML_RE.sub(" ", plain)          # strip tags defensively
        plain = sanitize_text(plain)
        res.meta["body_length"] = len(plain)
        res.meta["body_preview"] = sanitize_text(plain[:1500])

        # keyword / urgency signals
        hits: Dict[str, int] = {}
        for m in _KEYWORD_RE.finditer(plain):
            hits[m.group(0).lower()] = hits.get(m.group(0).lower(), 0) + 1
        if hits:
            res.meta["keyword_hits"] = hits
            top = sorted(hits.items(), key=lambda kv: -kv[1])[:5]
            res.add("PHISH_KEYWORDS", Severity.MEDIUM,
                    f"Phishing/urgency language detected: {', '.join(f'{k}x{v}' for k, v in top)}",
                    category="malicious")

        # urgency ratio
        sentences = re.split(r"[.!?]\s+", plain)
        if len(sentences) > 3:
            urgent = sum(1 for s in sentences if re.search(
                r"(?i)\b(urgent|immediately|asap|now|today)\b", s))
            if urgent / len(sentences) > 0.35:
                res.add("URGENCY_PRESSURE", Severity.LOW,
                        "High proportion of urgency/pressure sentences (social engineering)",
                        category="malicious")

        # request for credentials / payment (tripwire strings)
        if re.search(r"(?i)\b(verify your (account|password)|update your (password|billing)|"
                     r"password.*will.*expire|click.*sign in|enter your.*password)\b", plain):
            res.add("CRED_REQUEST", Severity.HIGH,
                    "Body asks the recipient to verify/enter credentials (classic phishing ask)",
                    category="malicious")

        if re.search(r"(?i)\b(wire transfer|send.*money|gift card|prepaid card|venmo|zelle|"
                     r"bitcoin|bank account details)\b", plain):
            res.add("PAYMENT_LURE", Severity.MEDIUM,
                    "Body references payment/money movement lures", category="malicious")
        return res


def _plain_part(msg, text: str) -> bool:
    return True