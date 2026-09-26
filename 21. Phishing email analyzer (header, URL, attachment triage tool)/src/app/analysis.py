"""Analysis pipeline: orchestrates all engines over a validated raw email.

All inputs pass through sec.validation (SI-10). Each engine runs fail-closed
and independently so one engine's failure never collapses the report.
"""
from __future__ import annotations

import email
import email.policy
import time
from typing import Dict, List

from .engines.attachment_engine import AttachmentEngine
from .engines.content_engine import ContentEngine
from .engines.header_engine import HeaderEngine
from .engines.model import AnalysisReport, EngineResult
from .engines.risk import score_report
from .engines.url_engine import URLEngine
from .sec.validation import validate_email_bytes


def analyze_raw_email(raw: bytes, reputation_key: str = "", resolve_hosts: bool = True,
                      engines: List[str] = ("header", "url", "attachment", "content")) -> AnalysisReport:
    raw = validate_email_bytes(raw)
    report = AnalysisReport(created=time.time())
    msg = email.message_from_bytes(raw, policy=email.policy.default)

    report.subject = (msg.get("subject") or "")[:512]
    report.message_id = (msg.get("message-id") or "")[:256]
    report.from_addr = str((msg.get("from") or ""))[:512]
    report.from_display = report.from_addr.split("<")[0].strip('" \'')[:128]
    report.to = str((msg.get("to") or ""))[:512]
    report.date = (msg.get("date") or "")[:128]

    # header engine also needs the raw body for DKIM; run from raw
    hdr_engine = HeaderEngine(raw)
    report.results["header"] = hdr_engine.analyze()

    # body text/html extraction for URL + content engines
    html_body, text_body = _extract_bodies(msg)

    results: Dict[str, EngineResult] = {}
    if "url" in engines:
        url_res = URLEngine(html_body=html_body, text_body=text_body).analyze(
            reputation_key=reputation_key, resolve_hosts=resolve_hosts)
        results["url"] = url_res
    if "attachment" in engines:
        results["attachment"] = AttachmentEngine(msg).analyze()
    if "content" in engines:
        results["content"] = ContentEngine(msg).analyze()
    for name, res in results.items():
        report.results[name] = res

    return score_report(report)


def _extract_bodies(msg) -> tuple:
    html: List[str] = []
    text: List[str] = []
    for part in msg.walk():
        if part.is_multipart():
            continue
        try:
            ctype = part.get_content_type().lower()
        except Exception:  # noqa: BLE001
            continue
        if ctype not in ("text/plain", "text/html"):
            continue
        try:
            payload = (part.get_payload(decode=True) or b"").decode(
                part.get_content_charset() or "utf-8", errors="replace")
        except Exception:  # noqa: BLE001
            continue
        (html if ctype == "text/html" else text).append(payload)
    return "\n".join(html), "\n".join(text)