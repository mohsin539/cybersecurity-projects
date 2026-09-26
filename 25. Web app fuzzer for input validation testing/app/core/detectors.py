"""Web App Fuzzer - detection oracles (differential + signature based)."""
from __future__ import annotations

import re
import time
from typing import Dict, Optional, Tuple

from .payloads import _SQL_ERROR_RE, _STACK_RE

_SEVERITY_LOW = "Low"
_SEVERITY_MED = "Medium"
_SEVERITY_HIGH = "High"

_TRAVERSAL_MARKERS = ("root:", "[fonts]", "uid=0(", "NetworkAddress:")
_SSRF_MARKERS = ("instance-id", "ami-id", "localhost", "127.0.0.1 bacula", "security-credentials")


def _headermap(headers: Dict) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for k, v in headers.items():
        out[k.lower()] = ";".join(v) if isinstance(v, list) else str(v)
    return out


def detect(
    module: str,
    payload_id: str,
    payload: str,
    marker: str,
    baseline: Dict,
    actual: Dict,
) -> Optional[Tuple[str, float, Dict]]:
    b_status, b_len = baseline.get("status"), len(baseline.get("body", "") or "")
    a_status, a_body = actual.get("status"), actual.get("body", "") or ""
    a_headers = _headermap(actual.get("headers", {}))
    a_len = len(a_body)
    a_time = float(actual.get("time", 0.0))
    b_time = float(baseline.get("time", 0.0))
    a_code_ok = isinstance(a_status, int) and 200 <= a_status < 400

    if module == "sqli":
        normal_blocked = isinstance(b_status, int) and b_status in (401, 403, 404)
        if "time" in payload_id and a_time - b_time >= 1.5 and a_code_ok:
            return _SEVERITY_HIGH, 0.9, {"signal": "time-based delay", "delta_s": round(a_time - b_time, 2)}
        if _re_find(_SQL_ERROR_RE, a_body):
            return _SEVERITY_HIGH, 0.9, {"signal": "SQL error signature", "sample": _sample(_SQL_ERROR_RE, a_body)}
        if normal_blocked and a_code_ok and a_len > 0:
            return _SEVERITY_HIGH, 0.7, {"signal": "injected value bypassed access status", "from": b_status, "to": a_status}
        if a_status != b_status and a_code_ok and abs(a_len - b_len) > max(200, b_len * 0.5):
            return _SEVERITY_LOW, 0.3, {"signal": "behaviour delta", "from": b_status, "to": a_status}
        return None

    if module == "xss":
        if marker and marker in a_body and "<script>" in payload:
            return _SEVERITY_MED, 0.9, {"signal": "marker reflected unencoded in script context"}
        if marker and marker in a_body:
            return _SEVERITY_MED, 0.85, {"signal": "marker reflected unencoded"}
        return None

    if module == "ssti":
        if "{{7*7}}" in a_body:
            return None
        if "49" in a_body and any(probe in payload for probe in ("7*7", "7*6")):
            return _SEVERITY_HIGH, 0.85, {"signal": "template expression evaluated (7*7=49)"}
        snippet = _find_num(a_body)
        if snippet and snippet not in {"49"}:
            if any(tok in payload for tok in ("7*7",)) and snippet in a_body:
                return None
        return None

    if module == "traversal":
        for tm in _TRAVERSAL_MARKERS:
            if tm in a_body:
                return _SEVERITY_HIGH, 0.9, {"signal": f"file content marker '{tm}'", "sample": _around(a_body, tm)}
        return None

    if module == "ssrf":
        for sm in _SSRF_MARKERS:
            if sm in a_body:
                return _SEVERITY_HIGH, 0.85, {"signal": f"SSRF fetch marker '{sm}'"}
        if "file://" in payload and "root:" in a_body:
            return _SEVERITY_HIGH, 0.9, {"signal": "file:// scheme read /etc/passwd"}
        return None

    if module == "cmdi":
        if marker and marker in a_body:
            return _SEVERITY_HIGH, 0.9, {"signal": "command output reflection (marker echo)"}
        return None

    if module == "header":
        if "x-injected-hdr" in a_headers:
            return _SEVERITY_MED, 0.8, {"signal": "injected response header present", "value": a_headers.get("x-injected-hdr", "")}
        if "<html>" in payload and marker and marker in a_body:
            return _SEVERITY_MED, 0.8, {"signal": "response body injection via CRLF"}
        return None

    if module == "errors":
        m = _re_find(_STACK_RE, a_body)
        if m:
            return _SEVERITY_MED, 0.8, {"signal": "verbose error / stack trace", "sample": m}
        if isinstance(a_status, int) and a_status >= 500:
            delta = a_len - b_len
            if delta > 400:
                return _SEVERITY_LOW, 0.4, {"signal": "5xx with large error body", "delta_bytes": delta}
        return None

    if module == "boundary":
        m = _re_find(_STACK_RE, a_body)
        if isinstance(a_status, int) and a_status >= 500 and (m or a_len - b_len > 400):
            return _SEVERITY_MED, 0.5, {"signal": "boundary input causes server error", "status": a_status}
        return None

    if module == "auth":
        if isinstance(b_status, int) and b_status in (401, 403) and a_code_ok:
            return _SEVERITY_HIGH, 0.7, {"signal": "auth-protected endpoint accepted tampered input", "from": b_status, "to": a_status}
        return None

    return None


def _re_find(pattern: str, text: str) -> str:
    m = re.search(pattern, text)
    return m.group(0) if m else ""


def _sample(pattern: str, text: str) -> str:
    m = re.search(pattern, text)
    return (text[max(0, m.start() - 60): m.end() + 60]) if m else ""


def _around(text: str, needle: str) -> str:
    i = text.find(needle)
    if i < 0:
        return ""
    return text[max(0, i - 40): i + 80]


def _find_num(text: str) -> str:
    m = re.search(r"\b\d{1,3}\b", text)
    return m.group(0) if m else ""