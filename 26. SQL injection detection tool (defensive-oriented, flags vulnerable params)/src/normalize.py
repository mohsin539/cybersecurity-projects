"""Parse & Normalize stage (ARCHITECTURE.md section 5.2).

- Extract named parameters from a URL, a raw HTTP request, or a query form.
- Deep-normalize values: repeat URL-decode, HTML-entity unescape, hex/unicode
  escapes, null bytes, whitespace variants, case folding marker.
- Never stores the raw wire value: only the decoded value plus a digest.
"""
from __future__ import annotations

import hashlib
import html
import urllib.parse
from dataclasses import dataclass, field
from typing import Dict, List, Tuple


@dataclass
class ParameterValue:
    name: str
    source: str          # query | body | header | cookie | path
    expected_type: str   # int | string | uuid | email | date | unknown
    decoded: str
    encodings_seen: List[str] = field(default_factory=list)
    digest: str = ""

    def finalize(self):
        self.digest = sha256_digest(self.decoded)
        return self


def sha256_digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()


def _decode_round(value: str) -> Tuple[str, str]:
    """One unquote pass; returns (value, kind)."""
    try:
        if "%" in value and value != urllib.parse.unquote(value):
            return urllib.parse.unquote(value), "percent"
    except Exception:
        pass
    if "&" in value:
        unesc = html.unescape(value)
        if unesc != value:
            return unesc, "html-entity"
    return value, "none"


def deep_decode(value: str, max_passes: int = 4) -> Tuple[str, List[str]]:
    """Decode nested encodings. Returns (decoded, encodings_seen)."""
    seen: List[str] = []
    cur = value
    for _ in range(max_passes):
        nxt, kind = _decode_round(cur)
        if kind != "none":
            seen.append(kind)
            cur = nxt
        else:
            break
    # unicode escapes: \u0041, %u0041
    cur = cur.replace("%u", "\\u")
    if "\\u" in cur:
        try:
            cur = cur.encode().decode("unicode_escape", errors="ignore")
            seen.append("unicode-escape")
        except Exception:
            pass
    cur = cur.replace("\x00", "")            # null bytes
    if "\r" in cur or "\n" in cur or "\t" in cur:
        seen.append("whitespace-variant")
    return cur, seen


def _infer_type(name: str, value: str) -> str:
    v = value.strip()
    if name and name.lower() in ("id", "uid", "userid", "order", "limit", "page"):
        return "int"
    if v.lstrip("-").replace(" ", "").isdigit():
        return "int"
    if "@" in v and "." in v:
        return "email"
    if len(v) in (36, 32) and (v[8] == "-" or "-" in v):
        return "uuid"
    if v and v[0].isdigit() and len(v) >= 8 and "-" not in v[2:6]:
        return "date-candidate"
    return "string"


def extract_parameters(
    target: str, raw_request: bool = False
) -> Tuple[List[ParameterValue], Dict[str, str]]:
    """Extract parameters from a URL or raw HTTP request.

    Returns (params, meta) where meta carries URL info / errors.
    """
    meta: Dict[str, str] = {}
    params: List[ParameterValue] = []

    if raw_request:
        url, headers, body = _parse_raw_request(target)
        meta["raw_url"] = url
        if not url:
            meta["error"] = "Could not parse first line of raw request."
            return params, meta
    else:
        url, headers, body = target.strip(), {}, ""

    parts = urllib.parse.urlsplit(url)
    meta["url"] = url
    meta["path"] = parts.path or "/"
    meta["method"] = raw_request and headers.get("method", "GET") or "GET"

    # Query string params
    for k, v in urllib.parse.parse_qsl(parts.query, keep_blank_values=True):
        dec, seen = deep_decode(v)
        params.append(ParameterValue(name=k, source="query",
                                     expected_type=_infer_type(k, dec),
                                     decoded=dec, encodings_seen=seen).finalize())
    # Path segments (heuristic): numeric path segments
    for seg in parts.path.split("/"):
        seg = seg.strip()
        if seg and not seg.startswith(("{", "[:")) and any(ch.isdigit() for ch in seg) and "-" not in seg:
            params.append(ParameterValue(name="path:" + seg, source="path",
                                         expected_type=_infer_type(seg, seg),
                                         decoded=seg, encodings_seen=[]).finalize())
    # Headers (only if raw request present)
    for name in ("User-Agent", "Referer", "Cookie", "X-Forwarded-For"):
        val = headers.get(name)
        if val:
            params.append(ParameterValue(name="header:" + name, source="header",
                                         expected_type="string", decoded=val,
                                         encodings_seen=[]).finalize())
    # Body params: form-encoded, JSON object, or raw
    if body:
        parsed, srctag = _body_params(body)
        for k, v in parsed.items():
            dec, seen = deep_decode(str(v))
            params.append(ParameterValue(name=k, source=srctag,
                                         expected_type=_infer_type(k, dec),
                                         decoded=dec, encodings_seen=seen).finalize())
        meta["body_type"] = srctag
    return params, meta


def _parse_raw_request(text: str) -> Tuple[str, Dict[str, str], str]:
    lines = text.splitlines()
    if not lines:
        return "", {}, ""
    head = lines[0].strip().split()
    if len(head) < 2:
        return "", {}, ""
    method, target = head[0], head[1]
    headers: Dict[str, str] = {"method": method}
    idx = 1
    while idx < len(lines):
        line = lines[idx]
        if not line.strip():
            idx += 1
            break
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().title()] = v.strip()
        idx += 1
    body = "\n".join(lines[idx:])
    if target.startswith("/"):
        scheme = "https"
        host = headers.get("Host", "localhost")
        target = f"{scheme}://{host}{target}"
    return target, headers, body


def _body_params(body: str) -> Tuple[Dict[str, str], str]:
    stripped = body.strip()
    if stripped.startswith("{") and "}" in stripped:
        try:
            import json
            data = json.loads(stripped)
            if isinstance(data, dict):
                return {str(k): str(v) for k, v in data.items()}, "body-json"
        except Exception:
            pass
    if "=" in stripped and ("&" in stripped or " " not in stripped.split("=", 1)[0]):
        parsed = dict(urllib.parse.parse_qsl(stripped, keep_blank_values=True))
        if parsed:
            return parsed, "body-form"
    return {}, "body-raw"