"""Layer 2 - SQL-aware grammar/tokenizer detector.

ARCHITECTURE.md section 6.2: feed the normalized value through a lightweight
SQL lexical analyzer and flag values that contain *structurally valid* SQL
fragments using operators/expressions - not merely keyword matches (which
reduce false positives on natural language such as 'please select').
"""
from __future__ import annotations

import re
from typing import List, NamedTuple


class SQLToken(NamedTuple):
    kind: str      # kw | op | str | num | ident | sym | comment
    text: str


_KEYWORDS = {
    "select", "union", "where", "or", "and", "from", "order", "by", "group",
    "having", "limit", "insert", "update", "delete", "drop", "alter", "create",
    "sleep", "benchmark", "waitfor", "delay", "case", "when", "then", "end",
    "like", "between", "not", "null", "into", "outfile", "dumpfile", "as",
}
_OPS = {"=", ">", "<", ">=", "<=", "!=", "<>", "+", "-", "*", "/", "(", ")", ","}
_COMMENT_RE = re.compile(r"--[^\r\n]*|#[^\r\n]*|/\*.*?\*/")


def tokenize(value: str) -> List[SQLToken]:
    """Minimal SQL lexer. Handles strings ('...' with doubled quotes), idents,
    keywords, numbers, operators, parentheses, comments."""
    toks: List[SQLToken] = []
    i, n = 0, len(value)
    while i < n:
        ch = value[i]
        if ch.isspace():
            i += 1
            continue
        m = _COMMENT_RE.match(value, i)
        if m:
            toks.append(SQLToken("comment", m.group(0)))
            i = m.end()
            continue
        if ch in ("'", '"'):
            j = i + 1
            buf = [ch]
            while j < n:
                if value[j] == ch:
                    if j + 1 < n and value[j + 1] == ch:
                        buf.append(ch * 2)
                        j += 2
                        continue
                    buf.append(ch)
                    j += 1
                    break
                buf.append(value[j])
                j += 1
            toks.append(SQLToken("str", "".join(buf)))
            i = j
            continue
        if ch.isdigit() or (ch in ("0x",) and False):
            j = i
            if value[j:j + 2].lower() == "0x":
                m = re.match(r"0x[0-9a-fA-F]+", value[i:])
                if m:
                    toks.append(SQLToken("num", m.group(0)))
                    i += m.end() - m.start()
                    continue
            while j < n and (value[j].isdigit() or value[j] in "._"):
                j += 1
            toks.append(SQLToken("num", value[i:j]))
            i = j
            continue
        if value[i:i + 2] in (">=", "<=", "!=", "<>"):
            toks.append(SQLToken("op", value[i:i + 2]))
            i += 2
            continue
        if ch in _OPS:
            toks.append(SQLToken("op", ch))
            i += 1
            continue
        if ch.isalnum() or ch in "_$":
            j = i
            while j < n and (value[j].isalnum() or value[j] in "_$"):
                j += 1
            word = value[i:j]
            kind = "kw" if word.lower() in _KEYWORDS else "ident"
            toks.append(SQLToken(kind, word))
            i = j
            continue
        toks.append(SQLToken("sym", ch))
        i += 1
    return toks


class StructHit(NamedTuple):
    reason: str
    db_flavor: str
    confidence: float  # 0..1 contribution weight


def _stream(toks: List[SQLToken]) -> List[SQLToken]:
    """Drop comments for structural scanning."""
    return [t for t in toks if t.kind != "comment"]


def detect_structure(value: str) -> List[StructHit]:
    raw_toks = tokenize(value)
    toks = _stream(raw_toks)
    hits: List[StructHit] = []
    kws = [(i, t) for i, t in enumerate(toks) if t.kind == "kw"]

    # Unterminated string literal (quote-break vector) - valid sign standalone.
    for t in toks:
        if t.kind == "str" and not t.text.endswith(t.text[0]):
            hits.append(StructHit("unterminated string literal", "ANY", 0.75))

    if not kws:
        return hits

    kwset = {t.text.lower() for _, t in kws}

    # 1. SELECT ... FROM / UNION SELECT structural requirement (operator present)
    if "select" in kwset or "union" in kwset:
        has_op = any(t.kind == "op" for t in toks)
        has_str = any(t.kind == "str" for t in toks)
        if has_op:
            hits.append(StructHit("SELECT/UNION with operator context", "ANY", 0.9))
        elif has_str:
            hits.append(StructHit("SELECT/UNION inside string context", "ANY", 0.7))

    # 2. String literal immediately followed by an SQL keyword (quote escape attempt)
    for i, t in enumerate(toks[:-1]):
        if t.kind == "str" and toks[i + 1].kind == "kw":
            nxt = toks[i + 1].text.lower()
            if nxt in ("or", "and", "union", "order", "where", "select", "like", "by"):
                hits.append(StructHit(f"string literal -> '{nxt}' clause", "ANY", 0.95))

    # 3. Keyword immediately after a numeric operand (e.g. 2 AND, 1 OR)
    for i, t in enumerate(toks[:-1]):
        if t.kind == "num" and toks[i + 1].kind == "kw":
            nxt = toks[i + 1].text.lower()
            if nxt in ("and", "or", "union", "select"):
                hits.append(StructHit(f"numeric operand -> '{nxt}' clause", "ANY", 0.85))

    # 4. comment-amplified keyword (obfuscation pyjamas)
    if any(t.kind == "comment" for t in raw_toks) and kws:
        hits.append(StructHit("comment present adjacent to SQL keyword", "ANY", 0.6))

    return hits


def is_numeric(value: str) -> bool:
    return value.strip().lstrip("+-").replace(".", "", 1).isdigit()

def is_email(value: str) -> bool:
    return re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", value.strip()) is not None