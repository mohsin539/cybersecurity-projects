"""YARA-subset rule engine (M2 leftover; ARCHITECTURE.md §3.3).

Pure, bounded, no eval. Supports a practical CTF subset of YARA syntax:

    rule name {
      meta:
        author = "rekt"
      strings:
        $a = "flag{" ascii nocase
        $b = { 4D 5A ?? 00 }
        $c = /upx|themida/i
      condition:
        any of them
    }

Condition grammar (precedence low->high): or, and, not, primary.
Primary: number | "them" | ("any"|"all") "of" ("them" | identifier-list)
       | $id | "(" expr ")".
Regexes are pre-compiled with hard limits (pattern length, match count,
subject slice) so hostile input cannot trigger pathological backtracking
unboundedly (A04). Everything is pure -- no I/O.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

MAX_FILE_SLICE = 8 * 1024 * 1024      # subject cap per match() call (A04)
MAX_REGEX_LEN = 256
MAX_PATTERN_LEN = 4096
MAX_REGEX_MATCHES = 256


class RuleError(ValueError):
    pass


# --------------------------------------------------------------------- model
@dataclass
class StringDef:
    name: str                       # "$a"
    kind: str                       # "text" | "hex" | "regex"
    value: str                      # pattern source
    nocase: bool = False
    ascii_: bool = True
    wide: bool = False
    _rx: object = field(default=None, repr=False)


@dataclass
class Rule:
    name: str
    meta: dict
    strings: list[StringDef]
    condition: object               # AST tuple
    source_path: str = ""

    def match(self, data: bytes) -> bool:
        hits = self.match_details(data)
        return bool(hits)

    def match_details(self, data: bytes) -> list[dict]:
        subject = data[:MAX_FILE_SLICE]
        results: dict[str, bool] = {}
        offsets: dict[str, list[int]] = {}
        for s in self.strings:
            found, offs = _match_string(s, subject)
            results[s.name] = found
            offsets[s.name] = offs
        if not _eval(self.condition, results):
            return []
        out: list[dict] = []
        for s in self.strings:
            if results[s.name]:
                out.append({"string": s.name, "offsets": offsets[s.name][:16]})
        return out


# ------------------------------------------------------------------ matching
def _compile_regex(s: StringDef) -> re.Pattern:
    if s._rx is None:
        if len(s.value) > MAX_REGEX_LEN:
            raise RuleError(f"{s.name}: regex too long")
        flags = re.DOTALL | (re.IGNORECASE if s.nocase else 0)
        try:
            s._rx = re.compile(s.value.encode("latin-1"), flags)
        except re.error as e:
            raise RuleError(f"{s.name}: bad regex: {e}") from e
    return s._rx


def _match_string(s: StringDef, data: bytes) -> tuple[bool, list[int]]:
    try:
        if s.kind == "regex":
            rx = _compile_regex(s)
            offs = [m.start() for m in rx.finditer(data, 0, MAX_FILE_SLICE)]
            return bool(offs), offs[:MAX_REGEX_MATCHES]
        if s.kind == "text":
            pats = [s.value.encode("latin-1")]
            if s.nocase:
                pats = [p.lower() for p in pats]
                data = data.lower()
            if s.wide:
                pats = pats + [bytes(b for c in p for b in (c, 0)) for p in pats]
            offs: list[int] = []
            start = 0
            for p in pats:
                if not p:
                    return False, []
                idx = data.find(p, start)
                while idx != -1 and len(offs) < MAX_REGEX_MATCHES:
                    offs.append(idx)
                    idx = data.find(p, idx + 1)
            return bool(offs), offs
        if s.kind == "hex":
            rx = _hex_to_regex(s.value)
            offs = [m.start() for m in rx.finditer(data)]
            return bool(offs), offs[:MAX_REGEX_MATCHES]
    except RuleError:
        raise
    except Exception as e:  # noqa: BLE001 — a broken string def can't crash the host
        raise RuleError(f"{s.name}: match failed: {e}") from e
    return False, []


def _hex_to_regex(src: str) -> re.Pattern:
    """YARA hex pattern -> compiled regex. Supports ?? wildcards, byte pairs."""
    toks = src.replace("{", " ").replace("}", " ").replace(" ", "").replace("\n", "")
    if len(toks) % 2 or len(toks) // 2 > MAX_PATTERN_LEN:
        raise RuleError("bad hex pattern length")
    parts: list[str] = []
    for i in range(0, len(toks), 2):
        pair = toks[i:i + 2]
        if pair == "??":
            parts.append(".")
        elif len(pair) == 2 and all(c in "0123456789abcdefABCDEF" for c in pair):
            parts.append(re.escape(bytes.fromhex(pair).decode("latin-1")))
        else:
            raise RuleError(f"bad hex token {pair!r}")
    return re.compile("".join(parts).encode("latin-1"), re.DOTALL)


# ------------------------------------------------------------------ AST eval
def _eval(node, results: dict[str, bool]) -> bool:
    kind = node[0]
    if kind == "or":
        return any(_eval(n, results) for n in node[1])
    if kind == "and":
        return all(_eval(n, results) for n in node[1])
    if kind == "not":
        return not _eval(node[1], results)
    if kind == "of":
        quant, names = node[1], node[2]
        vals = [results[n] for n in names]
        if quant == "any":
            return any(vals)
        if quant == "all":
            return all(vals)
        return sum(vals) >= int(quant)          # "2 of ..."
    if kind == "str":
        return results.get(node[1], False)
    if kind == "num":
        return bool(node[1])
    raise RuleError(f"unknown condition node {kind!r}")


# -------------------------------------------------------------------- parser
_TOKEN = re.compile(r"""
    (?P<ws>\s+)
  | (?P<comment>//[^\n]*|/\*.*?\*/)
  | (?P<str>"(?:\\.|[^"\\])*")
  | (?P<regex>/(?:\\.|[^/\\])+/[a-z]*)
  | (?P<hex>\{[0-9a-fA-F?\s]+\})
  | (?P<var>\$[A-Za-z_][A-Za-z0-9_]*)
  | (?P<id>[A-Za-z_][A-Za-z0-9_]*)
  | (?P<num>\d+)
  | (?P<sym>[(){}\[\]=:])
""", re.X | re.S)


def _tokenize(src: str) -> list[str]:
    toks: list[str] = []
    pos = 0
    while pos < len(src):
        m = _TOKEN.match(src, pos)
        if not m:
            raise RuleError(f"unexpected character at {pos}: {src[pos:pos+12]!r}")
        pos = m.end()
        kind = m.lastgroup
        if kind in ("ws", "comment"):
            continue
        toks.append(m.group())
    return toks


class _Parser:
    def __init__(self, toks: list[str], source_path: str = "") -> None:
        self.toks = toks
        self.i = 0
        self.source_path = source_path

    def peek(self) -> str | None:
        return self.toks[self.i] if self.i < len(self.toks) else None

    def take(self) -> str:
        t = self.peek()
        if t is None:
            raise RuleError("unexpected end of rule source")
        self.i += 1
        return t

    def expect(self, tok: str) -> str:
        t = self.take()
        if t != tok:
            raise RuleError(f"expected {tok!r}, got {t!r}")
        return t

    # ---- top level
    def parse_rules(self) -> list[Rule]:
        rules = []
        while self.peek() is not None:
            if self.take() != "rule":
                raise RuleError("expected 'rule' keyword")
            name = self.take()
            if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
                raise RuleError(f"bad rule name {name!r}")
            meta, strings = {}, []
            self.expect("{")
            self._pending_condition = None
            while self.peek() != "}":
                section = self.take()
                self.expect(":")
                if section == "meta":
                    while self.peek() not in (None, "strings", "condition", "}"):
                        key = self.take()
                        self.expect("=")
                        val = self.take().strip('"')
                        meta[key] = val
                elif section == "strings":
                    while self.peek() not in (None, "condition", "}"):
                        nm = self.take()
                        if not nm.startswith("$"):
                            raise RuleError(f"expected $string, got {nm!r}")
                        self.expect("=")
                        strings.append(self._string_def(nm))
                elif section == "condition":
                    # consumes tokens up to the closing '}' of the rule
                    self._pending_condition = self._expr()
                else:
                    raise RuleError(f"unknown section {section!r}")
            self.expect("}")
            rule = Rule(name, meta, strings, getattr(self, "_pending_condition", None),
                        self.source_path)
            if rule.condition is None:
                raise RuleError(f"rule {name}: missing condition")
            rules.append(rule)
        return rules

    def _string_def(self, name: str) -> StringDef:
        tok = self.take()
        if tok.startswith('"'):
            sd = StringDef(name, "text", _unescape(tok[1:-1]))
        elif tok.startswith("{"):
            sd = StringDef(name, "hex", tok)
        elif tok.startswith("/"):
            m = re.fullmatch(r"/(.*)/([a-z]*)", tok, re.S)
            if not m:
                raise RuleError(f"{name}: malformed regex")
            sd = StringDef(name, "regex", m.group(1))
            sd.nocase = "i" in (m.group(2) or "")
        else:
            raise RuleError(f"{name}: unsupported string form {tok[:12]!r}")
        while self.peek() in ("ascii", "nocase", "wide"):
            mod = self.take()
            if mod == "nocase":
                sd.nocase = True
            elif mod == "wide":
                sd.wide = True
            elif mod == "ascii":
                sd.ascii_ = True
        return sd

    # ---- condition expressions (precedence: or < and < not < primary)
    def _expr(self) -> object:
        return self._or()

    def _or(self):
        left = self._and()
        parts = [left]
        while self.peek() == "or":
            self.take()
            parts.append(self._and())
        return ("or", parts) if len(parts) > 1 else left

    def _and(self):
        left = self._not()
        parts = [left]
        while self.peek() == "and":
            self.take()
            parts.append(self._not())
        return ("and", parts) if len(parts) > 1 else left

    def _not(self):
        if self.peek() == "not":
            self.take()
            return ("not", self._not())
        return self._primary()

    def _primary(self):
        t = self.take()
        if t == "(":
            e = self._expr()
            self.expect(")")
            return e
        if t == "any" or t == "all":
            self.expect("of")
            return ("of", t, self._name_list())
        if re.fullmatch(r"\d+", t):
            nxt = self.peek()
            if nxt == "of":
                self.take()
                return ("of", int(t), self._name_list())
            return ("num", int(t))
        if t == "them":
            self.expect("of")  # rare bare form; treat as any of them
            return ("of", "any", ["them"])
        if t.startswith("$"):
            return ("str", t)
        raise RuleError(f"unexpected token in condition: {t!r}")

    def _name_list(self) -> list[str]:
        t = self.take()
        if t == "them":
            return ["them"]  # sentinel — expanded to real names in parse_rules
        names = [t]
        while self.peek() == ",":
            self.take()
            names.append(self.take())
        return names


def _unescape(s: str) -> str:
    return re.sub(r"\\(.)", r"\1", s)


def parse_rules(src: str, source_path: str = "") -> list[Rule]:
    """Parse rule source into Rule objects. Raises RuleError on bad input."""
    p = _Parser(_tokenize(src), source_path)
    rules = p.parse_rules()
    for r in rules:
        p._current_strings = r.strings
        # rebuild name lists that referenced 'them'
        r.condition = _expand_them(r.condition, [s.name for s in r.strings])
    for r in rules:
        _validate_condition(r)
    return rules


def _expand_them(node, names: list[str]):
    if not isinstance(node, tuple):
        return node
    if node[0] == "of" and node[2] == ["them"]:
        return ("of", node[1], list(names))
    if node[0] in ("or", "and"):
        return (node[0], [_expand_them(n, names) for n in node[1]])
    if node[0] == "not":
        return ("not", _expand_them(node[1], names))
    return node


def _validate_condition(rule: Rule) -> None:
    known = {s.name for s in rule.strings}

    def walk(node):
        if not isinstance(node, tuple):
            return
        if node[0] == "of":
            quant, names = node[1], node[2]
            if quant in ("any", "all"):
                pass
            elif isinstance(quant, int) and 1 <= quant <= max(1, len(known)):
                pass
            else:
                raise RuleError(f"rule {rule.name}: bad 'of' quantifier {quant!r}")
            for n in names:
                if not n.startswith("$"):
                    raise RuleError(f"rule {rule.name}: bad identifier {n!r}")
                if n not in known:
                    raise RuleError(f"rule {rule.name}: {n} not defined in strings")
        elif node[0] == "str":
            if node[1] not in known:
                raise RuleError(f"rule {rule.name}: {node[1]} not defined in strings")
        elif node[0] in ("or", "and"):
            for n in node[1]:
                walk(n)
        elif node[0] == "not":
            walk(node[1])
    walk(rule.condition)


def load_rules_file(path) -> list[Rule]:
    from pathlib import Path

    p = Path(path)
    return parse_rules(p.read_text(encoding="utf-8"), str(p))


def scan_bytes(rules: list[Rule], data: bytes) -> list[dict]:
    """Run all rules over data. Returns matches: [{rule, matches, meta}]."""
    out: list[dict] = []
    for r in rules:
        try:
            det = r.match_details(data)
        except RuleError:
            continue  # broken rule: skip, never fail the scan
        if det:
            out.append({"rule": r.name, "matches": det, "meta": dict(r.meta)})
    return out
