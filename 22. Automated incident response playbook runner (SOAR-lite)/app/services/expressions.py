"""Safe expression evaluator for playbook conditions.

A tiny strict parser (no eval/exec) supporting only:
  - dotted path lookups into a context dict (strategy: secure enumeration)
  - literals: int, float, str (single/double quoted), true/false/null, lists
  - operators: == != > >= < <= in not contains and or
Unsupported syntax raises `ParseError`, guaranteeing playbook authors (or a
compromised playbook) cannot inject code — OWASP A3, ISO 27001 A.14.2.6.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any


class ExprError(Exception):
    """Raised on unsafe / unparsable expression."""


@dataclass
class Token:
    kind: str  # ident|path|str|num|bool|null|op|paren|bracket
    value: Any
    pos: int


def _tokenize(expr: str) -> list[Token]:
    tokens: list[Token] = []
    i, n = 0, len(expr)
    while i < n:
        c = expr[i]
        if c.isspace():
            i += 1
            continue
        if c in "()":
            tokens.append(Token("paren", c, i))
            i += 1
            continue
        if c in "[]":
            tokens.append(Token("bracket", c, i))
            i += 1
            continue
        if c == "'" or c == '"':
            j = i + 1
            buf = []
            while j < n and expr[j] != c:
                if expr[j] == "\\" and j + 1 < n:
                    buf.append(expr[j + 1])
                    j += 2
                else:
                    buf.append(expr[j])
                    j += 1
            if j >= n:
                raise ExprError(f"unterminated string at {i}")
            tokens.append(Token("str", "".join(buf), i))
            i = j + 1
            continue
        if c.isdigit() or (c == "-" and i + 1 < n and expr[i + 1].isdigit()):
            j = i + 1
            while j < n and (expr[j].isdigit() or expr[j] == "."):
                j += 1
            text = expr[i:j]
            try:
                val = float(text) if "." in text else int(text)
            except ValueError:
                raise ExprError(f"bad number at {i}")
            tokens.append(Token("num", val, i))
            i = j
            continue
        if c.isalpha() or c == "_":
            j = i + 1
            while j < n and (expr[j].isalnum() or expr[j] in "._"):
                j += 1
            text = expr[i:j]
            if text in ("true", "True"):
                tokens.append(Token("bool", True, i))
            elif text in ("false", "False"):
                tokens.append(Token("bool", False, i))
            elif text in ("null", "None"):
                tokens.append(Token("null", None, i))
            elif text in ("and", "or", "not", "in", "contains"):
                tokens.append(Token("op", text, i))
            else:
                tokens.append(Token("path", text, i))
            i = j
            continue
        # operators: two-char first
        two = expr[i : i + 2]
        if two in ("==", "!=", ">=", "<="):
            tokens.append(Token("op", two, i))
            i += 2
            continue
        if c in "><":
            tokens.append(Token("op", c, i))
            i += 1
            continue
        if c == "," or c == ":" or c == "{":
            raise ExprError(f"unsupported character {c!r} at {i}")
        raise ExprError(f"unsupported character {c!r} at {i}")
    return tokens


class _Parser:
    def __init__(self, expr: str):
        self.tokens = _tokenize(expr)
        self.pos = 0
        self.expr = expr

    def peek(self) -> Token | None:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def next(self) -> Token:
        tok = self.peek()
        if tok is None:
            raise ExprError("unexpected end of expression")
        self.pos += 1
        return tok

    def parse(self):
        node = self.parse_or()
        if self.peek() is not None:
            raise ExprError(f"unexpected trailing input at {self.peek().pos}")
        return node

    def parse_or(self):
        left = self.parse_and()
        while self.peek() is not None and self.peek().kind == "op" and self.peek().value == "or":
            self.next()
            right = self.parse_and()
            left = ("or", left, right)
        return left

    def parse_and(self):
        left = self.parse_not()
        while self.peek() is not None and self.peek().kind == "op" and self.peek().value == "and":
            self.next()
            right = self.parse_not()
            left = ("and", left, right)
        return left

    def parse_not(self):
        if self.peek() is not None and self.peek().kind == "op" and self.peek().value == "not":
            self.next()
            return ("not", self.parse_not())
        return self.parse_comparison()

    def parse_comparison(self):
        left = self.parse_primary()
        tok = self.peek()
        if tok is not None and tok.kind == "op" and tok.value in ("==", "!=", ">", ">=", "<", "<=", "in", "contains"):
            self.next()
            right = self.parse_primary()
            return (tok.value, left, right)
        return left

    def parse_primary(self):
        tok = self.peek()
        if tok is None:
            raise ExprError("expected value")
        if tok.kind == "paren":
            self.next()  # (
            node = self.parse_or()
            closing = self.next()
            if closing.kind != "paren" or closing.value != ")":
                raise ExprError("expected )")
            return node
        if tok.kind in ("str", "num", "bool", "null"):
            self.next()
            return ("lit", tok.value)
        if tok.kind == "path":
            self.next()
            if ".." in tok.value or tok.value.startswith("_") or "__" in tok.value:
                raise ExprError(f"unsafe path {tok.value!r}")
            return ("path", tok.value)
        raise ExprError(f"unexpected token {tok.kind} at {tok.pos}")


def eval_expr(expr: str, context: dict | None = None) -> Any:
    """Parse and evaluate a condition expression safely."""
    if not expr or not expr.strip():
        return True
    context = context or {}
    ast = _Parser(expr).parse()
    return _evaluate(ast, context)


def _get_path(ctx: dict, path: str) -> Any:
    node: Any = ctx
    for part in path.split("."):
        if isinstance(node, dict) and part in node:
            node = node[part]
        elif isinstance(node, list) and part.isdigit() and int(part) < len(node):
            node = node[int(part)]
        else:
            return None
    return node


def _evaluate(node, ctx: dict) -> Any:
    kind = node[0]
    if kind == "lit":
        return node[1]
    if kind == "path":
        return _get_path(ctx, node[1])
    if kind == "not":
        return not _evaluate(node[1], ctx)
    if kind in ("and", "or"):
        left_v = _evaluate(node[1], ctx)
        if kind == "and" and not left_v:
            return False
        if kind == "or" and left_v:
            return True
        return _evaluate(node[2], ctx)
    if kind in ("==", "!=", ">", ">=", "<", "<="):
        left_v = _evaluate(node[1], ctx)
        right_v = _evaluate(node[2], ctx)
        if kind == "==":
            return left_v == right_v
        if kind == "!=":
            return left_v != right_v
        try:
            lf = float(left_v)
            rf = float(right_v)
        except (TypeError, ValueError):
            return False
        return {"<": lf < rf, "<=": lf <= rf, ">": lf > rf, ">=": lf >= rf}[kind]
    if kind == "in":
        left_v = _evaluate(node[1], ctx)
        right_v = _evaluate(node[2], ctx)
        try:
            return left_v in (right_v if isinstance(right_v, (list, tuple)) else [right_v])
        except TypeError:
            return False
    if kind == "contains":
        left_v = _evaluate(node[1], ctx)
        right_v = _evaluate(node[2], ctx)
        if isinstance(left_v, (list, dict, str)):
            try:
                return right_v in left_v
            except TypeError:
                return False
        return False
    raise ExprError(f"unknown node {kind!r}")


def validate_expr(expr: str) -> None:
    _Parser(expr).parse()