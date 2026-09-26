"""Injection contexts and their wrappers.

A context describes *how* the tester classifies an injection point so a
vector can be aimed and a fix scoped. Wrappers below are the reference
"lab page" shapes (OWASP WSTG classification):

  HTML    -> element text (encode: &, <, >)
  Attr    -> attribute value, quoted/unquoted (encode: &, ", ')
  Script  -> inside <script> JS string
  URL     -> inside href/src or query parameter (encode: URL encoding)
  DOM     -> sink such as innerHTML / document.write

Contexts never alter the real target request: they label the vector so the
payload is designed for that sink and the remediation is context-scoped.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Context(str, Enum):
    HTML = "html"
    ATTR = "attribute"
    SCRIPT = "script"
    URL = "url"
    DOM = "dom"


@dataclass(frozen=True)
class ContextSpec:
    name: str
    kind: Context
    wrapper: str
    description: str
    sanitization: str


CONTEXT_SPECS: dict[Context, list[ContextSpec]] = {
    Context.HTML: [
        ContextSpec(
            "html_element",
            Context.HTML,
            "<div id='probe'>{INJ}</div>",
            "Reflected inside an HTML element (no parsing context)",
            "HTML-encode with &, <, >, \", ', ` -> e.g. &lt;script&gt;",
        ),
    ],
    Context.ATTR: [
        ContextSpec(
            "attr_double",
            Context.ATTR,
            '<input id="probe" value="{INJ}">',
            "Inside a double-quoted attribute value",
            "Attribute-encode (quotes & angle brackets) + allow listing; avoid any &...; that can re-appear",
        ),
        ContextSpec(
            "attr_single",
            Context.ATTR,
            "<input id='probe' value='{INJ}'>",
            "Inside a single-quoted attribute value",
            "Same as double-quoted attribute",
        ),
        ContextSpec(
            "attr_unquoted",
            Context.ATTR,
            "<input id=probe value={INJ}>",
            "Inside an unquoted attribute value",
            "Quote the attribute AND encode spaces/angle brackets",
        ),
        ContextSpec(
            "attr_url",
            Context.ATTR,
            '<a id="probe" href="{INJ}">link</a>',
            "Inside an href attribute (URL context)",
            "Validate scheme against allowlist (never javascript:); encode non-URL chars",
        ),
    ],
    Context.SCRIPT: [
        ContextSpec(
            "script_string",
            Context.SCRIPT,
            "<script>var probe = '{INJ}';</script>",
            "Inside a single-quoted JS string in <script>",
            "Use JSON.stringify + context-aware JS encoding; forbid </script",
        ),
    ],
    Context.URL: [
        ContextSpec(
            "url_query",
            Context.URL,
            "/search?q={INJ}",
            "Inside a query string parameter reflected by the app",
            "URL-encode and HTML-encode; treat javascript: with a scheme allowlist",
        ),
        ContextSpec(
            "url_path",
            Context.URL,
            "/redirect/{INJ}",
            "Inside a path segment used by redirects",
            "Open-redirect-safe: relative-path allowlist, no scheme control",
        ),
    ],
    Context.DOM: [
        ContextSpec(
            "dom_innerhtml",
            Context.DOM,
            '<div id="probe">{INJ}</div>',
            "DOM sink: injected then assigned to innerHTML by JS",
            "Use textContent / safe DOM APIs; sanitize with an allowlist-based library",
        ),
    ],
}

CTX_INDEX: dict[str, ContextSpec] = {
    spec.name: spec for kinds in CONTEXT_SPECS.values() for spec in kinds
}