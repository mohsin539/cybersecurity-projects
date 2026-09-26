"""Remediation guidance per context type (OWASP XSS Prevention Cheat Sheet).

Returned inline with every finding so a report is actionable ("fix it", not
just "it's vulnerable").
"""

from __future__ import annotations

from app.engine.contexts import Context, ContextSpec

_CHEATSHEET = "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"

REMEDIATION: dict[Context, str] = {
    Context.HTML: (
        "HTML-body/context encode the reflection before placing it inside an element: "
        "escape &, <, >, \", ' and backtick (OWASP RULE #1). Use your framework's "
        "auto-escaping templates; never build HTML via string concatenation."
    ),
    Context.ATTR: (
        "Encode with the attribute-output encoder (escape &, \", ', <, >) AND quote "
        "attribute values (OWASP RULE #2). Enforce an allowlist of schemes for URL-ish "
        "attributes; `javascript:` must never reach an attribute."
    ),
    Context.SCRIPT: (
        "Put data only inside a JSON block rendered with JSON.stringify into a "
        "<script> tag and escape <, >, / (OWASP RULE #3). Prefer calling a safe "
        "parameterized API instead of toJSON; never inline untrusted data into JS code."
    ),
    Context.URL: (
        "URL-encode untrusted input (OWASP RULE #5) and validate the scheme against an "
        "allowlist (http:, https:, mailto:). Reject `javascript:`/`data:`. For redirect "
        "parameters use relative-path allowlists to prevent open-redirect+XSS."
    ),
    Context.DOM: (
        "Eliminate HTML sinks (innerHTML, document.write, insertAdjacentHTML, outerHTML). "
        "Use textContent / safe DOM APIs (OWASP RULE #4). If a sink is unavoidable, sanitize "
        "with an allowlist-based library configured to drop all event handlers and javascript: URLs."
    ),
}


def remediate(spec: ContextSpec) -> str:
    return f"{REMEDIATION[spec.kind]} ({_CHEATSHEET})"


def csp_recommendation() -> str:
    return (
        "Deploy a strict CSP as defense-in-depth (OWASP A05): `default-src 'none'; "
        "script-src 'self' 'nonce-<random>' 'strict-dynamic'; object-src 'none'; "
        "base-uri 'none'`. Where inline handlers are unavoidable, keep a narrowly "
        "scoped 'unsafe-inline' only on the specific script-src directive and add "
        "`require-trusted-types-for 'script'`."
    )


def header_checks() -> dict[str, str]:
    return {
        "Content-Security-Policy": "Policy should be present and not allow 'unsafe-inline'/'unsafe-eval' for script-src in production.",
        "Strict-Transport-Security": "max-age >= 6 months; includeSubDomains on HTTPS-only origins.",
        "X-Content-Type-Options": "must benosniff",
        "X-Frame-Options": "DENY/SAMEORIGIN or use CSP frame-ancestors.",
        "Referrer-Policy": "no-referrer or strict-origin-when-cross-origin recommended.",
        "Permissions-Policy": "Deny camera/mic/geolocation by default.",
        "Cross-Origin-Opener-Policy": "same-origin recommended.",
    }