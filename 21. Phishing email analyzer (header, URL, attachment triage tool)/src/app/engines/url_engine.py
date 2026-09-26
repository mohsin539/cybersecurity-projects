"""URL analysis engine: extraction, de-obfuscation, SSRF-hardened inspection.

Controls: OWASP A10 (SSRF) - the engine never dials arbitrary URLs; it only
reads the link, checks literal/resolved IPs against private/reserved ranges,
and optionally queries reputation APIs pinned to an explicit allowlist with
TLS verification. OWASP A03 - HTML is parsed (never executed) for href/text.
"""
from __future__ import annotations

import html.parser
import ipaddress
import re
import urllib.parse
from typing import Dict, List, Optional, Tuple

from ..sec import constants as C
from ..sec.validation import is_private_ip, sanitize_text
from . import dns as dns
from .model import EngineResult, Severity

URL_RE = re.compile(
    r"(?i)\b(https?://[^\s<>\"'(){}[\]\\]+)"
)
HTTP_ENTITY_RE = re.compile(r"&(?:amp|#38|#x26);", re.IGNORECASE)
PUNYCODE_RE = re.compile(r"(?i)xn--[a-z0-9-]+")
CRED_IN_URL_RE = re.compile(r"(?i)[a-z0-9._%+-]+:[^@\s]*@")


class _AnchorParser(html.parser.HTMLParser):
    """Extracts (href, anchor_text) pairs from HTML; no rendering/execution (A03)."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.anchors: List[Tuple[str, str]] = []
        self._cur: Optional[str] = None
        self._buf: List[str] = []

    def handle_starttag(self, tag, attrs):
        if tag.lower() == "a":
            href = dict(attrs).get("href")
            self._cur = href
            self._buf = []

    def handle_data(self, data):
        if self._cur is not None:
            self._buf.append(data)

    def handle_endtag(self, tag):
        if tag.lower() == "a" and self._cur is not None:
            text = " ".join("".join(self._buf).split())[:120]
            self.anchors.append((self._cur, text))
            self._cur = None
            self._buf = []


def _edit_distance(a: str, b: str, cap: int = 3) -> int:
    if abs(len(a) - len(b)) > cap:
        return cap + 1
    la, lb = len(a), len(b)
    prev = list(range(lb + 1))
    for i in range(1, la + 1):
        cur = [i] + [0] * lb
        for j in range(1, lb + 1):
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1,
                         prev[j - 1] + (0 if a[i - 1] == b[j - 1] else 1))
        prev = cur
    return prev[lb]


def _normalize_url(raw: str) -> Tuple[str, str, int, Optional[str]]:
    """Return (normalized, host, port, ip_literal). Fails closed on parse error."""
    raw = raw.strip().rstrip(".,;)]}>")
    u = urllib.parse.urlsplit(raw)
    host = (u.hostname or "").lower().strip(".")
    port = None
    try:
        port = u.port
    except ValueError:
        port = None
    ip_lit = None
    if host:
        try:
            ip_lit = str(ipaddress.ip_address(host))  # catches v4/v6 literal
        except ValueError:
            ip_lit = None
    return raw, host, port, ip_lit


class URLEngine:
    def __init__(self, html_body: str = "", text_body: str = ""):
        self.html = html_body or ""
        self.text = text_body or ""
        self.anchors: List[Tuple[str, str]] = []
        self.all_urls: List[str] = []
        self._collect()

    def _collect(self) -> None:
        parser = _AnchorParser()
        try:
            parser.feed(self.html[:C.MAX_EMAIL_BYTES])
            parser.close()
        except Exception:  # noqa: BLE001 - malicious HTML must never break us
            parser = _AnchorParser()
        self.anchors = list(parser.anchors)[:C.MAX_URLS_EXTRACT]
        seen: set = set()
        for href, _text in self.anchors:
            if href and href not in seen and len(href) <= C.MAX_URL_LENGTH:
                seen.add(href)
                self.all_urls.append(href)
        for m in URL_RE.finditer(self.text):
            u = m.group(1)
            if u and u not in seen and len(u) <= C.MAX_URL_LENGTH:
                seen.add(u)
                self.all_urls.append(u)
        self.all_urls = self.all_urls[: C.MAX_URLS_EXTRACT]

    # ------------------------------------------------------------------
    def analyze(self, reputation_key: str = "", resolve_hosts: bool = False) -> EngineResult:
        res = EngineResult("url")
        res.meta["url_count"] = len(self.all_urls)
        if not self.all_urls:
            res.add("NO_URLS", Severity.INFO, "No URLs found in message", category="info")
            return res

        for raw in self.all_urls:
            decoded = self._deobfuscate(raw)
            raw2, host, port, ip_lit = _normalize_url(decoded)
            rec: Dict = {"raw": sanitize_text(raw, 512), "decoded": sanitize_text(decoded, 700),
                         "host": host, "port": port}
            res.meta.setdefault("urls", []).append(rec)

            if not host:
                res.add("URL_NOHOST", Severity.LOW, f"URL without host: {sanitize_text(raw, 80)}",
                        category="anomaly")
                continue

            # A10: literal IP in private/reserved space? block hard.
            if ip_lit and is_private_ip(ip_lit):
                res.add("SSRF_BLOCK_IP", Severity.HIGH,
                        f"URL resolves to reserved/private IP literal {ip_lit} - never dial (SSRF)",
                        category="malicious")
            # userinfo credentials
            if CRED_IN_URL_RE.search(decoded):
                res.add("URL_CREDENTIALS", Severity.HIGH,
                        "URL embeds credentials (userinfo) - suspicious", detail=host, category="malicious")
            # non-standard port
            if port and port not in (80, 443, 8080, 8443):
                res.add("URL_ODDPORT", Severity.MEDIUM,
                        f"URL uses non-standard port {port}", category="anomaly")
            # clear http (insecure transport -> easy MITM in phishing kits)
            if decoded.lower().startswith("http:"):
                res.add("URL_INSECURE", Severity.LOW,
                        "URL uses cleartext http (not TLS)", category="anomaly")
            # shortener
            if host in C.URL_SHORTENERS:
                res.add("URL_SHORTENER", Severity.MEDIUM,
                        "URL shortened by known redirector (hides destination)",
                        detail=host, category="obfuscation")
            # punycode / non-ascii
            if PUNYCODE_RE.search(host):
                res.add("URL_PUNYCODE", Severity.MEDIUM,
                        "Domino uses punycode/IDN encoding - possible homoglyph spoof", detail=host,
                        category="obfuscation")
            elif any(ord(c) > 127 for c in host):
                res.add("URL_NONASCII", Severity.MEDIUM,
                        "Domain contains non-ASCII characters (homoglyph risk)", detail=host,
                        category="obfuscation")
            # suspicious TLD
            if host.rsplit(".", 1)[-1].lower() in C.SUSPICIOUS_TLDS:
                res.add("URL_BADTLD", Severity.MEDIUM,
                        f"URL domain uses cheap/low-trust TLD .{host.rsplit('.', 1)[-1]}",
                        category="anomaly")
            # typosquatting: host base-name vs brand watchlist + top banks
            self._typosquat(res, host)
            # resolve host only if caller opts in; never return private addrs
            if resolve_hosts and not ip_lit:
                addrs = dns.secure_resolve_host(host)
                if addrs:
                    res.meta.setdefault("resolved", {})[host] = addrs
                elif dns.dns_available():
                    res.add("URL_NXDOMAIN", Severity.LOW, f"Domain does not resolve: {host}",
                            category="anomaly")

        # display/href mismatch: text 'looks like' a host that differs from href host
        for href, text in self.anchors:
            _, hh, _, _ = _normalize_url(self._deobfuscate(href))
            m = re.search(r"([a-z0-9][a-z0-9.-]+\.[a-z]{2,})", text.lower())
            shown = m.group(1) if m else ""
            shown = shown.replace("www.", "").split("/")[0]
            if shown and hh and shown not in hh and hh != shown and \
                    not hh.endswith("." + shown) and not shown.endswith("." + hh):
                res.add("TEXT_HREF_MISMATCH", Severity.HIGH,
                        f"Anchor text '{text[:40]}' hides real URL on {hh} (visible vs actual)",
                        category="malicious")

        # optional reputation (allowlisted API, TLS verify, NO arbitrary fetch)
        if reputation_key:
            self._reputation(res, reputation_key)
        return res

    # ------------------------------------------------------------------
    def _typosquat(self, res: EngineResult, host: str) -> None:
        base = host
        for tld in ("com", "net", "org", "co", "io", "info", "biz", "xyz", "app", "online"):
            suf = f".{tld}"
            if base.endswith(suf):
                base = base[: -len(suf)]
                break
        base = base.split(".")[-1] if "." in base else base
        base = base.replace("www", "")
        for brand in C.BRAND_WATCHLIST:
            if brand in base and len(base) > len(brand):
                res.add("URL_BRAND_TYPO", Severity.HIGH,
                        f"Domain '{host}' embeds brand '{brand}' in a longer name (brand-abuse typo)",
                        category="malicious")
                return
            if abs(len(base) - len(brand)) <= 1 and base and _edit_distance(base, brand, 1) <= 1:
                res.add("URL_TYPO", Severity.MEDIUM,
                        f"Domain '{host}' is one edit away from brand '{brand}' - typosquatting risk",
                        category="malicious")
                return

    def _deobfuscate(self, raw: str) -> str:
        import urllib.parse as up
        out = HTTP_ENTITY_RE.sub(":", raw)
        out = up.unquote(out)           # percent decoding
        return out

    def _reputation(self, res: EngineResult, api_key: str) -> None:
        # Request-scoped, TLS-verified, allowlisted host only (SC-7 / A10).
        import requests
        from ..sec.validation import ensure_https_host
        domain_set = set()
        for u in res.meta.get("urls", []):
            if u.get("host"):
                domain_set.add(u["host"])
        if len(domain_set) > 10:
            res.add("REP_LIMIT", Severity.INFO, "Reputation check capped at 10 hosts", category="info")
        try:
            for host in list(domain_set)[:10]:
                try:
                    ensure_https_host(host)
                except Exception:  # noqa: BLE001
                    continue
                # identify the domain-level entity: keep 2 labels
                labels = host.split(".")[-2:]
                entity = ".".join(labels)
                if len(entity) < 3:
                    continue
                r = requests.get(
                    "https://www.virustotal.com/api/v3/domains/" + entity,
                    headers={"x-apikey": api_key},
                    timeout=(3.05, 8),
                    verify=True,
                )
                if r.status_code == 200:
                    stats = r.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                    malicious = int(stats.get("malicious", 0)) + int(stats.get("suspicious", 0))
                    if malicious:
                        res.add("URL_REP_BAD", Severity.HIGH,
                                f"Reputation check: VT flags {host} ({malicious} detections)",
                                category="reputation")
                    else:
                        res.meta.setdefault("reputation", {})[host] = malicious
        except Exception:  # noqa: BLE001 - reputation is best-effort, never blocks
            res.add("REP_UNAVAILABLE", Severity.INFO,
                    "Reputation lookup unavailable (network/limit)", category="info")