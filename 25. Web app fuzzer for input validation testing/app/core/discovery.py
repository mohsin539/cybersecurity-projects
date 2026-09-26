"""Web App Fuzzer - target discovery (crawl links/forms, extract parameters)."""
from __future__ import annotations

import html.parser
import re
import urllib.parse
from typing import Dict, List, Optional, Set, Tuple

from .models import Endpoint, Parameter

_FORM_TAG = "form"
_INPUT_TAG = "input"
_SELECT_TAG = "select"
_TEXTAREA_TAG = "textarea"
_A_TAG = "a"


class _FormParser(html.parser.HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.forms: List[Dict[str, object]] = []
        self._current: Optional[Dict[str, object]] = None

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        ad = {k.lower(): (v or "") for k, v in attrs}
        if tag == _FORM_TAG:
            self._current = {"action": ad.get("action", ""), "method": (ad.get("method", "get") or "get").lower(), "inputs": []}
            self.forms.append(self._current)
        elif self._current is not None and tag in (_INPUT_TAG, _SELECT_TAG, _TEXTAREA_TAG):
            name = ad.get("name", "")
            if name:
                self._current["inputs"].append({"name": name, "value": ad.get("value", "")})

    def handle_startendtag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        self.handle_starttag(tag, attrs)


def _extract_links(body: str, base: str) -> List[str]:
    out: List[str] = []
    for m in re.finditer(r"""\b(?:href|src|action)\s*=\s*["']([^"']+)["']""", body, re.I):
        url = urllib.parse.urljoin(base, m.group(1))
        if url.startswith(("http://", "https://")):
            out.append(url)
    return out


def _extract_query_params(url: str) -> List[Parameter]:
    parsed = urllib.parse.urlparse(url)
    return [
        Parameter(name=k, location="query", value=v, source="url")
        for k, v in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    ]


class Discovery:
    """Build a list of endpoints (GET query params + POST forms) from a seed URL."""

    def __init__(self, session, max_pages: int = 20, same_host_only: bool = True) -> None:
        self._session = session
        self._max_pages = max_pages
        self._same_host_only = same_host_only

    def crawl(self, seed: str, base_html: Optional[str] = None) -> Tuple[List[Endpoint], List[str]]:
        seen: Set[str] = set()
        queue: List[str] = [seed]
        endpoints: List[Endpoint] = []
        seed_host = urllib.parse.urlparse(seed).netloc

        while queue and len(seen) < self._max_pages:
            url = queue.pop(0)
            if url in seen:
                continue
            seen.add(url)

            body = ""
            if base_html is not None and url == seed:
                body = base_html
            else:
                try:
                    status, resp_body, _headers, _dt = self._session.get(url)
                    if status and 200 <= status < 400 and resp_body:
                        body = resp_body
                except Exception:
                    continue

            qparams = _extract_query_params(url)
            if qparams or body:
                endpoints.append(Endpoint(method="GET", url=url, params=qparams))

            parser = _FormParser()
            try:
                parser.feed(body)
            except Exception:
                parser.close()

            for form in parser.forms:
                action = str(form["action"])
                form_url = urllib.parse.urljoin(url, action) if action else url
                m = str(form["method"]).lower()
                inputs = [Parameter(name=str(i["name"]), location="form", value=str(i["value"]), source="form") for i in form["inputs"]]
                endpoints.append(Endpoint(method=m, url=form_url, params=inputs, content_type="application/x-www-form-urlencoded"))

            for link in _extract_links(body, url):
                if link in seen:
                    continue
                if self._same_host_only and urllib.parse.urlparse(link).netloc != seed_host:
                    continue
                queue.append(link)

        return endpoints, list(seen)