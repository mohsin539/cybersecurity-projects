"""XSS Payload Tester - discovery (same-host crawl + parameter extraction)."""
from __future__ import annotations

from html.parser import HTMLParser
from typing import Dict, List, Tuple
from urllib.parse import urljoin, urlparse, parse_qsl

from .http_client import Session
from .models import Endpoint, Parameter


class _LinkParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: List[str] = []
        self.forms: List[Tuple[str, List[str]]] = []

    def handle_starttag(self, tag: str, attrs) -> None:
        attrs = dict(attrs)
        if tag == "a" and attrs.get("href"):
            self.links.append(attrs["href"])
        if tag == "form":
            self.forms.append((attrs.get("action") or "", attrs.get("method") or "GET", []))
        if tag in ("input", "textarea", "select") and self.forms:
            name = attrs.get("name") or attrs.get("id") or ""
            if name and name not in self.forms[-1][-1]:
                self.forms[-1][-1].append(name)


def _page_q(url: str) -> Dict[str, str]:
    return dict(parse_qsl(urlparse(url).query, keep_blank_values=True))


class Discovery:
    def __init__(self, session: Session, max_pages: int = 10) -> None:
        self.session = session
        self.max_pages = max_pages

    def crawl(self, seed: str) -> Tuple[List[Endpoint], int]:
        host = urlparse(seed).netloc
        queue = [seed]
        seen_urls = set()
        visited: List[str] = []
        endpoints: List[Endpoint] = []

        while queue and len(visited) < self.max_pages:
            url = queue.pop(0)
            if url in seen_urls:
                continue
            seen_urls.add(url)
            if urlparse(url).netloc != host:
                continue
            visited.append(url)

            status, body, _, _ = self.session.get(url)
            if status is None or status >= 400:
                continue

            parser = _LinkParser()
            try:
                parser.feed(body or "")
            except Exception:
                pass
            parser.close()

            for link in parser.links:
                nxt = urljoin(url, link)
                np_ = urlparse(nxt)
                if np_.netloc == host and np_.scheme in ("http", "https") and nxt not in seen_urls:
                    queue.append(nxt)

            page_params = _page_q(url)
            if page_params:
                endpoints.append(self._endpoint("GET", url, page_params))

            for action, method, names in parser.forms:
                if not names:
                    continue
                form_url = urljoin(url, action) if action else url
                form_params = {n: page_params.get(n, "") for n in names}
                method = method.upper()
                if method not in ("GET", "POST"):
                    method = "GET"
                endpoints.append(self._endpoint(method, form_url, form_params))

        return _dedupe_endpoints(endpoints), len(visited)

    @staticmethod
    def _endpoint(method: str, url: str, params: Dict[str, str]) -> Endpoint:
        loc = "query" if method == "GET" else "body"
        return Endpoint(
            method=method,
            url=url,
            params=[Parameter(name=k, location=loc, value=v) for k, v in params.items()],
        )


def _dedupe_endpoints(endpoints: List[Endpoint]) -> List[Endpoint]:
    seen: Dict[Tuple[str, str], Endpoint] = {}
    for ep in endpoints:
        key = (ep.method, ep.url)
        prev = seen.get(key)
        if prev is None:
            seen[key] = Endpoint(method=ep.method, url=ep.url, params=list(ep.params), content_type=ep.content_type)
            continue
        for p in ep.params:
            if not any(p2.name == p.name for p2 in prev.params):
                prev.params.append(p)
    return list(seen.values())