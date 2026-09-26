"""XSS Payload Tester - minimal HTTP client (stdlib only) with scope control."""
from __future__ import annotations

import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from http.cookiejar import CookieJar
from typing import Dict, List, Optional, Tuple

_DEFAULT_TIMEOUT = 15
_DEFAULT_UA = "XssTester/1.0 (+security-testing-tool; authorized lab use only)"


class Session:
    """Feature-light HTTP session with cookie jar, proxy, timeouts and scope."""

    def __init__(
        self,
        user_agent: str = _DEFAULT_UA,
        timeout: int = _DEFAULT_TIMEOUT,
        verify_tls: bool = True,
        proxy: Optional[str] = None,
        cookies: Optional[Dict[str, str]] = None,
        extra_headers: Optional[Dict[str, str]] = None,
    ) -> None:
        self.user_agent = user_agent
        self.timeout = timeout
        self.verify_tls = verify_tls
        self.cookies: Dict[str, str] = dict(cookies or {})
        self.headers = dict(extra_headers or {})
        self.proxy = proxy

        handlers: List[urllib.request.BaseHandler] = []
        if proxy:
            handlers.append(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
        self._ssl_ctx = None
        if not verify_tls:
            self._ssl_ctx = ssl.create_default_context()
            self._ssl_ctx.check_hostname = False
            self._ssl_ctx.verify_mode = ssl.CERT_NONE
            handlers.append(urllib.request.HTTPSHandler(context=self._ssl_ctx))
        self._opener = urllib.request.build_opener(*handlers)

    def request(
        self,
        method: str,
        url: str,
        params: Optional[Dict[str, str]] = None,
        data: Optional[Dict[str, str]] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> Tuple[Optional[int], str, Dict[str, str], float]:
        method = (method or "GET").upper()
        if method == "GET" and params:
            url = _merge_query(url, params)
        body = None
        if method == "POST" and data is not None:
            body = urllib.parse.urlencode(data).encode("utf-8")

        req_headers = dict(self.headers)
        req_headers.setdefault("User-Agent", self.user_agent)
        if headers:
            req_headers.update(headers)
        if self.cookies:
            req_headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
        if body is not None and "Content-Type" not in {h.lower() for h in req_headers}:
            req_headers["Content-Type"] = "application/x-www-form-urlencoded"

        req = urllib.request.Request(url, data=body, headers=req_headers, method=method)

        start = time.time()
        try:
            with self._opener.open(req, timeout=self.timeout) as resp:
                status = resp.getcode()
                resp_headers = {k: v for k, v in resp.getheaders()}
                content = resp.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            resp_headers = {k: v for k, v in exc.headers.items()} if exc.headers else {}
            try:
                content = exc.read().decode("utf-8", errors="replace")
            except OSError:
                content = ""
            status = exc.code
        except (urllib.error.URLError, OSError, ValueError, ssl.SSLError) as exc:
            return None, f"ERROR: {type(exc).__name__}: {exc}", {}, time.time() - start
        return status, content, resp_headers, time.time() - start

    def get(self, url: str, params: Optional[Dict[str, str]] = None, headers: Optional[Dict[str, str]] = None):
        return self.request("GET", url, params=params, headers=headers)

    def post(self, url: str, data: Optional[Dict[str, str]] = None, headers: Optional[Dict[str, str]] = None):
        return self.request("POST", url, params=None, data=data, headers=headers)


def _merge_query(url: str, params: Dict[str, str]) -> str:
    parsed = urllib.parse.urlparse(url)
    merged = dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))
    merged.update(params)
    new_q = urllib.parse.urlencode(merged)
    return urllib.parse.urlunparse(parsed._replace(query=new_q))