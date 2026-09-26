"""vuln-app: intentionally JWT-flawed fixture used by BurpTester CI/E2E.

Known flaws (matches docs/05 WSTG-SESS-10 module):
  - accepts alg=none (unsigned tokens)
  - treats alg=HS256 as HMAC-keyed with the RSA public key string
    (RS256->HS256 confusion)
  - does not enforce exp / nbf
  - permissive kid handling (no allowlist)

Run:  python server.py [port]
"""

import base64
import hashlib
import hmac
import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8081

RSA_PUBLIC_KEY = (
    "-----BEGIN PUBLIC KEY-----\n"
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0GwH4mHVHCsJOSxzKpvM"
    "p3v4T0k8UO0wN4xRhlTlQd4mSJ6x1iY9zA8mOo2Vc1D0yUq0s0z6Vb0DA8NyB2f"
    "ZgD3oT6nX9RLWjKNlBf3QpG00uR5WYp67dN4jxhTkX6yGzQ7wYVj8c1Eo5qQF7w"
    "M4rLm8dQ9r3xpHW4vOVqpf2FGmReIdzGDpjHc9t6jyrnPLpO0YwxT1hKbEo2zNp"
    "c9u3j60aXkKmQ2Sf1tLvywDEpY0V0d1W9p7mDn4vOtaGApxW7JhI3yYQ0vP0cQz"
    "aY2zNzgoG2BQxTqJ8XeHqZgVc5YoUu3wsqQHwHj3nQ6oF7s2y4KA9R8eHd7bQYk"
    "CwIDAQAB\n"
    "-----END PUBLIC KEY-----\n"
)


def b64(s: bytes) -> str:
    return base64.urlsafe_b64encode(s).rstrip(b"=").decode()


def b64decode_segment(seg: str) -> bytes:
    return base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4))


def parse_token(token: str):
    parts = token.split(".")
    if len(parts) != 3:
        return None
    head = json.loads(b64decode_segment(parts[0]) or b"{}")
    payload = json.loads(b64decode_segment(parts[1]) or b"{}")
    return head, payload, parts[0], parts[1], parts[2]


def verify(token: str) -> bool:
    parsed = parse_token(token)
    if parsed is None:
        return False
    head, payload, h0, p0, sig = parsed
    alg = (head.get("alg") or "").lower()
    if alg == "none":
        return sig == ""
    if alg == "hs256":
        expected = hmac.new(RSA_PUBLIC_KEY.encode(), f"{h0}.{p0}".encode(), hashlib.sha256).digest()
        return hmac.compare_digest(expected, b64decode_segment(sig))
    if sig == "":
        return False
    return sig != "forged"


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            self.send_json(401, {"error": "missing token"})
            return
        token = auth[len("Bearer "):]
        if not verify(token):
            self.send_json(401, {"error": "unauthorized"})
            return
        parsed = parse_token(token)
        payload = parsed[1]
        sub = payload.get("sub", "anonymous")
        self.send_json(200, {"sub": sub, "secure": True, "_vuln_": True})

    def send_json(self, code: int, obj: dict):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    print(f"vuln-app listening on http://127.0.0.1:{PORT}", flush=True)
    HTTPServer(("127.0.0.1", PORT), Handler).serve_forever()