import argparse
import webbrowser

import uvicorn

from app.config import PORT, REPORTS_DIR
from app.core.security import ensure_admin_token, ensure_lab_certs

BANNER = r"""
  ==============================================================================
  |   C2 DECONFLICTION LAB  -  BLUE TEAM CONSOLE  (authorized lab ONLY)        |
  |                                                                            |
  |   TLS-wrapped beacon (T1071.001 / T1573.001)  +  traffic decryption        |
  |   OWASP Top 10 . NIST CSF . ISO 27001 . Reports: .xlsx .csv .html          |
  ==============================================================================
"""


def main():
    print(BANNER)
    p = argparse.ArgumentParser(description="C2 Deconfliction Lab — launch console")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=PORT)
    p.add_argument("--https", action="store_true", help="serve over TLS 1.3 with self-signed lab cert")
    p.add_argument("--seed", action="store_true", help="seed realistic demo evidence before launch")
    p.add_argument("--open", action="store_true", help="open the console in the default browser")
    args = p.parse_args()

    if args.seed:
        from tools.demo_seed import seed
        seed()

    token = ensure_admin_token()
    scheme = "https" if args.https else "http"
    if args.https:
        cert, key = ensure_lab_certs()
        print(f"[tls-1.3] cert={cert}  key={key}  (self-signed lab CA, import to trust)")
    url = f"{scheme}://{args.host}:{args.port}"
    print("=" * 70)
    print("  C2 Deconfliction Lab — Blue Team Console")
    print(f"  URL           {url}")
    print(f"  Admin token   {token}")
    print(f"  Evidence out  {REPORTS_DIR}")
    print("  Toggle auth   X-Lab-Token header on /api/panel, /api/blue, /api/reports, /api/admin")
    print("=" * 70)
    if args.open:
        webbrowser.open(url)
    ssl_kwargs = {}
    if args.https:
        cert, key = ensure_lab_certs()
        ssl_kwargs = {"ssl_keyfile": str(key), "ssl_certfile": str(cert)}
    uvicorn.run("app.main:app", host=args.host, port=args.port, log_level="warning", **ssl_kwargs)


if __name__ == "__main__":
    main()