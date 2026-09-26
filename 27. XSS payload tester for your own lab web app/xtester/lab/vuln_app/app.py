"""DELIBERATELY VULNERABLE lab application (XSS only).

Running this app against anything other than your own isolated lab is
dangerous. It is intentionally NOT production-security-hardened: it
reflects user input in raw HTML, attribute, JS, URL and DOM contexts.

Scope of use: this exact container is meant to run in a private Docker
network and be scanned BY xtester (which is itself allow-listed to lab
hosts). Keep it unreachable from the public internet.

Reference vectors mirror OWASP XSS cheat-sheet contexts.
"""

import html
import os

from flask import Flask, request

app = Flask(__name__)

# Admin-only flag so production of your labs isn't left open by accident.
if not os.environ.get("VULN_LAB_ALLOW", "1") == "1":
    raise SystemExit("VULN_LAB_ALLOW != 1; refusing to start the vulnerable lab")


def _inject():
    return request.args.get("name", request.args.get("q", "lab"))


# --------------------------------------------------------------------------- vulnerable contexts
@app.route("/html")
def vuln_html():
    return f"""<!DOCTYPE html><html><body>
    <h1>HTML context (vulnerable)</h1>
    <div id="probe">Hello {_inject()}</div>
    </body></html>"""


@app.route("/attr")
def vuln_attr():
    return f"""<!DOCTYPE html><html><body>
    <h1>Attribute context (vulnerable)</h1>
    <input id="probe" value="{_inject()}">
    </body></html>"""


@app.route("/js")
def vuln_js():
    return f"""<!DOCTYPE html><html><body>
    <h1>Script context (vulnerable)</h1>
    <script>var probe = '{_inject()}';</script>
    </body></html>"""


@app.route("/url")
def vuln_url():
    return f"""<!DOCTYPE html><html><body>
    <h1>URL context (vulnerable)</h1>
    <a id="probe" href="{_inject()}">next</a>
    </body></html>"""


@app.route("/dom")
def vuln_dom():
    return """<!DOCTYPE html><html><body>
    <h1>DOM sink (vulnerable)</h1>
    <div id="probe"></div>
    <script>
      var data = window.location.hash.slice(1);
      document.getElementById('probe').innerHTML = data;
    </script>
    </body></html>"""


# --------------------------------------------------------------------------- safe reference points
@app.route("/secure/html")
def safe_html():
    return f"""<!DOCTYPE html><html><body>
    <h1>HTML context (safe)</h1>
    <div id="probe">Hello {html.escape(_inject())}</div>
    </body></html>"""


@app.route("/secure/attr")
def safe_attr():
    return f"""<!DOCTYPE html><html><body>
    <h1>Attribute context (safe)</h1>
    <input id="probe" value="{html.escape(_inject())}">
    </body></html>"""


@app.route("/")
def index():
    return """<!DOCTYPE html><html><body>
    <h1>Vulnerable Lab App</h1>
    <p>Query builders to test with (they are intentionally unsafe):</p>
    <ul>
      <li><a href="/html?name=test">/html?name=...</a></li>
      <li><a href="/attr?name=test">/attr?name=...</a></li>
      <li><a href="/js?name=test">/js?name=...</a></li>
      <li><a href="/url?name=test">/url?name=...</a></li>
      <li><a href="/dom#test">/dom#...</a> (DOM sink, uses fragment)</li>
      <li><a href="/secure/html?name=test">/secure/html</a> (safe reference)</li>
    </ul>
    <p style="color:#944">This application is for authorized lab testing only.</p>
    </body></html>"""


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001)