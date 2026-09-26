"""Headless smoke test for the frozen .exe distribution.

Sets WELICS_PORT/WELICS_TOKEN so the URL is predictable, spawns the exe,
exercises import -> analyze -> report downloads -> shutdown, then confirms
the process exits on its own.
"""
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
DIST = os.path.join(os.path.dirname(HERE), "dist", "WELIntrusionCorrelationSuite.exe")
PORT = 18746
TOKEN = "aabbccddeeff00112233445566778899"
BASE = "http://127.0.0.1:%d/tk-%s" % (PORT, TOKEN)
DATA = os.path.join(HERE, "data", "case_guest.json")


def http(url, data=None, timeout=30):
    req = urllib.request.Request(url, data=(data.encode("utf-8") if data else None),
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.headers, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.headers, exc.read()


def wait_status(timeout=60):
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        try:
            st, hd, bd = http(BASE + "/api/status")
            if st == 200:
                return True
        except Exception as exc:
            last = exc
        time.sleep(1)
    print("BLOCKED: server never came up: %r" % (last,))
    return False


def main():
    if not os.path.exists(DIST):
        print("SKIP: %s not found" % DIST)
        return 0
    env = dict(os.environ)
    env["WELICS_PORT"] = str(PORT)
    env["WELICS_TOKEN"] = TOKEN
    proc = subprocess.Popen([DIST], env=env, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL)
    passed = 0
    checks = []

    def check(name, ok, extra=""):
        nonlocal passed
        checks.append((name, ok, ""))
        if ok:
            passed += 1
            print("PASS " + name)
        else:
            print("FAIL " + name + ("  [" + extra + "]" if extra else ""))

    try:
        check("server up", wait_status())
        if passed != 1:
            proc.terminate()
            return 1

        st, hd, bd = http(BASE + "/index.html")
        check("bundle serves index.html", st == 200 and b"WEL" in bd)
        st, hd, bd = http(BASE + "/app.js")
        check("bundle serves app.js", st == 200 and len(bd) > 10000)

        with open(DATA, "rb") as fh:
            raw = fh.read()
        req = urllib.request.Request(BASE + "/api/import", data=raw,
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            st, bd = resp.status, resp.read()
        ok = st == 200 and json.loads(bd).get("imported") == 37
        check("exe import events", ok, "st=%d bd=%r" % (st, bd[:180]) if not ok else "")

        st, hd, bd = http(BASE + "/api/analyze", "{}")
        check("exe analyze", st == 200 and json.loads(bd).get("incidents") > 30)

        st, hd, bd = http(BASE + "/api/report?type=html")
        check("exe html report", st == 200 and b"Kinetic" in bd or b"Intrusion" in bd or len(bd) > 30000)
        check("exe report security header", hd.get("Content-Security-Policy") is not None)

        st, hd, bd = http(BASE + "/api/audit")
        check("exe audit stream", st == 200 and json.loads(bd).get("stats", {}).get("entries", 0) > 0)

        st, hd, bd = http(BASE + "/api/shutdown", "{}")
        check("exe shutdown accepted", st == 200)

        rc = proc.wait(timeout=30)
        check("exe process exited", rc in (0, None))
    except Exception as exc:
        print("ERROR: %r" % exc)
        proc.terminate()

    failed = [n for n, ok, _ in checks if not ok]
    print("\n%d/%d passed" % (passed, len(checks)))
    if failed:
        print("FAILED: %s" % ", ".join(failed))
        return 1
    print("EXE SMOKE: ALL GREEN")
    return 0


if __name__ == "__main__":
    sys.exit(main())