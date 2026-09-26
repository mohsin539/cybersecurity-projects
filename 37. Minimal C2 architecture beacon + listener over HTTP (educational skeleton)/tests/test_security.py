"""Security behavior self-test - verifies auth, rate limiting, auditing work."""
import json
import sys
import time
import urllib.error
import urllib.request

sys.path.insert(0, ".")

from src.c2logging import AuditLog
from src.crypto import PayloadCrypto
from src.listener import C2Listener

PORT = 18099
BASE = f"http://127.0.0.1:{PORT}"

crypto = PayloadCrypto()


def envelope(body: dict) -> bytes:
    return json.dumps({"payload": crypto.encrypt(json.dumps(body, default=str))}).encode("utf-8")


audit = AuditLog("logs/audit.jsonl")
li = C2Listener(host="127.0.0.1", port=PORT, audit=audit)
li.start()
time.sleep(0.2)


def req(path, token=None, body=None, raw=False):
    data = envelope(body) if body and not raw else (json.dumps(body).encode() if body else None)
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if body:
        headers["Content-Type"] = "application/json"
    r = urllib.request.Request(BASE + path, data=data, headers=headers,
                               method="POST" if body else "GET")
    try:
        with urllib.request.urlopen(r, timeout=5) as resp:
            return resp.status
    except urllib.error.HTTPError as e:
        return e.code


results = []
results.append(("health no-auth       ", req("/api/v1/health")))
results.append(("checkin BAD token    ", req("/api/v1/checkin", "WRONG",
                                             {"beacon_id": "x", "meta": {}})))
results.append(("console WRONG token  ", req("/api/v1/beacons", "WRONG")))
results.append(("task w/ BEACON token ", req("/api/v1/task", "lab-beacon-token-0001",
                                             {"beacon_id": "x", "task": {"name": "get-timestamp"}})))
results.append(("checkin plaintext    ", req("/api/v1/checkin", "lab-beacon-token-0001",
                                             {"beacon_id": "x", "meta": {}}, raw=True)))
results.append(("beacon checkin GOOD  ", req("/api/v1/checkin", "lab-beacon-token-0001",
                                             {"beacon_id": "sec-test-1", "meta": {"x": 1}})))
results.append(("unknown route        ", req("/api/v1/nope", "lab-console-token-0001")))

fail_count = sum(1 for e in audit.read_all() if e["event"] == "auth.failure")
good = dict(results).get("beacon checkin GOOD  ")
print()
for name, code in results:
    print(f"{name} -> HTTP {code}")
print()
print("auth.failure events recorded:", fail_count)
ok = (good == 200 and fail_count >= 2
      and dict(results)["checkin BAD token    "] == 401
      and dict(results)["unknown route        "] == 404)
print("SECURITY SELF-TEST:", "PASS" if ok else "FAIL")
li.stop()