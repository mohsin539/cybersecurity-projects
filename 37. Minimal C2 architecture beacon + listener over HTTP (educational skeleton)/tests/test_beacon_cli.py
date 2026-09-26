"""Verify standalone beacon CLI works over HTTP against a running listener."""
import subprocess
import sys
import time

sys.path.insert(0, ".")

from src.c2logging import AuditLog
from src.listener import C2Listener

audit = AuditLog("logs/audit.jsonl")
li = C2Listener(host="127.0.0.1", port=18098, audit=audit)
li.start()
time.sleep(0.3)

proc = subprocess.run(
    [sys.executable, "beacon_entry.py", "--server", "http://127.0.0.1:18098",
     "--id", "cli-beacon-1", "--once"],
    capture_output=True, text=True, timeout=30,
)
print("exit:", proc.returncode)
print(proc.stdout.strip())
beacons = li.registry.snapshot()
print("registered beacons:", [b.get("beacon_id") for b in beacons])
print("CLI BEACON TEST:", "PASS" if proc.returncode == 0 and any(
    b.get("beacon_id") == "cli-beacon-1" for b in beacons) else "FAIL")
li.stop()