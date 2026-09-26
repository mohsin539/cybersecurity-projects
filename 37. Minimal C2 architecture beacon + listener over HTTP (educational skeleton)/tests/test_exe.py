"""Launch the built portable beacon.exe against a live listener."""
import subprocess
import sys
import time

sys.path.insert(0, ".")

from src.c2logging import AuditLog
from src.listener import C2Listener

audit = AuditLog("logs/audit.jsonl")
li = C2Listener(host="127.0.0.1", port=18097, audit=audit)
li.start()
time.sleep(0.3)

exe = "dist/C2StudyLab_Beacon.exe"
proc = subprocess.run(
    [exe, "--server", "http://127.0.0.1:18097", "--id", "exe-beacon-1", "--once"],
    capture_output=True, text=True, timeout=40,
)
print("exit:", proc.returncode)
print((proc.stdout or "")[-300:])
print((proc.stderr or "")[-300:])
beacons = li.registry.snapshot()
ok = proc.returncode == 0 and any(b.get("beacon_id") == "exe-beacon-1" for b in beacons)
print("PORTABLE EXE TEST:", "PASS" if ok else "FAIL")
li.stop()