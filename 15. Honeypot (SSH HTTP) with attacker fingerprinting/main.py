"""Honeypot main — start SSH + HTTP doors, export sessions, self-test mode.

Usage:
    py main.py --state data --run-once        # run doors then exit after N attrs
    py main.py --self-test                    # in-proc sim of attacker
"""
from __future__ import annotations

import argparse
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
os.chdir(Path(__file__).resolve().parent)

from honeypot.doors.http import HttpDoor, HttpSimulator
from honeypot.doors.ssh import SshDoor, SshSimulator
from honeypot.export.events import EventExporter


def self_test(host: str = "127.0.0.1") -> int:
    ssh_door = SshDoor(2222, honeytokens=["admin", "root-hun"])
    http_door_out = HttpDoor(8080)
    ssh_door.start()
    http_door_out.start()

    sim = SshSimulator(host, 2222)
    reps = sim.attempt(["root", "admin", "postgres", "ubuntu", "demo", "admin"])
    assert any("login_ok" in r for r in reps), "honeytoken login failed"
    assert any("uid=0(root)" in r for r in reps), "cmd loop not executed"

    hsim = HttpSimulator(host, 8080)
    out = hsim.probe(["/", "/.env", "/.git/config", "/admin"])
    assert any(p == "/.env" and s == 200 for p, s, _ in out), "http probe failed"

    # fingerprint assertions
    from honeypot.engine.fingerprint import attribute
    sessions = ssh_door.sessions
    if sessions:
        attr = attribute(sessions[-1])
        print("attribution:", attr["tool_scores"], "os:", attr["os_guess"])
        assert sessions[-1].signals, "no signals captured"

    print(f"PASS self-test  (ssh sessions={len(ssh_door.sessions)}, http sessions={len(http_door_out.sessions)})")
    try:
        ssh_door._sock.close()
    except Exception:
        pass
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--state", default="data")
    ap.add_argument("--run-once", action="store_true", help="serve one short window then exit")
    ap.add_argument("--forever", action="store_true", help="serve until Ctrl-C")
    ap.add_argument("--demo", action="store_true", help="fire a simulated attacker on boot")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()

    if args.self_test:
        return self_test()

    state = Path(args.state)
    exporter = EventExporter(state)
    ssh_door = SshDoor(2222, honeytokens=["admin", "root-hun"])
    http_door = HttpDoor(8080)
    try:
        ssh_door.start()
        http_door.start()
    except OSError as exc:
        print(f"[honeypot] FATAL cannot bind doors: {exc}\n"
              f"  Is another honeypot instance already running? Close it and retry.",
              file=sys.stderr)
        return 1
    print("[honeypot] ssh :2222  http :8080  (Ctrl-C to stop)")

    # By default run a short bounded demo (fires a simulated attacker so
    # there is visible output); --run-once tightens it, --forever serves
    # until Ctrl-C.
    demo = args.demo or not args.forever
    if demo:
        import threading

        def _sim():
            import time
            time.sleep(2.0)
            rep = SshSimulator("127.0.0.1", 2222).attempt(["root", "admin", "ubuntu", "admin"])
            print(f"  [demo] simulated SSH attacker -> {len([r for r in rep if 'login_ok' in r])} honeytoken hits")
            HttpSimulator("127.0.0.1", 8080).probe(["/", "/.env", "/.git/config", "/admin"])

        threading.Thread(target=_sim, daemon=True).start()
        print("  [demo] firing simulated attacker in 2s...")

    if args.forever:
        deadline = float("inf")
    elif args.run_once:
        deadline = time.time() + 20
    else:
        deadline = time.time() + 60
    try:
        while time.time() < deadline:
            time.sleep(2)
    except KeyboardInterrupt:
        pass

    for s in list(ssh_door.sessions) + list(http_door.sessions):
        exporter.export(s)
    exporter.close()
    print(f"[honeypot] exported {len(ssh_door.sessions) + len(http_door.sessions)} sessions")
    return 0


def _pause_on_windows() -> None:
    if (os.name == "nt" and not os.environ.get("TI_NO_PAUSE")
            and sys.stdin and sys.stdin.isatty()):
        input("\nPress Enter to exit...")


if __name__ == "__main__":
    try:
        _rc = main()
    except KeyboardInterrupt:
        _rc = 130
    finally:
        _pause_on_windows()
    raise SystemExit(_rc)