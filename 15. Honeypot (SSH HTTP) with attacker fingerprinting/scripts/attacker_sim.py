"""Attacker replay simulator — drives the SSH door with tool-like patterns.

Usage:
    py scripts/attacker_sim.py <host> <port>
"""
from __future__ import annotations

import sys
sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parent.parent))
from honeypot.doors.ssh import SshSimulator


def main() -> int:
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2] if len(sys.argv) > 2 else 2222)
    sim = SshSimulator(host, port)
    print(f"simulating hydra-like SSH brute-force at {host}:{port}")
    reps = sim.attempt(["root", "admin", "postgres", "ubuntu", "demo", "admin"])
    print("\n".join(reps[:12]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())