#!/usr/bin/env python3
"""Entry point — packet sniffer GUI.

Run:
  Windows :  py packet_sniffer_gui.py        (from an Administrator terminal)
  Linux   :  sudo python3 packet_sniffer_gui.py

A demo mode with synthetic traffic is available for testing without admin:
  py packet_sniffer_gui.py --demo
"""
from __future__ import annotations

import sys


def main() -> int:
    if "--demo" in sys.argv:
        from demo import run_demo
        run_demo()
        return 0
    from gui import run
    run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
