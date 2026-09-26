"""Standalone beacon entry point - builds the portable beacon.exe.

Usage: C2StudyLab_Beacon.exe --server http://127.0.0.1:8080 --id lab-1
"""
import argparse
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)


def main():
    p = argparse.ArgumentParser(description="C2 Study Lab - standalone educational beacon client")
    p.add_argument("--server", default="http://127.0.0.1:8080", help="listener base URL")
    p.add_argument("--id", default="beacon-exe-1", help="beacon identifier")
    p.add_argument("--interval", type=float, default=3, help="check-in interval (seconds)")
    p.add_argument("--once", action="store_true", help="check in once and exit")
    args = p.parse_args()

    from src.beacon import Beacon
    from src.c2logging import setup_logging

    logger, _ = setup_logging("logs")
    beacon = Beacon(beacon_id=args.id, server_url=args.server, logger=logger, interval=args.interval)
    if args.once:
        beacon.run_cycle()
        logger.info("single check-in complete")
        return 0
    try:
        beacon.run_forever()
    except KeyboardInterrupt:
        logger.info("beacon stopped by operator")
    return 0


if __name__ == "__main__":
    sys.exit(main())