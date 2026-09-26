"""Entry point - launch the GUI console (default) or headless demo.

Usage:
    python main.py            # GUI console
    python main.py --demo     # headless self-test (no GUI)
    python main.py --beacon   # run a standalone beacon client
"""
import argparse
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)


def run_demo():
    """End-to-end headless smoke test: listener + beacons + task + reports."""
    from src.c2logging import AuditLog, setup_logging
    from src.config import DEFAULT_PORT
    from src.listener import C2Listener
    from src.beacon import Beacon
    from src.reporting import export_all

    logger, _ = setup_logging("logs")
    audit = AuditLog("logs/audit.jsonl")

    port = DEFAULT_PORT + 9001  # avoid clashing with GUI default
    li = C2Listener(host="127.0.0.1", port=port, audit=audit, logger=logger)
    li.start()

    beacon = Beacon(beacon_id="demo-beacon-1", server_url=li.url, logger=logger, interval=1)
    beacon.run_cycle(); time.sleep(0.4); beacon.run_cycle()

    li.handle_new_task({"beacon_id": "demo-beacon-1", "task": {"name": "get-sysinfo"}})
    beacon.run_cycle()

    li.handle_new_task({"beacon_id": "demo-beacon-1", "task": {"name": "heartbeat-test"}})
    beacon.run_cycle()

    beacons = li.registry.snapshot()
    tasks = li.registry.all_tasks()
    events = audit.read_all()

    out_dir = os.path.join(HERE, "reports")
    written = export_all(beacons, events, tasks, out_dir)

    logger.info("DEMO SUMMARY: %d beacon(s), %d task(s), %d audit event(s)",
                len(beacons), len(tasks), len(events))
    for kind, paths in written.items():
        if isinstance(paths, list):
            logger.info("report [%s] OK: %s", kind, ", ".join(paths))
        else:
            logger.info("report [%s] OK: %s", kind, paths)
    li.stop()
    return 0


def run_beacon_forever():
    import argparse

    p = argparse.ArgumentParser(description="Run a standalone educational beacon client.")
    p.add_argument("--server", default="http://127.0.0.1:8080")
    p.add_argument("--id", default="standalone-beacon-1")
    p.add_argument("--interval", type=float, default=3)
    args = p.parse_args()

    from src.beacon import Beacon
    from src.c2logging import setup_logging

    logger, _ = setup_logging("logs")
    b = Beacon(beacon_id=args.id, server_url=args.server, logger=logger, interval=args.interval)
    try:
        b.run_forever()
    except KeyboardInterrupt:
        logger.info("beacon stopped")
    return 0


def main():
    parser = argparse.ArgumentParser(prog="C2StudyLab")
    parser.add_argument("--demo", action="store_true", help="headless self-test demo")
    parser.add_argument("--beacon", action="store_true", help="run standalone beacon client")
    args = parser.parse_args()

    if args.demo:
        return run_demo()
    if args.beacon:
        return run_beacon_forever()

    from src.gui import run
    run()
    return 0


if __name__ == "__main__":
    sys.exit(main())