"""Entry points: GUI (default), headless trials, scenario listing, self-test gate.

Usage:
  py main.py                              # GUI
  py main.py --list-scenarios
  py main.py --headless --scenario 03_kaminsky --seed 7 --json
  py main.py --self-test                   # CI gate (security.md section 6)
  py main.py --headless --scenario 05_defense_compare --seed 7
"""

import argparse
import json
import os
import random
import sys

PACKAGE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PACKAGE_DIR)

from resolver_lab import lab, packets  # noqa: E402
from resolver_lab.scenarios import SCENARIOS  # noqa: E402

LOG_DIR = os.path.join(PACKAGE_DIR, 'logs')


def parse_overrides(text):
    """'random_port=1,use_0x20=0' -> dict of ints."""
    out = {}
    if not text:
        return out
    for piece in text.split(','):
        piece = piece.strip()
        if not piece or '=' not in piece:
            continue
        k, v = piece.split('=', 1)
        out[k.strip()] = int(v)
    return out


def write_logs(res):
    fname = f"lab-{res.get('scenario', 'run')}-{res.get('seed', 0)}.json"
    try:
        os.makedirs(LOG_DIR, exist_ok=True)
        path = os.path.join(LOG_DIR, fname)
    except OSError:
        path = fname  # e.g. running from a read-only zipapp: log next to cwd
    with open(path, 'w', encoding='utf-8') as fh:
        json.dump(res, fh, indent=2)
    return path


def run_headless(args):
    res = lab.run_trial(args.scenario, args.seed, overrides=parse_overrides(args.overrides))
    if args.log:
        write_logs(res)
    if res.get('comparison'):
        for row in res['comparison']:
            print(f"[{row['combo']:>22}] verdict={row['verdict']:>8} "
                  f"P={row['race'].get('prob', 0):.6f} attempts={row['race'].get('attempts', 0)}")
        return
    print(f"scenario={res['scenario']} seed={res['seed']} verdict={res['verdict']}")
    print(f"  victim : {res['victim']}  got={res.get('got')} expected={res.get('expected')}")
    print(f"  race   : win={res['race'].get('win')} p={res['race'].get('prob', 0):.6f} "
          f"bits={res['race'].get('entropy_bits', 0)}")
    if res.get('labels_tried'):
        print(f"  kaminsky: labels tried={res['labels_tried']} hit={res.get('deleg_hit')}")
    print(f"  forged entries={len(res.get('forged', []))} tripwire={res.get('tripwire', 0)} "
          f"packets={res.get('packets_total', 0)}")
    if res.get('forged'):
        for row in res['forged'][:20]:
            print(f"    FORGED {row['name']} {row['rdata']} kind={row['kind']}")
    if args.json:
        print(json.dumps(res, indent=2))


def run_selftest():
    checks = []

    results, _ = lab.run_legit_check(seed=3)
    ok = all(invariant for _, _, invariant in results.values())
    checks.append(('legitimacy invariant (defenses ON, no attacker -> truth zone)', ok))

    bad = None
    for _ in range(4000):
        blob = os.urandom(random.randint(0, 512))
        try:
            packets.DnsMessage.parse(blob)
        except packets.DnsError:
            pass
        except Exception as exc:  # any other exception is a parser bug
            bad = repr(exc)
            break
    checks.append((f'parser robustness vs 4000 malformed blobs {bad or ""}', bad is None))

    r1 = lab.run_trial('01_static_id', 7)
    checks.append(('01 static-id spoofing -> poisoned', r1['verdict'] == 'poisoned'))

    r2 = lab.run_trial('04_bailiwick', 7, {'bailiwick_check': False})
    checks.append(('04 bailiwick OFF -> poisoned', r2['verdict'] == 'poisoned'))

    r2b = lab.run_trial('04_bailiwick', 7, {'bailiwick_check': True})
    checks.append(('04 bailiwick ON  -> blocked', r2b['verdict'] == 'blocked'))

    r3 = lab.run_trial('03_kaminsky', 7)
    checks.append(('03 kaminsky (static id) -> poisoned', r3['verdict'] == 'poisoned'))

    r3b = lab.run_trial('03_kaminsky', 7,
                        {'random_id': True, 'random_port': True, 'use_0x20': True})
    checks.append(('03 kaminsky with entropy -> blocked', r3b['verdict'] == 'blocked'))

    trip = all(x['tripwire'] == 0 for x in (r1, r2, r2b, r3, r3b))
    checks.append(('safety tripwire: zero out-of-prefix packets in all trials', trip))

    width = max(len(name) for name, _ in checks)
    print('=' * (width + 12))
    for name, ok in checks:
        print(f"{'PASS' if ok else 'FAIL'}  {name:<{width}}")
    print('=' * (width + 12))
    return all(ok for _, ok in checks)


def run_gui():
    from resolver_lab.gui import LabGUI
    import tkinter as tk
    root = tk.Tk()
    LabGUI(root)
    root.mainloop()


def main(argv=None):
    ap = argparse.ArgumentParser(description='DNS resolver + cache poisoning lab (isolated sim)')
    ap.add_argument('--headless', action='store_true', help='run a single scenario, no GUI')
    ap.add_argument('--scenario', default='03_kaminsky', choices=list(SCENARIOS),
                    help='scenario id')
    ap.add_argument('--seed', type=int, default=1337)
    ap.add_argument('--overrides', default='',
                    help="e.g. 'random_port=1,use_0x20=1,bailiwick_check=1,ttl_floor=0,random_id=1'")
    ap.add_argument('--json', action='store_true', help='print full JSON result')
    ap.add_argument('--log', action='store_true', help='write result JSON to logs/')
    ap.add_argument('--list-scenarios', action='store_true')
    ap.add_argument('--self-test', action='store_true', help='run the CI security gate')
    args = ap.parse_args(argv)

    if args.list_scenarios:
        for sid, s in SCENARIOS.items():
            print(f'{sid}  {s["title"]}')
            print(f'     {s.get("describe", "")}')
        return 0
    if args.self_test:
        return 0 if run_selftest() else 1
    if args.headless:
        run_headless(args)
        return 0
    run_gui()
    return 0


if __name__ == '__main__':
    sys.exit(main())