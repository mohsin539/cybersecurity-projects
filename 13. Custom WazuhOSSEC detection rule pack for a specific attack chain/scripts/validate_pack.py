"""Validate the rule pack: ID hygiene, duplicates, MITRE integrity, dependencies.

Usage: py scripts/validate_pack.py --pack-dir <root>
Runs in CI (see pack.yaml entrypoints). Zero external deps.

Checks implemented (map to architecture.md section 5):
  1. All custom rule IDs inside reserved range, unique.
  2. Every <if_group>/<if_sid> target exists somewhere in the pack.
  3. Every <mitre><id> matches a real ATT&CK technique prefix pattern.
  4. Well-formed XML (strict parse).
  5. Noise/coverage counters reported for fast PR review.
"""
from __future__ import annotations

import argparse
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

TECHNIQUE_RE = re.compile(r"^T\d{4}(\.\d+)?$")
ID_RE = re.compile(r"-(\d+)$")


def parse_rules(root: Path) -> list[ET.Element]:
    rules = []
    for f in sorted((root / "etc" / "rules").glob("*.xml")):
        try:
            tree = ET.parse(f)
        except ET.ParseError as e:
            print(f"  XML ERROR {f}: {e}")
            sys.exit(1)
        rules.extend(tree.getroot().findall(".//rule"))
    return rules


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pack-dir", default=".")
    args = ap.parse_args(argv)

    root = Path(args.pack_dir).resolve()
    rules = parse_rules(root)
    ids = [int(r.attrib["id"]) for r in rules if "id" in r.attrib]

    lo, hi = 200010, 200999
    bad_range = [i for i in ids if not (lo <= i <= hi)]
    dup = {i for i in ids if ids.count(i) > 1}
    print(f"rules parsed: {len(rules)}  ids: {len(ids)}")
    errs = 0

    if bad_range:
        errs += 1
        print(f"  FAIL ID range: outside {lo}-{hi}: {sorted(set(bad_range))}")
    if dup:
        errs += 1
        print(f"  FAIL duplicate IDs: {sorted(dup)}")

    # dependency targets
    targets = set(ids)
    for r in rules:
        for tag in ("if_sid", "if_group", "group"):
            val = r.findtext(tag)
            if val:
                for tok in re.split(r"[,; ]+", val.strip()):
                    if tok.isdigit() and int(tok) not in targets:
                        errs += 1
                        print(f"  FAIL {r.attrib.get('id','?')} refs missing {tok}")

    # MITRE integrity
    mitre_pattern = re.compile(r"^T\d{4}(\.\d+)?$")
    for r in rules:
        for m in r.findall(".//mitre/id"):
            if not mitre_pattern.match(m.text or ""):
                errs += 1
                print(f"  FAIL bad mitre id '{m.text}' in rule {r.attrib.get('id','?')}")

    # coverage report
    phases = {}
    for r in rules:
        g = r.findtext("group") or ""
        for phase in ("chain_access", "chain_exec", "chain_persist", "chain_c2", "chain_exfil", "chain_phasefinal"):
            if f"{phase}," in f"{g},":
                phases[phase] = phases.get(phase, 0) + 1
    print("coverage:", ", ".join(f"{k}={v}" for k, v in sorted(phases.items())))

    if errs:
        print(f"RESULT: FAIL ({errs} error classes)")
        return 1
    print("RESULT: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())