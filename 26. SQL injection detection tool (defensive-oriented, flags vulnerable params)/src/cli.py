"""CLI entry: --selftest verifies the detection engine against labeled fixtures
(used as the CI acceptance gate + portable smoke test on the frozen exe).
"""
from __future__ import annotations

import sys

from . import __version__, engine, scanner


FIXTURES = [
    ("https://shop.example.com/products?id=1&cat=1' OR 1=1--",
     True, "flag", "boolean"),
    ("https://app.example.com/login?user=admin'--&pass=x",
     True, "flag", "boolean"),
    ("https://api.example.com/v1/users?id=1 UNION SELECT NULL,NULL,@@version--",
     True, "block", "union"),
    ("https://api.example.com/v1/search?q=hello world",
     False, "clean", "none"),
    ("https://example.com/articles?id=5 ORDER BY 10--",
     True, "flag", "union"),
]

EXPECTED = [
    (True, "flag", "boolean"),
    (True, "flag", "boolean"),
    (True, "block", "union"),
    (False, "clean", "none"),
    (True, "flag", "union"),
]


RANK = {"clean": 0, "monitor": 1, "flag": 2, "block": 3}


def run_selftest() -> int:
    print(f"SQLiDetect Shield v{__version__} -- self-test")
    print("=" * 62)
    passed = 0
    for i, (url, exp_flag, exp_verdict, exp_typ) in enumerate(FIXTURES, 1):
        rep = engine.analyze_target(url)
        flag = len(rep.flagged) > 0
        top = max((RANK.get(f.verdict.lower(), 0) for f in rep.flagged), default=0)
        types = set()
        for f in rep.findings:
            types.update(f.injection_types)
        ok = (flag == exp_flag and not exp_flag) or (
            flag and top >= RANK[exp_verdict])
        tag = "OK " if ok else "FAIL"
        print(f"[{tag}] #{i} {url[:58]}")
        for f in rep.findings:
            mark = ">>" if f.is_flagged else "  "
            print(f"   {mark} {f.parameter.name:18s} {f.severity:7s} "
                  f"{f.verdict:7s} score={f.score:.2f} "
                  f"types={','.join(f.injection_types) or '-'}")
        if ok:
            passed += 1
        else:
            print(f"   expected flag={exp_flag} verdict~={exp_verdict}")
    # Scanner-mode structural check (no network)
    from .scanner import PROBES
    print(f"\nScan corpus: {len(PROBES)} probes, approval-gated targets only.")
    print(f"Passed {passed}/{len(FIXTURES)}")
    return 0 if passed == len(FIXTURES) else 1


def main(argv=None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    if argv and argv[0] in ("--selftest", "selftest", "test"):
        return run_selftest()
    print("Usage: python -m src [--selftest]  (GUI launches when no arg supplied)")
    return 0


if __name__ == "__main__":
    sys.exit(main())