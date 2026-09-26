"""Runtime probe: ground-truth module surface of the REAL soarlite tree."""
from __future__ import annotations

import importlib
import inspect
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def _dump(modname: str) -> None:
    print("#" * 60)
    print("# ", modname)
    print("#" * 60)
    try:
        mod = importlib.import_module(modname)
    except Exception as exc:
        print("  !!! IMPORT FAILED:", type(exc).__name__, exc)
        return
    names = sorted(n for n in dir(mod) if not n.startswith("_"))
    objs = []
    for n in names:
        o = getattr(mod, n)
        if inspect.isfunction(o) or inspect.isclass(o):
            try:
                sig = str(inspect.signature(o))
            except (TypeError, ValueError):
                sig = "(?)"
            objs.append(f"  def {n}{sig}")
        elif n.isupper():
            v = getattr(mod, n)
            objs.append(f"  {n} = {v!r}"[:160])
    print("\n".join(objs[:200]) if objs else "  (no public symbols)")


if __name__ == "__main__":
    for name in sys.argv[1:]:
        _dump(name)
