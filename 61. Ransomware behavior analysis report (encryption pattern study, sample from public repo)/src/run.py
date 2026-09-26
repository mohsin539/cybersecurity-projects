"""Entry point for RansomLens (used by PyInstaller)."""

import os
import sys


def _guard_paths() -> None:
    """Make sure bundled/normal module resolution works whether frozen or not."""
    here = os.path.dirname(os.path.abspath(__file__))
    if here not in sys.path:
        sys.path.insert(0, here)


def main() -> int:
    _guard_paths()
    from workbench.app import run
    run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())