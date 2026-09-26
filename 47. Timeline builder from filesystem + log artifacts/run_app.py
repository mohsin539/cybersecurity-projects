from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "src"))

from timeline_builder.__main__ import main

if __name__ == "__main__":
    raise SystemExit(main())
