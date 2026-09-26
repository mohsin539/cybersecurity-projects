"""PyInstaller entry point: imports the `app` package so relative imports resolve."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.main import main

sys.exit(main())