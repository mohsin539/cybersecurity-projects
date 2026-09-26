#!/usr/bin/env python3
"""Packaging entry point for the portable DIHT executable.

Keeps ``app`` as a proper package so relative imports inside it resolve in
the frozen one-file build.
"""

import sys

from app.main import main

if __name__ == "__main__":
    sys.exit(main())