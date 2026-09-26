"""Portable GUI entry point.

Built by PyInstaller into TrafficObfuscationDemo.exe (single-file, windowed).
"""
import sys

from src.gui import main

if __name__ == "__main__":
    sys.exit(main())