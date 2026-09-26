"""Build a portable, single-file Windows executable with PyInstaller.

Usage
-----
    python build_portable.py              # one-file GUI + CLI  (recommended)
    python build_portable.py --onedir     # faster-starting folder build
    python build_portable.py --console    # keep a console window (debug)
    python build_portable.py --clean      # wipe build/ dist/ first

The resulting artefact is written to ``dist/BrowserArtifactExtractor.exe`` and
has no external runtime dependencies: no Python install, no DLLs to copy.
"""
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys

PROJECT = os.path.dirname(os.path.abspath(__file__))
NAME = "BrowserArtifactExtractor"

# Modules PyInstaller's static analysis can miss because they are imported
# lazily inside functions.
HIDDEN_IMPORTS = [
    "cryptography.hazmat.primitives.ciphers.aead",
    "cryptography.hazmat.backends.openssl",
    "cryptography.hazmat.bindings._rust",
    "openpyxl",
    "openpyxl.styles",
    "openpyxl.utils",
    "reportlab",
    "reportlab.platypus",
    "reportlab.lib",
    "PIL",
    "PIL.Image",
    "tkinter",
    "tkinter.ttk",
    "tkinter.filedialog",
    "tkinter.messagebox",
    "sqlite3",
    "core.engine",
    "core.extractors",
    "core.decrypt",
    "core.winio",
    "core.paths",
    "sec.audit",
    "sec.integrity",
    "sec.compliance",
    "report.exporters",
    "ui.app",
    "ui.theme",
    "ui.widgets",
]

# Data files are intentionally minimal; the app is code-only and offline.
EXCLUDES = [
    "matplotlib", "numpy", "pandas", "scipy", "PyQt5", "PySide2",
    "notebook", "IPython", "pytest", "setuptools", "pip",
]


def build(onefile: bool, console: bool, clean: bool, icon: str = "",
          name: str = NAME) -> int:
    if clean:
        for path in ("build", "dist"):
            target = os.path.join(PROJECT, path)
            if os.path.isdir(target):
                shutil.rmtree(target, ignore_errors=True)
        for spec in (f"{NAME}.spec", f"{NAME}-CLI.spec"):
            target = os.path.join(PROJECT, spec)
            if os.path.isfile(target):
                os.remove(target)

    args = [
        sys.executable, "-m", "PyInstaller",
        "--noconfirm",
        "--name", name,
        "--onefile" if onefile else "--onedir",
        "--console" if console else "--windowed",
        "--paths", PROJECT,
    ]
    for mod in HIDDEN_IMPORTS:
        args += ["--hidden-import", mod]
    for mod in EXCLUDES:
        args += ["--exclude-module", mod]
    if icon and os.path.isfile(icon):
        args += ["--icon", icon]
    args += ["--collect-submodules", "cryptography"]
    args += ["--collect-submodules", "openpyxl"]
    args += ["--collect-submodules", "reportlab"]
    args += [os.path.join(PROJECT, "main.py")]

    print("Running:", " ".join(f'"{a}"' if " " in a else a for a in args))
    result = subprocess.run(args, cwd=PROJECT)
    if result.returncode != 0:
        print(f"\nBuild FAILED ({name}).", file=sys.stderr)
        return result.returncode

    out = os.path.join(PROJECT, "dist", name + (".exe" if onefile and os.name == "nt" else ""))
    if onefile and os.path.isfile(out):
        size_mb = os.path.getsize(out) / (1024 * 1024)
        print(f"\nBuild complete: {out}  ({size_mb:.1f} MB)")
    else:
        print(f"\nBuild complete. See: {os.path.join(PROJECT, 'dist', name)}")
    return 0


def build_both(clean: bool, icon: str = "") -> int:
    """Build the windowed GUI executable and the console CLI executable."""
    rc = build(onefile=True, console=False, clean=clean, icon=icon, name=NAME)
    if rc != 0:
        return rc
    return build(onefile=True, console=True, clean=False, icon=icon, name=f"{NAME}-CLI")


def main() -> int:
    parser = argparse.ArgumentParser(description="Build portable Browser Artifact Extractor .exe")
    parser.add_argument("--onedir", action="store_true", help="Produce a folder build instead of one-file.")
    parser.add_argument("--console", action="store_true", help="Keep a console window (debug builds).")
    parser.add_argument("--clean", action="store_true", help="Remove build/dist before building.")
    parser.add_argument("--icon", default="", help="Optional .ico path.")
    parser.add_argument("--single", action="store_true",
                        help="Build only the GUI one-file executable (skip the CLI build).")
    args = parser.parse_args()
    if args.single or args.onedir or args.console:
        return build(onefile=not args.onedir, console=args.console,
                     clean=args.clean, icon=args.icon)
    return build_both(clean=args.clean, icon=args.icon)


if __name__ == "__main__":
    raise SystemExit(main())
