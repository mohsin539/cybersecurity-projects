# -*- mode: python ; coding: utf-8 -*-
# PyInstaller spec: portable onedir exe (never onefile — docs/09 rationale).
import sys
sys.path.insert(0, "src")

from PyInstaller.utils.hooks import collect_data_files, collect_dynamic_libs, collect_submodules

hiddenimports = collect_submodules("cisguard") + ["structlog", "pydantic"]

# PySide6 Qt runtime data. Some PySide6/PyInstaller pairs fail to ship the Qt
# plugins (platforms/qwindows.dll etc.) that a GUI app NEEDS to start, which
# makes the frozen exe exit silently with "no Qt platform plugin could be
# initialized". Collect the specific plugin types this QWidgets app uses plus
# the qt_*.qm translations explicitly, so the onedir bundle is self-contained
# without dragging in whole unrelated Qt stacks (WebEngine, Multimedia, ...).
qt_plugins = collect_data_files(
    "PySide6",
    subdir="plugins",
    includes=[
        "platforms/**",
        "styles/**",
        "imageformats/**",
        "iconengines/**",
        "tls/**",
        "networkinformation/**",
        "platforminputcontexts/**",
        "generic/**",
    ],
)
qt_translations = collect_data_files("PySide6", subdir="translations", includes=["qt_*.qm"])
qt_data = qt_plugins + qt_translations

a = Analysis(
    ["launcher.py"],
    pathex=["src"],
    binaries=[],
    datas=qt_data,
    hiddenimports=hiddenimports,
    excludes=["tkinter", "unittest", "pydoc_data", "lib2to3",
              "yara", "sqlite3.test", "curses"],
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data)

exe = EXE(
    pyz, a.scripts, [],
    exclude_binaries=True,
    name="CISGuard",
    console=False,
)

coll = COLLECT(
    exe, a.binaries, a.zipfiles, a.datas,
    strip=False, upx=False,     # no UPX: AV false positives
    name="CISGuard",
)
