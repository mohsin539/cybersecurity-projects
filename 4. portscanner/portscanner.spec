# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec — builds dist/portscanner/portscan.exe (console CLI) and
dist/portscanner/portscan-gui.exe (windowed GUI) from one COLLECT.

Build (from project root):
    py -m venv .venv-build
    .venv-build/Scripts/python -m pip install pyinstaller
    .venv-build/Scripts/python -m PyInstaller portscanner.spec --noconfirm --clean

Why onedir (not onefile): instant startup, far fewer antivirus false
positives, and one shared _internal/ directory for both executables.
Distribute the whole dist/portscanner/ folder (zip of it works too).
"""
from PyInstaller.utils.hooks import collect_submodules

COMMON_KW = dict(
    pathex=["."],
    binaries=[],
    # Bundled at <_internal>/data/… which is exactly where service.py's
    # Path(__file__).parent.parent / "data" lookup lands when frozen.
    datas=[
        ("data/service-probes.toml", "data"),
        ("data/top-ports.csv", "data"),
    ],
    # scanner.py does dynamic __import__('portscanner.models', …) and engines
    # register via submodule imports — pull in every package submodule.
    hiddenimports=(
        collect_submodules("portscanner")
        + collect_submodules("portscanner.engines")
    ),
    excludes=["scapy", "tests"],  # optional raw-engine dep; never shipped
)

# ---- console CLI: portscan.exe -------------------------------------------
a_cli = Analysis(["scripts/portscan_cli.py"], **COMMON_KW)
pyz_cli = PYZ(a_cli.pure)
exe_cli = EXE(
    pyz_cli,
    a_cli.scripts,
    [],
    exclude_binaries=True,
    name="portscan",
    debug=False,
    strip=False,
    upx=False,
    console=True,
)

# ---- windowed GUI: portscan-gui.exe ---------------------------------------
a_gui = Analysis(["scripts/portscan_gui.py"], **COMMON_KW)
pyz_gui = PYZ(a_gui.pure)
exe_gui = EXE(
    pyz_gui,
    a_gui.scripts,
    [],
    exclude_binaries=True,
    name="portscan-gui",
    debug=False,
    strip=False,
    upx=False,
    console=False,
)

coll = COLLECT(
    exe_cli,
    exe_gui,
    a_cli.binaries,
    a_cli.datas,
    a_gui.binaries,
    a_gui.datas,
    strip=False,
    upx=False,
    name="portscanner",
)
