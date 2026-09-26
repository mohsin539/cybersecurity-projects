# -*- mode: python ; coding: utf-8 -*-
#
# PyInstaller spec for SecureNote Pro — portable single-file .exe
#
#   Build:  python -m PyInstaller --noconfirm --clean build.spec
#

from PyInstaller.utils.hooks import collect_submodules, collect_data_files

hiddenimports = (
    collect_submodules("winrt")
    + collect_submodules("argon2")
    + collect_submodules("cryptography")
    + collect_submodules("fpdf")
)

datas = collect_data_files("argon2") + collect_data_files("cryptography")

a = Analysis(
    ["main.py"],
    pathex=[".", "src"],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    runtime_hooks=[],
    excludes=["tkinter.test", "pydoc"],
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="SecureNotePro",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,          # --windowed
    disable_windowed_traceback=False,
    uac_admin=False,
    target_arch=None,
    icon=None,
)