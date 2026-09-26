# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec: portable one-file windowed build.

Output: dist/SubnetVLSMPlanner.exe — copy this single file anywhere and run it.
State is saved to state.json next to the exe (see state/state_manager.py).
"""
a = Analysis(
    ['main.py'],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=['gui.app'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['pytest', 'unittest', 'setuptools', 'pkg_resources'],
    noarchive=False,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='SubnetVLSMPlanner',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
