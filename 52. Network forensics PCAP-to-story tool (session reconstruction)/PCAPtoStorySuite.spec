# -*- mode: python ; coding: utf-8 -*-
from PyInstaller.utils.hooks import collect_data_files
from PyInstaller.utils.hooks import collect_submodules

datas = []
hiddenimports = ['app.gui', 'app.core.state', 'app.core.security', 'app.core.audit', 'app.core.pcap_engine', 'app.core.story_engine', 'app.core.reports', 'app.core.memory', 'reportlab.pdfbase.pdfmetrics', 'reportlab.lib.pagesizes', 'reportlab.platypus']
datas += collect_data_files('reportlab')
hiddenimports += collect_submodules('dpkt')


a = Analysis(
    ['main.py'],
    pathex=[],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='PCAPtoStorySuite',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
