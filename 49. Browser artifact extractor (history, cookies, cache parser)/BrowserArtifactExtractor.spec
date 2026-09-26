# -*- mode: python ; coding: utf-8 -*-
from PyInstaller.utils.hooks import collect_submodules

hiddenimports = ['cryptography.hazmat.primitives.ciphers.aead', 'cryptography.hazmat.backends.openssl', 'cryptography.hazmat.bindings._rust', 'openpyxl', 'openpyxl.styles', 'openpyxl.utils', 'reportlab', 'reportlab.platypus', 'reportlab.lib', 'PIL', 'PIL.Image', 'tkinter', 'tkinter.ttk', 'tkinter.filedialog', 'tkinter.messagebox', 'sqlite3', 'core.engine', 'core.extractors', 'core.decrypt', 'core.winio', 'core.paths', 'sec.audit', 'sec.integrity', 'sec.compliance', 'report.exporters', 'ui.app', 'ui.theme', 'ui.widgets']
hiddenimports += collect_submodules('cryptography')
hiddenimports += collect_submodules('openpyxl')
hiddenimports += collect_submodules('reportlab')


a = Analysis(
    ['D:/AI Masterclass/Project/18-09-2026/49. Browser artifact extractor (history, cookies, cache parser)/main.py'],
    pathex=['D:/AI Masterclass/Project/18-09-2026/49. Browser artifact extractor (history, cookies, cache parser)'],
    binaries=[],
    datas=[],
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['matplotlib', 'numpy', 'pandas', 'scipy', 'PyQt5', 'PySide2', 'notebook', 'IPython', 'pytest', 'setuptools', 'pip'],
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
    name='BrowserArtifactExtractor',
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
