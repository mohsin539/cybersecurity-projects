@echo off
setlocal
cd /d "%~dp0"
echo ==========================================
echo   PEM-CAT portable build (onefile .exe)
echo ==========================================

where python >nul 2>nul
if errorlevel 1 (
    echo ERROR: Python not found on PATH.
    exit /b 1
)

python -m pip install --upgrade pyinstaller openpyxl >nul 2>nul

if exist dist\PEMCAT.exe del dist\PEMCAT.exe

python -m PyInstaller ^
  --noconfirm ^
  --onefile ^
  --windowed ^
  --name PEMCAT ^
  --clean ^
  --icon pemcat.ico ^
  main.py

if not exist dist\PEMCAT.exe (
    echo BUILD FAILED.
    exit /b 1
)

echo.
echo Build OK: dist\PEMCAT.exe
echo Portable: copy the .exe anywhere; catalog data defaults to
echo           %%LOCALAPPDATA%%\PEMCAT or a ./data folder next to the exe.
endlocal