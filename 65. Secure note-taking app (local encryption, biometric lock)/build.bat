@echo off
REM ============================================================
REM  SecureNote Pro - portable .exe build script
REM  Builds a single-file, windowed, no-install executable.
REM  Output: dist\SecureNotePro.exe
REM ============================================================
setlocal
cd /d "%~dp0"

echo [1/3] Installing build dependencies...
python -m pip install -r requirements.txt || goto :err

echo [2/3] Building portable exe (onefile, windowed)...
python -m PyInstaller --noconfirm --clean build.spec || goto :err

echo [3/3] Verifying artifact...
if exist "dist\SecureNotePro.exe" (
    echo.
    echo BUILD OK  -^>  dist\SecureNotePro.exe
    echo.
    dir "dist\SecureNotePro.exe"
) else (
    echo ERROR: artifact missing.
    goto :err
)
exit /b 0

:err
echo BUILD FAILED.
exit /b 1