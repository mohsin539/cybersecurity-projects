@echo off
setlocal
cd /d %~dp0
echo [1/3] install build deps (if missing)
python -m pip install -q -r requirements.txt
echo [2/3] run test gate
python -m pytest -q
if errorlevel 1 (
  echo TEST GATE FAILED - aborting build
  exit /b 1
)
echo [3/3] building onefile exe
python -m PyInstaller specs\build.spec --noconfirm --clean
if errorlevel 1 exit /b 1
echo.
echo Build OK: dist\AgentJitterStudy.exe
endlocal