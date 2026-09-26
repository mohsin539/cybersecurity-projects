@echo off
cd /d "%~dp0"
echo Starting SOC Dashboard on port 5177...
npx vite --port 5177 --host
pause