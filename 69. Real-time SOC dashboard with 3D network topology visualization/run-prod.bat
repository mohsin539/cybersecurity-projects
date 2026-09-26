@echo off
cd /d "%~dp0"
echo Starting SOC Dashboard (production preview)...
npx vite preview --port 5177 --host
pause