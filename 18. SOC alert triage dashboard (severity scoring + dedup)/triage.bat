@echo off
rem SOC Alert Triage Dashboard launcher (Windows)
rem Stops any stale instance on :8080, then starts fresh and opens the browser.
cd /d "%~dp0"
echo [launch] checking port 8080...
for /f "tokens=5" %%p in ('netstat -ano ^| findstr ":8080" ^| findstr "LISTENING"') do (
  echo [launch] stopping stale instance PID %%p
  taskkill /F /PID %%p >nul 2>&1
)
echo [launch] starting SOC Alert Triage Dashboard...
start "SOC Triage" /min node server.js
timeout /t 2 /nobreak >nul
start "" http://localhost:8080
echo [launch] dashboard opened at http://localhost:8080
echo [launch] demo logins: analyst@t1 / lead@t1 / auditor@t1 / analyst@t2  (no password)
