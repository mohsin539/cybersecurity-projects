@echo off
cd /d "%~dp0"
set TI_NO_PAUSE=1
py main.py %*
echo.
echo Exit code: %ERRORLEVEL%
echo.
pause