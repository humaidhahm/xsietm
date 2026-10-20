@echo off
REM XSIEM - check whether the Kali side has finished its work (read-only, no elevation needed)
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0Check-KaliProgress.ps1"
pause
