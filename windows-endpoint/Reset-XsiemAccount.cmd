@echo off
REM XSIEM - reset the lab test account (unlock after a brute-force demo run).
REM Self-elevates: accept the UAC prompt.

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Requesting administrator privileges...
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0Reset-XsiemAccount.ps1"
pause
