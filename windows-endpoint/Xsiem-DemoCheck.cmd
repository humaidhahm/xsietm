@echo off
REM XSIEM demo pre-flight check. Self-elevates - accept the UAC prompt.
net session >nul 2>&1
if %errorlevel% neq 0 (
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0Xsiem-DemoCheck.ps1" %*
if "%~1"=="-evidence" pause
