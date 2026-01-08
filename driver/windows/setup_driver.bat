@echo off
echo [*] Launching Arakne Driver Installer...
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0install.ps1" -SetupMode
pause
