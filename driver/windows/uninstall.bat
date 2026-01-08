@echo off
REM ============================================
REM Arakne Driver - Uninstall Script
REM Run as Administrator!
REM ============================================

echo.
echo ============================================
echo    Arakne Kernel Driver Uninstaller
echo ============================================
echo.

REM Check Admin
net session >nul 2>&1
if errorlevel 1 (
    echo [!] ERROR: Yonetici olarak calistir!
    pause
    exit /b 1
)

set SERVICE_NAME=arakne
set INSTALL_DIR=C:\Arakne

echo [*] Driver durduruluyor...
sc stop %SERVICE_NAME% >nul 2>&1
timeout /t 2 >nul

echo [*] Servis siliniyor...
sc delete %SERVICE_NAME%
timeout /t 1 >nul

echo [*] Dosyalar temizleniyor...
if exist "%INSTALL_DIR%" (
    rd /s /q "%INSTALL_DIR%"
    echo [+] %INSTALL_DIR% silindi.
)

echo.
echo ============================================
echo [+] ARAKNE DRIVER KALDIRILDI!
echo ============================================
echo.
pause
