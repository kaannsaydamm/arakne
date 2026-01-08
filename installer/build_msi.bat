@echo off
setlocal
pushd "%~dp0"

echo [*] Checking for WiX Toolset v4+...

REM 1. Check existing PATH
where wix >nul 2>&1
if %errorlevel% equ 0 (
    echo    [+] Found 'wix' in PATH.
    goto :BUILD
)

REM 2. Check User Specified Path (v6)
set "USER_PATH=C:\Program Files\WiX Toolset v6.0"
if exist "%USER_PATH%\wix.exe" (
    echo    [+] Found wix.exe in "%USER_PATH%"
    set "PATH=%PATH%;%USER_PATH%"
    goto :BUILD
)
if exist "%USER_PATH%\bin\wix.exe" (
    echo    [+] Found wix.exe in "%USER_PATH%\bin"
    set "PATH=%PATH%;%USER_PATH%\bin"
    goto :BUILD
)

REM 3. Fallback / Failure
echo [!] WiX Toolset not found!
echo     Please install WiX v6 and ensure 'wix.exe' is in your PATH.
echo     Tried: %USER_PATH%
exit /b 1

:BUILD
echo.
echo [*] Building MSI with WiX v4+...
echo     Command: wix build Product.wxs -o ArakneSetup.msi -ext WixToolset.UI.wixext -ext WixToolset.Util.wixext
wix build Product.wxs -o ArakneSetup.msi -ext WixToolset.UI.wixext -ext WixToolset.Util.wixext

if %errorlevel% neq 0 (
    echo [!] Build Failed!
    exit /b %errorlevel%
)

echo.
echo [+] SUCCESS: installer\ArakneSetup.msi created.
echo    (Note: Driver files must be built first!)
