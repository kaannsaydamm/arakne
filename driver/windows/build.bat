@echo off
REM Arakne Windows Kernel Driver Build Script - Pure WDM
REM Requires: Visual Studio 2022 + Windows Driver Kit (WDK)

echo [*] Building Arakne WDM Driver (Pure WDM - No KMDF)...

REM Set WDK paths
set WDK_VERSION=10.0.26100.0
set WDK_ROOT=C:\Program Files (x86)\Windows Kits\10
set WDK_INC=%WDK_ROOT%\Include\%WDK_VERSION%
set WDK_LIB=%WDK_ROOT%\Lib\%WDK_VERSION%

REM Create output directory
if not exist "x64\Release" mkdir "x64\Release"

echo [*] Compiling callbacks.c...
cl.exe /c /kernel /W4 /WX- /O2 /Oi /GS- /Gz ^
    /I"%WDK_INC%\km" ^
    /I"%WDK_INC%\shared" ^
    /I"%WDK_INC%\km\crt" ^
    /D "NDEBUG" /D "_AMD64_" /D "_WIN64" /D "POOL_NX_OPTIN=1" ^
    /Fo"x64\Release\callbacks.obj" ^
    callbacks.c
if errorlevel 1 goto error

echo [*] Compiling main.c...
cl.exe /c /kernel /W4 /WX- /O2 /Oi /GS- /Gz ^
    /I"%WDK_INC%\km" ^
    /I"%WDK_INC%\shared" ^
    /I"%WDK_INC%\km\crt" ^
    /D "NDEBUG" /D "_AMD64_" /D "_WIN64" /D "POOL_NX_OPTIN=1" ^
    /Fo"x64\Release\main.obj" ^
    main.c
if errorlevel 1 goto error

echo [*] Compiling wfp.c...
cl.exe /c /kernel /W4 /WX- /O2 /Oi /GS- /Gz ^
    /I"%WDK_INC%\km" ^
    /I"%WDK_INC%\shared" ^
    /I"%WDK_INC%\km\crt" ^
    /D "NDEBUG" /D "_AMD64_" /D "_WIN64" /D "POOL_NX_OPTIN=1" /D "NDIS_SUPPORT_NDIS6=1" /D "NDIS630=1" ^
    /Fo"x64\Release\wfp.obj" ^
    wfp.c
if errorlevel 1 goto error

echo [*] Linking arakne_wfp.sys...
link.exe /DRIVER:WDM /SUBSYSTEM:NATIVE /ENTRY:DriverEntry /NODEFAULTLIB ^
    /LIBPATH:"%WDK_LIB%\km\x64" ^
    ntoskrnl.lib hal.lib wdmsec.lib fwpkclnt.lib uuid.lib BufferOverflowK.lib ^
    x64\Release\callbacks.obj ^
    x64\Release\main.obj ^
    x64\Release\wfp.obj ^
    /OUT:arakne_wfp.sys
if errorlevel 1 goto error

echo.
echo [+] BUILD SUCCESSFUL: arakne_wfp.sys
echo.
echo [!] To load driver, run as Admin:
echo     1. Sign: Set-AuthenticodeSignature -FilePath arakne_wfp.sys -Certificate (Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert)[0]
echo     2. Create: sc.exe create arakne type= kernel binPath= "%CD%\arakne_wfp.sys"
echo     3. Start: sc.exe start arakne
goto end

:error
echo.
echo [-] BUILD FAILED!
exit /b 1

:end
