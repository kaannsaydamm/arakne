# Arakne Unified Setup Script
$ErrorActionPreference = "Stop"

function Test-Command($cmd) {
    if (-not (Get-Command $cmd -ErrorAction SilentlyContinue)) {
        return $false
    }
    return $true
}

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "   ARAKNE UNIFIED SETUP (v1.1)" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan

# 1. Prerequisite Checks
Write-Host "`n[Check] Validating Environment..."
if (-not (Test-Command "go")) {
    Write-Host "[!] Error: 'go' is not installed or not in PATH." -ForegroundColor Red
    exit 1
}
Write-Host "   [+] Go runtime found."

# WE CANNOT easily check for cl.exe because it requires VsDevCmd.bat
# Usually build.bat handles it. We trust build.bat.

# 2. Build Driver
Write-Host "`n[Build] Compiling Kernel Driver..." -ForegroundColor Yellow
$DriverBuildScript = ".\driver\windows\build.bat"
if (Test-Path $DriverBuildScript) {
    # Run batch file
    Start-Process -FilePath "cmd.exe" -ArgumentList "/c $DriverBuildScript" -Wait -NoNewWindow
    
    if (-not (Test-Path ".\driver\windows\arakne_wfp.sys")) {
        Write-Host "[!] Driver Compilation Failed! (arakne_wfp.sys not found)" -ForegroundColor Red
        Write-Host "    Make sure you have Visual Studio + WDK installed."
        exit 1
    }
    Write-Host "   [+] Driver Compiled Successfully." -ForegroundColor Green
}
else {
    Write-Host "[!] Driver build script missing!" -ForegroundColor Red
    exit 1
}

# 3. Build Application
Write-Host "`n[Build] Compiling Arakne Application..." -ForegroundColor Yellow

# 3a. Embed Icon (go-winres)
if (Test-Path "winres.json") {
    if (-not (Test-Command "go-winres")) {
        Write-Host "   [*] Installing go-winres for icon embedding..."
        go install github.com/tc-hib/go-winres@latest
    }
    Write-Host "   [*] Generating Windows Resources (Icon/Manifest)..."
    go-winres make --product-version "1.1.0.0" --file-version "1.1.0.0"
}

go build -o arakne.exe ./cmd/arakne
if ($LASTEXITCODE -ne 0) {
    Write-Host "[!] App Compilation Failed!" -ForegroundColor Red
    exit 1
}
if (-not (Test-Path ".\arakne.exe")) {
    Write-Host "[!] arakne.exe was not created." -ForegroundColor Red
    exit 1
}
Write-Host "   [+] Application Compiled (arakne.exe)." -ForegroundColor Green

# 4. Install Driver
Write-Host "`n[Install] Installing & Loading Driver..." -ForegroundColor Yellow
$DriverInstallScript = ".\driver\windows\install.ps1"
if (Test-Path $DriverInstallScript) {
    # Call the powershell script
    # We use -NoExit if it fails? No, we want it automated.
    # The install script has interactive pauses. We might want to fix that later?
    # For now, we run it in a new window so user sees output.
    Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$DriverInstallScript`"" -Wait
    Write-Host "   [+] Driver Installation Step Completed."
}

# 5. Create Shortcut
Write-Host "`n[Setup] Creating Desktop Shortcut..."
$WshShell = New-Object -ComObject WScript.Shell
$DesktopPath = [Environment]::GetFolderPath("Desktop")
$Shortcut = $WshShell.CreateShortcut("$DesktopPath\Arakne.lnk")
$Shortcut.TargetPath = "$PWD\arakne.exe"
$Shortcut.Description = "Arakne Surgical Platform"
$Shortcut.WorkingDirectory = "$PWD"
# Run as Admin check? Properties logic is hard in PS.
$Shortcut.Save()
Write-Host "   [+] Shortcut created on Desktop." -ForegroundColor Green

Write-Host "`n==========================================" -ForegroundColor Cyan
Write-Host "   SETUP COMPLETE" -ForegroundColor Cyan
Write-Host "   Run 'Arakne' from your Desktop." -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Read-Host "Press Enter to exit..."
