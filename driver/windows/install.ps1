# Check for Administrator privileges
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "Re-launching as Administrator..." -ForegroundColor Yellow
    Start-Process powershell.exe "-NoExit -NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path $MyInvocation.MyCommand.Path
$DriverName = "arakne_wfp.sys"
$ServiceName = "arakne"
$InstallDir = "C:\Arakne\Drivers"

Write-Host "=== Arakne Driver Installer (PowerShell) ===" -ForegroundColor Cyan
Write-Host ""

try {
    # 1. Kill App
    Write-Host "[*] Closing Arakne app..."
    Stop-Process -Name "arakne" -Force -ErrorAction SilentlyContinue

    # 2. Check Source
    if (-not (Test-Path "$ScriptDir\$DriverName")) {
        throw "Driver file not found: $ScriptDir\$DriverName. Run build.bat first."
    }

    # 3. Clean Service
    Write-Host "[*] Cleaning old service..."
    sc.exe stop $ServiceName | Out-Null
    
    # Wait for stop
    $retries = 15
    while ($retries -gt 0) {
        $state = sc.exe query $ServiceName
        if ($state -match "STOPPED" -or $state -match "1060") { break }
        Write-Host "    Waiting for service to stop... ($retries)"
        Start-Sleep -Seconds 1
        $retries--
    }
    
    if ($retries -eq 0) {
        Write-Host "[!] Service stuck in stopping state. A reboot is likely required." -ForegroundColor Red
        # Attempt to proceed anyway (might fail at delete)
    }
    
    sc.exe delete $ServiceName | Out-Null
    Start-Sleep -Seconds 2

    # 4. Copy Driver (Robust)
    Write-Host "[*] Copying driver..."
    if (-not (Test-Path $InstallDir)) { New-Item -ItemType Directory -Path $InstallDir | Out-Null }
    
    $DestPath = "$InstallDir\$DriverName"
    
    # Try to rename old file if exists (Avoids file-in-use errors)
    if (Test-Path $DestPath) {
        $OldFile = "$DestPath.old"
        if (Test-Path $OldFile) { Remove-Item $OldFile -Force -ErrorAction SilentlyContinue }
        try {
            Rename-Item -Path $DestPath -NewName "$DriverName.old" -Force -ErrorAction Stop
            Write-Host "    Moved previous driver to .old"
        }
        catch {
            Write-Host "    [!] Could not rename existing driver (File locked?). Attempting direct overwrite..." -ForegroundColor Yellow
        }
    }
    
    # Retry Loop for Copy
    $copySuccess = $false
    $copyRetries = 5
    while ($copyRetries -gt 0) {
        try {
            Copy-Item "$ScriptDir\$DriverName" "$DestPath" -Force -ErrorAction Stop
            $copySuccess = $true
            break
        }
        catch {
            Write-Host "    [!] File locked. Retrying in 2 seconds... ($copyRetries left)" -ForegroundColor Yellow
            Start-Sleep -Seconds 2
            $copyRetries--
        }
    }
    
    if (-not $copySuccess) {
        throw "Failed to copy driver file. It is still locked by the Kernel. ALWAYS RESTART after a crash."
    }
    
    Write-Host "[+] Driver copied to $InstallDir"

    # 5. Test Signing Check
    Write-Host "[*] Checking Test Signing status..."
    $bcd = bcdedit /enum
    Write-Host "DEBUG: Checking BCD Output..." -ForegroundColor DarkGray
    # Write-Host $bcd -ForegroundColor DarkGray # Uncomment if needed
    
    $isTestSigningOn = $bcd -match "testsigning\s+(Yes|On|True|1|Evet)"
    if (-not $isTestSigningOn) {
        Write-Host "[!] Enabling Test Signing..." -ForegroundColor Yellow
        Write-Host "    (Current BCD output didn't show active Check)" -ForegroundColor DarkGray
        bcdedit /set testsigning on
        Write-Host ""
        Write-Host "[!!!] REBOOT REQUIRED [!!!]" -ForegroundColor Red -BackgroundColor Black
        Write-Host "Test Signing enabled. You must restart your computer." -ForegroundColor Red
        Write-Host "After restart, run this script again."
        Read-Host "Press Enter to exit..."
        exit
    }

    # 6. Sign Driver
    Write-Host "[*] Signing driver..."
    $certSubject = "CN=ArakneDriver"
    $cert = Get-ChildItem -Path 'Cert:\CurrentUser\My' -CodeSigningCert | Where-Object { $_.Subject -eq $certSubject } | Select-Object -First 1
    
    if (-not $cert) {
        Write-Host "    Generating self-signed certificate..."
        $cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject $certSubject -CertStoreLocation 'Cert:\CurrentUser\My' -NotAfter (Get-Date).AddYears(5)
    }
    
    $certPath = "$env:TEMP\ArakneDriver.cer"
    Write-Host "    Exporting certificate to $certPath..."
    Export-Certificate -Cert $cert -FilePath $certPath -Force | Out-Null
    
    Write-Host "    Adding to Trusted Stores (LocalMachine)..."
    Import-Certificate -FilePath $certPath -CertStoreLocation 'Cert:\LocalMachine\TrustedPublisher' -ErrorAction Stop | Out-Null
    Import-Certificate -FilePath $certPath -CertStoreLocation 'Cert:\LocalMachine\Root' -ErrorAction Stop | Out-Null
    
    Write-Host "    Applying Authenticode Signature..."
    Set-AuthenticodeSignature -FilePath "$InstallDir\$DriverName" -Certificate $cert -HashAlgorithm SHA256 | Out-Null
    Write-Host "[+] Driver signed successfully."

    # 7. Create Service
    Write-Host "[*] Creating service..."
    $scResult = sc.exe create $ServiceName type= kernel start= demand binPath= "$InstallDir\$DriverName" DisplayName= "Arakne Kernel Driver"
    if ($LASTEXITCODE -ne 0 -and $scResult -notmatch "1073") {
        # 1073 = exists
        # throw "SC Create failed" # Proceed anyway if exists
    }

    # 8. Start Service
    Write-Host "[*] Starting service..."
    sc.exe start $ServiceName
    if ($LASTEXITCODE -ne 0) {
        Write-Host "`n[!] Service failed to start. (Exit Code: $LASTEXITCODE)" -ForegroundColor Red
        Write-Host "    If you see Error 1058 or 'Delete Pending', you MUST REBOOT." -ForegroundColor Yellow
    }
    Start-Sleep -Seconds 1
    
    $query = sc.exe query $ServiceName | Out-String
    if ($query -match "STATE.*:.*4.*RUNNING") {
        Write-Host "`n[+] SUCCESS: Driver installed and RUNNING!" -ForegroundColor Green
    }
    else {
        Write-Host "`n[-] WARNING: Service created but state is NOT running." -ForegroundColor Yellow
        Write-Host "    Current State output:" -ForegroundColor DarkGray
        Write-Host $query -ForegroundColor DarkGray
        Write-Host "`n[!] PLEASE REBOOT YOUR COMPUTER to clear the old driver." -ForegroundColor Red -BackgroundColor Black
    }

}
catch {
    Write-Host "`n[!] ERROR: $_" -ForegroundColor Red
    Write-Host "Details: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host ""
Read-Host "Press Enter to exit..."
