Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Show-Banner {
    [CmdletBinding()]
    [OutputType([void])]
    param()

    $banner = @'
   ___      _     ____            _
  / __|__ _| |_  / ___| _   _ ___| |_ ___ _ __ ___
 | |  / _` | __| \___ \| | | / __| __/ _ \ '_ ` _ \
 | |_| (_| | |_   ___) | |_| \__ \ ||  __/ | | | | |
  \___\__,_|\__| |____/ \__, |___/\__\___|_| |_| |_|
                         |___/
'@

    Write-Host $banner -ForegroundColor Cyan
    Write-Host '======================================================' -ForegroundColor Cyan
    Write-Host ' [#] Cat-System Core Loaded.' -ForegroundColor White
    Write-Host (" [PC] System: {0}" -f [System.Environment]::OSVersion.VersionString) -ForegroundColor DarkGray
    Write-Host (" [@] User: {0} | Admin Mode" -f [System.Environment]::UserName) -ForegroundColor DarkGray
    Write-Host ' [T] Architect: Tc4dy | Version 4.1' -ForegroundColor DarkGray
    Write-Host '======================================================' -ForegroundColor Cyan

    Write-Host ''
    Write-Host 'MAIN CONTROL PANEL' -ForegroundColor Yellow
    Write-Host '  [1] GHOST PROTOCOL    (Privacy & Telemetry Blocker)'
    Write-Host '  [2] SCULPTOR ENGINE   (CPU & Power Optimization)'
    Write-Host '  [3] NET BOOSTER       (Network & DNS Configuration)'
    Write-Host '  [4] BROWSER CLEANER   (Cache, Cookies, History)'
    Write-Host '  [5] STARTUP MANAGER   (Manage Autostart Programs)'
    Write-Host '  [6] SYSTEM CLEANER    (Temp, Logs, Prefetch, DISM)'
    Write-Host '  [7] ROLLBACK CHANGES  (Undo All Modifications)'
    Write-Host '------------------------------------------------------' -ForegroundColor DarkGray
    Write-Host '  [0] SHUTDOWN SYSTEM'
    Write-Host '------------------------------------------------------' -ForegroundColor DarkGray
    Write-Host ''
}

function Show-MenuOption {
    [CmdletBinding()]
    [OutputType([void])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Key,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Label,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Description
    )

    Write-Host ("  [{0}] {1,-18} ({2})" -f $Key, $Label, $Description)
}

function Show-ExitAnimation {
    [CmdletBinding()]
    [OutputType([void])]
    param()

    Clear-Host
    Write-Host ''
    Write-Host '====================================================' -ForegroundColor Cyan
    Write-Host '            Shutting down Cat-System...              ' -ForegroundColor Cyan
    Write-Host '====================================================' -ForegroundColor Cyan

    for ($i = 0; $i -lt 3; $i++) {
        Start-Sleep -Milliseconds 400
        Write-Host '.' -NoNewline
    }

    Write-Host ''
    Write-Host ''
    Write-Host '[OK] System terminated successfully.' -ForegroundColor Green
    Start-Sleep -Milliseconds 800
}

Export-ModuleMember -Function Show-Banner, Show-MenuOption, Show-ExitAnimation