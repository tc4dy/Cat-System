Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:LogFilePath = Join-Path -Path (Split-Path -Parent $PSScriptRoot) -ChildPath 'CatSystem_Log.txt'
$script:LogLock = New-Object System.Object

function Write-CatLog {
    [CmdletBinding()]
    [OutputType([void])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Message,

        [Parameter(Mandatory = $true)]
        [ValidateSet('Info', 'Success', 'Warning', 'Error', 'System', 'Critical')]
        [string]$Type,

        [Parameter()]
        [AllowEmptyString()]
        [string]$Tag = ''
    )

    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $logLine = "[$timestamp] [$Type] $Tag $Message"

    try {
        [System.Threading.Monitor]::Enter($script:LogLock)
        try {
            Add-Content -Path $script:LogFilePath -Value $logLine -Encoding UTF8 -ErrorAction Stop
        }
        finally {
            [System.Threading.Monitor]::Exit($script:LogLock)
        }
    }
    catch {
        Write-Verbose "Log persistence failed: $($_.Exception.Message)"
    }

    $prefix = switch ($Type) {
        'Info'     { '[INFO]' }
        'Success'  { '[OK]' }
        'Warning'  { '[!]' }
        'Error'    { '[X]' }
        'System'   { '[SYS]' }
        'Critical' { '[!!!]' }
        default    { '[LOG]' }
    }

    $color = switch ($Type) {
        'Info'     { 'Cyan' }
        'Success'  { 'Green' }
        'Warning'  { 'Yellow' }
        'Error'    { 'Red' }
        'System'   { 'Magenta' }
        'Critical' { 'DarkRed' }
        default    { 'White' }
    }

    if ([string]::IsNullOrEmpty($Tag)) {
        Write-Host "$prefix $Message" -ForegroundColor $color
    }
    else {
        Write-Host "$prefix $Tag $Message" -ForegroundColor $color
    }
}

function Write-CatHeader {
    [CmdletBinding()]
    [OutputType([void])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Title,

        [Parameter()]
        [AllowEmptyString()]
        [string]$Tag = ''
    )

    $display = $Title.ToUpperInvariant()
    Write-Host ''
    Write-Host '+======================================================+' -ForegroundColor Yellow
    if ([string]::IsNullOrEmpty($Tag)) {
        Write-Host ("|  {0,-50}|" -f $display) -ForegroundColor White
    }
    else {
        Write-Host ("|  {0} {1,-47}|" -f $Tag, $display) -ForegroundColor White
    }
    Write-Host '+======================================================+' -ForegroundColor Yellow
}

function Write-CatSection {
    [CmdletBinding()]
    [OutputType([void])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Title
    )

    Write-Host ''
    Write-Host ">> $Title" -ForegroundColor Cyan
}

function Write-CatProgress {
    [CmdletBinding()]
    [OutputType([void])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Message
    )

    Write-Host "    -> $Message" -ForegroundColor DarkGray
}

Export-ModuleMember -Function Write-CatLog, Write-CatHeader, Write-CatSection, Write-CatProgress