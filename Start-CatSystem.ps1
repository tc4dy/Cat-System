#Requires -RunAsAdministrator
#Requires -Version 5.1

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:Root = $PSScriptRoot

$moduleOrder = @(
    'Helpers\SystemAnalyzer.psm1'
    'Helpers\Benchmark.psm1'
    'Helpers\UIRenderer.psm1'
    'Core\Logger.psm1'
    'Core\RollbackManager.psm1'
    'Core\RegistryHandler.psm1'
    'Modules\GhostProtocol.psm1'
    'Modules\SculptorEngine.psm1'
    'Modules\NetBooster.psm1'
    'Modules\BrowserCleaner.psm1'
    'Modules\StartupManager.psm1'
    'Modules\SystemCleaner.psm1'
)

foreach ($relative in $moduleOrder) {
    $full = Join-Path -Path $script:Root -ChildPath $relative
    if (-not (Test-Path -LiteralPath $full)) {
        throw "Required module missing: $full"
    }
    Import-Module $full -DisableNameChecking -ErrorAction Stop
}

try {
    [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
}
catch {
    Write-Verbose "UTF8 encoding unavailable: $($_.Exception.Message)"
}

function Invoke-RollbackChanges {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    $before = Get-SystemBenchmark
    Write-CatHeader -Title 'Rollback Changes' -Tag '[<]'

    $answer = [string](Read-Host 'Rollback all changes made by Cat-System? (y/n)')
    if ($answer.Trim() -notmatch '^[Yy]') {
        Write-CatLog -Message 'Rollback cancelled.' -Type Info
        return [pscustomobject]@{
            Module  = 'Rollback Changes'
            Before  = $before
            After   = $before
            Success = $false
        }
    }

    $result = Restore-AllChanges
    if ($result) {
        Clear-Backup
    }
    $after = Get-SystemBenchmark

    return [pscustomobject]@{
        Module  = 'Rollback Changes'
        Before  = $before
        After   = $after
        Success = $result
    }
}

$script:Actions = [ordered]@{
    '1' = @{ Name = 'Ghost Protocol';   Handler = { Invoke-GhostProtocol } }
    '2' = @{ Name = 'Sculptor Engine';  Handler = { Invoke-SculptorEngine } }
    '3' = @{ Name = 'Net Booster';      Handler = { Invoke-NetBooster } }
    '4' = @{ Name = 'Browser Cleaner';  Handler = { Invoke-BrowserCleaner } }
    '5' = @{ Name = 'Startup Manager';  Handler = { Invoke-StartupManager } }
    '6' = @{ Name = 'System Cleaner';   Handler = { Invoke-SystemCleaner } }
    '7' = @{ Name = 'Rollback Changes'; Handler = { Invoke-RollbackChanges } }
}

function Start-CatMainLoop {
    [CmdletBinding()]
    [OutputType([void])]
    param()

    while ($true) {
        try {
            Clear-Host
            Show-Banner

            $raw = Read-Host 'Awaiting Command'
            if ($null -eq $raw) { continue }
            $selection = ([string]$raw).Trim()

            if ($selection.Length -eq 0) { continue }

            if ($selection -eq '0') {
                Show-ExitAnimation
                return
            }

            if (-not $script:Actions.Contains($selection)) {
                Write-CatLog -Message 'Invalid selection.' -Type Warning -Tag '[!]'
                Start-Sleep -Milliseconds 1200
                continue
            }

            $action = $script:Actions[$selection]
            Clear-Host

            $result = & $action.Handler

            if ($null -ne $result -and -not $result.Success) {
                Write-CatLog -Message 'Module completed with warnings or no changes.' -Type Warning
            }

            Write-Host ''
            Write-Host '======================================================' -ForegroundColor DarkCyan
            Write-Host '  Press ANY KEY to return to Main Menu' -ForegroundColor DarkCyan
            Write-Host '======================================================' -ForegroundColor DarkCyan
            [void][System.Console]::ReadKey($true)
        }
        catch {
            Write-CatLog -Message "System error: $($_.Exception.Message)" -Type Critical
            Start-Sleep -Seconds 2
        }
    }
}

try {
    Start-CatMainLoop
}
finally {
    $loaded = Get-Module | Where-Object {
        $_.Path -and $_.Path.StartsWith($script:Root, [System.StringComparison]::OrdinalIgnoreCase)
    }
    foreach ($mod in $loaded) {
        Remove-Module -Name $mod.Name -Force -ErrorAction SilentlyContinue
    }
}