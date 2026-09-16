Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot

Import-Module (Join-Path $root 'Helpers\Benchmark.psm1') -DisableNameChecking -ErrorAction Stop
Import-Module (Join-Path $root 'Core\Logger.psm1') -DisableNameChecking -ErrorAction Stop

function Remove-DirectoryContents {
    [CmdletBinding()]
    [OutputType([long])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Path
    )

    $freed = 0L

    if (-not (Test-Path -LiteralPath $Path)) { return $freed }

    try {
        $items = @(Get-ChildItem -LiteralPath $Path -Force -ErrorAction SilentlyContinue)
        foreach ($item in $items) {
            try {
                if ($item.PSIsContainer) {
                    $size = (Get-ChildItem -LiteralPath $item.FullName -File -Recurse -Force -ErrorAction SilentlyContinue |
                        Measure-Object -Property Length -Sum).Sum
                    if ($null -eq $size) { $size = 0 }
                    Remove-Item -LiteralPath $item.FullName -Recurse -Force -ErrorAction Stop
                    $freed += [long]$size
                }
                else {
                    $size = [long]$item.Length
                    Remove-Item -LiteralPath $item.FullName -Force -ErrorAction Stop
                    $freed += $size
                }
            }
            catch {
                Write-Verbose "Delete failed: $($item.FullName)"
            }
        }
    }
    catch {
        Write-Verbose "Directory scan failed: $Path"
    }

    return $freed
}

function Clear-TempFolders {
    [CmdletBinding()]
    [OutputType([long])]
    param()

    Write-CatSection -Title 'Temporary Files'
    $freed = 0L

    $paths = @(
        [System.IO.Path]::GetTempPath()
        (Join-Path $env:windir 'Temp')
    )

    foreach ($dir in $paths) {
        if (Test-Path -LiteralPath $dir) {
            $freed += Remove-DirectoryContents -Path $dir
        }
    }

    Write-CatProgress -Message ('Temp folders freed: {0:F1} MB' -f ($freed / 1MB))
    return $freed
}

function Clear-PrefetchCache {
    [CmdletBinding()]
    [OutputType([long])]
    param()

    Write-CatSection -Title 'Prefetch Cache'
    $path = Join-Path $env:windir 'Prefetch'
    $freed = Remove-DirectoryContents -Path $path
    Write-CatProgress -Message ('Prefetch freed: {0:F1} MB' -f ($freed / 1MB))
    return $freed
}

function Clear-WindowsEventLogs {
    [CmdletBinding()]
    [OutputType([long])]
    param()

    Write-CatSection -Title 'Windows Event Logs'
    $freed = 0L

    $logPath = Join-Path $env:windir 'System32\winevt\Logs'
    if (Test-Path -LiteralPath $logPath) {
        try {
            $files = @(Get-ChildItem -LiteralPath $logPath -File -Filter '*.evtx' -Force -ErrorAction SilentlyContinue)
            foreach ($file in $files) {
                try {
                    $size = [long]$file.Length
                    Remove-Item -LiteralPath $file.FullName -Force -ErrorAction Stop
                    $freed += $size
                }
                catch {
                    Write-Verbose "Log delete skipped: $($file.Name)"
                }
            }
        }
        catch {
            Write-Verbose "Log folder scan failed: $($_.Exception.Message)"
        }
    }

    try {
        $output = @(& wevtutil.exe el 2>&1)
        if ($LASTEXITCODE -eq 0) {
            foreach ($logName in $output) {
                $cleanName = ([string]$logName).Trim()
                if ($cleanName.Length -gt 0) {
                    & wevtutil.exe cl $cleanName 2>&1 | Out-Null
                }
            }
            Write-CatProgress -Message 'Event logs cleared via wevtutil.'
        }
    }
    catch {
        Write-Verbose "wevtutil clear failed: $($_.Exception.Message)"
    }

    Write-CatProgress -Message ('Log files freed: {0:F1} MB' -f ($freed / 1MB))
    return $freed
}

function Invoke-DismCleanup {
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    Write-CatSection -Title 'Component Store (DISM)'
    Write-CatLog -Message 'Running DISM cleanup, this may take minutes...' -Type Info

    try {
        & dism.exe /Online /Cleanup-Image /StartComponentCleanup /ResetBase 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) {
            Write-CatProgress -Message 'DISM cleanup complete.'
            return $true
        }
        Write-CatLog -Message 'DISM completed with warnings.' -Type Warning
        return $false
    }
    catch {
        Write-CatLog -Message "DISM failed: $($_.Exception.Message)" -Type Warning
        return $false
    }
}

function Invoke-StorageSense {
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    Write-CatSection -Title 'Storage Sense'
    try {
        & cleanmgr.exe /sagerun:1 2>&1 | Out-Null
        Write-CatProgress -Message 'Disk Cleanup invoked.'
        return $true
    }
    catch {
        Write-CatLog -Message "Storage Sense skipped: $($_.Exception.Message)" -Type Warning
        return $false
    }
}

function Invoke-SystemCleaner {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    $before = Get-SystemBenchmark
    Write-CatHeader -Title 'System Cleaner' -Tag '[*]'
    Write-CatLog -Message 'Scanning for cleanable data...' -Type System

    $freed = 0L
    $freed += Clear-TempFolders
    $freed += Clear-PrefetchCache
    $freed += Clear-WindowsEventLogs
    $null = Invoke-DismCleanup
    $null = Invoke-StorageSense

    $mb = [math]::Round($freed / 1MB, 1)
    $after = Get-SystemBenchmark
    Write-CatLog -Message "Cleaning complete. Freed: ~$mb MB" -Type Success -Tag '[OK]'
    Write-CatLog -Message "Before: $before" -Type Info
    Write-CatLog -Message "After : $after" -Type Info

    return [pscustomobject]@{
        Module  = 'System Cleaner'
        Before  = $before
        After   = $after
        Success = ($freed -gt 0)
    }
}

Export-ModuleMember -Function Invoke-SystemCleaner