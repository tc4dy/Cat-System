Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot

Import-Module (Join-Path $root 'Helpers\Benchmark.psm1') -DisableNameChecking -ErrorAction Stop
Import-Module (Join-Path $root 'Core\Logger.psm1') -DisableNameChecking -ErrorAction Stop
Import-Module (Join-Path $root 'Core\RollbackManager.psm1') -DisableNameChecking -ErrorAction Stop
Import-Module (Join-Path $root 'Core\RegistryHandler.psm1') -DisableNameChecking -ErrorAction Stop

function Get-AllStartupItems {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param()

    $items = New-Object System.Collections.Generic.List[pscustomobject]

    $regPaths = @(
        @{ Hive = 'HKCU'; Path = 'Software\Microsoft\Windows\CurrentVersion\Run'; Source = 'Registry (CurrentUser)' }
        @{ Hive = 'HKLM'; Path = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Run'; Source = 'Registry (LocalMachine)' }
    )

    foreach ($reg in $regPaths) {
        try {
            $baseKey = if ($reg.Hive -eq 'HKLM') {
                [Microsoft.Win32.Registry]::LocalMachine
            }
            else {
                [Microsoft.Win32.Registry]::CurrentUser
            }

            $key = $baseKey.OpenSubKey($reg.Path)
            if ($null -eq $key) { continue }

            try {
                foreach ($name in $key.GetValueNames()) {
                    $value = $key.GetValue($name)
                    if (-not [string]::IsNullOrEmpty([string]$value)) {
                        $items.Add([pscustomobject]@{
                            Name   = $name
                            Path   = [string]$value
                            Source = $reg.Source
                        })
                    }
                }
            }
            finally {
                $key.Dispose()
            }
        }
        catch {
            Write-Verbose "Startup registry read failed: $($_.Exception.Message)"
        }
    }

    $startupFolder = [Environment]::GetFolderPath('Startup')
    if (Test-Path -LiteralPath $startupFolder) {
        try {
            $files = @(Get-ChildItem -LiteralPath $startupFolder -Filter '*.lnk' -ErrorAction Stop)
            foreach ($file in $files) {
                $items.Add([pscustomobject]@{
                    Name   = [System.IO.Path]::GetFileNameWithoutExtension($file.Name)
                    Path   = $file.FullName
                    Source = 'Startup Folder'
                })
            }
        }
        catch {
            Write-Verbose "Startup folder enumeration failed: $($_.Exception.Message)"
        }
    }

    return $items.ToArray()
}

function Add-StartupItemInteractive {
    [CmdletBinding()]
    [OutputType([void])]
    param()

    $name = [string](Read-Host 'Enter program name')
    if ([string]::IsNullOrWhiteSpace($name)) {
        Write-CatLog -Message 'Invalid name.' -Type Error
        return
    }

    $targetPath = [string](Read-Host 'Enter full program path')
    if ([string]::IsNullOrWhiteSpace($targetPath) -or -not (Test-Path -LiteralPath $targetPath)) {
        Write-CatLog -Message 'Invalid path.' -Type Error
        return
    }

    $shell = $null
    $shortcut = $null

    try {
        $startupFolder = [Environment]::GetFolderPath('Startup')
        $shortcutPath = Join-Path $startupFolder "$name.lnk"

        $shellType = [Type]::GetTypeFromProgID('WScript.Shell')
        if ($null -eq $shellType) { throw 'WScript.Shell not available.' }

        $shell = [Activator]::CreateInstance($shellType)
        $shortcut = $shell.CreateShortcut($shortcutPath)
        $shortcut.TargetPath = $targetPath
        $shortcut.Save()

        Write-CatLog -Message "Startup item added: $name" -Type Success -Tag '[OK]'
    }
    catch {
        Write-CatLog -Message "Failed to add: $($_.Exception.Message)" -Type Error
    }
    finally {
        if ($null -ne $shortcut) {
            try { [System.Runtime.InteropServices.Marshal]::ReleaseComObject($shortcut) | Out-Null } catch { }
        }
        if ($null -ne $shell) {
            try { [System.Runtime.InteropServices.Marshal]::ReleaseComObject($shell) | Out-Null } catch { }
        }
        [GC]::Collect()
        [GC]::WaitForPendingFinalizers()
    }
}

function Remove-StartupItemInteractive {
    [CmdletBinding()]
    [OutputType([void])]
    param()

    $items = @(Get-AllStartupItems)
    if ($items.Count -eq 0) {
        Write-CatLog -Message 'No startup items to remove.' -Type Warning
        return
    }

    Write-Host 'Select item to remove:' -ForegroundColor Cyan
    for ($i = 0; $i -lt $items.Count; $i++) {
        Write-Host ("  [{0}] {1} ({2})" -f ($i + 1), $items[$i].Name, $items[$i].Source)
    }

    $raw = [string](Read-Host 'Number')
    $index = 0
    if (-not [int]::TryParse($raw, [ref]$index)) {
        Write-CatLog -Message 'Invalid number.' -Type Error
        return
    }

    if ($index -lt 1 -or $index -gt $items.Count) {
        Write-CatLog -Message 'Number out of range.' -Type Error
        return
    }

    $item = $items[$index - 1]

    try {
        if ($item.Source -eq 'Registry (CurrentUser)') {
            $null = Remove-RegistryKey -Root 'HKCU' -SubKey 'Software\Microsoft\Windows\CurrentVersion\Run' -ValueName $item.Name
        }
        elseif ($item.Source -eq 'Registry (LocalMachine)') {
            $null = Remove-RegistryKey -Root 'HKLM' -SubKey 'SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -ValueName $item.Name
        }
        elseif (Test-Path -LiteralPath $item.Path) {
            Backup-FileItem -Path $item.Path
            Remove-Item -LiteralPath $item.Path -Force -ErrorAction Stop
        }

        Write-CatLog -Message "Removed: $($item.Name)" -Type Success -Tag '[OK]'
    }
    catch {
        Write-CatLog -Message "Removal failed: $($_.Exception.Message)" -Type Error
    }
}

function Invoke-StartupManager {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    $before = Get-SystemBenchmark
    Write-CatHeader -Title 'Startup Manager' -Tag '[=]'

    $running = $true

    while ($running) {
        Write-Host ''
        Write-Host 'STARTUP MANAGER' -ForegroundColor Cyan
        Write-Host ' [1] List Startup Items'
        Write-Host ' [2] Add Startup Program'
        Write-Host ' [3] Remove Startup Program'
        Write-Host ' [4] Back to Main Menu'
        Write-Host ''

        $choice = ([string](Read-Host 'Choice')).Trim()

        switch ($choice) {
            '1' {
                $items = @(Get-AllStartupItems)
                if ($items.Count -eq 0) {
                    Write-CatLog -Message 'No startup items found.' -Type Warning
                }
                else {
                    foreach ($item in $items) {
                        Write-CatProgress -Message "$($item.Name) -> $($item.Path) [$($item.Source)]"
                    }
                }
            }
            '2' { Add-StartupItemInteractive }
            '3' { Remove-StartupItemInteractive }
            '4' { $running = $false }
            default {
                Write-CatLog -Message 'Invalid choice.' -Type Warning
            }
        }

        if ($running -and ($choice -in @('1', '2', '3'))) {
            Write-Host ''
            Write-Host 'Press any key to continue...' -ForegroundColor DarkGray
            [void][System.Console]::ReadKey($true)
        }
    }

    $after = Get-SystemBenchmark
    Write-CatLog -Message "Before: $before" -Type Info
    Write-CatLog -Message "After : $after" -Type Info

    return [pscustomobject]@{
        Module  = 'Startup Manager'
        Before  = $before
        After   = $after
        Success = $true
    }
}

Export-ModuleMember -Function Invoke-StartupManager, Get-AllStartupItems