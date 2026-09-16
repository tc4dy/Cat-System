Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot 'Logger.psm1') -DisableNameChecking -ErrorAction Stop

$script:RegistryBackup = @{}
$script:FileBackup = @{}
$script:TaskBackup = @{}
$script:HostsBlockBackup = @{}
$script:BackupFolder = Join-Path -Path (Split-Path -Parent $PSScriptRoot) -ChildPath 'CatSystem_Rollback'
$script:RollbackLock = New-Object System.Object

function Backup-RegistryValue {
    [CmdletBinding()]
    [OutputType([void])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('HKLM', 'HKCU')]
        [string]$Root,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$SubKey,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$ValueName,

        [Parameter()]
        [AllowNull()]
        [object]$CurrentValue
    )

    $id = '{0}|{1}|{2}' -f $Root, $SubKey, $ValueName

    try {
        [System.Threading.Monitor]::Enter($script:RollbackLock)
        if (-not $script:RegistryBackup.ContainsKey($id)) {
            $script:RegistryBackup[$id] = [pscustomobject]@{
                Root      = $Root
                SubKey    = $SubKey
                ValueName = $ValueName
                Value     = $CurrentValue
                Existed   = ($null -ne $CurrentValue)
            }
        }
    }
    finally {
        [System.Threading.Monitor]::Exit($script:RollbackLock)
    }
}

function Backup-FileItem {
    [CmdletBinding()]
    [OutputType([void])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path)) { return }

    try {
        [System.Threading.Monitor]::Enter($script:RollbackLock)
        if ($script:FileBackup.ContainsKey($Path)) { return }

        if (-not (Test-Path -LiteralPath $script:BackupFolder)) {
            New-Item -ItemType Directory -Path $script:BackupFolder -Force | Out-Null
        }

        $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
        $stamp = [Guid]::NewGuid().ToString('N')
        $target = Join-Path -Path $script:BackupFolder -ChildPath ("{0}_{1}.bak" -f $item.Name, $stamp)

        if ($item.PSIsContainer) {
            Copy-Item -LiteralPath $Path -Destination $target -Recurse -Force -ErrorAction Stop
        }
        else {
            Copy-Item -LiteralPath $Path -Destination $target -Force -ErrorAction Stop
        }

        $script:FileBackup[$Path] = [pscustomobject]@{
            Original = $Path
            Backup   = $target
            IsFolder = [bool]$item.PSIsContainer
        }
    }
    catch {
        Write-Verbose "File backup failed for $Path : $($_.Exception.Message)"
    }
    finally {
        [System.Threading.Monitor]::Exit($script:RollbackLock)
    }
}

function Backup-ScheduledTaskState {
    [CmdletBinding()]
    [OutputType([void])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$TaskPath,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$TaskName,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$OriginalState
    )

    $id = '{0}|{1}' -f $TaskPath, $TaskName

    try {
        [System.Threading.Monitor]::Enter($script:RollbackLock)
        if (-not $script:TaskBackup.ContainsKey($id)) {
            $script:TaskBackup[$id] = [pscustomobject]@{
                TaskPath      = $TaskPath
                TaskName      = $TaskName
                OriginalState = $OriginalState
            }
        }
    }
    finally {
        [System.Threading.Monitor]::Exit($script:RollbackLock)
    }
}

function Backup-HostsBlock {
    [CmdletBinding()]
    [OutputType([void])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$StartMarker,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$EndMarker
    )

    try {
        [System.Threading.Monitor]::Enter($script:RollbackLock)
        if (-not $script:HostsBlockBackup.ContainsKey($Path)) {
            $script:HostsBlockBackup[$Path] = [pscustomobject]@{
                Path        = $Path
                StartMarker = $StartMarker
                EndMarker   = $EndMarker
            }
        }
    }
    finally {
        [System.Threading.Monitor]::Exit($script:RollbackLock)
    }
}

function Remove-MarkedBlockFromFile {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$StartMarker,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$EndMarker
    )

    if (-not (Test-Path -LiteralPath $Path)) { return $false }

    try {
        $lines = @(Get-Content -LiteralPath $Path -ErrorAction Stop)
    }
    catch {
        Write-Verbose "Block read failed: $Path : $($_.Exception.Message)"
        return $false
    }

    $output = New-Object System.Collections.Generic.List[string]
    $inside = $false
    $removed = 0

    foreach ($line in $lines) {
        $trimmed = ([string]$line).Trim()

        if ($trimmed -eq $StartMarker) {
            $inside = $true
            $removed++
            continue
        }

        if ($trimmed -eq $EndMarker) {
            $inside = $false
            $removed++
            continue
        }

        if (-not $inside) {
            $output.Add([string]$line)
        }
    }

    if ($removed -eq 0) { return $false }

    try {
        Set-Content -LiteralPath $Path -Value $output.ToArray() -Encoding ASCII -ErrorAction Stop
        return $true
    }
    catch {
        Write-Verbose "Block write failed: $Path : $($_.Exception.Message)"
        return $false
    }
}

function Restore-AllChanges {
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    $success = $true

    foreach ($entry in @($script:RegistryBackup.Values)) {
        try {
            $baseKey = if ($entry.Root -eq 'HKLM') {
                [Microsoft.Win32.Registry]::LocalMachine
            }
            else {
                [Microsoft.Win32.Registry]::CurrentUser
            }

            $key = $baseKey.OpenSubKey($entry.SubKey, $true)
            if ($null -eq $key) { continue }

            try {
                if ($entry.Existed) {
                    $key.SetValue($entry.ValueName, $entry.Value)
                }
                elseif ($null -ne $key.GetValue($entry.ValueName)) {
                    $key.DeleteValue($entry.ValueName, $false)
                }
            }
            finally {
                $key.Dispose()
            }

            Write-CatProgress -Message "Restored registry: $($entry.Root)\$($entry.SubKey)\$($entry.ValueName)"
        }
        catch {
            Write-CatLog -Message "Registry restore failed: $($_.Exception.Message)" -Type Error
            $success = $false
        }
    }

    foreach ($entry in @($script:HostsBlockBackup.Values)) {
        try {
            $removed = Remove-MarkedBlockFromFile -Path $entry.Path -StartMarker $entry.StartMarker -EndMarker $entry.EndMarker
            if ($removed) {
                Write-CatProgress -Message "Removed marked block: $($entry.Path)"
            }
        }
        catch {
            Write-CatLog -Message "Block removal failed: $($_.Exception.Message)" -Type Error
            $success = $false
        }
    }

    foreach ($entry in @($script:FileBackup.Values)) {
        try {
            if (-not (Test-Path -LiteralPath $entry.Backup)) { continue }

            if (Test-Path -LiteralPath $entry.Original) {
                Remove-Item -LiteralPath $entry.Original -Recurse -Force -ErrorAction SilentlyContinue
            }

            $parent = Split-Path -Parent $entry.Original
            if (-not [string]::IsNullOrEmpty($parent) -and -not (Test-Path -LiteralPath $parent)) {
                New-Item -ItemType Directory -Path $parent -Force | Out-Null
            }

            Move-Item -LiteralPath $entry.Backup -Destination $entry.Original -Force -ErrorAction Stop
            Write-CatProgress -Message "Restored file: $($entry.Original)"
        }
        catch {
            Write-CatLog -Message "File restore failed: $($_.Exception.Message)" -Type Error
            $success = $false
        }
    }

    foreach ($entry in @($script:TaskBackup.Values)) {
        try {
            if ($entry.OriginalState -eq 'Disabled') { continue }

            $task = Get-ScheduledTask -TaskPath $entry.TaskPath -TaskName $entry.TaskName -ErrorAction SilentlyContinue
            if ($null -eq $task) { continue }

            Enable-ScheduledTask -TaskPath $entry.TaskPath -TaskName $entry.TaskName -ErrorAction Stop | Out-Null
            Write-CatProgress -Message "Task enabled: $($entry.TaskName)"
        }
        catch {
            Write-CatLog -Message "Task restore failed: $($entry.TaskName): $($_.Exception.Message)" -Type Error
            $success = $false
        }
    }

    if ($success) {
        Write-CatLog -Message 'Rollback completed successfully.' -Type Success -Tag '[OK]'
    }
    else {
        Write-CatLog -Message 'Rollback completed with errors.' -Type Warning
    }

    return $success
}

function Clear-Backup {
    [CmdletBinding()]
    [OutputType([void])]
    param()

    try {
        [System.Threading.Monitor]::Enter($script:RollbackLock)
        $script:RegistryBackup = @{}
        $script:FileBackup = @{}
        $script:TaskBackup = @{}
        $script:HostsBlockBackup = @{}

        if (Test-Path -LiteralPath $script:BackupFolder) {
            Remove-Item -LiteralPath $script:BackupFolder -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
    finally {
        [System.Threading.Monitor]::Exit($script:RollbackLock)
    }
}

Export-ModuleMember -Function Backup-RegistryValue, Backup-FileItem, Backup-ScheduledTaskState, Backup-HostsBlock, Restore-AllChanges, Clear-Backup