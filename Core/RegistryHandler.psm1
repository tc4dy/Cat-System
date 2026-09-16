Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot 'Logger.psm1') -DisableNameChecking -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'RollbackManager.psm1') -DisableNameChecking -ErrorAction Stop

function Set-RegistryKey {
    [CmdletBinding()]
    [OutputType([bool])]
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

        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [object]$Value,

        [Parameter()]
        [ValidateSet('DWord', 'QWord', 'String', 'ExpandString', 'MultiString', 'Binary')]
        [string]$Kind = 'DWord'
    )

    try {
        $baseKey = if ($Root -eq 'HKLM') {
            [Microsoft.Win32.Registry]::LocalMachine
        }
        else {
            [Microsoft.Win32.Registry]::CurrentUser
        }

        $key = $baseKey.CreateSubKey($SubKey, $true)
        if ($null -eq $key) {
            Write-CatLog -Message "Failed to open registry key: $SubKey" -Type Error
            return $false
        }

        try {
            $existing = $key.GetValue($ValueName, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
            Backup-RegistryValue -Root $Root -SubKey $SubKey -ValueName $ValueName -CurrentValue $existing

            $regKind = [System.Enum]::Parse([Microsoft.Win32.RegistryValueKind], $Kind)
            $key.SetValue($ValueName, $Value, $regKind)
            Write-CatProgress -Message "Registry set: $ValueName"
            return $true
        }
        finally {
            $key.Dispose()
        }
    }
    catch {
        Write-CatLog -Message "Registry write failed ($ValueName): $($_.Exception.Message)" -Type Error
        return $false
    }
}

function Remove-RegistryKey {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('HKLM', 'HKCU')]
        [string]$Root,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$SubKey,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$ValueName
    )

    try {
        $baseKey = if ($Root -eq 'HKLM') {
            [Microsoft.Win32.Registry]::LocalMachine
        }
        else {
            [Microsoft.Win32.Registry]::CurrentUser
        }

        $key = $baseKey.OpenSubKey($SubKey, $true)
        if ($null -eq $key) { return $false }

        try {
            $existing = $key.GetValue($ValueName, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
            if ($null -eq $existing) { return $false }

            Backup-RegistryValue -Root $Root -SubKey $SubKey -ValueName $ValueName -CurrentValue $existing
            $key.DeleteValue($ValueName, $false)
            Write-CatProgress -Message "Registry removed: $ValueName"
            return $true
        }
        finally {
            $key.Dispose()
        }
    }
    catch {
        Write-CatLog -Message "Registry delete failed ($ValueName): $($_.Exception.Message)" -Type Error
        return $false
    }
}

Export-ModuleMember -Function Set-RegistryKey, Remove-RegistryKey