Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot

Import-Module (Join-Path $root 'Helpers\Benchmark.psm1') -DisableNameChecking -ErrorAction Stop
Import-Module (Join-Path $root 'Core\Logger.psm1') -DisableNameChecking -ErrorAction Stop
Import-Module (Join-Path $root 'Core\RollbackManager.psm1') -DisableNameChecking -ErrorAction Stop
Import-Module (Join-Path $root 'Core\RegistryHandler.psm1') -DisableNameChecking -ErrorAction Stop

function Show-NetworkAdapters {
    [CmdletBinding()]
    [OutputType([void])]
    param()

    try {
        $adapters = @(Get-NetAdapter -ErrorAction Stop | Where-Object {
            $_.Status -eq 'Up' -and $_.InterfaceType -ne 'Loopback'
        })

        if ($adapters.Count -eq 0) {
            Write-CatLog -Message 'No active network interfaces.' -Type Warning
            return
        }

        foreach ($adapter in $adapters) {
            $speed = if ($adapter.LinkSpeed) { $adapter.LinkSpeed } else { 'Unknown' }
            Write-CatProgress -Message "Interface: $($adapter.Name) | Speed: $speed"
        }
    }
    catch {
        Write-Verbose "Adapter enumeration failed: $($_.Exception.Message)"
    }
}

function Clear-DnsCache {
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    try {
        & ipconfig.exe /flushdns 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) {
            Write-CatProgress -Message 'DNS cache flushed.'
            return $true
        }
        return $false
    }
    catch {
        Write-CatLog -Message "DNS flush failed: $($_.Exception.Message)" -Type Warning
        return $false
    }
}

function Reset-NetworkStack {
    [CmdletBinding()]
    [OutputType([int])]
    param()

    Write-CatLog -Message 'Resetting network stack...' -Type Info
    $count = 0

    try {
        & netsh.exe winsock reset 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) {
            Write-CatProgress -Message 'Winsock catalog reset.'
            $count++
        }
    }
    catch {
        Write-Verbose "Winsock reset failed: $($_.Exception.Message)"
    }

    try {
        & netsh.exe int ip reset 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) {
            Write-CatProgress -Message 'TCP/IP stack reset.'
            $count++
        }
    }
    catch {
        Write-Verbose "TCP/IP reset failed: $($_.Exception.Message)"
    }

    return $count
}

function Set-TcpParameters {
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    try {
        & netsh.exe int tcp set global autotuninglevel=normal 2>&1 | Out-Null
        $null = Set-RegistryKey -Root 'HKLM' -SubKey 'SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' -ValueName 'Tcp1323Opts' -Value 1 -Kind DWord
        $null = Set-RegistryKey -Root 'HKLM' -SubKey 'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile' -ValueName 'NetworkThrottlingIndex' -Value 10 -Kind DWord
        Write-CatProgress -Message 'TCP/IP parameters applied.'
        return $true
    }
    catch {
        Write-CatLog -Message "TCP optimization failed: $($_.Exception.Message)" -Type Warning
        return $false
    }
}

function Set-DnsCacheSettings {
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    try {
        $null = Set-RegistryKey -Root 'HKLM' -SubKey 'SYSTEM\CurrentControlSet\Services\Dnscache\Parameters' -ValueName 'MaxCacheTtl' -Value 3600 -Kind DWord
        $null = Set-RegistryKey -Root 'HKLM' -SubKey 'SYSTEM\CurrentControlSet\Services\Dnscache\Parameters' -ValueName 'MaxNegativeCacheTtl' -Value 300 -Kind DWord
        Write-CatProgress -Message 'DNS cache settings applied.'
        return $true
    }
    catch {
        Write-CatLog -Message "DNS configuration failed: $($_.Exception.Message)" -Type Warning
        return $false
    }
}

function Invoke-NetBooster {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    $before = Get-SystemBenchmark
    Write-CatHeader -Title 'Net Booster' -Tag '[>>]'
    Write-CatLog -Message 'Analyzing network configuration...' -Type System

    Show-NetworkAdapters

    Write-CatLog -Message 'Applying TCP/IP optimizations...' -Type Info -Tag '[+]'

    $completed = 0
    if (Clear-DnsCache) { $completed++ }
    $completed += Reset-NetworkStack
    if (Set-TcpParameters) { $completed++ }
    if (Set-DnsCacheSettings) { $completed++ }

    $after = Get-SystemBenchmark
    Write-CatLog -Message "Module finished [$completed operations]" -Type Success -Tag '[OK]'
    Write-CatLog -Message "Before: $before" -Type Info
    Write-CatLog -Message "After : $after" -Type Info
    Write-CatLog -Message 'A restart is required for Winsock/TCP resets.' -Type Warning -Tag '[!]'

    return [pscustomobject]@{
        Module  = 'Net Booster'
        Before  = $before
        After   = $after
        Success = ($completed -gt 0)
    }
}

Export-ModuleMember -Function Invoke-NetBooster