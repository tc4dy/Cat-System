Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot 'SystemAnalyzer.psm1') -DisableNameChecking -ErrorAction Stop

function Get-DiskUsage {
    [CmdletBinding()]
    [OutputType([double])]
    param()

    try {
        $sample = Get-Counter -Counter '\PhysicalDisk(_Total)\% Disk Time' -SampleInterval 1 -MaxSamples 1 -ErrorAction Stop
        $value = [double]$sample.CounterSamples[0].CookedValue
        if ([double]::IsNaN($value) -or [double]::IsInfinity($value)) { return 0.0 }
        return [math]::Round($value, 1)
    }
    catch {
        return 0.0
    }
}

function Get-NetworkLatency {
    [CmdletBinding()]
    [OutputType([long])]
    param(
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$Target = '8.8.8.8',

        [Parameter()]
        [ValidateRange(100, 10000)]
        [int]$TimeoutMs = 1000
    )

    try {
        $ping = New-Object System.Net.NetworkInformation.Ping
        $reply = $ping.Send($Target, $TimeoutMs)
        if ($null -ne $reply -and $reply.Status -eq 'Success') {
            return [long]$reply.RoundtripTime
        }
        return 0L
    }
    catch {
        return 0L
    }
}

function Get-SystemBenchmark {
    [CmdletBinding()]
    [OutputType([string])]
    param()

    try {
        $metrics = Get-SystemMetrics
        $disk = Get-DiskUsage
        $ping = Get-NetworkLatency

        $availMb = [math]::Round($metrics.AvailableRAM / 1MB, 0)
        $totalMb = [math]::Round($metrics.TotalRAM / 1MB, 0)

        return ('RAM: {0}MB/{1}MB | CPU: {2:F1}% | DISK: {3:F1}% | PING: {4}ms' -f $availMb, $totalMb, $metrics.CPUUsage, $disk, $ping)
    }
    catch {
        return 'Benchmark unavailable'
    }
}

Export-ModuleMember -Function Get-SystemBenchmark, Get-DiskUsage, Get-NetworkLatency