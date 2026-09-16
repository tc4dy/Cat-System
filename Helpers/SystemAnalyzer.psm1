Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:MemorySource = @'
using System;
using System.Runtime.InteropServices;

public static class CatMemInfo
{
    [StructLayout(LayoutKind.Sequential)]
    public struct MEMORYSTATUSEX
    {
        public uint dwLength;
        public uint dwMemoryLoad;
        public ulong ullTotalPhys;
        public ulong ullAvailPhys;
        public ulong ullTotalPageFile;
        public ulong ullAvailPageFile;
        public ulong ullTotalVirtual;
        public ulong ullAvailVirtual;
        public ulong ullAvailExtendedVirtual;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GlobalMemoryStatusEx(ref MEMORYSTATUSEX lpBuffer);

    public static MEMORYSTATUSEX Query()
    {
        MEMORYSTATUSEX m = new MEMORYSTATUSEX();
        m.dwLength = (uint)Marshal.SizeOf(typeof(MEMORYSTATUSEX));
        GlobalMemoryStatusEx(ref m);
        return m;
    }
}
'@

function Get-MemoryStatus {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()

    try {
        if (-not ('CatMemInfo' -as [type])) {
            Add-Type -TypeDefinition $script:MemorySource -Language CSharp -ErrorAction Stop
        }
        $status = [CatMemInfo]::Query()
        return @{
            TotalRAM     = [long]$status.ullTotalPhys
            AvailableRAM = [long]$status.ullAvailPhys
        }
    }
    catch {
        try {
            $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
            return @{
                TotalRAM     = [long]$os.TotalVisibleMemorySize * 1024
                AvailableRAM = [long]$os.FreePhysicalMemory * 1024
            }
        }
        catch {
            return @{ TotalRAM = 0L; AvailableRAM = 0L }
        }
    }
}

function Get-CpuUsage {
    [CmdletBinding()]
    [OutputType([double])]
    param()

    try {
        $cpu = Get-CimInstance -ClassName Win32_Processor -ErrorAction Stop
        $avg = ($cpu | Measure-Object -Property LoadPercentage -Average).Average
        if ($null -eq $avg) { return 0.0 }
        return [double]$avg
    }
    catch {
        return 0.0
    }
}

function Get-ProcessCount {
    [CmdletBinding()]
    [OutputType([int])]
    param()

    try {
        return @(Get-Process -ErrorAction Stop).Count
    }
    catch {
        return 0
    }
}

function Get-SystemMetrics {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    $memory = Get-MemoryStatus
    $cpu = Get-CpuUsage
    $procs = Get-ProcessCount

    return [pscustomobject]@{
        TotalRAM     = $memory.TotalRAM
        AvailableRAM = $memory.AvailableRAM
        CPUUsage     = $cpu
        ProcessCount = $procs
    }
}

Export-ModuleMember -Function Get-MemoryStatus, Get-CpuUsage, Get-ProcessCount, Get-SystemMetrics