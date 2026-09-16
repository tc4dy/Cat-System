Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot

Import-Module (Join-Path $root 'Helpers\Benchmark.psm1') -DisableNameChecking -ErrorAction Stop
Import-Module (Join-Path $root 'Helpers\SystemAnalyzer.psm1') -DisableNameChecking -ErrorAction Stop
Import-Module (Join-Path $root 'Core\Logger.psm1') -DisableNameChecking -ErrorAction Stop
Import-Module (Join-Path $root 'Core\RollbackManager.psm1') -DisableNameChecking -ErrorAction Stop
Import-Module (Join-Path $root 'Core\RegistryHandler.psm1') -DisableNameChecking -ErrorAction Stop

$script:BackgroundTargets = @(
    'OneDrive'
    'SkypeApp'
    'YourPhone'
    'MicrosoftEdgeUpdate'
    'XboxGameBar'
    'GameBar'
    'PhoneExperienceHost'
)

function Optimize-BackgroundProcesses {
    [CmdletBinding()]
    [OutputType([int])]
    param()

    Write-CatLog -Message 'Analyzing background processes...' -Type Info -Tag '[?]'
    $optimized = 0

    try {
        $all = Get-Process -ErrorAction Stop
    }
    catch {
        Write-CatLog -Message "Process enumeration failed: $($_.Exception.Message)" -Type Warning
        return 0
    }

    foreach ($proc in $all) {
        try {
            if ($script:BackgroundTargets -notcontains $proc.ProcessName) { continue }
            if ($proc.HasExited) { continue }

            $proc.PriorityClass = [System.Diagnostics.ProcessPriorityClass]::Idle
            $optimized++
            Write-CatProgress -Message "Optimized: $($proc.ProcessName) (PID: $($proc.Id))"
        }
        catch {
            Write-Verbose "Skipped $($proc.ProcessName): $($_.Exception.Message)"
        }
        finally {
            if ($null -ne $proc) {
                try { $proc.Dispose() } catch { }
            }
        }
    }

    if ($optimized -eq 0) {
        Write-CatLog -Message 'No target background processes found.' -Type Info
    }

    return $optimized
}

function Optimize-MemorySettings {
    [CmdletBinding()]
    [OutputType([void])]
    param()

    Write-CatLog -Message 'Configuring memory settings...' -Type Info -Tag '[=]'
    $null = Set-RegistryKey -Root 'HKLM' -SubKey 'SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' -ValueName 'LargeSystemCache' -Value 0 -Kind DWord
}

function Set-HighPerformancePlan {
    [CmdletBinding()]
    [OutputType([void])]
    param()

    Write-CatLog -Message 'Configuring high performance power plan...' -Type Info -Tag '[>>]'

    $guid = $null

    try {
        $output = & powercfg.exe /list 2>&1
        foreach ($line in $output) {
            $text = [string]$line
            if ($text -match 'High performance|Y.ksek performans|Alto rendimiento|Haute performance|Hohe Leistung') {
                if ($text -match '([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})') {
                    $guid = $matches[1]
                    break
                }
            }
        }
    }
    catch {
        Write-Verbose "powercfg list failed: $($_.Exception.Message)"
    }

    if ([string]::IsNullOrEmpty($guid)) {
        try {
            $plans = Get-CimInstance -ClassName Win32_PowerPlan -Namespace 'root\cimv2\power' -ErrorAction Stop
            foreach ($plan in $plans) {
                if ([string]$plan.ElementName -match 'High') {
                    $guid = ([string]$plan.InstanceID -split '\\')[-1]
                    break
                }
            }
        }
        catch {
            Write-Verbose "CIM power plan lookup failed: $($_.Exception.Message)"
        }
    }

    if ([string]::IsNullOrEmpty($guid)) {
        Write-CatLog -Message 'High Performance plan not found.' -Type Warning
        return
    }

    try {
        & powercfg.exe /setactive $guid 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) {
            Write-CatProgress -Message "Power plan set: High Performance ($guid)"
        }
        else {
            Write-CatLog -Message 'Power plan change failed.' -Type Warning
        }
    }
    catch {
        Write-CatLog -Message "Power configuration failed: $($_.Exception.Message)" -Type Warning
    }
}

function Invoke-SculptorEngine {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    $before = Get-SystemBenchmark
    Write-CatHeader -Title 'Sculptor Engine' -Tag '[>>]'
    Write-CatLog -Message 'Performing system analysis...' -Type System

    try {
        $metrics = Get-SystemMetrics
        Write-CatProgress -Message ("Total RAM: {0}GB | Available: {1}MB" -f [math]::Round($metrics.TotalRAM / 1GB, 2), [math]::Round($metrics.AvailableRAM / 1MB, 0))
        Write-CatProgress -Message ("CPU: {0:F1}% | Processes: {1}" -f $metrics.CPUUsage, $metrics.ProcessCount)
    }
    catch {
        Write-CatLog -Message "Analysis failed: $($_.Exception.Message)" -Type Warning
    }

    Write-CatLog -Message 'Initiating optimization sequence...' -Type Info -Tag '[+]'

    $optimized = Optimize-BackgroundProcesses
    Optimize-MemorySettings
    Set-HighPerformancePlan

    $after = Get-SystemBenchmark
    Write-CatLog -Message "Module finished. Processes optimized: $optimized" -Type Success -Tag '[OK]'
    Write-CatLog -Message "Before: $before" -Type Info
    Write-CatLog -Message "After : $after" -Type Info
    Write-CatLog -Message 'A restart may be required.' -Type Warning -Tag '[!]'

    return [pscustomobject]@{
        Module  = 'Sculptor Engine'
        Before  = $before
        After   = $after
        Success = $true
    }
}

Export-ModuleMember -Function Invoke-SculptorEngine