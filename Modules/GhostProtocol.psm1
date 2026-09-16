Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot

Import-Module (Join-Path $root 'Helpers\Benchmark.psm1') -DisableNameChecking -ErrorAction Stop
Import-Module (Join-Path $root 'Core\Logger.psm1') -DisableNameChecking -ErrorAction Stop
Import-Module (Join-Path $root 'Core\RollbackManager.psm1') -DisableNameChecking -ErrorAction Stop
Import-Module (Join-Path $root 'Core\RegistryHandler.psm1') -DisableNameChecking -ErrorAction Stop

$script:TelemetryHosts = @(
    'vortex.data.microsoft.com'
    'vortex-win.data.microsoft.com'
    'telecommand.telemetry.microsoft.com'
    'oca.telemetry.microsoft.com'
    'sqm.telemetry.microsoft.com'
    'watson.telemetry.microsoft.com'
    'redir.metaservices.microsoft.com'
    'choice.microsoft.com'
    'df.telemetry.microsoft.com'
    'reports.wes.df.telemetry.microsoft.com'
    'wes.df.telemetry.microsoft.com'
    'services.wes.df.telemetry.microsoft.com'
    'sqm.df.telemetry.microsoft.com'
    'telemetry.microsoft.com'
    'watson.ppe.telemetry.microsoft.com'
    'settings-sandbox.data.microsoft.com'
    'i1.services.social.microsoft.com'
    'i1.services.social.microsoft.com.nsatc.net'
    'fe2.update.microsoft.com.akadns.net'
    'statsfe2.update.microsoft.com.akadns.net'
    'corpext.msitadfs.glbdns2.microsoft.com'
    'compatexchange.cloudapp.net'
    'cs1.wpc.v0cdn.net'
    'a-0001.a-msedge.net'
    'activity.windows.com'
    'browser.pipe.aria.microsoft.com'
    'telemetry.dropbox.com'
)

$script:TelemetryTasks = @(
    @{ Path = '\Microsoft\Windows\Application Experience\'; Name = 'Microsoft Compatibility Appraiser' }
    @{ Path = '\Microsoft\Windows\Application Experience\'; Name = 'ProgramDataUpdater' }
    @{ Path = '\Microsoft\Windows\Application Experience\'; Name = 'StartupAppTask' }
    @{ Path = '\Microsoft\Windows\Autochk\'; Name = 'Proxy' }
    @{ Path = '\Microsoft\Windows\Customer Experience Improvement Program\'; Name = 'Consolidator' }
    @{ Path = '\Microsoft\Windows\Customer Experience Improvement Program\'; Name = 'KernelCeipTask' }
    @{ Path = '\Microsoft\Windows\Customer Experience Improvement Program\'; Name = 'UsbCeip' }
    @{ Path = '\Microsoft\Windows\DiskDiagnostic\'; Name = 'Microsoft-Windows-DiskDiagnosticDataCollector' }
    @{ Path = '\Microsoft\Windows\Feedback\Siuf\'; Name = 'DmClient' }
    @{ Path = '\Microsoft\Windows\Feedback\Siuf\'; Name = 'DmClientOnScenarioDownload' }
    @{ Path = '\Microsoft\Windows\Windows Error Reporting\'; Name = 'QueueReporting' }
    @{ Path = '\Microsoft\Windows\CloudExperienceHost\'; Name = 'CreateObjectTask' }
)

$script:HardDisabledServices = @(
    'dmwappushservice'
    'WerSvc'
    'RetailDemo'
    'DiagTrack'
)

$script:ManualDisabledServices = @(
    'PcaSvc'
)

$script:HostsStartMarker = '# CatSystem-Telemetry-Block'
$script:HostsEndMarker = '# CatSystem-Telemetry-Block-END'

function Disable-Telemetry {
    [CmdletBinding()]
    [OutputType([void])]
    param()

    $null = Set-RegistryKey -Root 'HKLM' -SubKey 'SOFTWARE\Policies\Microsoft\Windows\DataCollection' -ValueName 'AllowTelemetry' -Value 0 -Kind DWord
    $null = Set-RegistryKey -Root 'HKLM' -SubKey 'SOFTWARE\Policies\Microsoft\Windows\DataCollection' -ValueName 'MaxTelemetryAllowed' -Value 0 -Kind DWord
    $null = Set-RegistryKey -Root 'HKLM' -SubKey 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection' -ValueName 'AllowTelemetry' -Value 0 -Kind DWord
    $null = Set-RegistryKey -Root 'HKLM' -SubKey 'SOFTWARE\Microsoft\SQMClient\Windows' -ValueName 'CEIPEnable' -Value 0 -Kind DWord
    $null = Set-RegistryKey -Root 'HKLM' -SubKey 'SOFTWARE\Microsoft\Windows\Windows Error Reporting' -ValueName 'Disabled' -Value 1 -Kind DWord
    $null = Set-RegistryKey -Root 'HKLM' -SubKey 'SOFTWARE\Policies\Microsoft\Windows\DataCollection' -ValueName 'DoNotShowFeedbackNotifications' -Value 1 -Kind DWord
}

function Disable-Advertising {
    [CmdletBinding()]
    [OutputType([void])]
    param()

    $null = Set-RegistryKey -Root 'HKLM' -SubKey 'SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo' -ValueName 'Enabled' -Value 0 -Kind DWord
    $null = Set-RegistryKey -Root 'HKCU' -SubKey 'Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo' -ValueName 'Enabled' -Value 0 -Kind DWord
    $null = Set-RegistryKey -Root 'HKCU' -SubKey 'Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -ValueName 'SilentInstalledAppsEnabled' -Value 0 -Kind DWord
    $null = Set-RegistryKey -Root 'HKCU' -SubKey 'Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -ValueName 'SystemPaneSuggestionsEnabled' -Value 0 -Kind DWord
    $null = Set-RegistryKey -Root 'HKCU' -SubKey 'Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -ValueName 'SubscribedContent-338388Enabled' -Value 0 -Kind DWord
    $null = Set-RegistryKey -Root 'HKCU' -SubKey 'Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -ValueName 'SubscribedContent-338389Enabled' -Value 0 -Kind DWord
}

function Disable-BingSearch {
    [CmdletBinding()]
    [OutputType([void])]
    param()

    $null = Set-RegistryKey -Root 'HKLM' -SubKey 'SOFTWARE\Policies\Microsoft\Windows\Windows Search' -ValueName 'DisableWebSearch' -Value 1 -Kind DWord
    $null = Set-RegistryKey -Root 'HKLM' -SubKey 'SOFTWARE\Policies\Microsoft\Windows\Windows Search' -ValueName 'ConnectedSearchUseWeb' -Value 0 -Kind DWord
    $null = Set-RegistryKey -Root 'HKLM' -SubKey 'SOFTWARE\Policies\Microsoft\Windows\Windows Search' -ValueName 'AllowCortana' -Value 0 -Kind DWord
    $null = Set-RegistryKey -Root 'HKLM' -SubKey 'SOFTWARE\Policies\Microsoft\Windows\Windows Search' -ValueName 'AllowCloudSearch' -Value 0 -Kind DWord
    $null = Set-RegistryKey -Root 'HKCU' -SubKey 'Software\Microsoft\Windows\CurrentVersion\Search' -ValueName 'BingSearchEnabled' -Value 0 -Kind DWord
}

function Disable-Location {
    [CmdletBinding()]
    [OutputType([void])]
    param()

    $null = Set-RegistryKey -Root 'HKLM' -SubKey 'SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location' -ValueName 'Value' -Value 'Deny' -Kind String
    $null = Set-RegistryKey -Root 'HKCU' -SubKey 'Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location' -ValueName 'Value' -Value 'Deny' -Kind String
    $null = Set-RegistryKey -Root 'HKLM' -SubKey 'SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config' -ValueName 'AutoConnectAllowedOEM' -Value 0 -Kind DWord
}

function Disable-ActivityHistory {
    [CmdletBinding()]
    [OutputType([void])]
    param()

    $null = Set-RegistryKey -Root 'HKLM' -SubKey 'SOFTWARE\Policies\Microsoft\Windows\System' -ValueName 'EnableActivityFeed' -Value 0 -Kind DWord
    $null = Set-RegistryKey -Root 'HKLM' -SubKey 'SOFTWARE\Policies\Microsoft\Windows\System' -ValueName 'PublishUserActivities' -Value 0 -Kind DWord
    $null = Set-RegistryKey -Root 'HKLM' -SubKey 'SOFTWARE\Policies\Microsoft\Windows\System' -ValueName 'UploadUserActivities' -Value 0 -Kind DWord
    $null = Set-RegistryKey -Root 'HKLM' -SubKey 'SOFTWARE\Policies\Microsoft\Windows\System' -ValueName 'AllowClipboardHistory' -Value 0 -Kind DWord
    $null = Set-RegistryKey -Root 'HKLM' -SubKey 'SOFTWARE\Policies\Microsoft\Windows\System' -ValueName 'AllowCrossDeviceClipboard' -Value 0 -Kind DWord
}

function Disable-InputPersonalization {
    [CmdletBinding()]
    [OutputType([void])]
    param()

    $null = Set-RegistryKey -Root 'HKCU' -SubKey 'Software\Microsoft\InputPersonalization' -ValueName 'RestrictImplicitInkCollection' -Value 1 -Kind DWord
    $null = Set-RegistryKey -Root 'HKCU' -SubKey 'Software\Microsoft\InputPersonalization' -ValueName 'RestrictImplicitTextCollection' -Value 1 -Kind DWord
    $null = Set-RegistryKey -Root 'HKCU' -SubKey 'Software\Microsoft\Input\TIPC' -ValueName 'Enabled' -Value 0 -Kind DWord
    $null = Set-RegistryKey -Root 'HKCU' -SubKey 'Software\Microsoft\Siuf\Rules' -ValueName 'NumberOfSIUFInPeriod' -Value 0 -Kind DWord
}

function Disable-AppDiagnostics {
    [CmdletBinding()]
    [OutputType([void])]
    param()

    $null = Set-RegistryKey -Root 'HKLM' -SubKey 'SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics' -ValueName 'Value' -Value 'Deny' -Kind String
    $null = Set-RegistryKey -Root 'HKCU' -SubKey 'Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics' -ValueName 'Value' -Value 'Deny' -Kind String
}

function Disable-ConsumerFeatures {
    [CmdletBinding()]
    [OutputType([void])]
    param()

    $null = Set-RegistryKey -Root 'HKLM' -SubKey 'SOFTWARE\Policies\Microsoft\Windows\CloudContent' -ValueName 'DisableWindowsConsumerFeatures' -Value 1 -Kind DWord
    $null = Set-RegistryKey -Root 'HKCU' -SubKey 'Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -ValueName 'OemPreInstalledAppsEnabled' -Value 0 -Kind DWord
    $null = Set-RegistryKey -Root 'HKCU' -SubKey 'Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -ValueName 'PreInstalledAppsEnabled' -Value 0 -Kind DWord
}

function Set-ServiceStartValue {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$ServiceName,

        [Parameter(Mandatory = $true)]
        [ValidateRange(2, 4)]
        [int]$StartValue
    )

    $regPath = "SYSTEM\CurrentControlSet\Services\$ServiceName"
    return Set-RegistryKey -Root 'HKLM' -SubKey $regPath -ValueName 'Start' -Value $StartValue -Kind DWord
}

function Disable-TelemetryServices {
    [CmdletBinding()]
    [OutputType([int])]
    param()

    $disabled = 0

    foreach ($svcName in $script:HardDisabledServices) {
        try {
            $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
            if ($null -eq $svc) { continue }

            $null = Set-ServiceStartValue -ServiceName $svcName -StartValue 4

            if ($svc.Status -eq 'Running') {
                Stop-Service -Name $svcName -Force -ErrorAction SilentlyContinue
            }

            Write-CatProgress -Message "Service disabled: $svcName"
            $disabled++
        }
        catch {
            Write-Verbose "Service disable skipped: $svcName : $($_.Exception.Message)"
        }
    }

    foreach ($svcName in $script:ManualDisabledServices) {
        try {
            $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
            if ($null -eq $svc) { continue }

            $null = Set-ServiceStartValue -ServiceName $svcName -StartValue 3

            if ($svc.Status -eq 'Running') {
                Stop-Service -Name $svcName -Force -ErrorAction SilentlyContinue
            }

            Write-CatProgress -Message "Service set to manual: $svcName"
            $disabled++
        }
        catch {
            Write-Verbose "Service manual-mode skipped: $svcName : $($_.Exception.Message)"
        }
    }

    return $disabled
}

function Disable-TelemetryTasks {
    [CmdletBinding()]
    [OutputType([int])]
    param()

    $disabled = 0

    foreach ($taskDef in $script:TelemetryTasks) {
        try {
            $task = Get-ScheduledTask -TaskPath $taskDef.Path -TaskName $taskDef.Name -ErrorAction SilentlyContinue
            if ($null -eq $task) { continue }
            if ($task.State -eq 'Disabled') { continue }

            Backup-ScheduledTaskState -TaskPath $taskDef.Path -TaskName $taskDef.Name -OriginalState $task.State

            Disable-ScheduledTask -TaskPath $taskDef.Path -TaskName $taskDef.Name -ErrorAction Stop | Out-Null
            Write-CatProgress -Message "Task disabled: $($taskDef.Name)"
            $disabled++
        }
        catch {
            Write-Verbose "Task disable skipped: $($taskDef.Name) : $($_.Exception.Message)"
        }
    }

    return $disabled
}

function Test-HostsBlockPresent {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Marker
    )

    if (-not (Test-Path -LiteralPath $Path)) { return $false }

    try {
        $content = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop
    }
    catch {
        return $false
    }

    if ($null -eq $content) { return $false }
    return ($content -match [regex]::Escape($Marker))
}

function Add-TelemetryHostsBlock {
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    $hostsPath = Join-Path $env:windir 'System32\drivers\etc\hosts'
    if (-not (Test-Path -LiteralPath $hostsPath)) {
        Write-CatLog -Message 'Hosts file not found.' -Type Warning
        return $false
    }

    if (Test-HostsBlockPresent -Path $hostsPath -Marker $script:HostsStartMarker) {
        Write-CatProgress -Message 'Telemetry hosts block already present.'
        return $false
    }

    Backup-HostsBlock -Path $hostsPath -StartMarker $script:HostsStartMarker -EndMarker $script:HostsEndMarker

    $builder = New-Object System.Text.StringBuilder
    [void]$builder.AppendLine('')
    [void]$builder.AppendLine($script:HostsStartMarker)
    foreach ($domain in $script:TelemetryHosts) {
        [void]$builder.AppendLine(('0.0.0.0 {0}' -f $domain))
    }
    [void]$builder.AppendLine($script:HostsEndMarker)

    try {
        Add-Content -LiteralPath $hostsPath -Value $builder.ToString() -Encoding ASCII -ErrorAction Stop
        Write-CatProgress -Message ("Hosts file updated with {0} blocked domains." -f $script:TelemetryHosts.Count)
        return $true
    }
    catch {
        Write-CatLog -Message "Hosts write failed: $($_.Exception.Message)" -Type Error
        return $false
    }
}

function Set-MemoryForensicMitigation {
    [CmdletBinding()]
    [OutputType([void])]
    param()

    $null = Set-RegistryKey -Root 'HKLM' -SubKey 'SYSTEM\CurrentControlSet\Control\CrashControl' -ValueName 'CrashDumpEnabled' -Value 0 -Kind DWord
    $null = Set-RegistryKey -Root 'HKLM' -SubKey 'SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' -ValueName 'ClearPageFileAtShutdown' -Value 1 -Kind DWord
}

function Invoke-GhostProtocol {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    $before = Get-SystemBenchmark
    Write-CatHeader -Title 'Ghost Protocol' -Tag '[+]'
    Write-CatLog -Message 'Performing privacy hardening...' -Type System

    Write-Host ''
    Write-Host 'Forensic mitigation (disable crash dumps, clear pagefile at shutdown)' -ForegroundColor Yellow
    Write-Host 'May slow down system shutdown on HDD.' -ForegroundColor DarkGray
    $forensicRaw = [string](Read-Host 'Enable forensic mitigation? (y/n)')
    $forensicEnabled = $forensicRaw.Trim() -match '^[Yy]'

    $tweaks = @(
        @{ Name = 'Windows Telemetry';         Action = { Disable-Telemetry } }
        @{ Name = 'Advertising Tracking';      Action = { Disable-Advertising } }
        @{ Name = 'Web Search in Start';       Action = { Disable-BingSearch } }
        @{ Name = 'Location Tracking';         Action = { Disable-Location } }
        @{ Name = 'Activity History';          Action = { Disable-ActivityHistory } }
        @{ Name = 'Input Personalization';     Action = { Disable-InputPersonalization } }
        @{ Name = 'App Diagnostics';           Action = { Disable-AppDiagnostics } }
        @{ Name = 'Consumer Features';         Action = { Disable-ConsumerFeatures } }
        @{ Name = 'Telemetry Services';        Action = { $null = Disable-TelemetryServices } }
        @{ Name = 'Telemetry Scheduled Tasks'; Action = { $null = Disable-TelemetryTasks } }
        @{ Name = 'Hosts Telemetry Blocker';   Action = { $null = Add-TelemetryHostsBlock } }
    )

    if ($forensicEnabled) {
        $tweaks += @{ Name = 'Forensic Mitigation'; Action = { Set-MemoryForensicMitigation } }
    }

    $completed = 0

    foreach ($tweak in $tweaks) {
        Write-CatLog -Message "Processing: $($tweak.Name)..." -Type Info -Tag '[+]'
        try {
            & $tweak.Action
            $completed++
        }
        catch {
            Write-CatLog -Message "Failed: $($tweak.Name): $($_.Exception.Message)" -Type Warning
        }
    }

    $after = Get-SystemBenchmark
    Write-CatLog -Message "Module finished [$completed/$($tweaks.Count)]" -Type Success -Tag '[OK]'
    Write-CatLog -Message "Before: $before" -Type Info
    Write-CatLog -Message "After : $after" -Type Info

    return [pscustomobject]@{
        Module  = 'Ghost Protocol'
        Before  = $before
        After   = $after
        Success = ($completed -gt 0)
    }
}

Export-ModuleMember -Function Invoke-GhostProtocol