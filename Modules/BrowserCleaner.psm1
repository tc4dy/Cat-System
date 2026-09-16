Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot

Import-Module (Join-Path $root 'Helpers\Benchmark.psm1') -DisableNameChecking -ErrorAction Stop
Import-Module (Join-Path $root 'Core\Logger.psm1') -DisableNameChecking -ErrorAction Stop
Import-Module (Join-Path $root 'Core\RollbackManager.psm1') -DisableNameChecking -ErrorAction Stop

$script:ChromiumTargets = @(
    'Cache'
    'Code Cache'
    'GPUCache'
    'Cookies'
    'Cookies-journal'
    'History'
    'History-journal'
    'Visited Links'
    'Web Data'
    'Web Data-journal'
    'Top Sites'
    'Shortcuts'
)

$script:FirefoxTargets = @(
    'cache2'
    'cookies.sqlite'
    'cookies.sqlite-journal'
    'places.sqlite'
    'places.sqlite-journal'
    'formhistory.sqlite'
    'downloads.sqlite'
    'webappsstore.sqlite'
)

function Get-BrowserProfiles {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param()

    $profiles = New-Object System.Collections.Generic.List[pscustomobject]
    $local = [Environment]::GetFolderPath('LocalApplicationData')
    $roaming = [Environment]::GetFolderPath('ApplicationData')

    $candidates = @(
        @{
            Name     = 'Chrome'
            Path     = Join-Path $local 'Google\Chrome\User Data'
            Profiles = @('Default', 'Profile 1', 'Profile 2', 'Profile 3')
        }
        @{
            Name     = 'Edge'
            Path     = Join-Path $local 'Microsoft\Edge\User Data'
            Profiles = @('Default', 'Profile 1', 'Profile 2', 'Profile 3')
        }
        @{
            Name     = 'Brave'
            Path     = Join-Path $local 'BraveSoftware\Brave-Browser\User Data'
            Profiles = @('Default', 'Profile 1', 'Profile 2')
        }
        @{
            Name     = 'Opera'
            Path     = Join-Path $roaming 'Opera Software\Opera Stable'
            Profiles = @('')
        }
    )

    foreach ($candidate in $candidates) {
        if (Test-Path -LiteralPath $candidate.Path) {
            $profiles.Add([pscustomobject]@{
                Name     = $candidate.Name
                Path     = $candidate.Path
                Profiles = $candidate.Profiles
            })
        }
    }

    $firefoxPath = Join-Path $roaming 'Mozilla\Firefox\Profiles'
    if (Test-Path -LiteralPath $firefoxPath) {
        $ffProfiles = @(Get-ChildItem -LiteralPath $firefoxPath -Directory -ErrorAction SilentlyContinue |
            Select-Object -ExpandProperty Name)
        if ($ffProfiles.Count -gt 0) {
            $profiles.Add([pscustomobject]@{
                Name     = 'Firefox'
                Path     = $firefoxPath
                Profiles = $ffProfiles
            })
        }
    }

    return $profiles.ToArray()
}

function Clear-BrowserProfile {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [pscustomobject]$Browser
    )

    $targets = if ($Browser.Name -eq 'Firefox') { $script:FirefoxTargets } else { $script:ChromiumTargets }
    $success = $false

    foreach ($profile in $Browser.Profiles) {
        $basePath = if ([string]::IsNullOrEmpty($profile)) { $Browser.Path } else { Join-Path $Browser.Path $profile }
        if (-not (Test-Path -LiteralPath $basePath)) { continue }

        foreach ($target in $targets) {
            $targetPath = Join-Path $basePath $target
            if (-not (Test-Path -LiteralPath $targetPath)) { continue }

            try {
                Backup-FileItem -Path $targetPath
                Remove-Item -LiteralPath $targetPath -Recurse -Force -ErrorAction Stop
                $profileLabel = if ([string]::IsNullOrEmpty($profile)) { 'default' } else { $profile }
                Write-CatProgress -Message "Cleared $target in $($Browser.Name) [$profileLabel]"
                $success = $true
            }
            catch {
                Write-Verbose "Failed to clear $targetPath : $($_.Exception.Message)"
            }
        }
    }

    return $success
}

function Invoke-BrowserCleaner {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    $before = Get-SystemBenchmark
    Write-CatHeader -Title 'Browser Cleaner' -Tag '[*]'
    Write-CatLog -Message 'Cleaning browser traces...' -Type System

    $browsers = @(Get-BrowserProfiles)
    $cleaned = 0

    if ($browsers.Count -eq 0) {
        Write-CatLog -Message 'No supported browsers found.' -Type Warning
    }
    else {
        foreach ($browser in $browsers) {
            Write-CatLog -Message "Cleaning $($browser.Name)..." -Type Info -Tag '[w]'
            if (Clear-BrowserProfile -Browser $browser) {
                $cleaned++
            }
        }
    }

    $after = Get-SystemBenchmark
    Write-CatLog -Message "Browser cleaner finished. Cleaned $cleaned/$($browsers.Count)." -Type Success -Tag '[OK]'
    Write-CatLog -Message "Before: $before" -Type Info
    Write-CatLog -Message "After : $after" -Type Info

    return [pscustomobject]@{
        Module  = 'Browser Cleaner'
        Before  = $before
        After   = $after
        Success = ($cleaned -gt 0)
    }
}

Export-ModuleMember -Function Invoke-BrowserCleaner, Get-BrowserProfiles, Clear-BrowserProfile