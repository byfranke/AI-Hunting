<#
.SYNOPSIS
    AI-Hunting Data Collector Module
    Enterprise Threat Hunting - Data Collection Scripts

.DESCRIPTION
    PowerShell module for collecting forensic artifacts from Windows systems.
    Outputs data in JSON format for consumption by the web dashboard.

.AUTHOR
    byFranke

.VERSION
    2.0.0
#>

#Requires -Version 5.1

# Configuration
$ErrorActionPreference = "SilentlyContinue"
$ProgressPreference = "SilentlyContinue"

function Get-SystemServices {
    <#
    .SYNOPSIS
        Collects Windows services information
    #>
    [CmdletBinding()]
    param()

    try {
        $services = Get-CimInstance -ClassName Win32_Service | Select-Object @{
            Name = 'Name'
            Expression = { $_.Name }
        }, @{
            Name = 'DisplayName'
            Expression = { $_.DisplayName }
        }, @{
            Name = 'State'
            Expression = { $_.State }
        }, @{
            Name = 'StartMode'
            Expression = { $_.StartMode }
        }, @{
            Name = 'PathName'
            Expression = { $_.PathName }
        }, @{
            Name = 'ProcessId'
            Expression = { $_.ProcessId }
        }, @{
            Name = 'StartName'
            Expression = { $_.StartName }
        }

        return $services | ConvertTo-Json -Depth 3 -Compress
    }
    catch {
        return @{ error = $_.Exception.Message } | ConvertTo-Json
    }
}

function Get-ServiceHashes {
    <#
    .SYNOPSIS
        Computes SHA256 hashes for service binaries
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [int]$MaxServices = 100
    )

    try {
        $services = Get-CimInstance -ClassName Win32_Service |
            Where-Object { $_.PathName } |
            Select-Object -First $MaxServices

        $results = @()

        foreach ($service in $services) {
            $path = $service.PathName

            # Clean the path (remove quotes and arguments)
            $cleanPath = $path -replace '"', ''
            $cleanPath = $cleanPath -replace '\s+-.*$', ''
            $cleanPath = $cleanPath -replace '\s+/.*$', ''
            $cleanPath = $cleanPath.Trim()

            if (Test-Path $cleanPath -PathType Leaf) {
                try {
                    $hash = (Get-FileHash -Path $cleanPath -Algorithm SHA256).Hash
                    $results += @{
                        ServiceName = $service.Name
                        Path = $cleanPath
                        Hash = $hash
                    }
                }
                catch {
                    # Skip files that cannot be hashed
                }
            }
        }

        return $results | ConvertTo-Json -Depth 3 -Compress
    }
    catch {
        return @{ error = $_.Exception.Message } | ConvertTo-Json
    }
}

function Get-StartupRegistry {
    <#
    .SYNOPSIS
        Collects startup registry entries
    #>
    [CmdletBinding()]
    param()

    try {
        $registryPaths = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
        )

        $results = @()

        foreach ($regPath in $registryPaths) {
            if (Test-Path $regPath) {
                $items = Get-ItemProperty -Path $regPath
                $items.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
                    $results += @{
                        Path = $regPath
                        Name = $_.Name
                        Value = $_.Value
                    }
                }
            }
        }

        return $results | ConvertTo-Json -Depth 3 -Compress
    }
    catch {
        return @{ error = $_.Exception.Message } | ConvertTo-Json
    }
}

function Get-ScheduledTasksInfo {
    <#
    .SYNOPSIS
        Collects scheduled tasks information
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [switch]$ActiveOnly
    )

    try {
        $tasks = Get-ScheduledTask

        if ($ActiveOnly) {
            $tasks = $tasks | Where-Object { $_.State -ne 'Disabled' }
        }

        $results = $tasks | Select-Object @{
            Name = 'TaskName'
            Expression = { $_.TaskName }
        }, @{
            Name = 'TaskPath'
            Expression = { $_.TaskPath }
        }, @{
            Name = 'State'
            Expression = { $_.State.ToString() }
        }, @{
            Name = 'Actions'
            Expression = { ($_.Actions | ForEach-Object { $_.Execute }) -join '; ' }
        }, @{
            Name = 'Author'
            Expression = { $_.Author }
        }

        return $results | ConvertTo-Json -Depth 3 -Compress
    }
    catch {
        return @{ error = $_.Exception.Message } | ConvertTo-Json
    }
}

function Get-SecurityEvents {
    <#
    .SYNOPSIS
        Collects security-relevant Windows events
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [int]$MaxEvents = 100,

        [Parameter(Mandatory = $false)]
        [int[]]$EventIds = @(7045, 7040, 4688, 4697)
    )

    try {
        $results = @()

        # System log - Service installations (7045)
        $systemEvents = Get-WinEvent -FilterHashtable @{
            LogName = 'System'
            Id = @(7045, 7040)
        } -MaxEvents $MaxEvents -ErrorAction SilentlyContinue

        foreach ($event in $systemEvents) {
            $results += @{
                LogName = 'System'
                TimeCreated = $event.TimeCreated.ToString('o')
                Id = $event.Id
                Message = $event.Message
                ProviderName = $event.ProviderName
            }
        }

        # Security log - Process creation (4688) and Service installation (4697)
        $securityEvents = Get-WinEvent -FilterHashtable @{
            LogName = 'Security'
            Id = @(4688, 4697)
        } -MaxEvents $MaxEvents -ErrorAction SilentlyContinue

        foreach ($event in $securityEvents) {
            $results += @{
                LogName = 'Security'
                TimeCreated = $event.TimeCreated.ToString('o')
                Id = $event.Id
                Message = $event.Message
                ProviderName = $event.ProviderName
            }
        }

        return $results | Sort-Object TimeCreated -Descending | ConvertTo-Json -Depth 3 -Compress
    }
    catch {
        return @{ error = $_.Exception.Message } | ConvertTo-Json
    }
}

function Get-LoadedDrivers {
    <#
    .SYNOPSIS
        Collects loaded drivers information
    #>
    [CmdletBinding()]
    param()

    try {
        $drivers = Get-CimInstance -ClassName Win32_SystemDriver | Select-Object @{
            Name = 'Name'
            Expression = { $_.Name }
        }, @{
            Name = 'DisplayName'
            Expression = { $_.DisplayName }
        }, @{
            Name = 'State'
            Expression = { $_.State }
        }, @{
            Name = 'PathName'
            Expression = { $_.PathName }
        }, @{
            Name = 'ServiceType'
            Expression = { $_.ServiceType }
        }, @{
            Name = 'StartMode'
            Expression = { $_.StartMode }
        }

        return $drivers | ConvertTo-Json -Depth 3 -Compress
    }
    catch {
        return @{ error = $_.Exception.Message } | ConvertTo-Json
    }
}

function Get-NetworkConnections {
    <#
    .SYNOPSIS
        Collects active network connections
    #>
    [CmdletBinding()]
    param()

    try {
        $connections = Get-NetTCPConnection -State Established, Listen | Select-Object @{
            Name = 'LocalAddress'
            Expression = { $_.LocalAddress }
        }, @{
            Name = 'LocalPort'
            Expression = { $_.LocalPort }
        }, @{
            Name = 'RemoteAddress'
            Expression = { $_.RemoteAddress }
        }, @{
            Name = 'RemotePort'
            Expression = { $_.RemotePort }
        }, @{
            Name = 'State'
            Expression = { $_.State.ToString() }
        }, @{
            Name = 'OwningProcess'
            Expression = { $_.OwningProcess }
        }, @{
            Name = 'ProcessName'
            Expression = { (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName }
        }

        return $connections | ConvertTo-Json -Depth 3 -Compress
    }
    catch {
        return @{ error = $_.Exception.Message } | ConvertTo-Json
    }
}

function Get-ProcessList {
    <#
    .SYNOPSIS
        Collects running processes with details
    #>
    [CmdletBinding()]
    param()

    try {
        $processes = Get-Process | Select-Object @{
            Name = 'Name'
            Expression = { $_.Name }
        }, @{
            Name = 'Id'
            Expression = { $_.Id }
        }, @{
            Name = 'Path'
            Expression = { $_.Path }
        }, @{
            Name = 'Company'
            Expression = { $_.Company }
        }, @{
            Name = 'CPU'
            Expression = { [math]::Round($_.CPU, 2) }
        }, @{
            Name = 'WorkingSet'
            Expression = { [math]::Round($_.WorkingSet64 / 1MB, 2) }
        }, @{
            Name = 'StartTime'
            Expression = { $_.StartTime.ToString('o') }
        }

        return $processes | ConvertTo-Json -Depth 3 -Compress
    }
    catch {
        return @{ error = $_.Exception.Message } | ConvertTo-Json
    }
}

function Get-SystemInfo {
    <#
    .SYNOPSIS
        Collects system information
    #>
    [CmdletBinding()]
    param()

    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem
        $bios = Get-CimInstance -ClassName Win32_BIOS

        $info = @{
            ComputerName = $env:COMPUTERNAME
            OSName = $os.Caption
            OSVersion = $os.Version
            OSBuild = $os.BuildNumber
            Architecture = $os.OSArchitecture
            Manufacturer = $cs.Manufacturer
            Model = $cs.Model
            Domain = $cs.Domain
            TotalMemoryGB = [math]::Round($cs.TotalPhysicalMemory / 1GB, 2)
            BIOSVersion = $bios.SMBIOSBIOSVersion
            SerialNumber = $bios.SerialNumber
            LastBootTime = $os.LastBootUpTime.ToString('o')
            CurrentUser = $env:USERNAME
            CollectionTime = (Get-Date).ToString('o')
        }

        return $info | ConvertTo-Json -Depth 3 -Compress
    }
    catch {
        return @{ error = $_.Exception.Message } | ConvertTo-Json
    }
}

function Invoke-FullCollection {
    <#
    .SYNOPSIS
        Runs full data collection and outputs combined results
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$OutputPath
    )

    $results = @{
        CollectionTime = (Get-Date).ToString('o')
        SystemInfo = Get-SystemInfo | ConvertFrom-Json
        Services = Get-SystemServices | ConvertFrom-Json
        Hashes = Get-ServiceHashes | ConvertFrom-Json
        Registry = Get-StartupRegistry | ConvertFrom-Json
        ScheduledTasks = Get-ScheduledTasksInfo -ActiveOnly | ConvertFrom-Json
        Events = Get-SecurityEvents -MaxEvents 50 | ConvertFrom-Json
        Drivers = Get-LoadedDrivers | ConvertFrom-Json
        NetworkConnections = Get-NetworkConnections | ConvertFrom-Json
        Processes = Get-ProcessList | ConvertFrom-Json
    }

    $json = $results | ConvertTo-Json -Depth 10

    if ($OutputPath) {
        $json | Out-File -FilePath $OutputPath -Encoding UTF8
        Write-Host "Results saved to: $OutputPath"
    }

    return $json
}

# Export functions
Export-ModuleMember -Function @(
    'Get-SystemServices',
    'Get-ServiceHashes',
    'Get-StartupRegistry',
    'Get-ScheduledTasksInfo',
    'Get-SecurityEvents',
    'Get-LoadedDrivers',
    'Get-NetworkConnections',
    'Get-ProcessList',
    'Get-SystemInfo',
    'Invoke-FullCollection'
)
