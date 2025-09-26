$global:DebugMode = $true
$logDir = "$env:USERPROFILE\Desktop\threat_hunt_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss')"
$outputExcel = "$logDir\threat_hunt_report.xlsx"
$quarantineDir = "$logDir\quarantine"
$scriptStartTime = Get-Date

Write-Host @"

                                 @@ *%%*                                        
                          %                    @,                               
                       #  &          @             @#                           
                       #                    ,*.                                 
                     .                  ,(            (   @(                    
                    .     %      .@ .&               ,        %                 
                   /                                   %      &                 
                   && &&        (,              # /@                            
                    @            %  .        ,*        ,.    %  %               
                 ,* *  #      (                                  ,              
                @        **    / (( /          /  /    &      @  ,              
     #     @                               *%     % @      #  &  ,              
    @                                #%/            #      .         %          
                                     @             @/          *           @    
                                 .                                              
                                                      ,                         
                                %.                    ,                         
                                                       /     ,/                 
                                                      #(                        
                                  %.                   ,                        
                                                       .                        
                                                       .                        

                             Advanced Incident Hunting
                                   byfranke 2025
                                https://byfranke.com
"@ -ForegroundColor Cyan

# Admin Privilege Verification
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "`nELEVATION REQUIRED: Run as Administrator`n" -ForegroundColor Red
    exit 1
}

# Logging Infrastructure
if (-not (Test-Path $logDir)) { New-Item -Path $logDir -ItemType Directory | Out-Null }
Start-Transcript -Path "$logDir\forensic_audit.log" -Append
New-Item -Path $quarantineDir -ItemType Directory -Force | Out-Null
#endregion

#region Enterprise Modules
# ------------------------
function Initialize-SecurityModules {
    $requiredModules = @("ImportExcel", "PSFramework")
    
    foreach ($module in $requiredModules) {
        if (-not (Get-Module -ListAvailable -Name $module)) {
            try {
                Install-Module -Name $module -Force -Scope CurrentUser -ErrorAction Stop
            }
            catch {
                Write-Host "CRITICAL: Failed to install $module module" -ForegroundColor Red
                exit 1
            }
        }
        Import-Module -Name $module -Force -ErrorAction Stop
    }
}
Initialize-SecurityModules
#endregion

#region Core Functions
# --------------------
function Get-SecureVTKey {
    $vtKeyPath = "$env:USERPROFILE\.vtkey"
    if (Test-Path $vtKeyPath) {
        return Get-Content $vtKeyPath -Raw
    }
    else {
        Write-Host "`nEnter VirusTotal API Key:" -ForegroundColor Yellow
        $secureKey = Read-Host -AsSecureString
        $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureKey)
        return [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
    }
}

function Invoke-ForensicCollection {
    [CmdletBinding()]
    param()

    try {
        $services = Get-CimInstance Win32_Service -ErrorAction Stop | 
                    Where-Object { $_.PathName -match '\.exe' }
    }
    catch {
        Write-Host "Service enumeration failed: $_" -ForegroundColor Red
        exit 1
    }

    $hashResults = $services | ForEach-Object -Parallel {
        $service = $_
        $rawPath = $service.PathName
        
        try {
            $cleanPath = ($rawPath -replace '"', '') -split ' ' | 
                        Select-Object -First 1 |
                        Where-Object { $_ -ne $null }

            if (-not $cleanPath -or -not (Test-Path -Path $cleanPath -PathType Leaf)) {
                return [PSCustomObject]@{
                    ServiceName = $service.Name
                    DisplayName = $service.DisplayName
                    BinaryPath  = if ($cleanPath) { $cleanPath } else { "INVALID_PATH" }
                    SHA256      = "INVALID_PATH"
                    VTStatus    = "ERROR"
                    IsLOLBAS    = $false
                }
            }

            $hash = try {
                Get-FileHash -Path $cleanPath -Algorithm SHA256 -ErrorAction Stop
            }
            catch {
                return [PSCustomObject]@{
                    ServiceName = $service.Name
                    DisplayName = $service.DisplayName
                    BinaryPath  = $cleanPath
                    SHA256      = "ACCESS_DENIED"
                    VTStatus    = "ERROR"
                    IsLOLBAS    = $false
                }
            }

            [PSCustomObject]@{
                ServiceName = $service.Name
                DisplayName = $service.DisplayName
                BinaryPath  = $cleanPath
                SHA256      = $hash.Hash
                VTStatus    = "Pending"
                IsLOLBAS    = $false
            }
        }
        catch {
            [PSCustomObject]@{
                ServiceName = $service.Name
                DisplayName = $service.DisplayName
                BinaryPath  = "UNKNOWN"
                SHA256      = "PROCESS_ERROR"
                VTStatus    = "ERROR"
                IsLOLBAS    = $false
            }
        }
    } -ThrottleLimit (([int]$env:NUMBER_OF_PROCESSORS)*2) -AsJob |
       Wait-Job -Timeout 600 |
       Receive-Job -ErrorAction SilentlyContinue

    if (-not $hashResults) {
        Write-Host "Forensic collection failed to return valid data" -ForegroundColor Red
        exit 1
    }

    return $hashResults
}

function Invoke-VTEnterpriseScan {
    param($hashResults, $VTApiKey)
    
    $vtResults = @()
    $global:VTCache = @{}
    $global:malicious = 0

    $uniqueHashes = $hashResults | Where-Object { 
        $_.SHA256 -match '^[A-F0-9]{64}$' -and 
        $_.VTStatus -eq "Pending"
    } | Group-Object SHA256 | ForEach-Object { $_.Group[0] }

    $total = $uniqueHashes.Count
    $counter = 0
    
    $uniqueHashes | ForEach-Object {
        $currentHash = $_
        $counter++
        Write-Progress -Activity "VirusTotal Enterprise Scan" -Status "$counter/$total" -PercentComplete ($counter/$total*100)
        
        try {
            if ($global:VTCache.ContainsKey($currentHash.SHA256)) {
                $status = $global:VTCache[$currentHash.SHA256]
            }
            else {
                $response = Invoke-RestMethod -Uri "https://www.virustotal.com/api/v3/files/$($currentHash.SHA256)" `
                    -Headers @{ "x-apikey" = $VTApiKey } `
                    -TimeoutSec 30

                $analysis = $response.data.attributes.last_analysis_stats
                $global:malicious = $analysis.malicious
                
                $status = switch ($global:malicious) {
                    { $_ -gt 10 } { "CRITICAL ($_/92)" }
                    { $_ -gt 0 }  { "SUSPICIOUS ($_/92)" }
                    default       { "CLEAN" }
                }
                
                $global:VTCache[$currentHash.SHA256] = $status
            }

            $hashResults | Where-Object { $_.SHA256 -eq $currentHash.SHA256 } | ForEach-Object {
                $_.VTStatus = $status
                if ($global:malicious -gt 0 -and $_.BinaryPath -ne "INVALID_PATH") {
                    $quarantinePath = Join-Path $quarantineDir (Split-Path $_.BinaryPath -Leaf)
                    if (Test-Path $_.BinaryPath -PathType Leaf) {
                        Move-Item -Path $_.BinaryPath -Destination $quarantinePath -Force -ErrorAction SilentlyContinue
                        if (Test-Path $quarantinePath) {
                            $_.VTStatus += " [QUARANTINED]"
                        }
                    }
                }
            }
        }
        catch {
            $hashResults | Where-Object { $_.SHA256 -eq $currentHash.SHA256 } | ForEach-Object {
                $_.VTStatus = "VT_API_ERROR"
            }
        }
        Start-Sleep -Milliseconds 1000
    }
    return $hashResults
}

function Get-LOLBASIndicators {
    $lolbasDB = try {
        Invoke-RestMethod "https://lolbas-project.github.io/api/lolbas.json" -TimeoutSec 30
    }
    catch {
        Write-Host "LOLBAS database unavailable" -ForegroundColor Yellow
        return @()
    }
    
    return $vtResults | Where-Object {
        $lolbasDB.FullPath -contains $_.BinaryPath
    }
}
#endregion

#region Enterprise Execution Flow
# -------------------------------
Write-Host "`nInitializing AI-Hunting..." -ForegroundColor Green

# Phase 1: Forensic Artifact Collection
$serviceData = Invoke-ForensicCollection

# Phase 2: Cloud Intelligence Integration
$VTApiKey = Get-SecureVTKey
$vtResults = Invoke-VTEnterpriseScan -hashResults $serviceData -VTApiKey $VTApiKey

# Phase 3: Tactical Pattern Detection
$lolbasMatches = Get-LOLBASIndicators

# Phase 4: Enhanced Enterprise Reporting
Write-Host "`nGenerating executive reports..." -ForegroundColor Cyan

$limitTime = (Get-Date).AddMinutes(-30)

$reportSections = [ordered]@{
    "VT Findings" = $vtResults | Select-Object ServiceName, DisplayName, BinaryPath, SHA256, VTStatus
    "LOLBAS Alerts" = $lolbasMatches | Select-Object ServiceName, DisplayName, BinaryPath, SHA256
    "Driver Audit" = (driverquery /FO CSV | ConvertFrom-Csv) | Select-Object "Display Name", "Driver Name", "State", "Start Mode"
    
    "Recent Services" = Get-CimInstance Win32_Service | 
        Where-Object { 
            $_.InstallDate -and 
            ([DateTime]::ParseExact($_.InstallDate, 'yyyyMMddHHmmss.ffffff', $null) -gt $limitTime)
        } |
        Select-Object Name, DisplayName, State, StartMode, StartName, PathName, 
            @{Name="InstallDate"; Expression={[DateTime]::ParseExact($_.InstallDate, 'yyyyMMddHHmmss.ffffff', $null)}}
    
    "Startup Entries" = foreach ($key in @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
    )) {
        try {
            Get-ItemProperty -Path $key -ErrorAction Stop | ForEach-Object {
                $_.PSObject.Properties | Where-Object Name -ne "PSPath" | ForEach-Object {
                    [PSCustomObject]@{
                        RegistryPath = $key
                        EntryName   = $_.Name
                        CommandLine = $_.Value
                        Executable  = ($_.Value -split '\s+' | Select-Object -First 1)
                    }
                }
            }
        } catch {
            Write-Warning "Failed to access registry key: $key"
            continue
        }
    }
    
    "Active Tasks" = Get-ScheduledTask | 
        Where-Object State -ne 'Disabled' |
        Select-Object TaskName, Description, State, Author,
            @{Name="Actions"; Expression={$_.Actions.Execute}},
            @{Name="Triggers"; Expression={$_.Triggers | Select-Object -ExpandProperty StartBoundary}}
    
    "Service Events" = try {
        Get-WinEvent -FilterHashtable @{
            LogName = 'System'
            Id = 7045
            StartTime = $limitTime
        } -ErrorAction Stop | ForEach-Object {
            [PSCustomObject]@{
                TimeCreated = $_.TimeCreated
                ServiceName = $_.Properties[0].Value
                BinaryPath  = $_.Properties[1].Value
                Account     = $_.Properties[2].Value
            }
        }
    } catch {
        Write-Warning "Failed to retrieve service events: $_"
        @()
    }
}

$reportSections["Executive Dashboard"] = [PSCustomObject]@{
    ScannedServices    = $vtResults.Count
    CriticalFindings   = ($vtResults | Where-Object { $_.VTStatus -match "CRITICAL" }).Count
    LOLBASMatches      = $lolbasMatches.Count
    QuarantinedItems   = ($vtResults | Where-Object { $_.VTStatus -match "QUARANTINED" }).Count
    NewServices        = ($reportSections."Recent Services" | Measure-Object).Count
    SuspiciousEntries  = ($reportSections."Startup Entries" | Where-Object {
        $_.Executable -notmatch '(?i)system32|program files|windowsapps'}).Count
    DetectionCoverage  = [Math]::Round(($vtResults | Where-Object VTStatus -ne 'Pending').Count / $vtResults.Count * 100, 1)
}

try {
    $excelParams = @{
        Path          = $outputExcel
        AutoSize      = $true
        TableStyle    = 'Medium2'
        FreezeTopRow  = $true
        BoldTopRow    = $true
        Numberformat  = 'Text'
        ErrorAction   = 'Stop'
    }

    $reportSections.GetEnumerator() | ForEach-Object {
        if ($_.Value -is [array] -and $_.Value.Count -gt 0) {
            $_.Value | Export-Excel @excelParams -WorksheetName $_.Key
        } else {
            Write-Warning "No data for worksheet: $($_.Key)"
        }
    }
    
    if (Test-Path $outputExcel) {
        Write-Host "Report generated: $outputExcel" -ForegroundColor Green
    } else {
        throw "Excel file creation failed"
    }
} catch {
    Write-Host "FATAL ERROR: Failed to generate report - $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

Stop-Transcript
Write-Host @"
`nAI-Hunting COMPLETE

 Forensic Package: $logDir
 Report Bundle: threat_hunt_report.xlsx
 Quarantined Artifacts: $quarantineDir

 byfranke | Advanced Incident Hunting
 https://byfranke.com | contact@byfranke.com
"@ -ForegroundColor Green
#endregion