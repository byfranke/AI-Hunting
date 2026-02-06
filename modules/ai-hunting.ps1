$global:DebugMode = $true
$logDir = "$env:USERPROFILE\Desktop\threat_hunt_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss')"
$outputExcel = "$logDir\threat_hunt_report.xlsx"
$quarantineDir = "$logDir\quarantine"
$scriptStartTime = Get-Date

# Configuration paths
$huntingConfigDir = "$env:USERPROFILE\.hunting"
$configFile = "$huntingConfigDir\config.json"

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
                                   byfranke 2026
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

#region Configuration Management
# ------------------------------
function Get-ConfigValue {
    param([string]$Key)
    
    if (Test-Path $configFile) {
        $config = Get-Content $configFile -Raw | ConvertFrom-Json -AsHashtable
        if ($config.ContainsKey($Key)) {
            return $config[$Key]
        }
    }
    return $null
}

function Set-ConfigValue {
    param(
        [string]$Key,
        [string]$Value
    )
    
    $config = @{}
    if (Test-Path $configFile) {
        $config = Get-Content $configFile -Raw | ConvertFrom-Json -AsHashtable
    }
    $config[$Key] = $Value
    
    if (-not (Test-Path $huntingConfigDir)) {
        New-Item -Path $huntingConfigDir -ItemType Directory -Force | Out-Null
    }
    $config | ConvertTo-Json | Set-Content $configFile -Force
}

function Test-ConfigExists {
    param([string]$Key)
    
    $value = Get-ConfigValue -Key $Key
    return ($null -ne $value -and $value -ne "")
}

function Get-DecryptedKey {
    param([string]$Key)
    
    $encrypted = Get-ConfigValue -Key $Key
    if ($null -eq $encrypted -or $encrypted -eq "") {
        return $null
    }
    
    try {
        $secure = $encrypted | ConvertTo-SecureString
        $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
        return [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
    }
    catch {
        return $null
    }
}

function Get-EncryptedValue {
    param([SecureString]$SecureValue)
    return $SecureValue | ConvertFrom-SecureString
}
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
    # First try to get from new config system
    $vtKey = Get-DecryptedKey -Key "VTApiKey"
    if ($vtKey) {
        return $vtKey
    }
    
    # Fallback to old .vtkey file for backward compatibility
    $vtKeyPath = "$env:USERPROFILE\.vtkey"
    if (Test-Path $vtKeyPath) {
        return Get-Content $vtKeyPath -Raw
    }
    
    # If no key found, prompt user
    Write-Host "`nVirusTotal API Key not found!" -ForegroundColor Red
    Write-Host "Please run setup.ps1 to configure your API keys." -ForegroundColor Yellow
    Write-Host "`nOr enter your VirusTotal API Key now:" -ForegroundColor Yellow
    $secureKey = Read-Host -AsSecureString
    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureKey)
    $key = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
    
    # Validate key is not empty
    if ([string]::IsNullOrWhiteSpace($key)) {
        Write-Host "No API key entered. Cannot proceed." -ForegroundColor Red
        exit 1
    }
    
    # Save to new config system
    $encrypted = Get-EncryptedValue -SecureValue $secureKey
    Set-ConfigValue -Key "VTApiKey" -Value $encrypted
    
    return $key
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
        catch [System.Net.WebException] {
            $statusCode = $null
            if ($_.Exception.Response) {
                $statusCode = [int]$_.Exception.Response.StatusCode
            }
            
            $hashResults | Where-Object { $_.SHA256 -eq $currentHash.SHA256 } | ForEach-Object {
                if ($statusCode -eq 404) {
                    $_.VTStatus = "NOT_FOUND_IN_VT"
                }
                elseif ($statusCode -eq 429) {
                    $_.VTStatus = "VT_RATE_LIMITED"
                }
                else {
                    $_.VTStatus = "VT_API_ERROR"
                }
            }
        }
        catch {
            $hashResults | Where-Object { $_.SHA256 -eq $currentHash.SHA256 } | ForEach-Object {
                $_.VTStatus = "VT_API_ERROR"
            }
        }
        # VT Public API: 4 requests/minute. Adjust delay based on your API tier.
        Start-Sleep -Milliseconds 1000
    }
    return $hashResults
}

function Get-LOLBASIndicators {
    param(
        [Parameter(Mandatory=$true)]
        $ServiceResults
    )
    
    $lolbasDB = try {
        Invoke-RestMethod "https://lolbas-project.github.io/api/lolbas.json" -TimeoutSec 30
    }
    catch {
        Write-Host "LOLBAS database unavailable: $($_.Exception.Message)" -ForegroundColor Yellow
        return @()
    }
    
    if (-not $lolbasDB -or $lolbasDB.Count -eq 0) {
        Write-Host "LOLBAS database returned empty data" -ForegroundColor Yellow
        return @()
    }
    
    # Extract binary names from LOLBAS database (e.g., cmd.exe, powershell.exe)
    $lolbasBinaries = $lolbasDB | ForEach-Object { 
        if ($_.Name) { $_.Name.ToLower() }
    } | Where-Object { $_ }
    
    $matches = $ServiceResults | Where-Object {
        if ($_.BinaryPath -and $_.BinaryPath -notin @("INVALID_PATH", "UNKNOWN", "ACCESS_DENIED")) {
            $binaryName = (Split-Path $_.BinaryPath -Leaf).ToLower()
            $lolbasBinaries -contains $binaryName
        }
    }
    
    # Mark matched services
    $matches | ForEach-Object { $_.IsLOLBAS = $true }
    
    return $matches
}

#region Sheep AI Integration
# --------------------------
function Show-SheepTermsPrompt {
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Yellow
    Write-Host "        SHEEP AI - TERMS OF SERVICE" -ForegroundColor Yellow
    Write-Host "========================================" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Before using Sheep AI for threat intelligence analysis," -ForegroundColor White
    Write-Host "you must review and accept the Terms of Service." -ForegroundColor White
    Write-Host ""
    Write-Host "Terms URL: https://sheep.byfranke.com/pages/terms.html" -ForegroundColor Cyan
    Write-Host ""
    
    $openTerms = Read-Host "Open Terms in browser? (Y/N)"
    if ($openTerms -eq "Y" -or $openTerms -eq "y") {
        Start-Process "https://sheep.byfranke.com/pages/terms.html"
        Write-Host "`nPlease review the terms..." -ForegroundColor Gray
        Start-Sleep -Seconds 3
    }
    
    Write-Host ""
    Write-Host "By accepting, you agree to:" -ForegroundColor Yellow
    Write-Host "  - Sheep AI Terms of Service" -ForegroundColor Gray
    Write-Host "  - Allow data to be sent to Sheep API for analysis" -ForegroundColor Gray
    Write-Host "  - Data processing per Sheep AI privacy policy" -ForegroundColor Gray
    Write-Host ""
    
    $accept = Read-Host "Type 'ACCEPT' to confirm"
    
    if ($accept -eq "ACCEPT") {
        Set-ConfigValue -Key "SheepTermsAccepted" -Value "true"
        Set-ConfigValue -Key "SheepTermsAcceptedDate" -Value (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
        Write-Host "`nTerms accepted!" -ForegroundColor Green
        return $true
    }
    
    Write-Host "`nTerms not accepted. Sheep AI analysis cancelled." -ForegroundColor Red
    return $false
}

function Get-SheepApiToken {
    # Check if token exists
    $token = Get-DecryptedKey -Key "SheepApiToken"
    if ($token) {
        return $token
    }
    
    Write-Host ""
    Write-Host "Sheep API Token not configured." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "[1] Enter Sheep API Token" -ForegroundColor White
    Write-Host "[2] Get a Token (open browser)" -ForegroundColor White
    Write-Host "[3] Cancel" -ForegroundColor White
    Write-Host ""
    
    $choice = Read-Host "Select option"
    
    switch ($choice) {
        "1" {
            Write-Host "`nEnter your Sheep API Token:" -ForegroundColor Yellow
            $secureToken = Read-Host -AsSecureString
            
            # Properly validate SecureString content
            $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureToken)
            $token = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
            
            if ([string]::IsNullOrWhiteSpace($token)) {
                Write-Host "No token entered." -ForegroundColor Red
                return $null
            }
            
            $encrypted = Get-EncryptedValue -SecureValue $secureToken
            Set-ConfigValue -Key "SheepApiToken" -Value $encrypted
            
            Write-Host "Token saved successfully!" -ForegroundColor Green
            return $token
        }
        "2" {
            Write-Host "`nOpening Sheep API page..." -ForegroundColor Cyan
            Start-Process "https://sheep.byfranke.com/pages/api.html"
            Write-Host "After obtaining your token, run the analysis again." -ForegroundColor Yellow
            return $null
        }
        default {
            return $null
        }
    }
}

function Invoke-SheepAIAnalysis {
    param(
        [Parameter(Mandatory=$true)]
        $ReportData,
        [Parameter(Mandatory=$true)]
        [string]$SheepToken
    )
    
    Write-Host "`nConnecting to Sheep AI for threat intelligence analysis..." -ForegroundColor Cyan
    
    # Prepare analysis context
    $criticalFindings = $ReportData.VTFindings | Where-Object { $_.VTStatus -match "CRITICAL|SUSPICIOUS" }
    $lolbasAlerts = $ReportData.LOLBASAlerts
    $recentServices = $ReportData.RecentServices
    $suspiciousStartup = $ReportData.StartupEntries | Where-Object {
        $_.Executable -notmatch '(?i)system32|program files|windowsapps'
    }
    
    # Build findings sections safely (avoid null/empty issues)
    $vtSection = "Total Scanned: $($ReportData.VTFindings.Count)`nCritical/Suspicious: $($criticalFindings.Count)"
    if ($criticalFindings.Count -gt 0) {
        $criticalList = ($criticalFindings | ForEach-Object { 
            "- $($_.ServiceName): $($_.BinaryPath) - Status: $($_.VTStatus)" 
        }) -join "`n"
        $vtSection += "`n$criticalList"
    } else {
        $vtSection += "`nNo critical findings."
    }
    
    $lolbasSection = if ($lolbasAlerts.Count -gt 0) {
        ($lolbasAlerts | ForEach-Object { "- $($_.ServiceName): $($_.BinaryPath)" }) -join "`n"
    } else { "No LOLBAS matches detected." }
    
    $recentSection = if ($recentServices.Count -gt 0) {
        ($recentServices | ForEach-Object { "- $($_.Name): $($_.PathName) - Started by: $($_.StartName)" }) -join "`n"
    } else { "No recent service installations." }
    
    $startupSection = if ($suspiciousStartup.Count -gt 0) {
        ($suspiciousStartup | ForEach-Object { "- $($_.EntryName): $($_.CommandLine)" }) -join "`n"
    } else { "No suspicious startup entries." }
    
    # Build the question for Sheep AI (clean string, no here-string interpolation issues)
    $analysisContext = @(
        "Analyze the following threat hunting findings from a Windows system:",
        "",
        "=== VIRUSTOTAL FINDINGS ===",
        $vtSection,
        "",
        "=== LOLBAS MATCHES ===",
        $lolbasSection,
        "",
        "=== RECENT SERVICES (Last 30 min) ===",
        $recentSection,
        "",
        "=== SUSPICIOUS STARTUP ENTRIES ===",
        $startupSection,
        "",
        "Based on this data, provide:",
        "1. Threat assessment summary",
        "2. Identified TTPs (MITRE ATT&CK mapping if applicable)",
        "3. Potential APT indicators",
        "4. Recommended remediation steps",
        "5. Priority actions for incident response"
    ) -join "`n"
    
    try {
        # Build request body as hashtable and convert to JSON with proper encoding
        $requestBody = @{
            question = $analysisContext
        }
        
        $jsonBody = $requestBody | ConvertTo-Json -Depth 10 -Compress
        $bodyBytes = [System.Text.Encoding]::UTF8.GetBytes($jsonBody)
        
        $response = Invoke-RestMethod -Uri "https://sheep.byfranke.com/api/ai/ask" `
            -Method POST `
            -Headers @{ 
                "X-API-Token" = $SheepToken
                "Content-Type" = "application/json; charset=utf-8"
            } `
            -Body $bodyBytes `
            -TimeoutSec 120
        
        return $response
    }
    catch {
        $statusCode = $null
        $errorDetails = $_.Exception.Message
        
        if ($_.Exception.Response) {
            $statusCode = [int]$_.Exception.Response.StatusCode
            try {
                $reader = [System.IO.StreamReader]::new($_.Exception.Response.GetResponseStream())
                $errorDetails = $reader.ReadToEnd()
                $reader.Close()
            } catch { }
        }
        
        Write-Host "Failed to connect to Sheep AI (HTTP $statusCode): $errorDetails" -ForegroundColor Red
        
        if ($statusCode -eq 400) {
            Write-Host "Hint: This may indicate an invalid token or malformed request." -ForegroundColor Yellow
        } elseif ($statusCode -eq 401 -or $statusCode -eq 403) {
            Write-Host "Hint: Check if your Sheep API token is valid." -ForegroundColor Yellow
        } elseif ($statusCode -eq 429) {
            Write-Host "Hint: Rate limit exceeded. Try again later." -ForegroundColor Yellow
        }
        
        return $null
    }
}

function Save-SheepAIReport {
    param(
        [Parameter(Mandatory=$true)]
        $SheepResponse,
        [Parameter(Mandatory=$true)]
        [string]$OutputPath
    )
    
    $reportFile = Join-Path $OutputPath "sheep_ai_analysis.txt"
    
    # Extract response text from API response
    $analysisText = if ($SheepResponse.response) {
        $SheepResponse.response
    } elseif ($SheepResponse.analysis) {
        $SheepResponse.analysis
    } else {
        $SheepResponse | Out-String
    }
    
    $reportContent = @"
================================================================================
                    SHEEP AI - THREAT INTELLIGENCE REPORT
================================================================================
Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
API Timestamp: $($SheepResponse.timestamp ?? 'N/A')
AI Engine: Sheep AI (https://sheep.byfranke.com)
================================================================================

$analysisText

================================================================================
                              END OF REPORT
================================================================================
Powered by Sheep AI - Advanced Threat Intelligence
https://sheep.byfranke.com
================================================================================
"@
    
    $reportContent | Set-Content -Path $reportFile -Force
    return $reportFile
}

function Start-SheepAIIntegration {
    param(
        [Parameter(Mandatory=$true)]
        $VTFindings,
        [Parameter(Mandatory=$true)]
        $LOLBASAlerts,
        [Parameter(Mandatory=$true)]
        $RecentServices,
        [Parameter(Mandatory=$true)]
        $StartupEntries,
        [Parameter(Mandatory=$true)]
        [string]$OutputDir
    )
    
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "        SHEEP AI INTEGRATION" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Sheep AI provides advanced threat intelligence analysis" -ForegroundColor White
    Write-Host "powered by MITRE ATT&CK framework and ML models." -ForegroundColor White
    Write-Host ""
    
    $useSheep = Read-Host "Would you like to generate a Sheep AI threat analysis report? (Y/N)"
    
    if ($useSheep -ne "Y" -and $useSheep -ne "y") {
        Write-Host "`nSheep AI analysis skipped." -ForegroundColor Gray
        return
    }
    
    # Check if terms are accepted
    if (-not (Test-ConfigExists -Key "SheepTermsAccepted")) {
        $accepted = Show-SheepTermsPrompt
        if (-not $accepted) {
            return
        }
    }
    
    # Get API token
    $sheepToken = Get-SheepApiToken
    if (-not $sheepToken) {
        Write-Host "`nSheep AI analysis cancelled - no token provided." -ForegroundColor Yellow
        return
    }
    
    # Prepare report data
    $reportData = @{
        VTFindings = $VTFindings
        LOLBASAlerts = $LOLBASAlerts
        RecentServices = $RecentServices
        StartupEntries = $StartupEntries
    }
    
    # Call Sheep AI
    $sheepResponse = Invoke-SheepAIAnalysis -ReportData $reportData -SheepToken $sheepToken
    
    if ($sheepResponse -and $sheepResponse.success -eq $true) {
        $reportFile = Save-SheepAIReport -SheepResponse $sheepResponse -OutputPath $OutputDir
        
        Write-Host ""
        Write-Host "========================================" -ForegroundColor Green
        Write-Host "    SHEEP AI ANALYSIS COMPLETE!" -ForegroundColor Green
        Write-Host "========================================" -ForegroundColor Green
        Write-Host ""
        Write-Host "Report saved to: $reportFile" -ForegroundColor Cyan
        Write-Host ""
        
        # Display summary in console
        Write-Host "--- SHEEP AI ANALYSIS SUMMARY ---" -ForegroundColor Yellow
        Write-Host ""
        
        $displayText = if ($sheepResponse.response) {
            $sheepResponse.response
        } elseif ($sheepResponse.analysis) {
            $sheepResponse.analysis
        } else {
            "Analysis completed. See report file for details."
        }
        
        Write-Host $displayText -ForegroundColor White
        Write-Host ""
    }
    elseif ($sheepResponse -and $sheepResponse.error) {
        Write-Host "`nSheep AI Error: $($sheepResponse.error)" -ForegroundColor Red
    }
    else {
        Write-Host "`nFailed to generate Sheep AI analysis." -ForegroundColor Red
    }
}
#endregion
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
$lolbasMatches = Get-LOLBASIndicators -ServiceResults $vtResults

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

    # Filter out empty sections before export
    $sectionsToExport = [ordered]@{}
    $reportSections.GetEnumerator() | ForEach-Object {
        $sectionData = $_.Value
        $hasData = $false
        
        if ($sectionData -is [array] -and $sectionData.Count -gt 0) {
            $hasData = $true
        } elseif ($sectionData -is [PSCustomObject]) {
            $hasData = $true
        } elseif ($sectionData -and $sectionData -isnot [array]) {
            $hasData = $true
        }
        
        if ($hasData) {
            $sectionsToExport[$_.Key] = $sectionData
        } else {
            Write-Warning "Skipping empty worksheet: $($_.Key)"
        }
    }

    # Check if Excel file is already open/locked
    if (Test-Path $outputExcel) {
        try {
            $fileStream = [System.IO.File]::Open($outputExcel, 'Open', 'ReadWrite', 'None')
            $fileStream.Close()
        } catch {
            Write-Warning "Excel file may be open in another application. Generating with timestamp..."
            $outputExcel = $outputExcel -replace '\.xlsx$', "_$(Get-Date -Format 'HHmmss').xlsx"
        }
    }

    # Export each section
    $sectionsToExport.GetEnumerator() | ForEach-Object {
        try {
            $_.Value | Export-Excel @excelParams -WorksheetName $_.Key
        } catch {
            Write-Warning "Failed to export worksheet '$($_.Key)': $($_.Exception.Message)"
        }
    }
    
    if (Test-Path $outputExcel) {
        Write-Host "Report generated: $outputExcel" -ForegroundColor Green
    } else {
        throw "Excel file creation failed"
    }
} catch {
    Write-Host "ERROR: Failed to generate Excel report - $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Attempting CSV fallback..." -ForegroundColor Yellow
    
    # Fallback: Export to CSV files
    try {
        $csvDir = Join-Path $logDir "csv_reports"
        New-Item -Path $csvDir -ItemType Directory -Force | Out-Null
        
        $reportSections.GetEnumerator() | ForEach-Object {
            if ($_.Value -and (($_.Value -is [array] -and $_.Value.Count -gt 0) -or $_.Value -is [PSCustomObject])) {
                $csvPath = Join-Path $csvDir "$($_.Key -replace '\s+','_').csv"
                $_.Value | Export-Csv -Path $csvPath -NoTypeInformation -Force
            }
        }
        Write-Host "CSV reports generated in: $csvDir" -ForegroundColor Green
    } catch {
        Write-Host "CSV fallback also failed: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Phase 5: Sheep AI Threat Intelligence Integration
Start-SheepAIIntegration `
    -VTFindings $vtResults `
    -LOLBASAlerts $lolbasMatches `
    -RecentServices $reportSections."Recent Services" `
    -StartupEntries $reportSections."Startup Entries" `
    -OutputDir $logDir

Stop-Transcript
Write-Host @"
`nAI-Hunting COMPLETE

 Forensic Package: $logDir
 Report Bundle: threat_hunt_report.xlsx
 Sheep AI Report: sheep_ai_analysis.txt (if generated)
 Quarantined Artifacts: $quarantineDir

 byfranke | Advanced Incident Hunting
 https://byfranke.com | contact@byfranke.com
"@ -ForegroundColor Green
#endregion