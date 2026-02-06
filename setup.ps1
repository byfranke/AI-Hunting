<#
.SYNOPSIS

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

AI-Hunting - Advanced Incident Hunting
byfranke | https://byfranke.com

.DESCRIPTION
Enterprise-grade threat hunting automation with forensic artifact collection,
advanced IOC detection, cloud integration, and professional reporting.
Now with Sheep AI integration for enhanced threat intelligence.

.NOTES
Version: 2.1
https://github.com/byfranke/AI-Hunting
PowerShell Policy: Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
#>

#region Initialization
# ---------------------
$huntingConfigDir = "$env:USERPROFILE\.hunting"
$configFile = "$huntingConfigDir\config.json"

# Ensure .hunting directory exists
if (-not (Test-Path $huntingConfigDir)) {
    New-Item -Path $huntingConfigDir -ItemType Directory -Force | Out-Null
}

#region Helper Functions
# ----------------------
function Get-EncryptedValue {
    param([SecureString]$SecureValue)
    return $SecureValue | ConvertFrom-SecureString
}

function Set-ConfigValue {
    param(
        [string]$Key,
        [string]$EncryptedValue
    )
    
    $config = @{}
    if (Test-Path $configFile) {
        $config = Get-Content $configFile -Raw | ConvertFrom-Json -AsHashtable
    }
    $config[$Key] = $EncryptedValue
    $config | ConvertTo-Json | Set-Content $configFile -Force
}

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

function Test-ConfigExists {
    param([string]$Key)
    
    $value = Get-ConfigValue -Key $Key
    return ($null -ne $value -and $value -ne "")
}

function Show-Banner {
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
}

function Show-ConfigMenu {
    Clear-Host
    Show-Banner
    
    $vtStatus = if (Test-ConfigExists -Key "VTApiKey") { "[Configured]" } else { "[Not Set]" }
    $sheepStatus = if (Test-ConfigExists -Key "SheepApiToken") { "[Configured]" } else { "[Not Set]" }
    $termsStatus = if (Test-ConfigExists -Key "SheepTermsAccepted") { "[Accepted]" } else { "[Not Accepted]" }
    
    Write-Host "`n==================== CONFIGURATION MENU ====================" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  [1] Configure VirusTotal API Key       $vtStatus" -ForegroundColor $(if ($vtStatus -eq "[Configured]") { "Green" } else { "Gray" })
    Write-Host "  [2] Configure Sheep API Token          $sheepStatus" -ForegroundColor $(if ($sheepStatus -eq "[Configured]") { "Green" } else { "Gray" })
    Write-Host "  [3] View Sheep AI Terms of Service     $termsStatus" -ForegroundColor $(if ($termsStatus -eq "[Accepted]") { "Green" } else { "Gray" })
    Write-Host "  [4] Get Sheep API Token (Open Browser)"
    Write-Host ""
    Write-Host "  [5] Run AI-Hunting Scan"
    Write-Host "  [6] Exit"
    Write-Host ""
    Write-Host "=============================================================" -ForegroundColor Yellow
    Write-Host ""
}

function Set-VirusTotalKey {
    Write-Host "`n--- Configure VirusTotal API Key ---" -ForegroundColor Cyan
    
    if (Test-ConfigExists -Key "VTApiKey") {
        Write-Host "A VirusTotal API Key is already configured." -ForegroundColor Yellow
        Write-Host "For security, the current key cannot be displayed." -ForegroundColor Gray
        $replace = Read-Host "Do you want to replace it? (Y/N)"
        if ($replace -ne "Y" -and $replace -ne "y") {
            return
        }
    }
    
    Write-Host "`nEnter your VirusTotal API Key:" -ForegroundColor Yellow
    Write-Host "(Get your key at: https://www.virustotal.com/gui/my-apikey)" -ForegroundColor Gray
    $secureKey = Read-Host -AsSecureString
    
    # Properly validate SecureString content
    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureKey)
    $keyValue = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
    
    if ([string]::IsNullOrWhiteSpace($keyValue)) {
        Write-Host "No key entered. Operation cancelled." -ForegroundColor Red
        return
    }
    
    $encrypted = Get-EncryptedValue -SecureValue $secureKey
    Set-ConfigValue -Key "VTApiKey" -EncryptedValue $encrypted
    
    Write-Host "`nVirusTotal API Key saved successfully!" -ForegroundColor Green
    Start-Sleep -Seconds 2
}

function Set-SheepApiToken {
    Write-Host "`n--- Configure Sheep API Token ---" -ForegroundColor Cyan
    
    # Check if terms are accepted
    if (-not (Test-ConfigExists -Key "SheepTermsAccepted")) {
        Write-Host "`nYou must accept the Sheep AI Terms of Service first." -ForegroundColor Yellow
        Write-Host "Please select option [3] from the menu to view and accept the terms." -ForegroundColor Gray
        Start-Sleep -Seconds 3
        return
    }
    
    if (Test-ConfigExists -Key "SheepApiToken") {
        Write-Host "A Sheep API Token is already configured." -ForegroundColor Yellow
        Write-Host "For security, the current token cannot be displayed." -ForegroundColor Gray
        $replace = Read-Host "Do you want to replace it? (Y/N)"
        if ($replace -ne "Y" -and $replace -ne "y") {
            return
        }
    }
    
    Write-Host "`nEnter your Sheep API Token:" -ForegroundColor Yellow
    Write-Host "(Get your token at: https://sheep.byfranke.com/pages/api.html)" -ForegroundColor Gray
    $secureToken = Read-Host -AsSecureString
    
    # Properly validate SecureString content
    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureToken)
    $tokenValue = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
    
    if ([string]::IsNullOrWhiteSpace($tokenValue)) {
        Write-Host "No token entered. Operation cancelled." -ForegroundColor Red
        return
    }
    
    $encrypted = Get-EncryptedValue -SecureValue $secureToken
    Set-ConfigValue -Key "SheepApiToken" -EncryptedValue $encrypted
    
    Write-Host "`nSheep API Token saved successfully!" -ForegroundColor Green
    Start-Sleep -Seconds 2
}

function Show-SheepTerms {
    Write-Host "`n--- Sheep AI Terms of Service ---" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Before using Sheep AI for threat intelligence analysis," -ForegroundColor Yellow
    Write-Host "you must review and accept the Terms of Service." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Terms of Service URL: https://sheep.byfranke.com/pages/terms.html" -ForegroundColor White
    Write-Host ""
    
    $openBrowser = Read-Host "Would you like to open the Terms in your browser? (Y/N)"
    if ($openBrowser -eq "Y" -or $openBrowser -eq "y") {
        Start-Process "https://sheep.byfranke.com/pages/terms.html"
        Start-Sleep -Seconds 2
    }
    
    Write-Host ""
    Write-Host "IMPORTANT: By accepting, you agree to:" -ForegroundColor Yellow
    Write-Host "  - The Sheep AI Terms of Service" -ForegroundColor Gray
    Write-Host "  - Allow AI-Hunting to send collected data to Sheep API" -ForegroundColor Gray
    Write-Host "  - Data processing according to Sheep AI privacy policy" -ForegroundColor Gray
    Write-Host ""
    
    $accept = Read-Host "Do you accept the Terms of Service? (Type 'ACCEPT' to confirm)"
    
    if ($accept -eq "ACCEPT") {
        Set-ConfigValue -Key "SheepTermsAccepted" -EncryptedValue "true"
        Set-ConfigValue -Key "SheepTermsAcceptedDate" -EncryptedValue (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
        Write-Host "`nTerms of Service accepted!" -ForegroundColor Green
    } else {
        Write-Host "`nTerms not accepted. Sheep AI features will be unavailable." -ForegroundColor Red
    }
    
    Start-Sleep -Seconds 2
}

function Open-SheepApiPage {
    Write-Host "`nOpening Sheep API page in your browser..." -ForegroundColor Cyan
    Write-Host "URL: https://sheep.byfranke.com/pages/api.html" -ForegroundColor Gray
    Start-Process "https://sheep.byfranke.com/pages/api.html"
    Start-Sleep -Seconds 2
}

function Start-AIHunting {
    # Check for admin privileges
    if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Host "`nELEVATION REQUIRED: Run as Administrator" -ForegroundColor Red
        Write-Host "Please restart this script with Administrator privileges." -ForegroundColor Yellow
        Start-Sleep -Seconds 3
        return
    }
    
    # Check for PowerShell 7
    if (-not (Get-Command pwsh -ErrorAction SilentlyContinue)) {
        Write-Host "`nPowerShell 7 not found. Installing..." -ForegroundColor Yellow
        winget install --id Microsoft.PowerShell --source winget --silent
        Write-Host "Please restart this script after PowerShell 7 installation." -ForegroundColor Yellow
        Start-Sleep -Seconds 3
        return
    }
    
    # Check if VirusTotal key is configured
    if (-not (Test-ConfigExists -Key "VTApiKey")) {
        Write-Host "`nVirusTotal API Key not configured!" -ForegroundColor Red
        Write-Host "Please configure your VirusTotal API Key first (Option 1)." -ForegroundColor Yellow
        Start-Sleep -Seconds 3
        return
    }
    
    Write-Host "`nStarting AI-Hunting scan..." -ForegroundColor Green
    Start-Sleep -Seconds 1
    
    # Run the main module
    pwsh -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot "modules\ai-hunting.ps1")
}
#endregion

#region Main Menu Loop
# --------------------
$exitMenu = $false

while (-not $exitMenu) {
    Show-ConfigMenu
    $choice = Read-Host "Select an option"
    
    switch ($choice) {
        "1" { Set-VirusTotalKey }
        "2" { Set-SheepApiToken }
        "3" { Show-SheepTerms }
        "4" { Open-SheepApiPage }
        "5" { Start-AIHunting }
        "6" { 
            $exitMenu = $true
            Write-Host "`nGoodbye!" -ForegroundColor Cyan
        }
        default {
            Write-Host "`nInvalid option. Please try again." -ForegroundColor Red
            Start-Sleep -Seconds 1
        }
    }
}
#endregion
