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

.NOTES
Version: 1.3.1
https://github.com/byfranke/AI-Hunting
Read-Host "Enter VT API Key" -AsSecureString | ConvertFrom-SecureString | Out-File "$env:USERPROFILE\.vtkey"
PowerShell Policy: Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
#>

#region Initialization
# ---------------------

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "ELEVATION REQUIRED: Run as Administrator" -ForegroundColor Red
    exit 1
}

if (-not (Get-Command pwsh -ErrorAction SilentlyContinue)) {
    Write-Host "PowerShell 7 not found. Installing..."
    winget install --id Microsoft.PowerShell --source winget --silent
}


pwsh -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot "modules\ai-hunting.ps1")
