<#
.SYNOPSIS
    AI-Hunting Dashboard - PowerShell Setup Script
    Enterprise Threat Hunting Web Application

.DESCRIPTION
    Setup script for AI-Hunting Dashboard.
    Installs Python dependencies and configures the environment.

.AUTHOR
    byFranke

.VERSION
    2.0.0

.LINK
    https://github.com/byfranke/AI-Hunting
    https://byfranke.com
#>

#Requires -Version 5.1

param(
    [switch]$SkipPythonCheck,
    [switch]$NoBrowser,
    [string]$Host = "127.0.0.1",
    [int]$Port = 8080
)

$ErrorActionPreference = "Stop"

# Banner
function Show-Banner {
    $banner = @"

    ================================================================

         ######  ######        ##  ## ##  ## ##  ## ######
         ##  ##    ##          ##  ## ##  ## ### ##   ##
         ######    ##    ##### ###### ##  ## ######   ##
         ##  ##    ##          ##  ## ##  ## ## ###   ##
         ##  ##  ######        ##  ##  ####  ##  ##   ##

              Enterprise Threat Hunting Dashboard v2.0.0
                         Author: byFranke

    ================================================================

"@
    Write-Host $banner -ForegroundColor Cyan
}

# Check Python installation
function Test-Python {
    Write-Host "[*] Checking Python installation..." -ForegroundColor Yellow

    $python = Get-Command python -ErrorAction SilentlyContinue
    if (-not $python) {
        Write-Host "[!] Python is not installed or not in PATH." -ForegroundColor Red
        Write-Host "[*] Please install Python 3.9+ from https://www.python.org/downloads/" -ForegroundColor Yellow
        return $false
    }

    $version = & python --version 2>&1
    Write-Host "[+] Found: $version" -ForegroundColor Green
    return $true
}

# Create virtual environment
function New-VirtualEnvironment {
    $venvPath = Join-Path $PSScriptRoot "venv"

    if (-not (Test-Path $venvPath)) {
        Write-Host "[*] Creating virtual environment..." -ForegroundColor Yellow
        & python -m venv $venvPath
    } else {
        Write-Host "[+] Virtual environment already exists." -ForegroundColor Green
    }

    return $venvPath
}

# Install dependencies
function Install-Dependencies {
    param([string]$VenvPath)

    Write-Host "[*] Installing dependencies..." -ForegroundColor Yellow

    $pipPath = Join-Path $VenvPath "Scripts\pip.exe"
    $requirementsPath = Join-Path $PSScriptRoot "requirements.txt"

    if (-not (Test-Path $pipPath)) {
        $pipPath = Join-Path $VenvPath "bin\pip"
    }

    & $pipPath install --upgrade pip
    & $pipPath install -r $requirementsPath

    if ($LASTEXITCODE -ne 0) {
        Write-Host "[!] Failed to install dependencies." -ForegroundColor Red
        return $false
    }

    Write-Host "[+] Dependencies installed successfully." -ForegroundColor Green
    return $true
}

# Start the dashboard
function Start-Dashboard {
    param(
        [string]$VenvPath,
        [string]$ServerHost,
        [int]$ServerPort,
        [switch]$NoBrowser
    )

    $pythonPath = Join-Path $VenvPath "Scripts\python.exe"
    if (-not (Test-Path $pythonPath)) {
        $pythonPath = Join-Path $VenvPath "bin\python"
    }

    $startScript = Join-Path $PSScriptRoot "start.py"

    Write-Host ""
    Write-Host "[*] Starting AI-Hunting Dashboard..." -ForegroundColor Yellow
    Write-Host "[*] Server: http://${ServerHost}:${ServerPort}" -ForegroundColor Cyan
    Write-Host "[*] Press Ctrl+C to stop the server." -ForegroundColor Yellow
    Write-Host ""

    $args = @("--host", $ServerHost, "--port", $ServerPort)
    if ($NoBrowser) {
        $args += "--no-browser"
    }

    & $pythonPath $startScript @args
}

# Main execution
function Main {
    Show-Banner

    # Change to script directory
    Set-Location $PSScriptRoot

    # Check Python
    if (-not $SkipPythonCheck) {
        if (-not (Test-Python)) {
            exit 1
        }
    }

    # Setup virtual environment
    $venvPath = New-VirtualEnvironment

    # Install dependencies
    if (-not (Install-Dependencies -VenvPath $venvPath)) {
        exit 1
    }

    Write-Host ""
    Write-Host "================================================================" -ForegroundColor Green
    Write-Host "   Setup Complete!" -ForegroundColor Green
    Write-Host "================================================================" -ForegroundColor Green
    Write-Host ""

    # Start dashboard
    Start-Dashboard -VenvPath $venvPath -ServerHost $Host -ServerPort $Port -NoBrowser:$NoBrowser
}

# Run
Main
