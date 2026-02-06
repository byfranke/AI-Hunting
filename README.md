# AI-Hunting

<p align="center">
  <a href="https://www.youtube.com/watch?v=11sqkThyr_Q">
    <img src="https://img.youtube.com/vi/11sqkThyr_Q/maxresdefault.jpg" alt="User Manual — AI-Hunting (Quick Summary)" width="600">
  </a>
</p>

<p align="center">
  <strong>Advanced Incident Hunting | Enterprise Threat Detection</strong><br>
  Version 2.1 | byFranke 2026
</p>

---

## Table of Contents

1. [Overview](#1-overview)
2. [Features](#2-features)
3. [Requirements](#3-requirements)
4. [Installation and Configuration](#4-installation-and-configuration)
5. [Execution](#5-execution)
6. [Scheduling and Automation](#6-scheduling-and-automation)
7. [Output Files and Reports](#7-output-files-and-reports)
8. [Security Best Practices](#8-security-best-practices)
9. [Troubleshooting](#9-troubleshooting)
10. [Sheep AI Integration](#10-sheep-ai-integration)
11. [Legal and Licensing](#11-legal-and-licensing)
12. [Support](#12-support)

---

## 1. Overview

AI-Hunting is an enterprise-grade threat hunting automation tool designed for Windows environments. It provides forensic artifact collection, advanced IOC detection, cloud intelligence integration, and professional reporting capabilities.

### Core Capabilities

| Capability | Description |
|------------|-------------|
| Forensic Collection | Automated enumeration and hashing of system services |
| VirusTotal Integration | Cloud-based malware analysis with automatic quarantine |
| LOLBAS Detection | Living Off The Land Binaries identification |
| Sheep AI Analysis | AI-powered threat intelligence with MITRE ATT&CK mapping |
| Executive Reporting | Professional Excel reports with multiple worksheets |

### Output Structure

```
%USERPROFILE%\Desktop\threat_hunt_YYYY-MM-DD_HH-mm-ss\
    threat_hunt_report.xlsx     # Executive report with all findings
    sheep_ai_analysis.txt       # AI-generated threat intelligence (optional)
    forensic_audit.log          # Detailed execution transcript
    quarantine\                 # Isolated malicious files
```

---

## 2. Features

### 2.1 Forensic Artifact Collection

- Enumeration of all Windows services with executable paths
- SHA256 hash calculation for each binary (parallelized)
- Service installation event monitoring (Event ID 7045)
- Registry startup entry analysis
- Scheduled task enumeration
- Driver audit

### 2.2 Cloud Intelligence

- VirusTotal API integration for hash reputation
- Automatic classification: CLEAN, SUSPICIOUS, CRITICAL
- Automatic quarantine of malicious binaries
- LOLBAS database cross-reference

### 2.3 Sheep AI Threat Intelligence

- MITRE ATT&CK framework mapping
- Advanced Persistent Threat (APT) indicator detection
- AI-generated remediation guidance
- Incident response prioritization
- Comprehensive threat assessment reports

---

## 3. Requirements

### System Requirements

| Requirement | Specification |
|-------------|---------------|
| Operating System | Windows 10/11 (updated) |
| PowerShell | Version 7.x (pwsh) recommended |
| Privileges | Administrator |
| Package Manager | Winget (for automatic PS7 installation) |

### External Dependencies

| Dependency | Purpose | Required |
|------------|---------|----------|
| VirusTotal API Key | Malware reputation lookup | Yes |
| Sheep API Token | AI threat intelligence | Optional |
| ImportExcel Module | Excel report generation | Auto-installed |
| PSFramework Module | Logging infrastructure | Auto-installed |

---

## 4. Installation and Configuration

### 4.1 Initial Setup

1. Download or clone the repository to your preferred location:

```powershell
# Example locations (choose your preferred path):
# C:\Tools\AI-Hunting
# D:\Security\AI-Hunting
# %USERPROFILE%\Documents\AI-Hunting

git clone https://github.com/byfranke/AI-Hunting.git
cd AI-Hunting
```

2. Unblock the downloaded files (adjust path to your installation):

```powershell
# Replace <YourPath> with your actual installation directory
Unblock-File -Path "<YourPath>\AI-Hunting\setup.ps1"
Unblock-File -Path "<YourPath>\AI-Hunting\modules\ai-hunting.ps1"
```

3. Set execution policy for the current user:

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### 4.2 Configuration Menu

Run `setup.ps1` as Administrator to access the configuration interface:

```powershell
# Navigate to your AI-Hunting directory and run setup
cd "<YourPath>\AI-Hunting"
Start-Process pwsh -Verb RunAs -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File',".\setup.ps1"
```

The configuration menu provides the following options:

```
==================== CONFIGURATION MENU ====================

  [1] Configure VirusTotal API Key       [Status]
  [2] Configure Sheep API Token          [Status]
  [3] View Sheep AI Terms of Service     [Status]
  [4] Get Sheep API Token (Open Browser)

  [5] Run AI-Hunting Scan
  [6] Exit

=============================================================
```

### 4.3 API Key Management

All credentials are stored securely in `%USERPROFILE%\.hunting\config.json`:

| Feature | Description |
|---------|-------------|
| Location | `%USERPROFILE%\.hunting\` |
| Encryption | Windows DPAPI (user-specific) |
| Recovery | Keys cannot be retrieved; generate new if lost |
| Replacement | Select menu option and confirm replacement |

### 4.4 Obtaining API Keys

**VirusTotal API Key:**
- Register at https://www.virustotal.com
- Navigate to your profile and copy the API key

**Sheep API Token:**
- Visit https://sheep.byfranke.com/pages/api.html
- Review Terms of Service before use

---

## 5. Execution

### 5.1 Standard Execution

**Via Configuration Menu (Recommended):**

```powershell
# Navigate to your AI-Hunting directory
cd "<YourPath>\AI-Hunting"
pwsh -NoProfile -ExecutionPolicy Bypass -File ".\setup.ps1"
```

Select option `[5] Run AI-Hunting Scan`

**Direct Execution:**

```powershell
cd "<YourPath>\AI-Hunting"
pwsh -NoProfile -ExecutionPolicy Bypass -File ".\modules\ai-hunting.ps1"
```

### 5.2 Elevated Execution

```powershell
cd "<YourPath>\AI-Hunting"
Start-Process pwsh -Verb RunAs -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File ".\setup.ps1"'
```

### 5.3 Execution Phases

The scan executes in five sequential phases:

| Phase | Description |
|-------|-------------|
| 1 | Forensic Artifact Collection |
| 2 | VirusTotal Cloud Intelligence |
| 3 | LOLBAS Pattern Detection |
| 4 | Excel Report Generation |
| 5 | Sheep AI Analysis (optional) |

---

## 6. Scheduling and Automation

### 6.1 Task Scheduler

Configure daily automated scans at 02:00 with elevated privileges:

```powershell
# Replace <YourPath> with your actual installation directory (use full absolute path)
schtasks /Create /SC DAILY /TN "AI-Hunting" /TR "pwsh -NoProfile -ExecutionPolicy Bypass -File \"<YourPath>\AI-Hunting\modules\ai-hunting.ps1\"" /ST 02:00 /RL HIGHEST /F
```

### 6.2 Windows Service (NSSM)

For continuous operation, deploy as a Windows service:

1. Download NSSM and place in `C:\nssm\nssm.exe`

2. Install and start the service (replace `<YourPath>` with your installation directory):

```powershell
C:\nssm\nssm.exe install AIHunting "C:\Program Files\PowerShell\7\pwsh.exe" "-NoProfile -ExecutionPolicy Bypass -File \"<YourPath>\AI-Hunting\modules\ai-hunting.ps1\""
C:\nssm\nssm.exe start AIHunting
```

---

## 7. Output Files and Reports

### 7.1 Excel Report Structure

The `threat_hunt_report.xlsx` contains the following worksheets:

| Worksheet | Content |
|-----------|---------|
| VT Findings | All services with VirusTotal status |
| LOLBAS Alerts | Binaries matching LOLBAS patterns |
| Driver Audit | System driver enumeration |
| Recent Services | Services installed in last 30 minutes |
| Startup Entries | Registry Run key entries |
| Active Tasks | Enabled scheduled tasks |
| Service Events | Event ID 7045 entries |
| Executive Dashboard | Summary metrics |

### 7.2 Sheep AI Report

The `sheep_ai_analysis.txt` includes:

- Threat assessment summary
- MITRE ATT&CK TTP mapping
- APT indicator analysis
- Remediation recommendations
- Incident response priorities

---

## 8. Security Best Practices

### Pre-Deployment

- Audit script contents before execution in production environments
- Test in isolated environments before deployment
- Maintain script integrity with code signing certificates

### Operational Security

- Do not set `ExecutionPolicy` to `Unrestricted` on production systems
- Evaluate firewall rules for external API communications
- Backup forensic logs before automated cleanup
- Whitelist through approved security processes if antivirus blocks execution

### Credential Management

- API keys are encrypted with Windows DPAPI
- Credentials are user-specific and non-transferable
- Rotate API keys periodically per organizational policy

---

## 9. Troubleshooting

| Issue | Resolution |
|-------|------------|
| Permission error / Admin required | Execute PowerShell as Administrator |
| pwsh: command not found | Install PowerShell 7: `winget install --id Microsoft.PowerShell --source winget --silent` |
| Module not found | Verify `modules\ai-hunting.ps1` exists with read permissions |
| Antivirus blocked | Review detection and whitelist through approved process |
| Excel generation failed | Ensure ImportExcel module installed: `Install-Module ImportExcel -Force` |
| VirusTotal API error | Verify API key configuration and rate limits |
| Sheep AI connection failed | Check network connectivity and token validity |

---

## 10. Sheep AI Integration

### 10.1 About Sheep AI

Sheep AI is a specialized threat intelligence platform powered by machine learning models trained on cybersecurity frameworks including MITRE ATT&CK. It provides contextual analysis of threat hunting findings.

### 10.2 Capabilities

- TTP identification and classification
- APT campaign correlation
- Vulnerability context
- Remediation guidance
- Risk assessment

### 10.3 Configuration

1. Accept Terms of Service (required for first use)
2. Obtain API token from https://sheep.byfranke.com/pages/api.html
3. Configure token via setup menu (Option 2)

### 10.4 Usage

After standard scan completion, the system prompts for Sheep AI analysis. Select `Y` to generate an AI-powered threat intelligence report.

---

## 11. Legal and Licensing

### License

This software is licensed under the byFranke License. See [LICENSE](LICENSE) for complete terms.

### Sheep AI Terms

Use of Sheep AI integration is subject to additional terms:

| Document | URL |
|----------|-----|
| Privacy Policy | https://sheep.byfranke.com/pages/privacy.html |
| Terms of Service | https://sheep.byfranke.com/pages/terms.html |

### Copyright

Copyright (c) 2026 byFranke. All rights reserved.

---

## 12. Support

### Contact

For licensing inquiries, technical support, or partnership opportunities:

- Website: https://byfranke.com
- Contact Form: https://byfranke.com/#Contact

### Development Support

This tool is maintained through community support:

[![Support Development](https://img.shields.io/badge/Support-Development-blue?style=for-the-badge)](https://buy.byfranke.com/b/8wM03kb3u7THeIgaEE)

---

<p align="center">
  <strong>AI-Hunting</strong> | Advanced Incident Hunting<br>
  byFranke 2026 | https://byfranke.com
</p>
