# AI Hunting

<p align="center">
  <a href="https://www.youtube.com/watch?v=11sqkThyr_Q=">
    <img src="https://img.youtube.com/vi/11sqkThyr_Q=/maxresdefault.jpg" alt="User Manual — AI Hunting (Quick Summary)" width="600">
  </a>
</p>

## 1. Overview

* The scripts create a logs directory on your desktop: `%USERPROFILE%\Desktop\threat_hunt_YYYY-MM-DD_HH-mm-ss`.
* Generate an Excel report: `threat_hunt_report.xlsx`.
* Create a quarantine folder inside the logs directory: `quarantine`.
* Require execution as Administrator and PowerShell 7 (pwsh). If pwsh does not exist, they attempt to install it via `winget`.
* Call a module in `modules\ai-hunting.ps1` (check if it exists and has permissions).

## 2. Requirements

* Updated Windows 10/11.
* Account with Administrator privileges (or ability to elevate).
* PowerShell 7 (pwsh) preferred — but they also work in Windows PowerShell if adapted.
* Winget available (for automatic installation of PowerShell 7 if necessary).
* `modules\` directory with `ai-hunting.ps1` present in the same directory as the scripts.

## 3. Preparation (permissions and execution policy)

Run PowerShell as Administrator and execute the commands below according to the desired level.

1. Allow execution **temporarily** only in the current session (recommended for testing):

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File "C:\path\to\ai-hunting.ps1"
```

2. Set policy for the current user (recommended for continuous use):

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

3. Set policy for the entire machine (requires Admin; less secure):

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine
```

4. Unblock downloaded file (if necessary):

```powershell
Unblock-File -Path "C:\path\to\ai-hunting.ps1"
```

5. Run a script **elevated** (executes as Administrator via UAC prompt):

```powershell
Start-Process pwsh -Verb RunAs -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File',"C:\path\to\ai-hunting.ps1"
```

6. Install PowerShell 7 (if `pwsh` does not exist):

```powershell
winget install --id Microsoft.PowerShell --source winget --silent
```

7. For development/testing — run with bypass only in session (does not change permanent policy):

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File "C:\path\to\ai-hunting.ps1"
```

## 4. How to run (practical examples)

* Run normally (PowerShell 5.x):

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File "C:\scripts\ai-hunting.ps1"
```

* Run with pwsh (PowerShell 7+):

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File "C:\scripts\ai-hunting.ps1"
```

* Run with elevation (automatically open elevated window):

```powershell
Start-Process pwsh -Verb RunAs -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File "C:\scripts\ai-hunting.ps1"'
```

## 5. Scheduling (e.g., schedule via Task Scheduler)

* Schedule with `schtasks` (runs daily at 02:00 with elevated privileges):

```powershell
schtasks /Create /SC DAILY /TN "AI-Hunting" /TR "pwsh -NoProfile -ExecutionPolicy Bypass -File \"C:\scripts\ai-hunting.ps1\"" /ST 02:00 /RL HIGHEST /F
```

## 6. Run in background (service / NSSM)

* Recommended: NSSM to turn into a service:

1. Download nssm.exe and copy to `C:\nssm\nssm.exe`.
2. Install service:

```powershell
C:\nssm\nssm.exe install AIHunting "C:\Program Files\PowerShell\7\pwsh.exe" "-NoProfile -ExecutionPolicy Bypass -File \"C:\scripts\ai-hunting.ps1\""
C:\nssm\nssm.exe start AIHunting
```

## 7. Parameters and logs

* The script creates `threat_hunt_YYYY-MM-DD_HH-mm-ss` directory on the user’s Desktop and generates:

  * `threat_hunt_report.xlsx`
  * `quarantine\` containing quarantined files
* Check variables at the top of the script: `$logDir`, `$outputExcel`, `$quarantineDir`, `$scriptStartTime`.

## 8. Best practices and security

* Check contents of `modules\ai-hunting.ps1` before running (audit).
* Run first in an isolated environment (test machine) before production.
* Do not set `ExecutionPolicy` as `Unrestricted` globally on production machines.
* Consider signing the script with a certificate if deploying across multiple hosts:

  * Generate self-signed certificate and sign with `Set-AuthenticodeSignature`.
* Backup logs before automatic cleanup.
* If the script interacts with network/Internet, evaluate firewall and proxy rules.

## 9. Common error handling

* **Permission error / Admin required** — open PowerShell as Administrator or use `Start-Process -Verb RunAs`.
* **pwsh: command not found** — install PowerShell 7 with `winget` (or adjust to `powershell.exe`).
* **Module not found (`modules\ai-hunting.ps1`)** — confirm `modules` exists in the same directory and file has read permissions.
* **Antivirus blocked** — review detection; do not disable AV without justification. If internal tool, whitelist via approved process.
* **Failed to create Excel** — check dependencies (if using COM Excel, Excel must be installed; if using module to generate XLSX, ensure `ImportExcel` module is installed).

## 10. Complete example (quick step-by-step)

1. Copy scripts to `C:\scripts`.
2. Open PowerShell as Administrator.
3. Unblock:

```powershell
Unblock-File -Path "C:\scripts\ai-hunting.ps1"
Unblock-File -Path "C:\scripts\setup.ps1"
```

4. Adjust ExecutionPolicy for current user:

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

5. Run:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File "C:\scripts\ai-hunting.ps1"
```

6. Check folder `%USERPROFILE%\Desktop\threat_hunt_*` for reports and `quarantine`.

## 11. How to verify script ran and find outputs

* Open Explorer → Desktop → look for `threat_hunt_` with timestamp.
* Open `threat_hunt_report.xlsx` (Excel or LibreOffice).
* PowerShell log (if implemented) — look for messages in console output; if desired, modify script to write a `run.log` inside `$logDir`.

## Donation Support

This tool is maintained through community support. Help keep it active:

[![Donate](https://img.shields.io/badge/Support-Development-blue?style=for-the-badge&logo=github)](https://buy.byfranke.com/b/8wM03kb3u7THeIgaEE)
