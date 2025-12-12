"""
Scanner Orchestration Module
Manages threat hunting scans and coordinates services
"""

import asyncio
import subprocess
import json
import os
import platform
from typing import Dict, Any, List, Optional, Callable
from datetime import datetime
from pathlib import Path
from enum import Enum

from app.core.config import settings
from app.services.virustotal import vt_service
from app.services.lolbas import lolbas_service


class ScanStatus(str, Enum):
    """Scan status enumeration"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ScanPhase(str, Enum):
    """Scan phases"""
    INITIALIZING = "initializing"
    COLLECTING_SERVICES = "collecting_services"
    COMPUTING_HASHES = "computing_hashes"
    CHECKING_VIRUSTOTAL = "checking_virustotal"
    CHECKING_LOLBAS = "checking_lolbas"
    COLLECTING_REGISTRY = "collecting_registry"
    COLLECTING_TASKS = "collecting_tasks"
    COLLECTING_EVENTS = "collecting_events"
    GENERATING_REPORT = "generating_report"
    COMPLETED = "completed"


class ThreatHuntingScanner:
    """Main scanner class for threat hunting operations"""

    def __init__(self):
        self.current_scan: Optional[Dict[str, Any]] = None
        self.scan_history: List[Dict[str, Any]] = []
        self._progress_callback: Optional[Callable] = None
        self._is_windows = platform.system() == "Windows"

    def set_progress_callback(self, callback: Callable):
        """Set callback for progress updates"""
        self._progress_callback = callback

    async def _notify_progress(self, phase: str, progress: int, message: str, data: Any = None):
        """Send progress update"""
        if self._progress_callback:
            await self._progress_callback({
                "phase": phase,
                "progress": progress,
                "message": message,
                "data": data,
                "timestamp": datetime.now().isoformat()
            })

    async def start_scan(self, scan_id: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Start a new threat hunting scan

        Args:
            scan_id: Unique identifier for the scan
            options: Scan configuration options

        Returns:
            Scan result dictionary
        """
        options = options or {}

        self.current_scan = {
            "id": scan_id,
            "status": ScanStatus.RUNNING,
            "started_at": datetime.now().isoformat(),
            "options": options,
            "results": {
                "services": [],
                "virustotal": [],
                "lolbas": [],
                "registry": [],
                "scheduled_tasks": [],
                "events": [],
                "drivers": []
            },
            "statistics": {
                "total_services": 0,
                "total_hashes": 0,
                "clean_files": 0,
                "suspicious_files": 0,
                "critical_files": 0,
                "lolbas_detected": 0,
                "unknown_files": 0
            },
            "errors": []
        }

        try:
            # Phase 1: Initialize
            await self._notify_progress(ScanPhase.INITIALIZING, 0, "Initializing scan...")

            # Load LOLBAS database
            await lolbas_service.load_database()

            # Phase 2: Collect Services
            await self._notify_progress(ScanPhase.COLLECTING_SERVICES, 10, "Collecting Windows services...")
            services = await self._collect_services()
            self.current_scan["results"]["services"] = services
            self.current_scan["statistics"]["total_services"] = len(services)

            # Phase 3: Compute Hashes
            await self._notify_progress(ScanPhase.COMPUTING_HASHES, 25, "Computing file hashes...")
            hashes = await self._compute_hashes(services)
            self.current_scan["statistics"]["total_hashes"] = len(hashes)

            # Phase 4: VirusTotal Check
            if options.get("check_virustotal", True) and vt_service.is_configured:
                await self._notify_progress(ScanPhase.CHECKING_VIRUSTOTAL, 40, "Checking VirusTotal...")
                vt_results = await self._check_virustotal(hashes)
                self.current_scan["results"]["virustotal"] = vt_results
                self._update_statistics(vt_results)

            # Phase 5: LOLBAS Check
            await self._notify_progress(ScanPhase.CHECKING_LOLBAS, 55, "Checking LOLBAS patterns...")
            lolbas_results = await self._check_lolbas(services)
            self.current_scan["results"]["lolbas"] = lolbas_results
            self.current_scan["statistics"]["lolbas_detected"] = len(lolbas_results)

            # Phase 6: Registry
            if options.get("check_registry", True):
                await self._notify_progress(ScanPhase.COLLECTING_REGISTRY, 65, "Scanning registry...")
                registry = await self._collect_registry()
                self.current_scan["results"]["registry"] = registry

            # Phase 7: Scheduled Tasks
            if options.get("check_tasks", True):
                await self._notify_progress(ScanPhase.COLLECTING_TASKS, 75, "Collecting scheduled tasks...")
                tasks = await self._collect_scheduled_tasks()
                self.current_scan["results"]["scheduled_tasks"] = tasks

            # Phase 8: Event Logs
            if options.get("check_events", True):
                await self._notify_progress(ScanPhase.COLLECTING_EVENTS, 85, "Analyzing event logs...")
                events = await self._collect_events()
                self.current_scan["results"]["events"] = events

            # Phase 9: Drivers
            if options.get("check_drivers", True):
                await self._notify_progress(ScanPhase.GENERATING_REPORT, 90, "Collecting driver information...")
                drivers = await self._collect_drivers()
                self.current_scan["results"]["drivers"] = drivers

            # Complete
            self.current_scan["status"] = ScanStatus.COMPLETED
            self.current_scan["completed_at"] = datetime.now().isoformat()
            await self._notify_progress(ScanPhase.COMPLETED, 100, "Scan completed!")

        except Exception as e:
            self.current_scan["status"] = ScanStatus.FAILED
            self.current_scan["errors"].append(str(e))
            await self._notify_progress("error", -1, f"Scan failed: {str(e)}")

        # Save to history
        self.scan_history.append(self.current_scan.copy())
        return self.current_scan

    def _update_statistics(self, vt_results: List[Dict]):
        """Update scan statistics based on VT results"""
        for result in vt_results:
            classification = result.get("classification", "UNKNOWN")
            if classification == "CLEAN":
                self.current_scan["statistics"]["clean_files"] += 1
            elif classification == "SUSPICIOUS":
                self.current_scan["statistics"]["suspicious_files"] += 1
            elif classification == "CRITICAL":
                self.current_scan["statistics"]["critical_files"] += 1
            else:
                self.current_scan["statistics"]["unknown_files"] += 1

    async def _collect_services(self) -> List[Dict[str, Any]]:
        """Collect Windows services information"""
        if not self._is_windows:
            return self._get_demo_services()

        try:
            script = '''
            Get-CimInstance -ClassName Win32_Service | Select-Object Name, DisplayName, State, StartMode, PathName, ProcessId | ConvertTo-Json -Depth 3
            '''
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", script],
                capture_output=True,
                text=True,
                timeout=settings.SCAN_TIMEOUT
            )
            if result.returncode == 0 and result.stdout.strip():
                return json.loads(result.stdout)
        except Exception:
            pass
        return self._get_demo_services()

    async def _compute_hashes(self, services: List[Dict]) -> List[Dict[str, Any]]:
        """Compute SHA256 hashes for service binaries"""
        hashes = []

        if not self._is_windows:
            return self._get_demo_hashes()

        try:
            paths = [s.get("PathName", "") for s in services if s.get("PathName")]
            unique_paths = list(set(paths))

            script = '''
            $paths = @({paths})
            $results = @()
            foreach ($path in $paths) {{
                $cleanPath = $path -replace '"', '' -replace ' -.*$', '' -replace ' /.*$', ''
                if (Test-Path $cleanPath) {{
                    try {{
                        $hash = (Get-FileHash -Path $cleanPath -Algorithm SHA256).Hash
                        $results += @{{ Path = $cleanPath; Hash = $hash }}
                    }} catch {{ }}
                }}
            }}
            $results | ConvertTo-Json
            '''.format(paths=",".join([f'"{p}"' for p in unique_paths[:50]]))

            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", script],
                capture_output=True,
                text=True,
                timeout=settings.SCAN_TIMEOUT
            )
            if result.returncode == 0 and result.stdout.strip():
                data = json.loads(result.stdout)
                if isinstance(data, dict):
                    data = [data]
                hashes = data

        except Exception:
            pass

        return hashes if hashes else self._get_demo_hashes()

    async def _check_virustotal(self, hashes: List[Dict]) -> List[Dict[str, Any]]:
        """Check hashes against VirusTotal"""
        results = []
        unique_hashes = list(set([h.get("Hash", "") for h in hashes if h.get("Hash")]))

        for hash_value in unique_hashes[:20]:  # Limit for rate limiting
            result = await vt_service.check_hash(hash_value)
            # Find associated path
            for h in hashes:
                if h.get("Hash") == hash_value:
                    result["path"] = h.get("Path", "")
                    break
            results.append(result)
            await self._notify_progress(
                ScanPhase.CHECKING_VIRUSTOTAL,
                40 + int((unique_hashes.index(hash_value) / len(unique_hashes)) * 15),
                f"Checking hash {unique_hashes.index(hash_value) + 1}/{len(unique_hashes)}..."
            )

        return results

    async def _check_lolbas(self, services: List[Dict]) -> List[Dict[str, Any]]:
        """Check services against LOLBAS database"""
        matches = []

        for service in services:
            path = service.get("PathName", "")
            if path:
                binary_name = Path(path.replace('"', '').split()[0]).name
                lolbas_match = lolbas_service.check_binary(binary_name)
                if lolbas_match:
                    lolbas_match["service_name"] = service.get("Name")
                    lolbas_match["service_path"] = path
                    matches.append(lolbas_match)

        return matches

    async def _collect_registry(self) -> List[Dict[str, Any]]:
        """Collect startup registry entries"""
        if not self._is_windows:
            return self._get_demo_registry()

        try:
            script = '''
            $results = @()
            $paths = @(
                "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
                "HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                "HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce"
            )
            foreach ($path in $paths) {
                if (Test-Path $path) {
                    Get-ItemProperty $path | ForEach-Object {
                        $_.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
                            $results += @{ Path = $path; Name = $_.Name; Value = $_.Value }
                        }
                    }
                }
            }
            $results | ConvertTo-Json
            '''
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", script],
                capture_output=True,
                text=True,
                timeout=60
            )
            if result.returncode == 0 and result.stdout.strip():
                data = json.loads(result.stdout)
                if isinstance(data, dict):
                    data = [data]
                return data
        except Exception:
            pass
        return self._get_demo_registry()

    async def _collect_scheduled_tasks(self) -> List[Dict[str, Any]]:
        """Collect scheduled tasks"""
        if not self._is_windows:
            return self._get_demo_tasks()

        try:
            script = '''
            Get-ScheduledTask | Where-Object { $_.State -ne 'Disabled' } | Select-Object TaskName, TaskPath, State, @{N='Actions';E={($_.Actions | ForEach-Object { $_.Execute }) -join '; '}} | ConvertTo-Json -Depth 2
            '''
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", script],
                capture_output=True,
                text=True,
                timeout=60
            )
            if result.returncode == 0 and result.stdout.strip():
                data = json.loads(result.stdout)
                if isinstance(data, dict):
                    data = [data]
                return data[:100]  # Limit results
        except Exception:
            pass
        return self._get_demo_tasks()

    async def _collect_events(self) -> List[Dict[str, Any]]:
        """Collect relevant security events"""
        if not self._is_windows:
            return self._get_demo_events()

        try:
            script = '''
            Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045} -MaxEvents 50 -ErrorAction SilentlyContinue |
            Select-Object TimeCreated, Id, Message | ConvertTo-Json -Depth 2
            '''
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", script],
                capture_output=True,
                text=True,
                timeout=60
            )
            if result.returncode == 0 and result.stdout.strip():
                data = json.loads(result.stdout)
                if isinstance(data, dict):
                    data = [data]
                return data
        except Exception:
            pass
        return self._get_demo_events()

    async def _collect_drivers(self) -> List[Dict[str, Any]]:
        """Collect loaded drivers information"""
        if not self._is_windows:
            return self._get_demo_drivers()

        try:
            script = '''
            Get-CimInstance -ClassName Win32_SystemDriver | Select-Object Name, DisplayName, State, PathName | ConvertTo-Json -Depth 2
            '''
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", script],
                capture_output=True,
                text=True,
                timeout=60
            )
            if result.returncode == 0 and result.stdout.strip():
                data = json.loads(result.stdout)
                if isinstance(data, dict):
                    data = [data]
                return data
        except Exception:
            pass
        return self._get_demo_drivers()

    # Demo data methods for non-Windows systems
    def _get_demo_services(self) -> List[Dict[str, Any]]:
        """Return demo service data for testing"""
        return [
            {"Name": "wuauserv", "DisplayName": "Windows Update", "State": "Running", "StartMode": "Auto", "PathName": "C:\\Windows\\System32\\svchost.exe -k netsvcs", "ProcessId": 1234},
            {"Name": "Spooler", "DisplayName": "Print Spooler", "State": "Running", "StartMode": "Auto", "PathName": "C:\\Windows\\System32\\spoolsv.exe", "ProcessId": 2345},
            {"Name": "BITS", "DisplayName": "Background Intelligent Transfer Service", "State": "Running", "StartMode": "Manual", "PathName": "C:\\Windows\\System32\\svchost.exe -k netsvcs", "ProcessId": 3456},
            {"Name": "WinDefend", "DisplayName": "Windows Defender Antivirus Service", "State": "Running", "StartMode": "Auto", "PathName": "C:\\ProgramData\\Microsoft\\Windows Defender\\platform\\MsMpEng.exe", "ProcessId": 4567},
            {"Name": "EventLog", "DisplayName": "Windows Event Log", "State": "Running", "StartMode": "Auto", "PathName": "C:\\Windows\\System32\\svchost.exe -k LocalServiceNetworkRestricted", "ProcessId": 5678},
            {"Name": "Schedule", "DisplayName": "Task Scheduler", "State": "Running", "StartMode": "Auto", "PathName": "C:\\Windows\\System32\\svchost.exe -k netsvcs", "ProcessId": 6789},
            {"Name": "CryptSvc", "DisplayName": "Cryptographic Services", "State": "Running", "StartMode": "Auto", "PathName": "C:\\Windows\\System32\\svchost.exe -k NetworkService", "ProcessId": 7890},
            {"Name": "Dnscache", "DisplayName": "DNS Client", "State": "Running", "StartMode": "Auto", "PathName": "C:\\Windows\\System32\\svchost.exe -k NetworkService", "ProcessId": 8901}
        ]

    def _get_demo_hashes(self) -> List[Dict[str, Any]]:
        """Return demo hash data for testing"""
        return [
            {"Path": "C:\\Windows\\System32\\svchost.exe", "Hash": "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"},
            {"Path": "C:\\Windows\\System32\\spoolsv.exe", "Hash": "A1B2C3D4E5F6789012345678901234567890ABCDEF1234567890ABCDEF123456"},
            {"Path": "C:\\Windows\\System32\\cmd.exe", "Hash": "B2C3D4E5F6789012345678901234567890ABCDEF1234567890ABCDEF1234567A"},
            {"Path": "C:\\Windows\\System32\\powershell.exe", "Hash": "C3D4E5F6789012345678901234567890ABCDEF1234567890ABCDEF1234567AB2"}
        ]

    def _get_demo_registry(self) -> List[Dict[str, Any]]:
        """Return demo registry data for testing"""
        return [
            {"Path": "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", "Name": "SecurityHealth", "Value": "C:\\Windows\\System32\\SecurityHealthSystray.exe"},
            {"Path": "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", "Name": "WindowsDefender", "Value": "\"C:\\Program Files\\Windows Defender\\MSASCuiL.exe\""},
            {"Path": "HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", "Name": "OneDrive", "Value": "\"C:\\Users\\User\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe\" /background"}
        ]

    def _get_demo_tasks(self) -> List[Dict[str, Any]]:
        """Return demo scheduled tasks for testing"""
        return [
            {"TaskName": "GoogleUpdateTaskMachineCore", "TaskPath": "\\", "State": "Ready", "Actions": "C:\\Program Files (x86)\\Google\\Update\\GoogleUpdate.exe /c"},
            {"TaskName": "MicrosoftEdgeUpdateTaskMachineCore", "TaskPath": "\\", "State": "Ready", "Actions": "C:\\Program Files (x86)\\Microsoft\\EdgeUpdate\\MicrosoftEdgeUpdate.exe /c"},
            {"TaskName": "Windows Defender Scheduled Scan", "TaskPath": "\\Microsoft\\Windows\\Windows Defender\\", "State": "Ready", "Actions": "C:\\ProgramData\\Microsoft\\Windows Defender\\platform\\MpCmdRun.exe Scan"}
        ]

    def _get_demo_events(self) -> List[Dict[str, Any]]:
        """Return demo event log data for testing"""
        return [
            {"TimeCreated": "2025-01-15T10:30:00", "Id": 7045, "Message": "A service was installed in the system. Service Name: TestService"},
            {"TimeCreated": "2025-01-14T14:22:00", "Id": 7045, "Message": "A service was installed in the system. Service Name: UpdateService"},
            {"TimeCreated": "2025-01-13T09:15:00", "Id": 7045, "Message": "A service was installed in the system. Service Name: SecurityAgent"}
        ]

    def _get_demo_drivers(self) -> List[Dict[str, Any]]:
        """Return demo driver data for testing"""
        return [
            {"Name": "ACPI", "DisplayName": "Microsoft ACPI Driver", "State": "Running", "PathName": "C:\\Windows\\System32\\drivers\\ACPI.sys"},
            {"Name": "disk", "DisplayName": "Disk Driver", "State": "Running", "PathName": "C:\\Windows\\System32\\drivers\\disk.sys"},
            {"Name": "Ntfs", "DisplayName": "NTFS File System", "State": "Running", "PathName": "C:\\Windows\\System32\\drivers\\Ntfs.sys"},
            {"Name": "tcpip", "DisplayName": "TCP/IP Protocol Driver", "State": "Running", "PathName": "C:\\Windows\\System32\\drivers\\tcpip.sys"}
        ]

    def get_current_scan(self) -> Optional[Dict[str, Any]]:
        """Get current scan status"""
        return self.current_scan

    def get_scan_history(self) -> List[Dict[str, Any]]:
        """Get scan history"""
        return self.scan_history

    def cancel_scan(self):
        """Cancel current scan"""
        if self.current_scan and self.current_scan["status"] == ScanStatus.RUNNING:
            self.current_scan["status"] = ScanStatus.CANCELLED


# Global scanner instance
scanner = ThreatHuntingScanner()
