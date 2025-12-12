"""
API Routes for AI-Hunting Dashboard
"""

import uuid
from typing import Optional
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

from app.core.scanner import scanner, ScanStatus
from app.core.config import settings
from app.services.virustotal import vt_service
from app.services.lolbas import lolbas_service


router = APIRouter(prefix="/api", tags=["api"])


# Request/Response Models
class ScanRequest(BaseModel):
    check_virustotal: bool = True
    check_registry: bool = True
    check_tasks: bool = True
    check_events: bool = True
    check_drivers: bool = True


class APIKeyRequest(BaseModel):
    api_key: str


class HashCheckRequest(BaseModel):
    hash: str


class SearchRequest(BaseModel):
    query: str


# System Routes
@router.get("/status")
async def get_system_status():
    """Get system and configuration status"""
    return {
        "status": "online",
        "version": settings.APP_VERSION,
        "virustotal_configured": vt_service.is_configured,
        "lolbas_loaded": lolbas_service.is_loaded,
        "lolbas_entries": len(lolbas_service._database) if lolbas_service.is_loaded else 0
    }


@router.get("/config")
async def get_config():
    """Get application configuration"""
    return {
        "app_name": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "scan_timeout": settings.SCAN_TIMEOUT,
        "vt_rate_limit": settings.VT_RATE_LIMIT_DELAY,
        "suspicious_threshold": settings.SUSPICIOUS_THRESHOLD,
        "critical_threshold": settings.CRITICAL_THRESHOLD
    }


# API Key Management
@router.post("/config/virustotal")
async def set_virustotal_key(request: APIKeyRequest):
    """Set VirusTotal API key"""
    vt_service.api_key = request.api_key
    return {"status": "success", "message": "VirusTotal API key configured"}


# Scan Routes
@router.post("/scan/start")
async def start_scan(request: ScanRequest = None):
    """Start a new threat hunting scan"""
    if scanner.current_scan and scanner.current_scan["status"] == ScanStatus.RUNNING:
        raise HTTPException(status_code=400, detail="A scan is already in progress")

    scan_id = str(uuid.uuid4())
    options = request.model_dump() if request else {}

    # Start scan in background (will be managed via WebSocket)
    return {
        "scan_id": scan_id,
        "status": "initiated",
        "message": "Scan initiated. Connect to WebSocket for real-time updates.",
        "options": options
    }


@router.get("/scan/status")
async def get_scan_status():
    """Get current scan status"""
    current = scanner.get_current_scan()
    if not current:
        return {"status": "idle", "message": "No active scan"}
    return current


@router.post("/scan/cancel")
async def cancel_scan():
    """Cancel current scan"""
    scanner.cancel_scan()
    return {"status": "cancelled", "message": "Scan cancellation requested"}


@router.get("/scan/history")
async def get_scan_history(limit: int = Query(default=10, le=100)):
    """Get scan history"""
    history = scanner.get_scan_history()
    return {"history": history[-limit:], "total": len(history)}


@router.get("/scan/{scan_id}")
async def get_scan_by_id(scan_id: str):
    """Get specific scan results"""
    for scan in scanner.scan_history:
        if scan.get("id") == scan_id:
            return scan
    raise HTTPException(status_code=404, detail="Scan not found")


# VirusTotal Routes
@router.post("/virustotal/check")
async def check_hash(request: HashCheckRequest):
    """Check a single hash against VirusTotal"""
    if not vt_service.is_configured:
        raise HTTPException(status_code=400, detail="VirusTotal API key not configured")

    result = await vt_service.check_hash(request.hash)
    return result


# LOLBAS Routes
@router.get("/lolbas/status")
async def get_lolbas_status():
    """Get LOLBAS database status"""
    return lolbas_service.get_database_stats()


@router.post("/lolbas/reload")
async def reload_lolbas():
    """Reload LOLBAS database"""
    success = await lolbas_service.load_database(force=True)
    if success:
        return {"status": "success", "entries": len(lolbas_service._database)}
    raise HTTPException(status_code=500, detail="Failed to reload LOLBAS database")


@router.get("/lolbas/search")
async def search_lolbas(query: str = Query(..., min_length=2)):
    """Search LOLBAS database"""
    if not lolbas_service.is_loaded:
        await lolbas_service.load_database()
    results = lolbas_service.search(query)
    return {"query": query, "results": results, "count": len(results)}


@router.get("/lolbas/check/{binary_name}")
async def check_lolbas_binary(binary_name: str):
    """Check if a binary is in LOLBAS database"""
    if not lolbas_service.is_loaded:
        await lolbas_service.load_database()
    result = lolbas_service.check_binary(binary_name)
    if result:
        return result
    return {"name": binary_name, "is_lolbas": False}


# Statistics Routes
@router.get("/stats/dashboard")
async def get_dashboard_stats():
    """Get dashboard statistics"""
    current = scanner.get_current_scan()
    history = scanner.get_scan_history()

    total_scans = len(history)
    total_threats = sum(
        s.get("statistics", {}).get("critical_files", 0) +
        s.get("statistics", {}).get("suspicious_files", 0)
        for s in history
    )
    total_services_scanned = sum(
        s.get("statistics", {}).get("total_services", 0)
        for s in history
    )

    return {
        "total_scans": total_scans,
        "total_threats_detected": total_threats,
        "total_services_scanned": total_services_scanned,
        "last_scan": history[-1] if history else None,
        "current_scan": current
    }
