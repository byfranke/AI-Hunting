"""
VirusTotal Integration Service
Handles malware reputation checking via VT API
"""

import asyncio
import httpx
from typing import Optional, Dict, Any
from datetime import datetime
from app.core.config import settings


class VirusTotalService:
    """Service for VirusTotal API interactions"""

    BASE_URL = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or settings.VIRUSTOTAL_API_KEY
        self._cache: Dict[str, Dict[str, Any]] = {}
        self._last_request_time: Optional[datetime] = None

    @property
    def is_configured(self) -> bool:
        """Check if VT API key is configured"""
        return bool(self.api_key)

    async def _rate_limit(self):
        """Implement rate limiting for VT API"""
        if self._last_request_time:
            elapsed = (datetime.now() - self._last_request_time).total_seconds()
            if elapsed < settings.VT_RATE_LIMIT_DELAY:
                await asyncio.sleep(settings.VT_RATE_LIMIT_DELAY - elapsed)
        self._last_request_time = datetime.now()

    async def check_hash(self, file_hash: str) -> Dict[str, Any]:
        """
        Check file hash against VirusTotal database

        Args:
            file_hash: SHA256 hash to check

        Returns:
            Dict with scan results and classification
        """
        # Check cache first
        if file_hash in self._cache:
            return self._cache[file_hash]

        if not self.is_configured:
            return {
                "hash": file_hash,
                "status": "error",
                "message": "VirusTotal API key not configured",
                "classification": "UNKNOWN"
            }

        await self._rate_limit()

        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"{self.BASE_URL}/files/{file_hash}",
                    headers={"x-apikey": self.api_key},
                    timeout=30.0
                )

                if response.status_code == 404:
                    result = {
                        "hash": file_hash,
                        "status": "not_found",
                        "message": "Hash not found in VirusTotal database",
                        "classification": "UNKNOWN",
                        "malicious": 0,
                        "suspicious": 0,
                        "harmless": 0,
                        "undetected": 0
                    }
                elif response.status_code == 200:
                    data = response.json()
                    stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                    malicious = stats.get("malicious", 0)
                    suspicious = stats.get("suspicious", 0)

                    # Classify based on detections
                    if malicious >= settings.CRITICAL_THRESHOLD:
                        classification = "CRITICAL"
                    elif malicious >= settings.SUSPICIOUS_THRESHOLD or suspicious > 0:
                        classification = "SUSPICIOUS"
                    else:
                        classification = "CLEAN"

                    result = {
                        "hash": file_hash,
                        "status": "success",
                        "classification": classification,
                        "malicious": malicious,
                        "suspicious": suspicious,
                        "harmless": stats.get("harmless", 0),
                        "undetected": stats.get("undetected", 0),
                        "total_engines": sum(stats.values()) if stats else 0,
                        "file_name": data.get("data", {}).get("attributes", {}).get("meaningful_name", ""),
                        "file_type": data.get("data", {}).get("attributes", {}).get("type_description", ""),
                        "scan_date": data.get("data", {}).get("attributes", {}).get("last_analysis_date", "")
                    }
                else:
                    result = {
                        "hash": file_hash,
                        "status": "error",
                        "message": f"API error: {response.status_code}",
                        "classification": "UNKNOWN"
                    }

                # Cache the result
                self._cache[file_hash] = result
                return result

        except httpx.TimeoutException:
            return {
                "hash": file_hash,
                "status": "error",
                "message": "Request timeout",
                "classification": "UNKNOWN"
            }
        except Exception as e:
            return {
                "hash": file_hash,
                "status": "error",
                "message": str(e),
                "classification": "UNKNOWN"
            }

    async def check_multiple_hashes(self, hashes: list) -> list:
        """Check multiple hashes (with rate limiting)"""
        results = []
        for hash_value in hashes:
            result = await self.check_hash(hash_value)
            results.append(result)
        return results

    def clear_cache(self):
        """Clear the results cache"""
        self._cache.clear()


# Global instance
vt_service = VirusTotalService()
