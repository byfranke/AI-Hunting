"""
LOLBAS Detection Service
Living Off The Land Binaries And Scripts detection
"""

import httpx
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta


class LOLBASService:
    """Service for LOLBAS pattern detection"""

    LOLBAS_URL = "https://lolbas-project.github.io/api/lolbas.json"

    def __init__(self):
        self._database: List[Dict[str, Any]] = []
        self._last_update: Optional[datetime] = None
        self._cache_duration = timedelta(hours=24)

    @property
    def is_loaded(self) -> bool:
        """Check if LOLBAS database is loaded"""
        return len(self._database) > 0

    @property
    def needs_update(self) -> bool:
        """Check if database needs refresh"""
        if not self._last_update:
            return True
        return datetime.now() - self._last_update > self._cache_duration

    async def load_database(self, force: bool = False) -> bool:
        """
        Load LOLBAS database from remote source

        Args:
            force: Force reload even if cache is valid

        Returns:
            True if successful, False otherwise
        """
        if not force and not self.needs_update and self.is_loaded:
            return True

        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(self.LOLBAS_URL, timeout=30.0)

                if response.status_code == 200:
                    self._database = response.json()
                    self._last_update = datetime.now()
                    return True
                else:
                    return False

        except Exception:
            return False

    def get_lolbas_names(self) -> List[str]:
        """Get list of all LOLBAS binary names"""
        return [entry.get("Name", "").lower() for entry in self._database]

    def check_binary(self, binary_name: str) -> Optional[Dict[str, Any]]:
        """
        Check if a binary is in the LOLBAS database

        Args:
            binary_name: Name of the binary to check

        Returns:
            LOLBAS entry if found, None otherwise
        """
        binary_lower = binary_name.lower()

        for entry in self._database:
            if entry.get("Name", "").lower() == binary_lower:
                return {
                    "name": entry.get("Name"),
                    "description": entry.get("Description"),
                    "author": entry.get("Author"),
                    "created": entry.get("Created"),
                    "commands": entry.get("Commands", []),
                    "full_path": entry.get("Full_Path", []),
                    "detection": entry.get("Detection", []),
                    "resources": entry.get("Resources", []),
                    "acknowledgement": entry.get("Acknowledgement", []),
                    "is_lolbas": True
                }
        return None

    def check_binaries(self, binaries: List[str]) -> List[Dict[str, Any]]:
        """
        Check multiple binaries against LOLBAS database

        Args:
            binaries: List of binary names to check

        Returns:
            List of LOLBAS matches
        """
        matches = []
        for binary in binaries:
            result = self.check_binary(binary)
            if result:
                matches.append(result)
        return matches

    def get_database_stats(self) -> Dict[str, Any]:
        """Get statistics about the LOLBAS database"""
        return {
            "total_entries": len(self._database),
            "last_update": self._last_update.isoformat() if self._last_update else None,
            "is_loaded": self.is_loaded
        }

    def search(self, query: str) -> List[Dict[str, Any]]:
        """Search LOLBAS database"""
        results = []
        query_lower = query.lower()

        for entry in self._database:
            name = entry.get("Name", "").lower()
            description = entry.get("Description", "").lower()

            if query_lower in name or query_lower in description:
                results.append({
                    "name": entry.get("Name"),
                    "description": entry.get("Description"),
                    "commands": entry.get("Commands", [])
                })

        return results


# Global instance
lolbas_service = LOLBASService()
