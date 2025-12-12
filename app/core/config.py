"""
Configuration module for AI-Hunting Dashboard
"""

import os
from pathlib import Path
from typing import Optional
from pydantic_settings import BaseSettings
from pydantic import Field


class Settings(BaseSettings):
    """Application settings"""

    # Application Info
    APP_NAME: str = "AI-Hunting Dashboard"
    APP_VERSION: str = "2.0.0"
    APP_DESCRIPTION: str = "Enterprise Threat Hunting Web Application"
    DEBUG: bool = Field(default=False)

    # Server Configuration
    HOST: str = Field(default="127.0.0.1")
    PORT: int = Field(default=8080)

    # API Keys
    VIRUSTOTAL_API_KEY: Optional[str] = Field(default=None)

    # Paths
    BASE_DIR: Path = Path(__file__).resolve().parent.parent.parent
    DATA_DIR: Path = Field(default=None)
    LOGS_DIR: Path = Field(default=None)
    REPORTS_DIR: Path = Field(default=None)
    QUARANTINE_DIR: Path = Field(default=None)

    # Scanning Configuration
    SCAN_TIMEOUT: int = Field(default=600)  # seconds
    MAX_PARALLEL_SCANS: int = Field(default=4)
    VT_RATE_LIMIT_DELAY: float = Field(default=15.0)  # seconds between VT API calls

    # Thresholds
    SUSPICIOUS_THRESHOLD: int = Field(default=3)  # VT detections
    CRITICAL_THRESHOLD: int = Field(default=10)  # VT detections

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        # Set default paths
        if self.DATA_DIR is None:
            self.DATA_DIR = self.BASE_DIR / "data"
        if self.LOGS_DIR is None:
            self.LOGS_DIR = self.BASE_DIR / "logs"
        if self.REPORTS_DIR is None:
            self.REPORTS_DIR = self.DATA_DIR / "reports"
        if self.QUARANTINE_DIR is None:
            self.QUARANTINE_DIR = self.DATA_DIR / "quarantine"

        # Create directories
        for directory in [self.DATA_DIR, self.LOGS_DIR, self.REPORTS_DIR, self.QUARANTINE_DIR]:
            directory.mkdir(parents=True, exist_ok=True)


# Global settings instance
settings = Settings()
