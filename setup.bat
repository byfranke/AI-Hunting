@echo off
REM AI-Hunting Dashboard Setup Script for Windows
REM Enterprise Threat Hunting Web Application
REM Author: byFranke

echo.
echo ================================================================
echo    AI-Hunting Dashboard - Setup Script
echo    Enterprise Threat Hunting Web Application
echo ================================================================
echo.

REM Check for Python
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python is not installed or not in PATH.
    echo Please install Python 3.9+ from https://www.python.org/downloads/
    pause
    exit /b 1
)

echo [*] Python found. Checking version...

REM Check Python version
for /f "tokens=2" %%i in ('python --version 2^>^&1') do set PYVER=%%i
echo [*] Python version: %PYVER%

REM Create virtual environment
echo.
echo [*] Creating virtual environment...
python -m venv venv

REM Activate virtual environment
echo [*] Activating virtual environment...
call venv\Scripts\activate.bat

REM Upgrade pip
echo [*] Upgrading pip...
python -m pip install --upgrade pip

REM Install requirements
echo.
echo [*] Installing dependencies...
pip install -r requirements.txt

if %errorlevel% neq 0 (
    echo [ERROR] Failed to install dependencies.
    pause
    exit /b 1
)

echo.
echo ================================================================
echo    Setup Complete!
echo ================================================================
echo.
echo To start the dashboard:
echo    1. Run: venv\Scripts\activate.bat
echo    2. Run: python start.py
echo.
echo Or simply run: run.bat
echo.

REM Create run.bat
echo @echo off > run.bat
echo call venv\Scripts\activate.bat >> run.bat
echo python start.py %%* >> run.bat

echo [*] Created run.bat for easy startup.
echo.

pause
