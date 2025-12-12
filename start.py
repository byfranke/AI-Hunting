#!/usr/bin/env python3
"""
AI-Hunting Dashboard Launcher
Enterprise Threat Hunting Web Application

Author: byFranke
Version: 2.0.0

Usage:
    python start.py [--host HOST] [--port PORT] [--debug]
"""

import argparse
import os
import sys
import webbrowser
from pathlib import Path
from threading import Timer


def check_requirements():
    """Check if required packages are installed"""
    required = ['fastapi', 'uvicorn', 'httpx', 'websockets']
    missing = []

    for package in required:
        try:
            __import__(package)
        except ImportError:
            missing.append(package)

    if missing:
        print(f"Missing required packages: {', '.join(missing)}")
        print("Install with: pip install -r requirements.txt")
        return False
    return True


def open_browser(url):
    """Open browser after a delay"""
    webbrowser.open(url)


def print_banner():
    """Print application banner"""
    banner = """
    ================================================================

         █████╗ ██╗      ██╗  ██╗██╗   ██╗███╗   ██╗████████╗
        ██╔══██╗██║      ██║  ██║██║   ██║████╗  ██║╚══██╔══╝
        ███████║██║█████╗███████║██║   ██║██╔██╗ ██║   ██║
        ██╔══██║██║╚════╝██╔══██║██║   ██║██║╚██╗██║   ██║
        ██║  ██║██║      ██║  ██║╚██████╔╝██║ ╚████║   ██║
        ╚═╝  ╚═╝╚═╝      ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝

              Enterprise Threat Hunting Dashboard v2.0.0
                         Author: byFranke

    ================================================================
    """
    print(banner)


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='AI-Hunting Dashboard - Enterprise Threat Hunting Web Application'
    )
    parser.add_argument(
        '--host',
        default='127.0.0.1',
        help='Host to bind the server (default: 127.0.0.1)'
    )
    parser.add_argument(
        '--port',
        type=int,
        default=8080,
        help='Port to bind the server (default: 8080)'
    )
    parser.add_argument(
        '--debug',
        action='store_true',
        help='Enable debug mode with auto-reload'
    )
    parser.add_argument(
        '--no-browser',
        action='store_true',
        help='Do not open browser automatically'
    )

    args = parser.parse_args()

    # Print banner
    print_banner()

    # Check requirements
    if not check_requirements():
        sys.exit(1)

    # Set environment variables
    os.environ['HOST'] = args.host
    os.environ['PORT'] = str(args.port)
    os.environ['DEBUG'] = str(args.debug).lower()

    # Import uvicorn after environment setup
    import uvicorn

    # Open browser after delay
    if not args.no_browser:
        url = f"http://{args.host}:{args.port}"
        Timer(2.0, open_browser, [url]).start()
        print(f"    [*] Opening browser at {url}")

    print(f"    [*] Starting server on {args.host}:{args.port}")
    print(f"    [*] Debug mode: {'enabled' if args.debug else 'disabled'}")
    print(f"    [*] Press Ctrl+C to stop the server")
    print()

    # Run server
    uvicorn.run(
        "app.main:app",
        host=args.host,
        port=args.port,
        reload=args.debug,
        log_level="info" if args.debug else "warning"
    )


if __name__ == "__main__":
    main()
