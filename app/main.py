"""
AI-Hunting Dashboard - Main Application
Enterprise Threat Hunting Web Application

Author: byFranke
Version: 2.0.0
"""

import os
from pathlib import Path
from contextlib import asynccontextmanager

from fastapi import FastAPI, WebSocket
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings
from app.api.routes import router as api_router
from app.api.websocket import handle_websocket
from app.services.lolbas import lolbas_service


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan events"""
    # Startup
    print(f"""
    ╔═══════════════════════════════════════════════════════════════╗
    ║                                                               ║
    ║     █████╗ ██╗      ██╗  ██╗██╗   ██╗███╗   ██╗████████╗      ║
    ║    ██╔══██╗██║      ██║  ██║██║   ██║████╗  ██║╚══██╔══╝      ║
    ║    ███████║██║█████╗███████║██║   ██║██╔██╗ ██║   ██║         ║
    ║    ██╔══██║██║╚════╝██╔══██║██║   ██║██║╚██╗██║   ██║         ║
    ║    ██║  ██║██║      ██║  ██║╚██████╔╝██║ ╚████║   ██║         ║
    ║    ╚═╝  ╚═╝╚═╝      ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝         ║
    ║                                                               ║
    ║           Enterprise Threat Hunting Dashboard                 ║
    ║                    Version {settings.APP_VERSION}                          ║
    ║                                                               ║
    ╚═══════════════════════════════════════════════════════════════╝

    🚀 Starting server at http://{settings.HOST}:{settings.PORT}
    📊 Dashboard: http://{settings.HOST}:{settings.PORT}
    📡 API Docs: http://{settings.HOST}:{settings.PORT}/docs
    """)

    # Pre-load LOLBAS database
    try:
        await lolbas_service.load_database()
        print(f"    ✅ LOLBAS database loaded: {len(lolbas_service._database)} entries")
    except Exception as e:
        print(f"    ⚠️  Failed to load LOLBAS database: {e}")

    yield

    # Shutdown
    print("\\n    👋 Shutting down AI-Hunting Dashboard...")


# Create FastAPI application
app = FastAPI(
    title=settings.APP_NAME,
    description=settings.APP_DESCRIPTION,
    version=settings.APP_VERSION,
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API routes
app.include_router(api_router)

# Static files
static_path = Path(__file__).parent / "static"
if static_path.exists():
    app.mount("/static", StaticFiles(directory=str(static_path)), name="static")


# WebSocket endpoint
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint for real-time updates"""
    await handle_websocket(websocket)


# Root route - serve dashboard
@app.get("/")
async def root():
    """Serve the main dashboard"""
    index_path = static_path / "index.html"
    if index_path.exists():
        return FileResponse(str(index_path))
    return {
        "name": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "status": "online",
        "message": "Welcome to AI-Hunting Dashboard API",
        "docs": "/docs"
    }


# Health check
@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "version": settings.APP_VERSION}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=settings.DEBUG
    )
