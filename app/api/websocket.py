"""
WebSocket handlers for real-time scan updates
"""

import asyncio
import uuid
from typing import Dict, Set
from fastapi import WebSocket, WebSocketDisconnect
from app.core.scanner import scanner


class ConnectionManager:
    """Manages WebSocket connections"""

    def __init__(self):
        self.active_connections: Dict[str, WebSocket] = {}
        self.scan_subscribers: Dict[str, Set[str]] = {}

    async def connect(self, websocket: WebSocket) -> str:
        """Accept a new WebSocket connection"""
        await websocket.accept()
        connection_id = str(uuid.uuid4())
        self.active_connections[connection_id] = websocket
        return connection_id

    def disconnect(self, connection_id: str):
        """Remove a WebSocket connection"""
        if connection_id in self.active_connections:
            del self.active_connections[connection_id]
        # Remove from all scan subscriptions
        for scan_id in self.scan_subscribers:
            self.scan_subscribers[scan_id].discard(connection_id)

    def subscribe_to_scan(self, connection_id: str, scan_id: str):
        """Subscribe a connection to scan updates"""
        if scan_id not in self.scan_subscribers:
            self.scan_subscribers[scan_id] = set()
        self.scan_subscribers[scan_id].add(connection_id)

    async def send_personal(self, connection_id: str, message: dict):
        """Send a message to a specific connection"""
        if connection_id in self.active_connections:
            try:
                await self.active_connections[connection_id].send_json(message)
            except Exception:
                self.disconnect(connection_id)

    async def broadcast(self, message: dict):
        """Broadcast a message to all connections"""
        disconnected = []
        for connection_id, websocket in self.active_connections.items():
            try:
                await websocket.send_json(message)
            except Exception:
                disconnected.append(connection_id)

        for conn_id in disconnected:
            self.disconnect(conn_id)

    async def broadcast_to_scan(self, scan_id: str, message: dict):
        """Broadcast a message to all connections subscribed to a scan"""
        if scan_id not in self.scan_subscribers:
            return

        disconnected = []
        for connection_id in self.scan_subscribers[scan_id]:
            if connection_id in self.active_connections:
                try:
                    await self.active_connections[connection_id].send_json(message)
                except Exception:
                    disconnected.append(connection_id)

        for conn_id in disconnected:
            self.disconnect(conn_id)


# Global connection manager
manager = ConnectionManager()


async def handle_websocket(websocket: WebSocket):
    """Main WebSocket handler"""
    connection_id = await manager.connect(websocket)

    # Send welcome message
    await manager.send_personal(connection_id, {
        "type": "connected",
        "connection_id": connection_id,
        "message": "Connected to AI-Hunting Dashboard"
    })

    try:
        while True:
            # Receive message from client
            data = await websocket.receive_json()
            message_type = data.get("type", "")

            if message_type == "ping":
                await manager.send_personal(connection_id, {"type": "pong"})

            elif message_type == "start_scan":
                # Start a new scan
                scan_id = str(uuid.uuid4())
                options = data.get("options", {})

                # Subscribe to this scan
                manager.subscribe_to_scan(connection_id, scan_id)

                # Set up progress callback
                async def progress_callback(progress_data):
                    await manager.broadcast_to_scan(scan_id, {
                        "type": "scan_progress",
                        "scan_id": scan_id,
                        **progress_data
                    })

                scanner.set_progress_callback(progress_callback)

                # Send scan started message
                await manager.send_personal(connection_id, {
                    "type": "scan_started",
                    "scan_id": scan_id,
                    "message": "Scan started"
                })

                # Run scan in background
                asyncio.create_task(run_scan_task(scan_id, options, connection_id))

            elif message_type == "subscribe_scan":
                scan_id = data.get("scan_id")
                if scan_id:
                    manager.subscribe_to_scan(connection_id, scan_id)
                    await manager.send_personal(connection_id, {
                        "type": "subscribed",
                        "scan_id": scan_id
                    })

            elif message_type == "cancel_scan":
                scanner.cancel_scan()
                await manager.broadcast({
                    "type": "scan_cancelled",
                    "message": "Scan cancelled by user"
                })

            elif message_type == "get_status":
                current_scan = scanner.get_current_scan()
                await manager.send_personal(connection_id, {
                    "type": "status",
                    "current_scan": current_scan
                })

    except WebSocketDisconnect:
        manager.disconnect(connection_id)
    except Exception:
        manager.disconnect(connection_id)


async def run_scan_task(scan_id: str, options: dict, connection_id: str):
    """Run scan as background task"""
    try:
        result = await scanner.start_scan(scan_id, options)

        # Send completion message
        await manager.broadcast_to_scan(scan_id, {
            "type": "scan_completed",
            "scan_id": scan_id,
            "result": result
        })

    except Exception as e:
        await manager.broadcast_to_scan(scan_id, {
            "type": "scan_error",
            "scan_id": scan_id,
            "error": str(e)
        })
