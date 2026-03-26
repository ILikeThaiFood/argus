"""WebSocket connection manager for real-time broadcasts."""

from __future__ import annotations

import json
import logging
from typing import Any

from fastapi import WebSocket

logger = logging.getLogger(__name__)


class ConnectionManager:
    """Manages WebSocket connections grouped by channel."""

    def __init__(self) -> None:
        # channel -> set of active websockets
        self._channels: dict[str, set[WebSocket]] = {}

    async def connect(self, websocket: WebSocket, channel: str = "default") -> None:
        await websocket.accept()
        self._channels.setdefault(channel, set()).add(websocket)
        logger.info("WS client connected to channel '%s' (%d total)", channel, len(self._channels[channel]))

    def disconnect(self, websocket: WebSocket, channel: str = "default") -> None:
        if channel in self._channels:
            self._channels[channel].discard(websocket)
            logger.info("WS client disconnected from '%s' (%d remaining)", channel, len(self._channels[channel]))

    async def broadcast(self, channel: str, data: Any) -> None:
        """Send JSON payload to every client on *channel*."""
        if channel not in self._channels:
            return
        payload = json.dumps(data, default=str)
        dead: list[WebSocket] = []
        for ws in self._channels[channel]:
            try:
                await ws.send_text(payload)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self._channels[channel].discard(ws)

    async def broadcast_event(self, event_data: dict) -> None:
        await self.broadcast("events", event_data)

    async def broadcast_alert(self, alert_data: dict) -> None:
        await self.broadcast("alerts", alert_data)

    async def broadcast_stats(self, stats_data: dict) -> None:
        await self.broadcast("stats", stats_data)

    @property
    def active_connections(self) -> int:
        return sum(len(s) for s in self._channels.values())


# Singleton instance used across the application
manager = ConnectionManager()
