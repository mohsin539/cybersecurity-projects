"""WebSocket client registry with cross-thread publishing.

The telemetry loop runs on a background thread while broadcasting must happen
on the asyncio event loop; ``call_soon_threadsafe`` bridges the two safely.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any, Dict, Optional, Set

from fastapi import WebSocket

logger = logging.getLogger(__name__)


class ConnectionManager:
    def __init__(self) -> None:
        self._clients: Set[WebSocket] = set()
        self._loop: Optional[asyncio.AbstractEventLoop] = None

    def bind_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        """Remember the event loop on which websockets live."""
        self._loop = loop

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        self._clients.add(websocket)

    def disconnect(self, websocket: WebSocket) -> None:
        self._clients.discard(websocket)

    @property
    def client_count(self) -> int:
        return len(self._clients)

    def publish(self, payload: Dict[str, Any]) -> None:
        """Schedule a broadcast from the monitoring thread."""
        loop = self._loop
        if loop is None or not self._clients:
            return
        loop.call_soon_threadsafe(
            lambda: asyncio.create_task(self._broadcast(payload))
        )

    async def _broadcast(self, payload: Dict[str, Any]) -> None:
        dead: list[WebSocket] = []
        for websocket in list(self._clients):
            try:
                await websocket.send_json(payload)
            except Exception:  # noqa: BLE001 - websocket may have dropped
                dead.append(websocket)
        for websocket in dead:
            self._clients.discard(websocket)