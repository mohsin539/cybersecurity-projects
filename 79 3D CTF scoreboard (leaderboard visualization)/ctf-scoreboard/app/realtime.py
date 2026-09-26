"""Server-sent events fan-out.

One projector publishes; every connected browser receives. Frames are small
JSON objects with an ``id`` equal to the log sequence number, so a client that
reconnects can send ``Last-Event-ID`` and either continue from the replay buffer
or ask for a snapshot resync when the gap is too large
(``state.md`` section 9).
"""

from __future__ import annotations

import asyncio
import contextlib
import json
from collections import deque
from datetime import timedelta
from typing import Any, AsyncIterator

from .eventlog import iso, utcnow


class StreamHub:
    def __init__(self, service, replay_size: int = 500, heartbeat: int = 15) -> None:
        self.service = service
        self.replay: deque[dict[str, Any]] = deque(maxlen=replay_size)
        self.heartbeat = heartbeat
        self._subscribers: set[asyncio.Queue] = set()
        self._loop: asyncio.AbstractEventLoop | None = None
        self._lock = asyncio.Lock()
        self._counter = 0
        self.dropped = 0

    def bind_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        self._loop = loop

    # --------------------------------------------------------------- publish --
    def publish(self, frame: dict[str, Any]) -> None:
        """Thread-safe publish; called from request handlers and the projector."""
        self._counter += 1
        frame.setdefault("sent_at", iso(utcnow()))
        frame["frame"] = self._counter
        self.replay.append(frame)
        if self._loop is None:
            return
        try:
            running = asyncio.get_running_loop()
        except RuntimeError:
            running = None
        for queue in list(self._subscribers):
            try:
                if running is not None and running is self._loop:
                    queue.put_nowait(frame)
                else:
                    self._loop.call_soon_threadsafe(self._offer, queue, frame)
            except RuntimeError:  # loop shutting down
                continue

    def _offer(self, queue: asyncio.Queue, frame: dict[str, Any]) -> None:
        if queue.full():
            # A slow client sheds frames instead of stalling the projector; the
            # client detects the gap from the frame id and resyncs.
            with contextlib.suppress(asyncio.QueueEmpty):
                queue.get_nowait()
            self.dropped += 1
        with contextlib.suppress(asyncio.QueueFull):
            queue.put_nowait(frame)

    # ------------------------------------------------------------- subscribe --
    async def subscribe(self, last_event_id: int | None = None) -> AsyncIterator[dict[str, Any]]:
        queue: asyncio.Queue = asyncio.Queue(maxsize=64)
        async with self._lock:
            self._subscribers.add(queue)
        try:
            backlog: list[dict[str, Any]] = []
            if last_event_id is not None:
                for frame in self.replay:
                    if frame.get("id", 0) > last_event_id:
                        backlog.append(frame)
            for frame in backlog:
                yield frame
            deadline = utcnow() + timedelta(seconds=self.heartbeat)
            while True:
                timeout = max(0.5, (deadline - utcnow()).total_seconds())
                try:
                    frame = await asyncio.wait_for(queue.get(), timeout=timeout)
                except asyncio.TimeoutError:
                    yield {"type": "heartbeat", "sent_at": iso(utcnow())}
                    deadline = utcnow() + timedelta(seconds=self.heartbeat)
                    continue
                yield frame
        finally:
            async with self._lock:
                self._subscribers.discard(queue)

    # ---------------------------------------------------------------- status --
    def status(self) -> dict[str, Any]:
        return {
            "subscribers": len(self._subscribers),
            "replay_buffer": len(self.replay),
            "frames_published": self._counter,
            "frames_dropped": self.dropped,
            "oldest_replay_id": self.replay[0].get("id") if self.replay else None,
            "newest_replay_id": self.replay[-1].get("id") if self.replay else None,
        }


def sse_encode(frame: dict[str, Any]) -> str:
    """Encode one frame in the text/event-stream format."""
    lines: list[str] = []
    frame_id = frame.get("id")
    if frame_id is not None:
        lines.append(f"id: {frame_id}")
    if frame.get("retry"):
        lines.append(f"retry: {frame['retry']}")
    event = frame.get("type", "message")
    lines.append(f"event: {event}")
    data = json.dumps({k: v for k, v in frame.items() if k not in {"retry"}}, separators=(",", ":"), default=str)
    for chunk in data.split("\n"):
        lines.append(f"data: {chunk}")
    return "\n".join(lines) + "\n\n"
