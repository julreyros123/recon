"""
events.py — Server-Sent Events (SSE) Real-Time Alert Stream

Provides a persistent SSE connection at GET /api/events/stream.
Background tasks and routes call push_event() to broadcast real-time
notifications to all connected clients.

No external dependencies — uses FastAPI StreamingResponse + asyncio.Queue.

Event types emitted:
  - new_device      : A never-before-seen device was discovered by the scanner
  - device_offline  : A previously active device went offline
  - security_alert  : A workstation threat alert was generated
  - scan_complete   : A background network scan finished
"""
import asyncio
import json
import time
from typing import AsyncGenerator, Dict, Any
from fastapi import APIRouter, Request
from fastapi.responses import StreamingResponse

router = APIRouter()

# In-memory broadcast queue. Each item is a dict with 'event' and 'data' keys.
# Weak-referenced per-connection queues allow clean disconnection.
_subscribers: list[asyncio.Queue] = []


def push_event(event_type: str, data: Dict[str, Any]):
    """
    Broadcasts a real-time event to all connected SSE clients.
    Safe to call from any synchronous or async context.
    Should be called from route handlers or background scan tasks.
    """
    payload = {"event": event_type, "data": data, "timestamp": time.time()}
    for queue in list(_subscribers):
        try:
            queue.put_nowait(payload)
        except asyncio.QueueFull:
            pass  # Slow client — skip rather than block


async def _event_generator(request: Request, queue: asyncio.Queue) -> AsyncGenerator[str, None]:
    """Async generator that yields SSE-formatted messages until the client disconnects."""
    # Send initial connection confirmation
    yield f"event: connected\ndata: {json.dumps({'status': 'connected', 'message': 'Recon NDS event stream active'})}\n\n"

    try:
        while True:
            # Check if client disconnected
            if await request.is_disconnected():
                break

            try:
                # Wait up to 20s for an event, then send a keepalive comment
                payload = await asyncio.wait_for(queue.get(), timeout=20.0)
                event_type = payload.get("event", "message")
                data       = payload.get("data", {})
                yield f"event: {event_type}\ndata: {json.dumps(data)}\n\n"
            except asyncio.TimeoutError:
                # SSE keepalive — prevents proxy/browser from closing idle connections
                yield ": keepalive\n\n"
    except asyncio.CancelledError:
        pass
    finally:
        # Clean up this connection's queue on disconnect
        if queue in _subscribers:
            _subscribers.remove(queue)


@router.get("/stream")
async def sse_stream(request: Request):
    """
    SSE endpoint. Connect to receive real-time events as they happen:
      - new_device      : New unknown device discovered on network
      - device_offline  : Known device went offline
      - security_alert  : Workstation threat alert triggered
      - scan_complete   : Background scan finished

    Events are formatted as standard Server-Sent Events (text/event-stream).
    """
    queue: asyncio.Queue = asyncio.Queue(maxsize=50)
    _subscribers.append(queue)

    return StreamingResponse(
        _event_generator(request, queue),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",  # Disable nginx buffering
            "Connection": "keep-alive",
        }
    )


@router.get("/subscribers")
async def get_subscriber_count():
    """Returns the number of active SSE subscriber connections (admin utility)."""
    return {"active_connections": len(_subscribers)}
