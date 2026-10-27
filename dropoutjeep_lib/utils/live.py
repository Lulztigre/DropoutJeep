"""WebSocket live-dashboard infrastructure.

Event-producing routes push lightweight messages into a queue; a background
thread broadcasts them to all currently connected dashboard clients.
"""

import json
import queue
import threading
import time
from typing import Any

# Thread-safe connection registry.
_connections = set()
_connections_lock = threading.Lock()

# Messages are dicts that will be JSON-serialized.
event_queue: queue.Queue[dict] = queue.Queue()


def _safe_send(ws, message: str):
    try:
        ws.send(message)
    except Exception:
        # Connection likely closed; drop it next cleanup.
        pass


def register(ws):
    """Register a WebSocket connection."""
    with _connections_lock:
        _connections.add(ws)


def unregister(ws):
    """Remove a WebSocket connection."""
    with _connections_lock:
        _connections.discard(ws)


def broadcast(message: dict):
    """Broadcast a message to every connected WebSocket client."""
    payload = json.dumps(message)
    with _connections_lock:
        dead = set()
        for ws in _connections:
            try:
                ws.send(payload)
            except Exception:
                dead.add(ws)
        _connections.difference_update(dead)


def enqueue(message: dict):
    """Queue a message to be broadcast by the background thread."""
    event_queue.put(message)


def _broadcaster_loop():
    """Background thread that drains the event queue and broadcasts."""
    while True:
        try:
            message = event_queue.get(timeout=1.0)
        except queue.Empty:
            # Send periodic heartbeat to keep connections alive and prune dead ones.
            broadcast({'type': 'heartbeat'})
            continue
        broadcast(message)


def start_broadcaster():
    """Start the background broadcaster thread (idempotent)."""
    for t in threading.enumerate():
        if t.name == 'dj-broadcaster':
            return
    thread = threading.Thread(target=_broadcaster_loop, name='dj-broadcaster', daemon=True)
    thread.start()


def push_event(event_type: str, campaign_id: int | None = None, recipient_id: int | None = None, meta: Any = None):
    """Called by event-producing HTTP routes to push a live update."""
    enqueue({
        'type': 'event',
        'event_type': event_type,
        'campaign_id': campaign_id,
        'recipient_id': recipient_id,
        'meta': meta,
        'ts': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
    })
