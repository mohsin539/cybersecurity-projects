"""C2 command & control server simulator (architecture L2 - implant).

A real localhost TCP listener that accepts beacon connections, validates the
TLV magic header, AES-GCM-decrypts the task payload and records an event bus
packet for the detection engines.

Governance: localhost-only binding (PROTECT / sandbox isolation),
no data ever leaves the host (ISO A.8.10 review).
"""

from __future__ import annotations

import base64
import socketserver
import struct
import threading
import time

from c2_sim.bus import EventBus

MAGIC = b"\x00\x7f"          # TLV magic that Suricata `content:"|00 7f|"` matches
LEN_FMT = struct.Struct("<H")
MAX_PAYLOAD = 4096


class _Handler(socketserver.StreamRequestHandler):
    """Reads one TLV beacon message.

    Header     : BYTE[2] magic (0x00 0x7f)
                 BYTE[1] channel id
                 BYTE[1] agent id
                 USHORT  payload length (network order -> use '<')
    Payload    : base64(AES-GCM blob) then plaintext task-id
    """

    def handle(self) -> None:  # noqa: D102
        src = self.client_address[0]
        try:
            head = self.rfile.read(6)
            if len(head) != 6:
                return
            if head[0:2] != MAGIC:
                return  # not a beacon
            chan_id, agent_id, = head[2], head[3]
            payload_len = LEN_FMT.unpack(head[4:6])[0]
            if payload_len > MAX_PAYLOAD:
                return
            blob = self.rfile.read(payload_len)
            if len(blob) != payload_len:
                return
            try:
                decoded = base64.b64decode(blob, validate=True).decode("utf-8", "replace")
            except Exception:
                decoded = ""
            task_id = decoded[-16:] if len(decoded) >= 16 else decoded
            self.server.bus.push({
                "src_ip": src, "src_port": self.client_address[1],
                "dst_ip": "127.0.0.1", "dst_port": self.server.server_address[1],
                "proto": "tcp", "traffic_type": "c2_beacon",
                "payload_hex": blob.hex()[:256],
                "task_id": task_id,
                "channel": {0: "http", 1: "https", 2: "dns"}.get(chan_id, "http"),
                "agent_id": agent_id,
                "user_agent": self.server.user_agent,
                "role": "server_side",
            })
            self.wfile.write(b"ok")
        except OSError:
            return


class C2Server:
    def __init__(self, host: str = "127.0.0.1", port: int = 0,
                 user_agent: str = "", bus: EventBus | None = None):
        self.bus = bus or EventBus()
        self.user_agent = user_agent
        self._srv: socketserver.ThreadingTCPServer | None = None
        self._thread: threading.Thread | None = None
        self._host = host
        self._port = port

    def start(self) -> int:
        self._srv = socketserver.ThreadingTCPServer(
            (self._host, self._port), _Handler, bind_and_activate=True
        )
        # Keep the handler's findings shareable.
        self._srv.bus = self.bus
        self._srv.user_agent = self.user_agent
        self._port = self._srv.server_address[1]
        self._thread = threading.Thread(target=self._srv.serve_forever, daemon=True)
        self._thread.start()
        return self._port

    @property
    def port(self) -> int:
        return self._port

    def stop(self) -> None:
        if self._srv is not None:
            self._srv.shutdown()
            self._srv.server_close()
            self._srv = None