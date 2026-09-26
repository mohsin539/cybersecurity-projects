"""SSH door emulation (application-level). Not a real sshd.

Session flow:
  banner -> handshake -> password auth (honeytoken or reject) -> optional cmd loop
Everything runs in-process under the sandbox; no real shell ever spawns.
"""
from __future__ import annotations

import socket
import threading
from typing import List

from ..engine.sessions import Session

SSH_BANNER = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"


class SshDoor:
    def __init__(self, bind_port: int, honeytokens: List[str], session_id_fn=None):
        self.port = bind_port
        self.honeytokens = set(honeytokens or [])
        self.session_id_fn = session_id_fn or (lambda peer: f"ssh-{peer[0]}")
        self.sessions: List[Session] = []

    def start(self):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("0.0.0.0", self.port))
        self._sock.listen(8)
        t = threading.Thread(target=self._accept_loop, daemon=True)
        t.start()
        return t

    def _accept_loop(self):
        while True:
            try:
                conn, peer = self._sock.accept()
            except OSError:
                break
            threading.Thread(target=self._handle, args=(conn, peer), daemon=True).start()

    def _recv(self, conn, timeout: float = 8.0):
        conn.settimeout(timeout)
        try:
            return conn.recv(4096)
        except (socket.timeout, OSError):
            return b""

    def _handle(self, conn, peer):
        session = Session(sid=self.session_id_fn(peer), peer_ip=peer[0], peer_port=peer[1],
                          protocol="ssh")
        auths = []
        try:
            conn.sendall(SSH_BANNER.encode() + b"\r\n")
            while True:
                data = self._recv(conn)
                if not data:
                    break
                text = data.decode("utf-8", errors="replace").strip()
                if text.startswith("SSH-2.0-") or "key-exchange" in text:
                    session.add_signal("proto", text)
                    conn.sendall(b"kex_init_ok\r\n")
                    continue
                # treated as simple password attempt line for demo emulation
                if " " in text:
                    word = text.rsplit(" ", 1)
                    user = word[0].lstrip("user:").strip() if len(word) == 2 else text
                else:
                    user = text
                auths.append(user)
                session.add_signal("auth-attempt", user)
                if user in self.honeytokens:
                    conn.sendall(b"login_ok\r\n> ")
                    while True:
                        cmd = self._recv(conn)
                        if not cmd or cmd.strip() in (b"exit", b"logout"):
                            break
                        session.add_signal("cmd", cmd.decode("utf-8", errors="replace"))
                        reply = self._fake_exec(cmd.decode("utf-8", errors="replace"))
                        conn.sendall(reply.encode() + b"\r\n> ")
                else:
                    conn.sendall(b"auth_fail\r\n")
        finally:
            session.close()
            self.sessions.append(session)
            conn.close()

    def _fake_exec(self, raw_cmd: str) -> str:
        c = raw_cmd.strip().lower()
        if c.startswith("id"):
            return "uid=0(root) gid=0(root)"
        if c.startswith("uname"):
            return "Linux honeybox 5.15.0-100"
        if c.startswith("cat /etc/passwd"):
            return "root:x:0:0:root:/root:/bin/bash\nadmin:x:1000:1000"
        if "ls" in c:
            return "/root  /home /tmp /etc"
        return "command not found"


class SshSimulator:
    """Client simulator for tests (acts like hydra/medusa)."""
    def __init__(self, host: str, port: int):
        self.host, self.port = host, port

    def attempt(self, users: List[str]) -> List[str]:
        replies = []
        with socket.create_connection((self.host, self.port), timeout=8) as s:
            banner = s.recv(256)
            replies.append(banner.decode(errors="replace"))
            for u in users:
                s.sendall((u + "\n").encode())
                reply = s.recv(256).decode(errors="replace")
                replies.append(reply)
                if "login_ok" in reply:
                    s.sendall(b"id; uname -a\r\n")
                    replies.append(s.recv(512).decode(errors="replace"))
                    s.sendall(b"cat /etc/passwd; ls -la\r\n")
                    replies.append(s.recv(512).decode(errors="replace"))
                    break
        return replies
