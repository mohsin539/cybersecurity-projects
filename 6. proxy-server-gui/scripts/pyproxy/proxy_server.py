#!/usr/bin/env python3
"""
ProxySuite Python Edition — dependency-free (stdlib-only) proxy server.

Features
  HTTP/1.1 forward proxy   (absolute-URI requests)
  CONNECT tunneling        (HTTPS)
  SOCKS5 (RFC 1928)        (CONNECT, no-auth + user/pass)
  Policy engine            (first-match-wins rules: allow/deny, wildcard, CIDR, port, protocol)
  Guards                   (per-client connection slots, connect rate limiting, SSRF private-target block)
  Audit log                (JSONL, SHA-256 hash-chained, size/date rotation, matching C# AuditLogger)
  Status API               (JSON status file for GUI/dashboard polling)
  Graceful shutdown        (SIGINT/SIGTERM + local admin TCP control channel)

Usage
  py proxy_server.py                      # use config.json next to this file (defaults if absent)
  py proxy_server.py --config my.json
  py proxy_server.py --check-config       # validate config and exit

Config keys (all optional; defaults match the C# engine's defaults): see config.sample.json.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import signal
import socket
import socketserver
import ssl
import sys
import threading
import time
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
GENESIS_HASH = "GENESIS"

# Match the C# engine's supported auth modes / upstream types.
AUTH_MODES = ("None", "Basic", "IpAllowlist")

# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------

DEFAULT_CONFIG = {
    "schemaVersion": 1,
    "listeners": {
        "http":   {"bind": "127.0.0.1", "port": 8080, "authMode": "None"},
        "socks5": {"bind": "127.0.0.1", "port": 1080, "authMode": "None"},
    },
    "upstreams": [{"name": "direct", "type": "Direct"}],
    "routing": {"default": "direct", "failover": []},
    "rules": [{"id": 1, "action": "Allow", "match": {}}],
    "limits": {
        "maxConnections": 2000,
        "maxConnectionsPerClient": 128,
        "connectRatePerMinute": 240,
        "rateBlockSeconds": 60,
        "idleTimeoutSec": 300,
        "connectTimeoutSec": 15,
        "maxHeaderBytes": 32768,
    },
    "security": {
        "denyPrivateTargets": False,
        "resolveViaUpstream": False,
        "httpRatePerMinute": 600,
        "socks5Users": {},
        "clients": {"allow": [], "deny": []},
    },
    "logging": {
        "level": "info",
        "directory": "logs",
        "maxFileBytes": 104857600,
        "maxFiles": 14,
    },
}


def _deep_merge(base: dict, override: dict) -> dict:
    out = dict(base)
    for k, v in (override or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def load_config(path: Path) -> dict:
    cfg = json.loads(json.dumps(DEFAULT_CONFIG))  # deep copy
    if path.exists():
        user = json.loads(path.read_text(encoding="utf-8-sig"))
        cfg = _deep_merge(cfg, user)
    else:
        print(f"[config] {path.name} not found — using built-in defaults", file=sys.stderr)
    return cfg


# --------------------------------------------------------------------------
# Small utilities (input hygiene, mirroring InputValidator.cs posture)
# --------------------------------------------------------------------------

_UNSAFE_RE = re.compile(r"[\r\n\x00-\x1f\x7f]")


def safe_str(value, max_len: int = 256) -> str:
    """Strip control chars (log-injection defense) and clamp length."""
    if value is None:
        return ""
    s = str(value)
    s = _UNSAFE_RE.sub("", s)
    return s[:max_len]


def is_valid_host(host: str) -> bool:
    if not host or len(host) > 253:
        return False
    if _UNSAFE_RE.search(host):
        return False
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    return re.fullmatch(r"(?=.{1,253}$)([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\.?", host) is not None


# --------------------------------------------------------------------------
# Bind-address resolution (manual IP setup: localhost / auto / * / hostname / IP)
# --------------------------------------------------------------------------

def resolve_bind(configured: str) -> str:
    """Resolve a bind string to a concrete IP for socket binding.

    "127.0.0.1"  -> that IP (default, loopback-only posture)
    "localhost"  -> 127.0.0.1
    "auto"       -> first RFC1918 LAN IPv4 on a live interface, else 127.0.0.1 (fail closed)
    "*"/"0.0.0.0"-> 0.0.0.0 (all interfaces; explicit user choice)
    hostname/IP  -> resolved via socket.getaddrinfo
    Raises SystemExit with a clear message if unresolvable — never silently binds elsewhere.
    """
    raw = (configured or "").strip() or "127.0.0.1"
    if raw in ("*", "0.0.0.0", "::"):
        return "0.0.0.0"
    if raw.lower() == "localhost":
        return "127.0.0.1"
    if raw.lower() == "auto":
        lan = detect_lan_ip()
        if lan is None:
            print("[config] bind 'auto': no LAN IPv4 found - falling back to 127.0.0.1", file=sys.stderr)
            return "127.0.0.1"
        print(f"[config] bind 'auto' resolved to {lan}", flush=True)
        return lan
    try:
        ipaddress.ip_address(raw)
        return raw
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(raw, None, type=socket.SOCK_STREAM)
        for fam, _, _, _, sa in infos:
            if fam == socket.AF_INET:
                return sa[0]
        return infos[0][4][0]
    except OSError as e:
        raise SystemExit(f"[config] FATAL: bind '{raw}' could not be resolved: {e}")


def detect_lan_ip() -> str | None:
    """The IPv4 address the OS would use to reach the LAN (primary route).

    UDP connect sends no packets; it asks the routing table which source address a
    LAN-bound packet would use — so virtual adapters (VirtualBox/Hyper-V) that are not
    the default route don't win. Falls back to trying common RFC1918 gateways.
    """
    for probe in ("192.168.255.255", "10.255.255.255", "172.31.255.255"):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect((probe, 1))
            ip = s.getsockname()[0]
            if ip and not ip.startswith("127."):
                return ip
        except OSError:
            pass
        finally:
            s.close()
    return None


# --------------------------------------------------------------------------
# Audit logger — hash-chained JSONL, compatible layout with AuditLogger.cs
# --------------------------------------------------------------------------

class AuditLogger:
    SEV = {"debug": 0, "info": 1, "warn": 2, "error": 3, "security": 4}

    def __init__(self, directory: Path, level: str = "info",
                 max_file_bytes: int = 104857600, max_files: int = 14):
        self.dir = Path(directory)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.min_sev = self.SEV.get((level or "info").lower(), 1)
        self.max_file_bytes = max_file_bytes
        self.max_files = max(1, max_files)
        self._lock = threading.Lock()
        self._prev_hash: str | None = None
        self._fh = None
        self._seq = 0
        self._file_date = None
        self._restore_chain_tail()

    def _restore_chain_tail(self) -> None:
        files = sorted(self.dir.glob("audit-*.jsonl"), reverse=True)
        if not files:
            return
        try:
            with files[0].open("r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        ev = json.loads(line)
                        if ev.get("hash"):
                            self._prev_hash = ev["hash"]
                    except json.JSONDecodeError:
                        continue
        except OSError:
            pass

    def log(self, sev: str, etype: str, proto: str | None = None,
            client: str | None = None, user: str | None = None,
            host: str | None = None, port: int | None = None,
            rule: int | None = None, action: str | None = None,
            bytes_up: int | None = None, bytes_down: int | None = None,
            duration_ms: int | None = None, detail: str | None = None) -> None:
        if self.SEV.get(sev, 1) < self.min_sev:
            return
        ev = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "sev": sev,
            "type": safe_str(etype, 64),
            "proto": safe_str(proto, 16) if proto else None,
            "client": safe_str(client, 64) if client else None,
            "user": safe_str(user, 32) if user else None,
            "host": safe_str(host, 253) if host else None,
            "port": int(port) if port else None,
            "rule": int(rule) if rule else None,
            "action": safe_str(action, 16) if action else None,
            "bytesUp": int(bytes_up) if bytes_up else None,
            "bytesDown": int(bytes_down) if bytes_down else None,
            "durationMs": int(duration_ms) if duration_ms else None,
            "detail": safe_str(detail, 200) if detail else None,
        }
        with self._lock:
            ev["prev"] = self._prev_hash or GENESIS_HASH
            ev["hash"] = self._hash(ev)
            self._prev_hash = ev["hash"]
            self._roll_if_needed()
            if self._fh is None:
                self._open_new_file()
            self._fh.write(json.dumps(ev, separators=(",", ":")) + "\n")
            self._fh.flush()

    @staticmethod
    def _hash(ev: dict) -> str:
        import hashlib
        canonical = "|".join(str(ev.get(k)) for k in (
            "prev", "ts", "sev", "type", "proto", "client", "user",
            "host", "port", "rule", "action", "bytesUp", "bytesDown",
            "durationMs", "detail"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest().upper()

    def _roll_if_needed(self) -> None:
        if self._fh is not None:
            size = self._fh.tell()
            today = datetime.now(timezone.utc).date()
            if size >= self.max_file_bytes or today != self._file_date:
                self._close()
                self._open_new_file()

    def _open_new_file(self) -> None:
        self._seq += 1
        now = datetime.now(timezone.utc)
        self._file_date = now.date()
        path = self.dir / f"audit-{now:%Y%m%d}-{self._seq:06d}.jsonl"
        self._fh = path.open("a", encoding="utf-8")

    def _close(self) -> None:
        if self._fh:
            self._fh.close()
            self._fh = None
        self._prune()

    def _prune(self) -> None:
        try:
            files = sorted(self.dir.glob("audit-*.jsonl"), reverse=True)
            for f in files[self.max_files:]:
                f.unlink(missing_ok=True)
        except OSError:
            pass

    def close(self) -> None:
        with self._lock:
            self._close()


# --------------------------------------------------------------------------
# Metrics + status
# --------------------------------------------------------------------------

class Metrics:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.sessions_active = 0
        self.sessions_total = 0
        self.denied_total = 0
        self.errors_total = 0
        self.bytes_up = 0
        self.bytes_down = 0
        self.started = time.time()

    def session_open(self) -> None:
        with self._lock:
            self.sessions_active += 1
            self.sessions_total += 1

    def session_close(self) -> None:
        with self._lock:
            self.sessions_active = max(0, self.sessions_active - 1)

    def denied(self) -> None:
        with self._lock:
            self.denied_total += 1

    def error(self) -> None:
        with self._lock:
            self.errors_total += 1

    def bytes(self, up: int, down: int) -> None:
        with self._lock:
            self.bytes_up += up
            self.bytes_down += down

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "sessionsActive": self.sessions_active,
                "sessionsTotal": self.sessions_total,
                "deniedTotal": self.denied_total,
                "errorsTotal": self.errors_total,
                "bytesUp": self.bytes_up,
                "bytesDown": self.bytes_down,
            }

    def uptime(self) -> int:
        return int(time.time() - self.started)


# --------------------------------------------------------------------------
# Rule engine (first-match-wins; wildcard + CIDR + port + protocol + user)
# --------------------------------------------------------------------------

class RuleEngine:
    def __init__(self, rules: list[dict], default_action: str = "allow"):
        self.default_action = default_action
        self.rules = [r for r in rules if r.get("enabled", True)]

    def evaluate(self, host: str, port: int, protocol: str,
                 user: str | None, target_ip: str | None) -> dict:
        for rule in self.rules:
            m = rule.get("match") or {}
            if m.get("port") is not None and int(m["port"]) != port:
                continue
            if m.get("protocol") and m["protocol"].lower() != protocol.lower():
                continue
            if m.get("user") and (user or "").lower() != m["user"].lower():
                continue
            if m.get("host") and not self._wildcard(m["host"], host):
                continue
            if m.get("ip") and target_ip and not self._cidr(m["ip"], target_ip):
                continue
            return {"action": rule.get("action", "Allow").lower(),
                    "rule": rule.get("id"), "route": rule.get("route")}
        return {"action": self.default_action, "rule": None, "route": None}

    @staticmethod
    def _wildcard(pattern: str, host: str) -> bool:
        if not host:
            return False
        if pattern in ("*", "*.*"):
            return pattern == "*" or "." in host
        if pattern.startswith("*."):
            suffix = pattern[1:]  # ".example.com"
            return host.lower().endswith(suffix.lower()) or host.lower() == pattern[2:].lower()
        if pattern.endswith("*"):
            return host.lower().startswith(pattern[:-1].lower())
        return pattern.lower() == host.lower()

    @staticmethod
    def _cidr(cidr: str, ip: str) -> bool:
        try:
            return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            return False


# --------------------------------------------------------------------------
# Guards: per-client slots + rate limiting + SSRF
# --------------------------------------------------------------------------

class AccessGuard:
    def __init__(self, cfg: dict):
        lim = cfg["limits"]
        self.max_per_client = int(lim["maxConnectionsPerClient"])
        self.max_total = int(lim["maxConnections"])
        self.rate_per_min = int(lim["connectRatePerMinute"])
        self.block_seconds = int(lim["rateBlockSeconds"])
        self.deny_private = bool(cfg["security"]["denyPrivateTargets"])
        self.http_rate = int(cfg["security"].get("httpRatePerMinute", 600))

        # Client-IP allowlist (AC-3 posture): CIDRs or single IPs. Empty allow = permit all.
        self._allow_nets = self._parse_cidrs(cfg["security"].get("clients", {}).get("allow", []))
        self._deny_nets = self._parse_cidrs(cfg["security"].get("clients", {}).get("deny", []))

        self._lock = threading.Lock()
        self._client_slots: dict[str, int] = defaultdict(int)
        self._total_slots = 0
        self._connect_times: dict[str, list[float]] = defaultdict(list)
        self._http_times: dict[str, list[float]] = defaultdict(list)
        self._blocked_until: dict[str, float] = {}

    @staticmethod
    def _parse_cidrs(entries) -> list:
        nets = []
        for e in entries or []:
            try:
                nets.append(ipaddress.ip_network(e if "/" in str(e) else f"{e}/32", strict=False))
            except ValueError:
                print(f"[config] WARNING: invalid CIDR {e!r} in security.clients (entry ignored)", file=sys.stderr)
        return nets

    # -- client allowlist -------------------------------------------------
    def is_client_allowed(self, client_ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(client_ip)
        except ValueError:
            return False
        for net in self._deny_nets:
            if addr in net:
                return False
        if not self._allow_nets:
            return True
        return any(addr in net for net in self._allow_nets)

    # -- slots ------------------------------------------------------------
    def reserve_slot(self, client: str) -> bool:
        with self._lock:
            if self._total_slots >= self.max_total:
                return False
            if self._client_slots[client] >= self.max_per_client:
                return False
            self._client_slots[client] += 1
            self._total_slots += 1
            return True

    def release_slot(self, client: str) -> None:
        with self._lock:
            if self._client_slots.get(client, 0) > 0:
                self._client_slots[client] -= 1
                self._total_slots = max(0, self._total_slots - 1)

    # -- rate -------------------------------------------------------------
    def admit_connect(self, client: str) -> bool:
        return self._admit(client, self._connect_times, self.rate_per_min)

    def admit_http(self, client: str) -> bool:
        return self._admit(client, self._http_times, self.http_rate)

    def _admit(self, client: str, table: dict, limit: int) -> bool:
        now = time.time()
        with self._lock:
            until = self._blocked_until.get(client, 0)
            if now < until:
                return False
            times = table[client]
            times[:] = [t for t in times if now - t < 60]
            if len(times) >= limit:
                self._blocked_until[client] = now + self.block_seconds
                times.clear()
                return False
            times.append(now)
            return True

    # -- SSRF -------------------------------------------------------------
    def is_private_ip(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return True  # unparseable → treat as private (fail closed)
        return (addr.is_private or addr.is_loopback or addr.is_link_local
                or addr.is_reserved or addr.is_multicast or addr.is_unspecified)

    def check_target_ip(self, ip: str) -> None:
        """Raise PermissionError when private targets are denied."""
        if self.deny_private and self.is_private_ip(ip):
            raise PermissionError(f"private target blocked: {ip}")


# --------------------------------------------------------------------------
# Upstream connector (Direct / HTTP parent / SOCKS5 parent)
# --------------------------------------------------------------------------

class UpstreamRouter:
    def __init__(self, cfg: dict, audit: AuditLogger, metrics: Metrics):
        self.cfg = cfg
        self.audit = audit
        self.metrics = metrics
        self.upstreams = {u.get("name", "direct"): u for u in cfg.get("upstreams", [])}
        self.default = cfg.get("routing", {}).get("default", "direct")
        self.connect_timeout = int(cfg["limits"]["connectTimeoutSec"])
        self.idle_timeout = int(cfg["limits"]["idleTimeoutSec"])

    def resolve_upstream(self, name: str | None) -> dict:
        if name and name in self.upstreams:
            return self.upstreams[name]
        return self.upstreams.get(self.default) or {"name": "direct", "type": "Direct"}

    def connect(self, plan_route: str | None, host: str, port: int) -> socket.socket:
        """Open an upstream socket to host:port (via the routed upstream)."""
        up = self.resolve_upstream(plan_route)
        utype = (up.get("type") or "Direct").lower()

        if utype in ("direct", ""):
            return self._connect_direct(host, port)

        parent_host, parent_port = up.get("host"), int(up.get("port", 0))
        if not parent_host or not (0 < parent_port < 65536):
            raise OSError(f"upstream '{up.get('name')}' misconfigured (host/port)")

        if utype == "http":
            return self._connect_via_http_parent(up, host, port)
        if utype == "socks5":
            return self._connect_via_socks5_parent(up, host, port)
        raise OSError(f"unsupported upstream type: {up.get('type')}")

    def _connect_direct(self, host: str, port: int) -> socket.socket:
        last_err: Exception | None = None
        for fam, stype, proto, _, sa in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM):
            try:
                s = socket.socket(fam, stype, proto)
                s.settimeout(self.connect_timeout)
                s.connect(sa)
                s.settimeout(None)
                return s
            except OSError as e:
                last_err = e
                try:
                    s.close()
                except Exception:
                    pass
        raise OSError(f"connect {host}:{port} failed: {last_err}")

    def _connect_via_http_parent(self, up: dict, host: str, port: int) -> socket.socket:
        s = self._connect_direct(up["host"], int(up.get("port", 8080)))
        try:
            req = f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n"
            s.sendall(req.encode("ascii"))
            resp = self._read_http_head(s)
            status_line = resp.split("\r\n", 1)[0]
            code = int(status_line.split()[1])
            if code != 200:
                raise OSError(f"HTTP parent refused CONNECT: {status_line}")
            return s
        except Exception:
            s.close()
            raise

    def _connect_via_socks5_parent(self, up: dict, host: str, port: int) -> socket.socket:
        s = self._connect_direct(up["host"], int(up.get("port", 1080)))
        try:
            user = up.get("username")
            pwd = up.get("password")
            methods = b"\x02" if user else b"\x00"
            s.sendall(b"\x05\x01" + methods)
            resp = self._recv_exact(s, 2)
            if resp[0] != 5:
                raise OSError("SOCKS5 parent: bad version")
            if resp[1] == 0x02:
                if not user:
                    raise OSError("SOCKS5 parent demands auth but none configured")
                ub = user.encode("utf-8")[:255]
                pb = (pwd or "").encode("utf-8")[:255]
                s.sendall(bytes([1, len(ub)]) + ub + bytes([len(pb)]) + pb)
                if self._recv_exact(s, 2)[1] != 0:
                    raise OSError("SOCKS5 parent: auth rejected")
            elif resp[1] != 0x00:
                raise OSError(f"SOCKS5 parent: no acceptable method (0x{resp[1]:02x})")

            hb = socket.inet_aton(host) if _is_ipv4(host) else None
            if hb:
                addr = b"\x01" + hb
            elif ":" in host:
                addr = b"\x04" + socket.inet_pton(socket.AF_INET6, host)
            else:
                hb = host.encode("idna")
                addr = b"\x03" + bytes([len(hb)]) + hb
            s.sendall(b"\x05\x01\x00" + addr + port.to_bytes(2, "big"))
            resp = self._recv_exact(s, 4)
            if resp[1] != 0:
                raise OSError(f"SOCKS5 parent: connect failed (code 0x{resp[1]:02x})")
            atyp = resp[3]
            skip = {1: 4, 4: 16}.get(atyp)
            if skip:
                self._recv_exact(s, skip)
            elif atyp == 3:
                dlen = self._recv_exact(s, 1)[0]
                self._recv_exact(s, dlen)
            self._recv_exact(s, 2)  # port
            return s
        except Exception:
            s.close()
            raise

    @staticmethod
    def _read_http_head(sock: socket.socket) -> str:
        buf = b""
        while b"\r\n\r\n" not in buf and len(buf) < 32768:
            chunk = sock.recv(4096)
            if not chunk:
                break
            buf += chunk
        return buf.decode("latin-1", "replace")

    @staticmethod
    def _recv_exact(sock: socket.socket, n: int) -> bytes:
        buf = b""
        while len(buf) < n:
            chunk = sock.recv(n - len(buf))
            if not chunk:
                raise OSError("SOCKS5 parent: short read")
            buf += chunk
        return buf

    # -- relay ------------------------------------------------------------
    def relay(self, a: socket.socket, b: socket.socket,
              client_ip: str, host: str, port: int, proto: str,
              rule: int | None, user: str | None) -> None:
        """Bidirectional pump with idle timeout; audits the session at the end."""
        idle = self.idle_timeout
        a.settimeout(None)
        b.settimeout(None)
        started = time.time()
        holder = {"up": 0, "down": 0}

        def pump(src: socket.socket, dst: socket.socket, key: str) -> None:
            total = 0
            try:
                while True:
                    src.settimeout(idle)
                    try:
                        data = src.recv(65536)
                    except socket.timeout:
                        break
                    if not data:
                        break
                    dst.sendall(data)
                    total += len(data)
            except OSError:
                pass
            finally:
                holder[key] = total

        t1 = threading.Thread(target=pump, args=(a, b, "up"), daemon=True)
        t2 = threading.Thread(target=pump, args=(b, a, "down"), daemon=True)
        t1.start(); t2.start()
        t1.join(); t2.join()

        self.metrics.bytes(holder["up"], holder["down"])
        self.audit.log("info", "session.end", proto, client_ip, user, host, port,
                       rule, "allow", holder["up"], holder["down"],
                       int((time.time() - started) * 1000))
        for s in (a, b):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass


def _is_ipv4(host: str) -> bool:
    try:
        socket.inet_aton(host)
        return True
    except OSError:
        return False


# --------------------------------------------------------------------------
# Shared policy enforcement point (single place every protocol must pass — D8)
# --------------------------------------------------------------------------

class PolicyMixin:
    """Rules + SSRF evaluation shared by the HTTP and SOCKS5 handlers."""

    def decide(self, host: str, port: int, proto: str, user: str | None) -> dict:
        """Evaluate rules + SSRF. Raises PermissionError on deny."""
        target_ip = None
        try:
            ipaddress.ip_address(host)
            target_ip = host
        except ValueError:
            if not self.cfg["security"]["resolveViaUpstream"]:
                try:
                    target_ip = socket.gethostbyname(host)
                except OSError:
                    target_ip = None
        decision = self.rules.evaluate(host, port, proto, user, target_ip)
        if decision["action"] == "deny":
            raise PermissionError(f"denied by rule {decision['rule']}" if decision["rule"]
                                  else "denied by default policy")
        if target_ip:
            self.guard.check_target_ip(target_ip)
        return decision

    @property
    def cfg(self): return self.server.cfg
    @property
    def rules(self): return self.server.rules
    @property
    def guard(self): return self.server.guard
    @property
    def router(self): return self.server.router
    @property
    def audit(self): return self.server.audit
    @property
    def metrics(self): return self.server.metrics


# --------------------------------------------------------------------------
# HTTP proxy handler
# --------------------------------------------------------------------------

class HttpProxyHandler(PolicyMixin, socketserver.BaseRequestHandler):
    server_version = "ProxySuite-Py/1.0"

    def handle(self) -> None:
        client_ip = self.client_address[0]
        self.metrics.session_open()
        try:
            if not self.guard.is_client_allowed(client_ip):
                self.metrics.denied()
                self.audit.log("security", "client.denied", "http", client_ip,
                               detail="not in security.clients.allow")
                self._send_error(403, "Forbidden")
                return
            if not self.guard.reserve_slot(client_ip):
                self._send_error(503, "Too many connections")
                return
            try:
                if not self.guard.admit_http(client_ip):
                    self._send_error(429, "Rate limited")
                    return
                self._serve()
            finally:
                self.guard.release_slot(client_ip)
        except (ConnectionError, socket.timeout, OSError):
            self.metrics.error()
        except Exception as e:  # noqa: BLE001 — last-resort guard, keep server alive
            self.metrics.error()
            try:
                self.audit.log("error", "handler.crash", "http", client_ip,
                               detail=safe_str(e, 200))
            except Exception:
                pass
        finally:
            self.metrics.session_close()

    # -- request head -------------------------------------------------------
    def _read_head(self) -> tuple[str, str] | None:
        buf = b""
        max_head = int(self.cfg["limits"]["maxHeaderBytes"])
        while len(buf) < max_head:
            chunk = self.request.recv(min(8192, max_head - len(buf)))
            if not chunk:
                return None
            buf += chunk
            if b"\r\n\r\n" in buf:
                head = buf.split(b"\r\n\r\n", 1)[0].decode("latin-1")
                line_end = head.find("\r\n")
                if line_end < 0:
                    return head, ""
                return head[:line_end], head[line_end + 2:]
        return None  # header cap exceeded

    def _serve(self) -> None:
        head = self._read_head()
        if head is None:
            self._send_error(400, "Bad request")
            return
        request_line, headers = head
        parts = request_line.split(" ")
        if len(parts) != 3:
            self._send_error(400, "Malformed request line")
            return
        method, target, version = parts

        if not version.upper().startswith("HTTP/1."):
            self._send_error(505, "HTTP version not supported")
            return

        if method.upper() == "CONNECT":
            self._handle_connect(target)
        else:
            self._handle_plain(method, target, version, headers)

    # -- CONNECT ------------------------------------------------------------
    def _handle_connect(self, authority: str) -> None:
        sep = authority.rfind(":")
        if sep <= 0:
            self._send_error(400, "Bad CONNECT authority")
            return
        host, port_s = authority[:sep], authority[sep + 1:]
        try:
            port = int(port_s)
            if not (1 <= port <= 65535):
                raise ValueError
        except ValueError:
            self._send_error(400, "Bad CONNECT authority")
            return

        client_ip = self.client_address[0]
        if not is_valid_host(host):
            self._send_error(400, "Invalid host")
            return
        if not self.guard.admit_connect(client_ip):
            self._send_error(429, "Rate limited")
            return

        try:
            decision = self.decide(host, port, "https", None)
            upstream = self.router.connect(decision["route"], host, port)
        except PermissionError as e:
            self.metrics.denied()
            self.audit.log("security", "rule.deny", "https", client_ip, host=host, port=port,
                           detail=safe_str(e, 100))
            self._send_error(403, "Forbidden")
            return
        except OSError as e:
            self.audit.log("warn", "upstream.fail", "https", client_ip, host=host, port=port,
                           detail=safe_str(e, 120))
            self._send_error(502, "Upstream unreachable")
            return

        try:
            self.request.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            self.router.relay(self.request, upstream, client_ip, host, port,
                              "https", decision["rule"], None)
        finally:
            try:
                upstream.close()
            except OSError:
                pass

    # -- plain HTTP ----------------------------------------------------------
    def _handle_plain(self, method: str, target: str,
                      version: str, headers: str) -> None:
        if not target.lower().startswith("http://"):
            self._send_error(400, "Origin-form not supported on proxy; use absolute URI")
            return
        # Parse host/port from the absolute URI
        rest = target[7:]
        slash = rest.find("/")
        netloc = rest if slash < 0 else rest[:slash]
        path = "/" if slash < 0 else rest[slash:]
        if "@" in netloc:  # strip userinfo
            netloc = netloc.rsplit("@", 1)[1]
        if netloc.startswith("["):  # IPv6 literal
            host = netloc[1:netloc.find("]")]
            port_part = netloc[netloc.find("]") + 1:]
            port = int(port_part[1:]) if port_part.startswith(":") else 80
        else:
            host, _, port_part = netloc.partition(":")
            port = int(port_part) if port_part else 80

        client_ip = self.client_address[0]
        if not is_valid_host(host) or not (1 <= port <= 65535):
            self._send_error(400, "Invalid host")
            return
        if not self.guard.admit_http(client_ip):
            self._send_error(429, "Rate limited")
            return

        try:
            decision = self.decide(host, port, "http", None)
        except PermissionError as e:
            self.metrics.denied()
            self.audit.log("security", "rule.deny", "http", client_ip, host=host, port=port,
                           detail=safe_str(e, 100))
            self._send_error(403, "Forbidden")
            return

        try:
            upstream = self.router.connect(decision["route"], host, port)
        except OSError as e:
            self.audit.log("warn", "upstream.fail", "http", client_ip, host=host, port=port,
                           detail=safe_str(e, 120))
            self._send_error(502, "Upstream unreachable")
            return

        try:
            rewritten = self._rewrite_head(method, f"http://{host}:{port}{path}",
                                           version, headers)
            upstream.sendall(rewritten.encode("latin-1"))
            self.router.relay(self.request, upstream, client_ip, host, port,
                              "http", decision["rule"], None)
        finally:
            try:
                upstream.close()
            except OSError:
                pass

    @staticmethod
    def _rewrite_head(method: str, url: str, version: str, headers: str) -> str:
        hop_by_hop = {"proxy-connection", "proxy-authorization", "keep-alive",
                      "te", "trailers", "upgrade", "host"}
        lines = [f"{method} {url} HTTP/1.1"]
        for raw in headers.split("\r\n"):
            if not raw:
                continue
            idx = raw.find(":")
            if idx <= 0:
                continue
            name = raw[:idx].strip()
            value = raw[idx + 1:].strip()
            if name.lower() in hop_by_hop:
                continue
            if "\r" in value or "\n" in value:
                continue
            lines.append(f"{safe_str(name, 128)}: {safe_str(value, 4096)}")
        lines.append(f"Host: {url.split('://', 1)[1].split('/', 1)[0]}")
        lines.append("Connection: close")
        return "\r\n".join(lines) + "\r\n\r\n"

    # -- policy: see PolicyMixin.decide --------------------------------------

    # -- helpers ---------------------------------------------------------------
    def _send_error(self, code: int, msg: str) -> None:
        body = f"<html><body><h1>{code} {msg}</h1></body></html>"
        resp = (f"HTTP/1.1 {code} {msg}\r\n"
                f"Content-Type: text/html\r\n"
                f"Content-Length: {len(body.encode())}\r\n"
                f"Connection: close\r\n\r\n{body}")
        try:
            self.request.sendall(resp.encode("utf-8"))
        except OSError:
            pass


class ThreadedHttpProxy(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    request_queue_size = 128


# --------------------------------------------------------------------------
# SOCKS5 proxy handler
# --------------------------------------------------------------------------

class Socks5Handler(PolicyMixin, socketserver.BaseRequestHandler):
    def handle(self) -> None:
        client_ip = self.client_address[0]
        self.metrics.session_open()
        try:
            if not self.guard.is_client_allowed(client_ip):
                self.metrics.denied()
                self.audit.log("security", "client.denied", "socks5", client_ip,
                               detail="not in security.clients.allow")
                self._reply(0x02)
                return
            if not self.guard.reserve_slot(client_ip):
                self._reply(0x01)
                return
            try:
                self._negotiate(client_ip)
            finally:
                self.guard.release_slot(client_ip)
        except (ConnectionError, socket.timeout, OSError):
            self.metrics.error()
        except Exception as e:  # noqa: BLE001
            self.metrics.error()
            try:
                self.audit.log("error", "handler.crash", "socks5", client_ip,
                               detail=safe_str(e, 200))
            except Exception:
                pass
        finally:
            self.metrics.session_close()

    def _recv_exact(self, n: int) -> bytes:
        buf = b""
        while len(buf) < n:
            chunk = self.request.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("short read")
            buf += chunk
        return buf

    def _negotiate(self, client_ip: str) -> None:
        head = self._recv_exact(2)
        if head[0] != 0x05:
            return
        n_methods = head[1]
        if not (1 <= n_methods <= 32):
            return
        methods = self._recv_exact(n_methods)

        auth_mode = (self.cfg["listeners"]["socks5"].get("authMode") or "None")
        users = self.cfg["security"].get("socks5Users") or {}
        need_auth = auth_mode == "Basic" and bool(users)

        if need_auth:
            chosen = 0x02 if 0x02 in methods else None
        else:
            chosen = 0x00 if 0x00 in methods else None
        if chosen is None:
            self.request.sendall(b"\x05\xff")
            return
        self.request.sendall(bytes([0x05, chosen]))

        user = None
        if chosen == 0x02:
            ver = self._recv_exact(2)
            ulen = ver[1]
            username = self._recv_exact(ulen).decode("utf-8", "replace")
            plen = self._recv_exact(1)[0]
            password = self._recv_exact(plen).decode("utf-8", "replace")
            if users.get(username) != password:
                self.audit.log("security", "auth.fail", "socks5", client_ip,
                               safe_str(username, 32))
                self.metrics.denied()
                self.request.sendall(b"\x01\x01")
                return
            self.audit.log("info", "auth.ok", "socks5", client_ip, safe_str(username, 32))
            user = username
            self.request.sendall(b"\x01\x00")

        req = self._recv_exact(4)
        if req[0] != 0x05 or req[1] != 0x01:  # CONNECT only
            self._reply(0x07)
            return
        atyp = req[3]
        try:
            if atyp == 0x01:
                host = socket.inet_ntoa(self._recv_exact(4))
            elif atyp == 0x03:
                dlen = self._recv_exact(1)[0]
                if not (1 <= dlen <= 253):
                    return self._reply(0x08)
                host = self._recv_exact(dlen).decode("utf-8", "replace")
            elif atyp == 0x04:
                host = socket.inet_ntop(socket.AF_INET6, self._recv_exact(16))
            else:
                return self._reply(0x08)
            port = int.from_bytes(self._recv_exact(2), "big")
        except (ConnectionError, OSError):
            return

        if not is_valid_host(host):
            return self._reply(0x08)
        if not self.guard.admit_connect(client_ip):
            return self._reply(0x02)

        try:
            decision = self.decide(host, port, "socks", user)
        except PermissionError as e:
            self.metrics.denied()
            self.audit.log("security", "rule.deny", "socks5", client_ip, host=host,
                           port=port, detail=safe_str(e, 100))
            return self._reply(0x02)

        try:
            upstream = self.router.connect(decision["route"], host, port)
        except OSError as e:
            self.audit.log("warn", "upstream.fail", "socks5", client_ip, user,
                           safe_str(host), port, detail=safe_str(e, 120))
            return self._reply(0x05)

        self.request.sendall(b"\x05\x00\x00\x01" + socket.inet_aton("0.0.0.0")
                             + (0).to_bytes(2, "big"))
        try:
            self.router.relay(self.request, upstream, client_ip, host, port,
                              "socks", decision["rule"], user)
        finally:
            try:
                upstream.close()
            except OSError:
                pass

    def _reply(self, code: int) -> None:
        try:
            self.request.sendall(bytes([0x05, code, 0x00, 0x01])
                                 + socket.inet_aton("0.0.0.0") + (0).to_bytes(2, "big"))
        except OSError:
            pass


class ThreadedSocks5Proxy(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    request_queue_size = 128


# --------------------------------------------------------------------------
# Status API (JSON status file for the GUI / dashboards)
# --------------------------------------------------------------------------

class StatusWriter:
    def __init__(self, path: Path):
        self.path = path
        self._lock = threading.Lock()

    def write(self, cfg: dict, metrics: Metrics, listeners_up: bool) -> None:
        payload = {
            "service": "ProxySuite-Python",
            "version": "1.0.0",
            "uptimeSec": metrics.uptime(),
            "listenersUp": listeners_up,
            "pid": os.getpid(),
            "listeners": cfg["listeners"],
            "metrics": metrics.snapshot(),
            "ts": datetime.now(timezone.utc).isoformat(),
        }
        tmp = self.path.with_suffix(".tmp")
        try:
            with self._lock, tmp.open("w", encoding="utf-8") as fh:
                json.dump(payload, fh, indent=2)
            tmp.replace(self.path)
        except OSError:
            pass


# --------------------------------------------------------------------------
# Server assembly
# --------------------------------------------------------------------------

class ProxyServer:
    def __init__(self, cfg: dict, home: Path):
        self.cfg = cfg
        self.home = home
        log_cfg = cfg["logging"]
        log_dir = Path(log_cfg["directory"])
        if not log_dir.is_absolute():
            log_dir = home / log_dir
        self.audit = AuditLogger(log_dir, log_cfg.get("level", "info"),
                                 int(log_cfg.get("maxFileBytes", 104857600)),
                                 int(log_cfg.get("maxFiles", 14)))
        self.metrics = Metrics()
        self.rules = RuleEngine(cfg.get("rules", []))
        self.guard = AccessGuard(cfg)
        self.router = UpstreamRouter(cfg, self.audit, self.metrics)
        self.status = StatusWriter(home / "status.json")
        self._servers: list[socketserver.BaseServer] = []
        self._stop = threading.Event()
        self._control = None

    # -- lifecycle ----------------------------------------------------------
    _cleaned = False

    def start(self) -> None:
        http = self.cfg["listeners"]["http"]
        socks = self.cfg["listeners"]["socks5"]

        http_ip = resolve_bind(http["bind"])
        socks_ip = resolve_bind(socks["bind"])
        http["resolvedBind"] = http_ip
        socks["resolvedBind"] = socks_ip

        http_srv = ThreadedHttpProxy((http_ip, int(http["port"])), HttpProxyHandler)
        socks_srv = ThreadedSocks5Proxy((socks_ip, int(socks["port"])), Socks5Handler)
        # Handlers reach shared state via self.server.<attr>
        for srv in (http_srv, socks_srv):
            srv.cfg = self.cfg
            srv.rules = self.rules
            srv.guard = self.guard
            srv.router = self.router
            srv.audit = self.audit
            srv.metrics = self.metrics
        self._servers = [http_srv, socks_srv]

        for srv, name, bind in ((http_srv, "http", http), (socks_srv, "socks5", socks)):
            t = threading.Thread(target=srv.serve_forever,
                                 kwargs={"poll_interval": 0.5}, daemon=True, name=f"{name}-acceptor")
            t.start()
            print(f"[svc] {name} proxy listening on {bind['bind']} -> {bind['resolvedBind']}:{bind['port']}", flush=True)

        allow = self.cfg["security"].get("clients", {}).get("allow") or []
        if str(http["bind"]).lower() in ("0.0.0.0", "*", "auto") or str(socks["bind"]).lower() in ("0.0.0.0", "*", "auto"):
            hint = "all LAN clients" if not allow else "allowed: " + ", ".join(allow)
            print(f"[svc] LAN exposure active ({hint})", flush=True)

        self.status.write(self.cfg, self.metrics, True)
        self.audit.log("info", "engine.start", detail="ProxyServer started (python)")

        self._start_control_channel()
        self._install_signal_handlers()
        try:
            while not self._stop.is_set():
                self._stop.wait(1.0)
        except KeyboardInterrupt:
            self.request_shutdown()
        finally:
            self.shutdown()

    def _status_loop(self) -> None:
        while not self._stop.wait(2.0):
            self.status.write(self.cfg, self.metrics, True)

    def request_shutdown(self, signum=None, frame=None) -> None:
        if self._stop.is_set():
            return
        self._stop.set()
        self.audit.log("info", "engine.stop", detail="shutdown requested")
        for srv in self._servers:
            threading.Thread(target=srv.shutdown, daemon=True).start()

    def _install_signal_handlers(self) -> None:
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                signal.signal(sig, self.request_shutdown)
            except (ValueError, OSError):
                pass

    # -- local control channel (127.0.0.1 only) --------------------------------
    def _start_control_channel(self) -> None:
        port = 8085
        try:
            self._control = socket.create_server(("127.0.0.1", port), reuse_port=False)
        except OSError:
            return
        t = threading.Thread(target=self._control_loop, daemon=True, name="ctl")
        t.start()

    def _control_loop(self) -> None:
        while not self._stop.is_set():
            try:
                conn, addr = self._control.accept()
            except OSError:
                break
            with conn:
                try:
                    data = conn.recv(1024).decode("ascii", "ignore").strip().upper()
                    if addr[0] != "127.0.0.1":
                        continue
                    if data in ("STATUS", "PING"):
                        snap = self.metrics.snapshot()
                        conn.sendall(json.dumps({
                            "ok": True, "uptimeSec": self.metrics.uptime(),
                            "metrics": snap,
                        }).encode())
                    elif data == "STOP":
                        conn.sendall(b'{"ok":true,"action":"stopping"}')
                        self.request_shutdown()
                    else:
                        conn.sendall(b'{"ok":false,"error":"unknown command"}')
                except OSError:
                    pass

    def shutdown(self) -> None:
        if self._cleaned:
            return
        self._cleaned = True
        for srv in self._servers:
            srv.server_close()
        if self._control:
            try:
                self._control.close()
            except OSError:
                pass
        self.status.write(self.cfg, self.metrics, False)
        self.audit.close()
        print("[svc] stopped cleanly", flush=True)


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def validate_config(cfg: dict) -> list[str]:
    problems = []
    for name in ("http", "socks5"):
        l = cfg["listeners"][name]
        b = str(l["bind"]).strip().lower()
        if b not in ("auto", "*", "localhost", "0.0.0.0", "::"):
            try:
                ipaddress.ip_address(b)
            except ValueError:
                # hostname binds are allowed; validate shape only
                if not re.fullmatch(r"[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?", b):
                    problems.append(f"listeners.{name}.bind: invalid host/IP ({l['bind']!r})")
        if not (0 < int(l["port"]) < 65536):
            problems.append(f"listeners.{name}.port out of range")
    if cfg["listeners"]["http"]["port"] == cfg["listeners"]["socks5"]["port"]:
        problems.append("http and socks5 ports must differ")
    for u in cfg.get("upstreams", []):
        if (u.get("type") or "Direct").lower() != "direct":
            if not u.get("host") or not (0 < int(u.get("port", 0)) < 65536):
                problems.append(f"upstream {u.get('name')!r}: host/port required for non-direct")
    for r in cfg.get("rules", []):
        if str(r.get("action", "")).lower() not in ("allow", "deny", "route"):
            problems.append(f"rule {r.get('id')}: unknown action {r.get('action')!r}")
    return problems


def main() -> int:
    ap = argparse.ArgumentParser(description="ProxySuite Python proxy server")
    ap.add_argument("--config", default=str(BASE_DIR / "config.json"))
    ap.add_argument("--check-config", action="store_true")
    ap.add_argument("--version", action="store_true")
    # Manual IP setup overrides (beat config file values)
    ap.add_argument("--http-bind", default=None,
                    help="HTTP listen IP: 127.0.0.1 | auto | 0.0.0.0 | a LAN IP | hostname")
    ap.add_argument("--http-port", type=int, default=None)
    ap.add_argument("--socks-bind", default=None,
                    help="SOCKS5 listen IP: 127.0.0.1 | auto | 0.0.0.0 | a LAN IP | hostname")
    ap.add_argument("--socks-port", type=int, default=None)
    ap.add_argument("--allow", default=None,
                    help="comma-separated client CIDRs, e.g. 192.168.1.0/24 (beats config)")
    args = ap.parse_args()

    if args.version:
        print("ProxySuite-Python 1.0.0")
        return 0

    cfg = load_config(Path(args.config))

    # CLI overrides for manual IP setup
    if args.http_bind:
        cfg["listeners"]["http"]["bind"] = args.http_bind
    if args.http_port:
        cfg["listeners"]["http"]["port"] = args.http_port
    if args.socks_bind:
        cfg["listeners"]["socks5"]["bind"] = args.socks_bind
    if args.socks_port:
        cfg["listeners"]["socks5"]["port"] = args.socks_port
    if args.allow:
        cl = cfg["security"].setdefault("clients", {})
        cl["allow"] = [a.strip() for a in args.allow.split(",") if a.strip()]

    problems = validate_config(cfg)
    if args.check_config:
        if problems:
            print("CONFIG INVALID:")
            for p in problems:
                print("  -", p)
            return 1
        print("Config OK. HTTP", cfg["listeners"]["http"]["bind"], cfg["listeners"]["http"]["port"],
              "| SOCKS5", cfg["listeners"]["socks5"]["bind"], cfg["listeners"]["socks5"]["port"])
        return 0
    if problems:
        print("Refusing to start with invalid config:", file=sys.stderr)
        for p in problems:
            print("  -", p, file=sys.stderr)
        return 2

    home = Path(args.config).resolve().parent
    server = ProxyServer(cfg, home)
    print(f"[svc] ProxySuite-Python starting (home: {home})", flush=True)
    server.start()   # blocks until shutdown; cleans up on exit
    return 0


if __name__ == "__main__":
    sys.exit(main())
