"""
MSGRPC integration for the custom Metasploit module.

Implements a thin JSON-RPC client for Metasploit's HTTP MSGRPC transport
(127.0.0.1:55553) and a faithful off-line simulator so the portable console
works even when the Framework is not installed. The simulator mirrors the
console semantics of `console.create / console.write / console.read`.
"""
import json
import time
import urllib.error
import urllib.request

MSGRPC_HTTP = "http://127.0.0.1:55553/api"

CHECK_FLOW = [
    ("run", "[*] msf6 exploit(lab/vulnlab_cmd) > set RHOSTS {host}"),
    ("neutral", "RHOSTS => {host}"),
    ("run", "[*] msf6 exploit(lab/vulnlab_cmd) > set RPORT {port}"),
    ("neutral", "RPORT => {port}"),
    ("run", "[*] msf6 exploit(lab/vulnlab_cmd) > set FLAG_MODE {mode}"),
    ("neutral", "FLAG_MODE => {mode}"),
    ("run", "[*] msf6 exploit(lab/vulnlab_cmd) > check"),
    ("target", "[+] {host}:{port} - The target is vulnerable. sink={mode} banner=VulnLab/1.0 (debug)"),
    ("neutral", "[*] {host}:{port} - probe sent to /api/echo header X-Cmd"),
    ("ok", "[+] Command output captured: uid=0(root) gid=0(root)"),
    ("warn", "[!] Evidence saved to findings/evidence_{mid}.json"),
    ("info", "[*] Module check completed in 0.42s"),
]

VERIFY_FLOW = [
    ("run", "[*] msf6 exploit(lab/vulnlab_cmd) > set VERBOSE true"),
    ("neutral", "VERBOSE => true"),
    ("run", "[*] msf6 exploit(lab/vulnlab_cmd) > exploit -j"),
    ("target", "[*] Started reverse TCP handler on 127.0.0.1:4444"),
    ("ok", "[+] {host}:{port} - vulnlab_cmd executed (proof of concept)"),
    ("warn", "[!] Session 1 opened (127.0.0.1:4444 -> {host}:{port})"),
]

EXPLOIT_FLOW_TIMEOUT = 2.4


class MsgrpcClient:
    def __init__(self, url: str = MSGRPC_HTTP, password: str = ""):
        self.url = url
        self.token = ""
        self.console_id: int | None = None
        self._log = []

    def _call(self, method, *params, timeout=6):
        body = {"jsonrpc": "2.0", "method": method, "params": list(params), "id": 1}
        req = urllib.request.Request(
            self.url,
            data=json.dumps(body).encode(),
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            method="POST",
        )
        if self.token:
            req.add_header("Authorization", self.token)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode())

    def ping(self) -> bool:
        try:
            self._call("core.version")
            return True
        except (urllib.error.URLError, OSError, KeyError):
            return False


class RealConsoleBackend:
    """Talks to the running Metasploit Framework over MSGRPC."""

    def __init__(self, password: str = ""):
        self.client = MsgrpcClient(password=password)
        self.real = self.client.ping()

    @property
    def available(self) -> bool:
        return self.real

    def create(self):
        try:
            res = self.client._call("console.create")
            self.client.console_id = int(res.get("result", 0))
        except Exception:
            pass

    def write(self, cmd: str):
        try:
            self.client._call("console.write", self.client.console_id, cmd + "\n")
        except Exception:
            pass

    def read(self) -> str:
        try:
            res = self.client._call("console.read", self.client.console_id)
            return str(res.get("data", "") or res.get("result", ""))
        except Exception:
            return ""

    def destroy(self):
        try:
            self.client._call("console.destroy", self.client.console_id)
        except Exception:
            pass

    def pump(self, command: str) -> list[str]:
        self.create()
        self.write(command)
        lines: list[str] = []
        for _ in range(40):
            out = self.read()
            if out:
                lines.extend([l for l in out.splitlines() if l.strip()])
            time.sleep(0.15)
            if "meterpreter" in out or "] exploited" in out:
                break
        self.destroy()
        return lines


class SimBackend:
    """Off-line simulator. Deliberate, deterministic, lab-safe output."""

    _mid = 12

    def __init__(self, *_, **__):
        self.available = True

    def _next_mid(self):
        self._mid += 1
        return self._mid

    def pump(self, command: str, mode: str = "inject", host: str = "10.10.10.5",
             port: int = 1337) -> list[tuple[str, str]]:
        cmd = command.strip().lower()
        flow = []
        if cmd in ("check", "run check"):
            mid = self._next_mid()
            flow = [(k, v.format(host=host, port=port, mode=mode, mid=mid))
                    for k, v in CHECK_FLOW]
        elif cmd in ("verify", "exploit"):
            if cmd == "exploit" and EXPLOIT_FLOW_TIMEOUT:
                time.sleep(0.6)
            flow = [(k, v.format(host=host, port=port, mode=mode))
                    for k, v in VERIFY_FLOW]
        else:
            flow = [("neutral", f"[*] simulator parsed command: {command}"),
                    ("warn", "[!] no sink matched; nothing to do (safe default)")]
        return flow