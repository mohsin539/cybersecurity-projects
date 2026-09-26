# Guideline — Changing the Proxy Server IP

Step-by-step instructions for changing the IP address the proxy listens on.
Applies to **both** editions (C# `ProxyCoreSvc.exe` and Python `pyproxy/proxy_server.py`).

---

## Step 0 — Find the available IPs on this machine

Open PowerShell and run:

```powershell
Get-NetIPAddress -AddressFamily IPv4 |
  Where-Object { $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*' } |
  Select-Object IPAddress, InterfaceAlias
```

Pick the IP of the adapter your clients will reach (usually the Wi-Fi or Ethernet one,
e.g. `192.168.0.102`). Avoid virtual adapters (VirtualBox `192.168.56.1`,
Hyper-V `172.x`, WSL) unless you specifically want them.

---

## Step 1 — Stop the running proxy

Config is only read at startup, so the service must be stopped first.

C# service (either way works):

```powershell
taskkill /F /IM ProxyCoreSvc.exe
```
or just close the ProxyCoreSvc console window.

Python edition: close its window, or send the stop command:

```powershell
$c = New-Object Net.Sockets.TcpClient('127.0.0.1', 8085)
$s = $c.GetStream(); $b = [Text.Encoding]::ASCII.GetBytes("STOP`n")
$s.Write($b, 0, $b.Length); $c.Close()
```

---

## Step 2 — Choose HOW you want to set the new IP

### Option A — Interactive helper (recommended; updates both editions at once)

```powershell
powershell -ExecutionPolicy Bypass -File scripts\set-my-ip.ps1
```

What it does:
1. Lists your machine's IPs — type the number of the one you want, or accept `auto`.
2. Asks which clients may use the proxy — press Enter to accept the suggested
   subnet (e.g. `192.168.0.0/24`). It automatically adds `127.0.0.1/32` so this
   PC keeps working.
3. Writes `config.json` for BOTH the C# service (`dist\ProxySuite-Portable-win-x64\`)
   and the Python edition (`scripts\pyproxy\`).

One-shot variant (no prompts):

```powershell
powershell -ExecutionPolicy Bypass -File scripts\set-my-ip.ps1 -Bind 192.168.0.50 -Allow 192.168.0.0/24
```

### Option B — Manual edit of `config.json`

Open the config next to the exe you run:

- C# service: `dist\ProxySuite-Portable-win-x64\config.json`
- Python edition: `scripts\pyproxy\config.json`

Change the two `bind` values:

```json
"listeners": {
  "http":   { "bind": "192.168.0.50", "port": 8080, "authMode": "None" },
  "socks5": { "bind": "192.168.0.50", "port": 1080, "authMode": "None" }
}
```

**Also check the client allowlist** (a few lines below, under `security`):

```json
"security": {
  "clients": {
    "allow": [ "192.168.0.0/24", "127.0.0.1/32" ],
    "deny":  []
  }
}
```

Make sure it covers the subnet of the NEW IP — otherwise clients (including this PC
if `127.0.0.1/32` is missing) get 403 Forbidden.

Bind value cheat-sheet:

| bind | meaning |
|---|---|
| `192.168.0.50` | one specific manual IP (must exist on this machine) |
| `auto` | auto-detect the machine's LAN IPv4 at every startup |
| `0.0.0.0` or `*` | all interfaces (loopback + LAN + virtual adapters) |
| `127.0.0.1` | this PC only |
| `myhost.local` | a hostname, resolved once at startup |

### Option C — Python edition one-shot CLI (no file edit)

```bash
py scripts/pyproxy/proxy_server.py --http-bind 192.168.0.50 --socks-bind 192.168.0.50 --allow 192.168.0.0/24
```

CLI flags override the config file: `--http-bind`, `--http-port`,
`--socks-bind`, `--socks-port`, `--allow`.

---

## Step 3 — Start the proxy again

C# service:

```powershell
cd dist\ProxySuite-Portable-win-x64
start-service.cmd        :: or double-click it
```

Check the console banner — it shows exactly what was bound:

```
HTTP  proxy listening on 192.168.0.50 -> 192.168.0.50:8080
SOCKS5 proxy listening on 192.168.0.50 -> 192.168.0.50:1080
Client allowlist: 192.168.0.0/24, 127.0.0.1/32
```

Python edition:

```powershell
cd dist\ProxySuite-Portable-win-x64   (or scripts\pyproxy)
start-pyproxy.cmd
```

---

## Step 4 — Verify it works

From THIS machine:

```powershell
curl.exe -x http://NEW-IP:8080 http://example.com/ -m 15 -o NUL -w "%{http_code}`n"
curl.exe --socks5-hostname NEW-IP:1080 https://example.com/ -m 15 -o NUL -w "%{http_code}`n"
```

Both should print `200`.

From ANOTHER device (phone/PC on the same LAN): set its proxy to
`NEW-IP:8080` (HTTP) or `NEW-IP:1080` (SOCKS5) and open any website.

If it fails from other devices but works locally → Windows Firewall.
Allow the app on Private networks, or add the rule manually:

```powershell
netsh advfirewall firewall add rule name="ProxySuite HTTP" dir=in action=allow protocol=TCP localport=8080 profile=private
netsh advfirewall firewall add rule name="ProxySuite SOCKS5" dir=in action=allow protocol=TCP localport=1080 profile=private
```

(Run that once, as Administrator.)

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `FATAL: failed to start proxy listeners: ... invalid IP` | The bind IP doesn't exist on this machine | Pick an IP from Step 0, or use `auto` / `0.0.0.0` |
| `FATAL ... address already in use` / port busy | Old instance still running or another app owns the port | `taskkill /F /IM ProxyCoreSvc.exe`, or change the `port` values |
| Service starts, but clients get **403 Forbidden** | Client's IP is not in `security.clients.allow` | Add the client's subnet to `allow` (keep `127.0.0.1/32` too) |
| Works locally, not from other devices | Windows Firewall | Step 4 firewall commands |
| `auto` binds a virtual-adapter IP | Rare; only if the routing probe fails | Set the exact IP manually (Option B) |
| Bind error mentions hostname | DNS can't resolve the name at startup | Use a literal IP instead |

---

## Quick reference

| File | Purpose |
|---|---|
| `dist\ProxySuite-Portable-win-x64\config.json` | C# service config (bind + allowlist) |
| `scripts\pyproxy\config.json` | Python edition config |
| `scripts\set-my-ip.ps1` | Interactive IP picker (writes both configs) |
| `docs\CHANGE-PROXY-IP.md` | This guide |
