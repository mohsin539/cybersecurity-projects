# MEMORY.md — Session Memory & Engineering Ledger

> **Purpose:** Preserves *why* — design decisions, bugs found and fixed,
> environment specifics, and the exact verification commands. Companion to
> `STATE.md` (what/now). If a future session wonders "why is it like this?",
> the answer should be here.

**Last updated:** 2026-09-09 (session 2)

---

## 1. Environment (as observed)

| Item | Value |
|---|---|
| OS | Windows 11 (win32), bash shell (Git Bash) |
| Python | 3.12.7 via `py` launcher — **`python` is NOT on PATH** (Store alias disabled) |
| tkinter | available |
| Host machine name dir | `C:\Users\mohsi\` |
| Project dir | `C:\Users\mohsi\packet-sniffer\` (cwd is user profile root) |
| Consoles | cp1252 — always use `PYTHONIOENCODING=utf-8` when printing Unicode (▸, █, →) in tests |
| Local interfaces seen | 192.168.0.102 (primary), 192.168.158.1 (VMnet), 192.168.42.1, 192.168.56.1 (VirtualBox host-only) |

## 2. Key Design Decisions & Rationale

1. **Stdlib-only** — no scapy/npfact deps: zero-install portability, and the
   point of the exercise was raw-socket engineering, not library wrapping.
2. **Producer/consumer with bounded queue (25k, drop-oldest)** — under flood,
   losing UI/DB rows is acceptable; stalling the kernel socket buffer is not.
   This is the single most important perf decision in the design.
3. **Synthetic Ethernet header on Windows** — raw IP sockets deliver IP-only
   frames. Rather than fork the parser logic per-OS, the capture loop
   prepends a fake ETH header (broadcast dst + local MAC via `uuid.getnode()`),
   so the parser and PCAP export always see uniform L2 frames.
4. **UI never renders per-packet** — 33 ms coalesced `after()` drain +
   incremental append-only rendering + 2000-row visible window. Full-tree
   rebuilds were tried first and rejected (see bug #2).
5. **Threat cooldown keyed `(kind, src_ip, severity)`** — first attempt keyed
   `(kind, src_ip)` and suppressed severity escalation (medium fired, then the
   high alert was eaten). Keying by severity lets escalation through while
   still deduping repeat alerts.
6. **No UAC elevation in exe manifest** — least privilege; the app detects
   missing rights and prints a remediation hint instead. User launches
   elevated when they want capture.
7. **Authorization gate + consent table** — dual-use tool; the guardrail is
   part of the product, not just documentation.
8. **`raw` full-frame bytes + `raw_hex` 96-byte prefix** on the Packet
   dataclass — full frame needed for PCAP; prefix for quick display/hex-copy.

## 3. Bugs Found & Fixed (war stories — do not regress)

| # | Bug | Symptom | Fix |
|---|---|---|---|
| 1 | `len(self.stats.pps_history > 60)` | TypeError in capture loop | `len(...) > 60` |
| 2 | Undefined `ifr_name` in Linux promisc ioctl + missing `.fileno()` | NameError on Linux path | bind `ifname` var, pass `s.fileno()` to ioctl |
| 3 | GUI full-tree rebuild every 33 ms | Would freeze under load | incremental `_append_new_rows` + `_render_window` |
| 4 | `p.time` attribute didn't exist | AttributeError in render | use `p.timestamp` |
| 5 | PCAP wrote reconstructed 14-byte stubs | Wireshark-invalid export | write `pkt.raw` (full frame) |
| 6 | Windows raw path never prepended ETH header | Parser would misread IP as ETH | synth header in `_loop` when `IS_WINDOWS` |
| 7 | Threat `emit` re-alerted every packet | Event flood | cooldown in `_emit_once` (see decision 5) |
| 8 | `Storage.stop()` discarded buffered rows | Data loss on shutdown | drain-on-stop loop condition (`stop_drain` flag) |
| 9 | `ThreatEvent.desc` vs `.description` | AttributeError in GUI | use `description` |
| 10 | Hex-dump ternary precedence `p.raw or x if ... else b""` | Wrong fallback binding | explicit `p.raw if p.raw else (...)` |
| 11 | Threat events never persisted to `events` table | ARCHITECTURE §3.6 violation | session 2: `add_event` call in `_on_threat_event` |
| 12 | Demo frame index drift in tests | Assertion failures in tests (not code) | recompute indices: 0=ARP, 2=SYN, 5=HTTP-creds, 6=DNS, 7=ICMP-big, 39=IPv6 |
| 13 | `ev.src` vs `ev.src_ip` in persistence wiring | AttributeError on first live threat event | use `src_ip` (same family as bug #9 — ThreatEvent fields are `ts/kind/src_ip/description/severity`) |
| 14 | Consent row double-insert in wire test | Count assertion failed (c==2) | test artifact: prior crashed run left residue in `_wire_test.db`; clean DB before re-run |

## 4. Verified Commands (copy-paste to re-verify)

```bash
# syntax
cd packet-sniffer && py -m py_compile parsers.py capture.py storage.py \
    pcap_writer.py threat.py gui_theme.py gui.py demo.py packet_sniffer_gui.py

# backend tests (parsers/threat/pcap/storage/interfaces)
cd packet-sniffer && PYTHONIOENCODING=utf-8 py - <<'PY'
import parsers, capture, threat, storage, pcap_writer, demo, time as _t
frames = demo.build_frames()
evts = []
ta = threat.ThreatAnalyzer(emit=evts.append)
now = _t.time()
for port in range(20, 50):
    f = demo._eth(demo.MAC_B, demo.MAC_A, 0x0800) + demo._ipv4(
        '45.33.32.156', '10.0.0.5', 6,
        demo._tcp(40000 + port, port, 0x02))
    ta.analyze(parsers.parse_packet(f, now))
kinds = [(e.kind, e.severity) for e in evts]
assert kinds.count(('PORTSCAN', 'medium')) == 1
assert kinds.count(('PORTSCAN', 'high')) == 1
ta.analyze(parsers.parse_packet(frames[5], now))  # HTTP creds frame
assert any(e.kind == 'CREDS' for e in evts)
ta.analyze(parsers.parse_packet(frames[7], now))  # big ICMP frame
assert any(e.kind == 'ICMP_TUNNEL' for e in evts)
w = pcap_writer.PcapWriter('_t.pcap')
w.write_packet(1700000000.123456, frames[2]); w.close()
st = storage.Storage('_t.db')
st.add_packet((now, '1.2.3.4', '5.6.7.8', 1, 2, 'TCP', 60, 'x', 0, ''))
st.add_event((now, 'PORTSCAN', '1.2.3.4', 'd', 'high'))
st.stop()
import sqlite3
conn = sqlite3.connect('_t.db')
assert conn.execute('SELECT COUNT(*) FROM events').fetchone()[0] >= 1
conn.close()
print('backend OK')
PY

# GUI pipeline test (150 frames through real processor → render → filter)
# see session 2 transcript; feeds raw_q, ticks _ui_tick/_append_new_rows,
# asserts rows==150, filter 443 → 12, threats ≥ 3.

# build exe
cd packet-sniffer && build_exe.bat
```

## 5. Build & Packaging Notes

- **Built & verified this session:** `py -m PyInstaller packet_sniffer.spec
  --noconfirm` → `dist/PacketSniffer.exe` (12,511,589 bytes, ~31–60 s).
- PyInstaller 6.22.2 already present on the machine (no install needed;
  `build_exe.bat` handles the install path on machines that lack it).
- Spec: one-file, `console=False`, UPX off (avoids AV false positives),
  excludes pytest/setuptools/numpy/pandas/PIL.
- **One-file exes show TWO processes in tasklist** (bootloader parent + app
  child, ~8.6 MB + ~40 MB RAM) — normal, not a fork bomb.
- Launch test: started `dist/PacketSniffer.exe --demo` headless, confirmed
  in tasklist after 10 s, `taskkill //F //IM` clean.
- SmartScreen: unsigned exe → "More info → Run anyway" (documented).
- If AV flags the unsigned raw-socket exe (heuristic on SIO_RCVALL usage),
  whitelist it — this is expected for capture tools.
- **After any source change, REBUILD the exe** — it snapshots code at build
  time; a stale exe silently runs old logic.

## 6. Lessons / Gotchas for Future Sessions

- **Always** `PYTHONIOENCODING=utf-8` on this Windows console (cp1252) when
  tests print box-drawing/arrow glyphs.
- `write_file` requires the `instructions` param — two tool failures in
  session 2 were exactly this (empty instructions); keep it one sentence.
- Windows raw sockets ≠ loopback and ≠ ARP. Don't "fix" ARP-on-Windows
  reports as bugs — it's an OS limitation, documented in ARCHITECTURE §3.4/§7.
- Demo frame builder (`demo.build_frames()`) order: 3×ARP block first (0–1),
  TCP handshake (2–4), HTTP (5), DNS (6), ICMP (7), scan 30× (8–37),
  NTP UDP (38), IPv6 stub (39). Index changes = test breakage.
- `py`, not `python`, everywhere.
- In bash on Windows, `taskkill //F //IM name.exe` (double slashes — single
  `/F` gets mangled into a path by MSYS path translation).
- PyInstaller must run from the `packet-sniffer/` dir so the spec's relative
  entry point resolves; build dir is `build/packet_sniffer/` (safe to delete).
