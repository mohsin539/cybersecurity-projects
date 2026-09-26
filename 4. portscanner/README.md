# Port Scanner (Python)

Authorized-use TCP/UDP port scanner with **CLI + tkinter GUI**, implementing the
design in [`architecture.md`](architecture.md) and the controls in
[`security.md`](security.md) (ISO 27001 / NIST 800-53 / OWASP Top 10 mapping).

- **Stdlib-only core** — no required third-party packages.
- Optional: `pip install scapy` enables SYN/FIN/NULL/XMAS raw engines (admin/root + Npcap on Windows).

## Quickstart

```bash
py portscanner/cli.py --help          # module CLI
py -m portscanner 127.0.0.1 -p 80,443 --yes
py -m portscanner --gui               # desktop GUI
py portscanner/gui.py                 # or directly
```

Examples:

```bash
py -m portscanner 10.0.0.0/30 -p top100 -f json -o report.json --yes
py -m portscanner 10.0.0.5 -p 1-1024 --rate 500 --jitter 20 --yes
py -m portscanner --resume scan.wal          # continue an interrupted scan
```

## Safety & compliance

- **Authorization gate** — non-private targets require `--yes` or an interactive
  confirmation phrase; refusals are logged (ISO 27001 A.8.8, NIST CM-7, OWASP A05).
- **Audit log** — `~/.portscanner/audit.log` records who/when/what (ISO A.8.15, NIST AU-2).
- **Hardened output** — banners sanitized against terminal escape injection; path
  traversal blocked; secrets redacted (OWASP A03/A01, ISO A.5.17).
- **Resource caps** — bounded targets, workers, expansion, and rate (OWASP A04).

See [`security.md`](security.md) for the full control matrix,
[`state.md`](state.md) for build/run state, and [`memory.md`](memory.md) for
project memory and decisions. Run tests: `py -m unittest discover -s tests -v`.
