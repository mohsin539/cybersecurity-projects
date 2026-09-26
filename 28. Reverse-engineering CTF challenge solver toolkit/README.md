# REkt — Reverse-Engineering CTF Challenge Solver Toolkit

Portable, GUI-based toolkit for solving reverse-engineering CTF challenges.
Ships as a single folder with `rekt.exe` — no installer, no admin rights, no
registry writes, no network access. Designed against OWASP Top 10 (2021),
NIST SSDF/800-53/CSF, and ISO/IEC 27001:2022 controls from day one
(see `ARCHITECTURE.md` §6 for the full mapping).

## Features (v1.0)

- **Static analysis** — file identification, entropy profile + graph, PE/ELF
  structure, packer heuristics, imports, strings (ASCII + UTF-16LE)
- **Flag finder** — `flag{...}`, `picoCTF{...}`, `HTB{...}`, `THM{...}` and more,
  surfaced automatically into the Findings pane
- **Sandboxed analysis** — every job runs in a disposable child process with
  Windows Job Object caps (memory/CPU/process), network null-routed, writes
  confined to a per-job scratch dir, watchdog + hard timeout
- **Recipe toolbox** — Base16/32/64/85, hex, URL, ROT13, XOR (incl. custom-key
  pipelines), SHA-256; one-click recipes + JSON custom pipelines
- **Carver** — embedded PNG/JPEG/ZIP extraction with zip-bomb and
  path-traversal guards
- **Plugin system** — Ed25519-signed allow-list; Developer Mode for unsigned
  review, always audited
- **Tamper-evident audit log** — hash-chained JSONL, verified at boot,
  one-click verification from the File menu

## Quick start

### Portable .exe (recommended)

1. Copy `dist/rekt-portable/` anywhere (USB stick, `%TEMP%`, anywhere writable).
2. Run `rekt.exe`.
3. **File → Add sample…**, then **Run analysis**. Flags appear under *Findings*.

Portable mode stores data next to your choice: pass `--data-dir <path>`, or set
`REKT_PORTABLE=<path>` to keep everything on the stick.

### From source

```bash
pip install -r requirements.txt
python -m rekt                # GUI
python -m pytest tests/ -q    # test suite (50 tests)
```

### Demo: solve your first challenge in 60 seconds

```bash
python scripts/make_demo_sample.py     # generates REKT-LOCAL/demo_crackme.exe
python -m rekt --data-dir REKT-LOCAL
```

The crafted crackme contains a **decoy** flag (`flag{n0t_th3_r34l_fl4g}`, which
the flag rules will happily surface) and the **real** flag hidden as
base64(XOR-7(flag)). Solve path: run *Run analysis* → copy the base64ish blob
from *Findings* → *Recipes* → custom pipeline `[b64_decode, xor key "7"]` →
`flag{S4ndb0x_F1rst_D1s4ss}`. The *Disassembly* tab shows the sandboxed
Capstone listing of its `.text` section.

For Ghidra decompilation: install [Ghidra](https://ghidra-sre.org/) locally,
set `REKT_GHIDRA_HOME` (or paste the path in the *Decompiler* tab), and press
**Decompile (consent-gated)** — Java and your local install are used; nothing
is downloaded.

## Building the portable exe

```bash
python scripts/build_exe.py   # → dist/rekt-portable/rekt.exe
```

The build is `--onedir --windowed`, no UPX (fewer AV false positives), and
bundles `rules/` + `plugins/`. For release distribution: Authenticode-sign
`rekt.exe`, publish SHA-256SUMS alongside, and distribute `trust.pub` out-of-band
(`scripts/sign_plugin.py keygen` shows the trust-model workflow).

## Security model (summary)

| Guarantee | Mechanism |
|---|---|
| Samples never execute in v1.x | `SAMPLE_EXEC` ships disabled; consent-gated architecture |
| Analysis can't phone home | network denied at Policy level + socket null-route in child |
| Analysis can't touch your files | write-guard confined to job scratch + Job Object limits |
| Runaway jobs die | hard timeout + CPU/memory caps + watchdog, fail-closed |
| Plugins are trusted code | signed allow-list; unsigned ⇒ Developer Mode + audit |
| Logs can't be silently forged | hash-chained audit, verified at boot |

Full invariants and honest limitations: `SECURITY.md`. Threat model:
`ARCHITECTURE.md` §7.

## Repository map

```
rekt/
├─ rekt/               application source (platform/core/sandbox/application/presentation)
├─ plugins/            first-party signed plugin (suspicious_strings)
├─ rules/              flag rules (shipped to the exe)
├─ scripts/            build_exe.py, sign_plugin.py, verify_release.py
├─ tests/              pytest suite (41 tests incl. end-to-end sandbox)
├─ ARCHITECTURE.md     full architecture + OWASP/NIST/ISO mappings
├─ SECURITY.md         security policy & invariants
├─ STATE.md            current project state snapshot
├─ MEMORY.md           engineering memory for future sessions
└─ rekt.spec           PyInstaller spec
```

## License

MIT for REkt itself; bundled components keep their licenses (PySide6/Qt 6 is
LGPLv3 — dynamically linked; see `ARCHITECTURE.md` §12).

## Responsible use

REkt is for **authorized** CTF, education, and research. You are responsible
for complying with the laws of your jurisdiction and the rules of any event
you attend. The toolkit is analysis-only: it contains no packing, obfuscation,
or evasion capability.
