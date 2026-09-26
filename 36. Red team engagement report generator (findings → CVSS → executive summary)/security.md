# Security.md — Security Design

Scope: the Red Team Engagement Report Generator **desktop GUI** and the
portable **.exe** bundle. This file is the reserved security design record
for the tool (see also `architecture.md` for the pipeline diagram, `state.md`
for persisted state, and `memory.md` for design decisions).

## Threat model

| Actor | Capability | Applied countermeasure |
|---|---|---|
| Malicious findings file | Crafted JSON that triggers code execution or path traversal | Strict schema parsing (`_parse_finding`), no `eval`/`exec`, output rendered to a user-chosen directory only |
| Malicious report HTML | XSS via finding text | HTML reporter escapes all text fields before interpolation |
| Malicious CVSS vector | Odd-length/duplicate/unknown metrics | `CVSS3Engine` validates keys/values and refuses unknown metrics; invalid vectors still render safely by returning `CVSS3Result(valid=False)` |
| Local eavesdropper | Read secrets from memory/disk/config | Tool holds **no secrets by design**; no credentials are accepted, stored or logged |
| Network attacker | Exfiltrate findings | **Zero-network design**: all catalogs embedded, no sockets, no telemetry, no outbound calls |

## Core principles

1. **Zero network.** The GUI performs no I/O over sockets and parses no remote
   content. Findings, catalogs and reports stay on the analyst's machine —
   making the tool usable in air-gapped / classified environments.
2. **No secrets stored.** There is no credential, API key, or token storage.
   `state.json` persisted to `%LOCALAPPDATA%` holds only two last-used *paths*
   (see `state.md`), never file contents and never secrets.
3. **Fail closed on parse.** Invalid input produces an explicit error surfaced
   in the GUI log/status bar instead of silently trusting malformed data.
4. **No code generation.** Findings are data. Nothing is `eval`'d, no shell
   interpolation of finding content, and HTML/CSV/XLSX cells are escaped in
   the reporter layer.

## Hardening controls

- **Path handling** — all output paths are user-selected via dialogs; the
  pipeline writes inside that directory only. The GUI `open_folder` action
  launches the OS file manager against the resolved path (no shell).
- **Console discipline** — the PyInstaller bundle is built `--windowed`
  (`console=False`), so no hidden console captures stray output; CLI errors
  are written to stderr only.
- **Dependency surface** — bundle excludes unused heavy libs
  (`numpy`, `pandas`, `matplotlib`, Qt bindings) from the spec, shrinking the
  attack surface and artifact size.
- **Validation** — `state_store` filters values to a fixed key allow-list and
  drops empty or non-string entries before serializing.

## Packaging & supply-chain notes

- Build via `redteam_report.spec` / `build_exe.ps1`; PyInstaller modules are
  pinned through the `gui,build` extra (`pyinstaller`, `openpyxl`).
- For distribution, sign the artifact (Authenticode) and publish a SHA-256
  digest: `Get-FileHash dist\RedTeamReport.exe -Algorithm SHA256`.
- The `.exe` is **portable** — it does not write to Program Files, requires no
  admin, and stores state only under the current user's `%LOCALAPPDATA%`.

## Reporting data classification

Findings describe vulnerabilities (often CUI / export-controlled material).
The tool stamps no metadata into files beyond engagement fields the analyst
already supplies; remember that generated `.xlsx` / `.html` artifacts inherit
the classification of the input data and should be handled per your data
governance policy.

## Known residuals

- State file is plain text (a *path cache*, not secrets); if this is a
  concern in a shared-workstation environment, restrict `%LOCALAPPDATA%`
  access or remove the profile.
- No in-app authentication; the tool assumes the authenticated analyst is
  the same user who launched the process.

## Checklist before shipping a build

- [ ] `python -m pytest -q` — all green
- [ ] `build_exe.ps1` produces `dist\RedTeamReport.exe` cleanly
- [ ] Artifact scanned by local AV
- [ ] SHA-256 digest published
- [ ] `console=False`, no debug bootloader, no `--debug` flags in spec