# memory.md — Durable Memory

**Purpose:** everything a future session needs to continue this project without
re-asking questions. Read this + `state.md` + `architecture.md` first.

**Project root:** `D:\AI Masterclass\Subnet Mask Calculator and VLSM planner\`
**Last updated:** 2026-09-09

---

## 1. User preferences (observed & explicit)

- **Save location convention:** user wants all project artifacts (docs, code,
  exe, memory files) inside
  `D:\AI Masterclass\Subnet Mask Calculator and VLSM planner\` — never scatter.
- **Language:** user communicates in English; keep docs in English.
- **Style:** user asks for "GUI based solution" + "portable .exe" — prefers
  runnable desktop deliverables over web stacks for this project.
- Spelling in prompts is informal ("archetecture", "locatoin") — interpret by
  intent, confirm ambiguous targets before writing.

## 2. Key decisions & their rationale

| Decision | Why |
|---|---|
| Python 3.12 + Tkinter GUI instead of React web (architecture.md §2) | Explicit user request to build a GUI solution in Python; layer structure kept 1:1 with the web architecture. architecture.md still describes the React plan — treat `domain/` sections (§5, §6, §9, §10) as the authoritative shared spec. |
| `Result[T, E]` (Ok/Err) instead of exceptions | architecture.md §5 rule: UI never receives thrown exceptions from domain. |
| VLSM descending allocation, failures don't abort plan | Every requirement gets a subnet-or-explained-failure — the learning-tool value (§6.3). |
| `cidr_for_hosts` via `bit_length()` (exact, no float log2) | Avoids float edge cases at 2^n boundaries; formula: `32 - ceil(log2(hosts+2))`. |
| One-file PyInstaller build, console=False | "Portable .exe" requirement; state.json written next to exe for true portability (APPDATA fallback exists for read-only dirs). |
| /31 and /32 special-cased per RFC 3021 / host-route | Architecture §6.2 requires it; tests pin the behavior. |

## 3. Environment facts (this machine)

- **Python:** 3.12.7 64-bit, invoke as `py` (NOT `python` — that hits the
  Microsoft Store alias and fails with exit code 49).
- **Tkinter:** available in this build.
- **PyInstaller:** 6.22.2 installed via `py -m pip install pyinstaller`.
- **Shell:** Git Bash on Windows — use POSIX syntax (`rm -rf`, forward slashes),
  `taskkill //F //IM name.exe` (double slashes for Git Bash), quote paths with spaces.
- **Console encoding:** cp1252 — printing `█`/emoji from scripts crashes unless
  `py -X utf8` is used. Tk GUI itself is unaffected.
- **No git repo** initialized in the project folder (as of this date).

## 4. Gotchas learned while building (do not regress)

1. **VLSM alignment gaps are impossible with pure descending allocation** — each
   next block always divides the previous one, so the cursor stays aligned. The
   gap machinery in `vlsm_planner.py` is defensive (kept for future start-offset
   features); tests assert `plan.gaps == ()` for standard scenarios.
2. Golden scenario math: 192.168.1.0/24 with 50/25/10 hosts → /26+/27+/28 = 112
   of 256 addresses = **43.75% used**, leftover .112–.255. (Intuition says "more"
   — it isn't, because blocks double.)
3. 2 hosts → **/30** (4 addresses), not /29. Hosts+2 (network+broadcast) rule.
4. Tk widgets: never rebuild labels in a trace callback without clearing the
   parent first (`_grid_rows` clears; MaskBitGrid caches `_built_for` to skip
   redundant rebuilds). Canvas has `find_all()`, not `findall()`.
5. In one-file PyInstaller mode two processes appear (bootloader + app) — that's
   normal, don't "fix" it.
6. PyInstaller must be invoked as `py -m PyInstaller` (not bare `pyinstaller`).

## 5. Where everything is

| Thing | Location |
|---|---|
| Design doc | `architecture.md` |
| Current status | `state.md` |
| This file | `memory.md` |
| Entry point | `main.py` |
| Pure domain logic (tested) | `domain/*.py` |
| GUI (only tkinter importer) | `gui/app.py` |
| Persistence | `state/state_manager.py` → `state.json` (created at runtime next to exe) |
| Tests (31) | `tests/test_domain.py` — `py -m unittest discover -s tests` |
| Build recipe | `SubnetVLSMPlanner.spec` |
| **Deliverable exe** | `dist\SubnetVLSMPlanner.exe` (~11 MB, portable, verified launching) |
| Disposable build scratch | `build\` (safe to delete) |

## 6. Open threads / future direction

- architecture.md §12 backlog: IPv6 (`bigint` in domain), CSV/Markdown export,
  share-URLs (n/a for desktop — maybe .vlsm file import), supernetting tool, PWA (web-only).
- Unsigned exe → SmartScreen warning on other machines; signing is optional polish.
- No app icon yet; add `icon=` to the spec if the user provides/requests one.
- If the user returns asking to "continue", check `state.md` §6 first — it lists
  the immediate next steps as of last session.

## 7. Session log

- **2026-09-09 (session 1):** Created `architecture.md` (React web design v1.0).
  User pivoted to Python desktop: built full domain layer + Tkinter GUI + 31
  tests (all passing) + `dist\SubnetVLSMPlanner.exe` (portable, launch-verified).
  Wrote `state.md` and `memory.md`. Environment quirks recorded in §3/§4 above.
