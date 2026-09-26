# State.md — Application State & Persistence

Reserved design record for how the desktop GUI recalls and rehydrates session
information between runs. State is deliberately **minimal**: the tool is
stateless by default and persists only navigation affordances, never report
content.

## State contract

| Key | Type | Meaning | Persisted? |
|---|---|---|---|
| `input_file` | `str (path)` | Last loaded engagement JSON | Yes |
| `output_dir` | `str (path)` | Last output directory | Yes |
| engagement (in-memory) | dict/dataclass | Loaded `Engagement` object | No — rebuilt from file |
| report results (in-memory) | dict | `ReportResult` map from a generation run | No — files live on disk |
| view state (scroll positions, selection) | — | ephemeral UI state | No |

## Where it lives

- Windows: `%LOCALAPPDATA%\redteam_report\state.json`
- Fallback (no `LOCALAPPDATA`): `~/.redteam_report/state.json`
- File shape:

```json
{
  "input_file": "C:\\engagements\\helios.json",
  "output_dir": "C:\\engagements\\reports"
}
```

## Implementation

- Module: `src/redteam_report/state_store.py
  `load_state()` / `save_state()` / `clear_state()`, key allow-list
  `DEFAULT_KEYS = ("input_file", "output_dir")`.
- GUI hooks:
  - `_restore_state()` on startup re-populates the input/output fields.
  - `_save_state()` after a successful load and after a generation completes.
- The pipeline (`pipeline.py`) never touches state — persistence is a GUI-only
  concern, keeping the core engine pure and testable.

## Rules

1. **Fail open** — if `state.json` is corrupt or absent, the GUI starts with
   blank fields; nothing raises.
2. **Allow-list only** — unexpected keys are never serialized.
3. **Values validated** — entries must be non-empty strings; the input path is
   re-checked for existence on restore.
4. **No content** — state stores *paths*, not file bytes, summaries, or data.
5. **Atomic-ish writes** — JSON is written with `encoding="utf-8"`, indent=2,
   after parent dir creation; failures return `None` (no crash).

## Known limitations & roadmap

- Single user profile; no multi-profile scoping yet.
- Window geometry not yet persisted (candidate key: `window_geometry`).
- Per-user format preferences could extend the allow-list later
  (candidate: `formats: ["xlsx", "csv", "html"]`).

## Testing

`tests/test_state_store.py` covers: round-trip save/load, key filtering,
corrupt-file tolerance, missing base dir creation, and `clear_state`.

---

Reserved companion records: `architecture.md` (what the tool is),
`security.md` (how data is protected), `state.md` (this file — what is
remembered), `memory.md` (design decisions & how the app runs).