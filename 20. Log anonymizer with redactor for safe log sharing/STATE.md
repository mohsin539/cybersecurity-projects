# State Preservation - Log Anonymizer Desktop GUI

## Purpose

The desktop tool persists its operational state between sessions so the user resumes exactly where they left off — same window size, last policy, remembered salt and recent directories — without exposing any sensitive content from previous sessions.

---

## 1. State File Format

| Location | Path |
|----------|------|
| Default | `%APPDATA%\LogAnonymizer\state.json` |
| Override | `ANON_APP_DIR` environment variable |
| In tests | Isolated `tmp_path` directory |

### Layout

```
LAC1-STATE <payload_length>\n
<sha256_integrity_mac>\n
{
  "version": 1,
  "window": { "width": 1180, "height": 780, "x": null, "y": null },
  "preferences": {
    "theme": "dark",
    "keep_last_chars": 4,
    "mask_char": "*",
    "default_date_shift_days": 0,
    "max_line_length": 100000,
    "preview_lines": 500
  },
  "recent": {
    "last_policy_id": "default",
    "last_open_dir": "",
    "last_export_dir": "",
    "audit_dir": ""
  },
  "secrets": {
    "token_salt": "<DPAPI-encrypted or cleartext>",
    "session_passphrase_hash": ""
  },
  "safer": "genuine_preservation_state",
  "updated_at": "2026-09-17T12:00:00Z"
}
```

---

## 2. Integrit y Protection

| Field | Mechanism | Standard |
|-------|-----------|----------|
| Entire file | SHA-256 MAC over `LAC1-STATE + payload_bytes` prepended as line 2 | ISO A.8.24, A.8.15 |
| Write atomicity | Write to temp file → `os.fsync` → `os.replace` (atomic on NTFS) | NIST AU.10 |
| Truncation detection | Length prefix compared with actual payload length at load time | SI.4 / safe fail |
| Tamper detection | Any bit-flip in payload changes MAC → `StateError("tampered")` raised | NIST SI.7 |

If the state file is missing (first run), secure defaults are returned without error.

---

## 3. Sensitive Field Protection

| Field | At Rest | On Windows (DPAPI) | On Non-Windows |
|-------|---------|---------------------|----------------|
| `token_salt` | DPAPI-encrypted `CryptProtectData(..., CRYPTPROTECT_UI_FORBIDDEN)` | AES-256, bound to Windows user login credentials; no app-stored key | Cleartext (documented limitation; user must accept risk) |
| `session_passphrase_hash` | scrypt hash (length-verified, 64-char hex) | Stored in cleartext JSON (the hash itself is not reversible; used for session gating only) | Same |

**Why DPAPI for the salt:** the token salt is used to derive tokenization values. If it is stored in cleartext, anyone who reads `state.json` can reverse HMAC tokens back to the original values. DPAPI eliminates that risk by binding the ciphertext to the Windows user profile — the ciphertext can only be decrypted by the same user who encrypted it (NIST SP 800-53 SC.12).

---

## 4. State Schema (`AppState`)

```python
@dataclass
class AppState:
    version: int = 1
    window_width: int = 1180
    window_height: int = 780
    window_x: int | None = None
    window_y: int | None = None
    last_policy_id: str = "default"
    last_open_dir: str = ""
    last_export_dir: str = ""
    theme: str = "dark"                  # "dark" | "light"
    keep_last_chars: int = 4             # partial mask retain count
    mask_char: str = "*"                 # masking character
    default_date_shift_days: int = 0     # date-shift strategy offset
    max_line_length: int = 100_000       # OWASP A03 input limit
    preview_lines: int = 500             # max lines rendered in preview
    token_salt: str = ""                 # DPAPI-encrypted
    session_passphrase_hash: str = ""    # scrypt hash (session gate)
    audit_dir: str = ""                  # default: data/audit
    updated_at: str = ""                 # ISO 8601
```

---

## 5. When State is Written

| Trigger | Action |
|---------|--------|
| Window close (`destroy()`) | Window geometry + current preferences → save |
| `Settings > Save` | Updated preferences → save |
| `Anonymize` completes | Last policy ID saved immediately |
| File opened | `last_open_dir` set and saved |
| Export completed | `last_export_dir` saved |

All writes go through the atomic temp-file path (`tempfile.mkstemp` → `os.replace`).

---

## 6. Privacy Constraints

**STATE NEVER CONTAINS LOG CONTENT.** The following are the only categories stored:

| Allowed | Examples |
|---------|----------|
| Window geometry | width, height, x, y |
| UI preferences | theme, mask_char, keep_last_chars |
| Paths | last_open_dir, last_export_dir |
| Identifiers | last_policy_id, request_id |
| Cryptographic material | token_salt (encrypted), passphrase_hash |
| Timestamps | updated_at |

| Forbidden | Examples |
|-----------|----------|
| Raw log lines | Never |
| Redacted log lines | Never |
| Original PII values | Never |
| API keys / salts in plaintext | Never |

---

## 7. Erasure (GDPR Art. 17 Right to be Forgotten)

```python
state_manager.forget()   # deletes state.json, resets to DEFAULT_STATE
memory_manager.forget_all()  # deletes memory.json, resets to Memory()
```

Both are available from `Settings > Forget State & Memory`.

After erasure:
- State file is deleted from disk
- Memory file is deleted from disk
- All in-memory variables reset to defaults
- No backup or recovery mechanism exists (by design)

---

## 8. Failure Modes

| Failure | Behaviour | Standard |
|---------|-----------|----------|
| State file missing | Load secure defaults silently | NIST PR.IP-1 (continuity) |
| State file truncated | `StateError` raised; defaults used; warning dialog | A.8.14 |
| Integrity tag mismatch | `StateError("tampered")` raised; defaults used; warning dialog | NIST SI.7 |
| DPAPI decryption failure | `StateError("cannot decrypt")` raised; user is prompted | SC.12 |
| Write failure (disk full) | Error propagated to caller; `destroy()` catches and logs to stderr | A.12.1 |
| Non-Windows platform | Secrets stored in cleartext with `secrets_in_clear=True` warning | Documented limitation |

---

## 9. Test Coverage

| Test | What it validates |
|------|-------------------|
| `test_defaults_loaded_when_no_file` | First-run returns secure defaults |
| `test_save_load_roundtrip` | State survives a save→load cycle |
| `test_atomic_write_leaves_no_temp_files` | No orphaned `.state-*` files on success |
| `test_integrity_detects_tampering` | Single-bit flip raises `StateError` |
| `test_truncation_detected` | Half-written file rejected |
| `test_secret_roundtrip_is_dpapi_protected` | Salt is not plaintext in file; round-trips correctly |
| `test_update_dotted_keys` | `update("window.width", 1111)` works correctly |
| `test_forget_removes_file` | State file deleted and defaults restored |
| `test_marker_required` | Missing `safer` marker causes `StateError` |
| `test_safer_marker_present` | `safer` key written to every state file |