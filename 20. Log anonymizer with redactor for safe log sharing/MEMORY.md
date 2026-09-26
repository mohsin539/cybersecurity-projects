# Memory Preservation - Log Anonymizer Desktop GUI

## Purpose

Memory is the long-lived "brain" of the desktop tool: it remembers which files the user opened, their preferences, custom detection rules and aggregate entity statistics — all without retaining a single line of original or redacted content. This document specifies what is stored, how it is protected and how it is erased on request.

---

## 1. Memory File Format

| Location | Path |
|----------|------|
| Default | `%APPDATA%\LogAnonymizer\memory.json` |
| Override | `ANON_APP_DIR` environment variable |
| In tests | Isolated `tmp_path` directory |

### Layout

```
LAC1-MEMORY <payload_length>\n
<sha256_integrity_mac>\n
{
  "version": 1,
  "theme": "dark",
  "keep_last_chars": 4,
  "last_policy_id": "default",
  "recent_files": [
    { "path": "C:\\logs\\app.log", "opened_at": "...", "line_count": 1234, "sensitive_hits": 5, "size_bytes": 2048 }
  ],
  "custom_rules": [
    { "entity_type": "INTERNAL_ID", "pattern": "ID-\\d{6}", "classification": "HIGH", "strategy": "PARTIAL_MASK", "note": "" }
  ],
  "entity_stats": { "<fingerprint>": 42 },
  "safer": "genuine_memory_store",
  "updated_at": "2026-09-17T12:00:00Z"
}
```

---

## 2. What is Stored vs. What is Never Stored

| Category | Stored | Format | Never Stored |
|----------|--------|--------|--------------|
| File references | Path only | Full resolved path string | File content (any form) |
| File metadata | line_count, size_bytes, sensitive_hits | Integer counts | Log line content or extracted values |
| Detection statistics | Fingerprinted entity type → count | SHA-256 16-char fingerprint of entity name | Entity type names in plain text |
| Custom rules | Regex pattern, classification, strategy | User-supplied parameters | Values matched by rules |
| UI preferences | theme, keep_last_chars, last_policy_id | Simple string/int | Token salt, passwords |
| Timestamps | opened_at, updated_at | ISO 8601 | — |
| Custom rule patterns | Regex strings | Raw text (user-authored) | — |

**Critical rule:** the `recent_files[].path` field is the *only* part of any original file that is ever persisted. The path is stored so the user can reopen the file quickly; the content is never read into the memory store under any circumstance.

---

## 3. Sanitization Pipeline

Every piece of data passes through sanitization before it enters the memory file:

### 3.1 `recent_files[].path`
- Stored as-is (full resolved path)
- Rationale: the path is needed to reopen the file; it is not secret in itself
- Privacy consideration: a user who considers the path sensitive can use `Forget All` (Art. 17)

### 3.2 Entity type statistics
Entity type names (SSN, EMAIL, etc.) are **fingerprinted** before storage:
```python
def _fingerprint(name: str) -> str:
    return hashlib.sha256(name.encode("utf-8", "replace")).hexdigest()[:16]
```
This means `entity_stats` keys are opaque 16-character hex strings, not readable entity names. The raw statistics are useful for aggregate dashboard views without revealing which specific entity types were detected.

### 3.3 Custom rules
Custom regex patterns are stored in cleartext because they are user-authored inputs, not values derived from log content. They are retained as-is so the detection engine can load them on the next launch.

### 3.4 Recent files list
Capped at 20 entries (most recent first). Older entries are discarded automatically.

---

## 4. Integrity Protection

| Field | Mechanism | Standard |
|-------|-----------|----------|
| Entire file | SHA-256 MAC over `LAC1-MEMORY + payload_bytes` | ISO A.8.24 |
| Write atomicity | `tempfile.mkstemp` → `fsync` → `os.replace` | NIST AU.10 |
| Truncation detection | Length prefix at load | SI.4 |
| Tamper detection | Any modification → `MemoryError("tampered")` | NIST SI.7 |

The format is identical in structure to the state file for consistency and auditability.

---

## 5. Lifecycle of a Memory Record

### 5.1 On File Open
```python
memory.remember_file(path, line_count=..., sensitive_hits=...)
memory.record_stats(entity_counts)  # fingerprinted automatically
memory.save()
```

### 5.2 On Preference Change
```python
memory.set_preference("theme", "light")  # only allowed keys accepted
memory.set_preference("last_policy_id", "share-with-analytics")
```

### 5.3 On Custom Rule Added/Removed
```python
memory.add_rule(CustomRule("CUSTOM_ID", r"ID-\d{6}", strategy="PARTIAL_MASK"))
memory.remove_rule("CUSTOM_ID")
```

### 5.4 On Erasure Request (GDPR Art. 17)
```python
memory.forget_all()
```
This:
1. Resets all in-memory attributes to `Memory()` defaults
2. Deletes `memory.json` from disk if it exists
3. Returns immediately; no recovery is possible

---

## 6. How Memory Feeds Back into the Application

| Memory field | Used by | Effect on next launch |
|--------------|---------|----------------------|
| `theme` | `SettingsDialog` | Default theme restored in settings |
| `keep_last_chars` | `SettingsDialog` | Default partial mask count pre-filled |
| `last_policy_id` | `SettingsDialog` | Policy dropdown pre-selects last used policy |
| `recent_files` | `RecentDialog` | Quick-access list of recently opened files |
| `custom_rules` | `EngineBridge.scan()` | Custom detection rules injected into `PatternDetector` |
| `entity_stats` | `SecurityDashboard` | Aggregate entity histogram (fingerprinted labels) |

---

## 7. Privacy (GDPR Art. 17) Compliance

| GDPR Requirement | How Met |
|------------------|---------|
| Right to erasure | `forget_all()` deletes `memory.json` and resets all state |
| Data minimization | Only paths, counts and user-authored rules stored; no content |
| Purpose limitation | Fields stored only serve specific UI functions (listed in §6) |
| Storage limitation | Recent files capped at 20; no indefinite accumulation |
| Accuracy | File metadata re-read from disk on each open; no stale cache |

---

## 8. State vs. Memory: Key Differences

| Property | State (`state.json`) | Memory (`memory.json`) |
|----------|----------------------|------------------------|
| Contents | UI geometry, preferences, secrets | File history, rules, aggregate stats |
| Encrypts secrets | Yes (DPAPI) | No (no secrets stored) |
| Integrity tag | Yes | Yes |
| Write frequency | On close, on settings change | On file open, on rule change |
| Erasure method | `state_manager.forget()` | `memory.forget_all()` |
| Contains log content | Never | Never |

---

## 9. Test Coverage

| Test | What it validates |
|------|-------------------|
| `test_empty_memory_defaults` | First run returns clean `Memory` |
| `test_remember_file_stores_metadata_only` | Path stored; file content never present |
| `test_remember_dedupes_and_caps_recent` | Max 20 entries; no duplicates |
| `test_custom_rule_roundtrip` | Rule survives save→load with all fields |
| `test_add_duplicate_rule_replaces` | Same entity_type replaces, not duplicates |
| `test_entity_stats_are_fingerprinted` | Raw entity names absent from file |
| `test_preferences_allowlist` | Only theme/keep_last_chars/last_policy accepted |
| `test_integrity_detects_tampering` | Single-bit flip causes `MemoryError` |
| `test_forget_all_erases` | File deleted; defaults restored |
| `test_safer_marker_present` | `safer` key written to every memory file |

---

## 10. Audit Considerations

The memory store is **not** an audit record and is not covered by the tamper-evident chain. It is a user-convenience layer. Sensitive audit evidence lives exclusively in `data/audit/*.json` and is governed by the audit trail design in ARCHITECTURE.md.

If an auditor requires proof that memory was erased, the absence of `memory.json` after `forget_all()` is sufficient evidence (the file was never backed up or cached elsewhere by design).