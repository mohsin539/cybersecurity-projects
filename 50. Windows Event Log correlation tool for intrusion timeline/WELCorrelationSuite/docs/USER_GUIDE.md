# User Guide — WEL Intrusion Correlation Suite

## 1. Starting the tool

### Portable exe (responder/scenario use)

Double-click `WELIntrusionCorrelationSuite.exe`. No install, no admin rights. After ~1 s a browser
tab opens at:

```
http://127.0.0.1:<random port>/tk-<session token>/index.html
```

Keep that URL to yourself — it is your single-use session door. The exe self-terminates after
**30 minutes idle**. Everything (audit trail, exports, temp files) is stored next to the exe under
`welics_case_data\`.

Optional automation knobs (env vars `WELICS_PORT`, `WELICS_TOKEN`) let CI/IR scripts fix the URL.

### From source

```powershell
python app\main.py          # opens the dashboard the same way
```

Press Ctrl+C to stop.

## 2. Loading data

Three ways — pick one on the **Dashboard** tab:

| Action | What it does |
|---|---|
| **Collect live logs** | Queries Security/System/Application/PowerShell/OpsMgr channels via native `wevtutil` (last 500 events per channel, newest first). Needs no admin. |
| **Import file** | Drag in a forensic **`.evtx`** (wevtutil `qe /lf:true`), a **CSV** export (Sysmon/EvtxECmd compatible — column aliases auto-detected), or a **JSON** case export (same schema this tool writes). |
| **New case** | Wipes the working set (audit trail is retained — the reset is itself logged). |

## 3. Run correlation

Click **Run correlation**. The engine:

1. normalizes every event and fingerprints it (SHA-256),
2. evaluates the **40-rule MITRE-mapped pack** (R-001..R-040, e.g. quick brute-force logon, service
   persistence, Kerberos misuse, PowerShell obfuscation, lateral-movement passes, clearing the log),
3. clusters related events into **campaign clusters**, detects **activity surge windows**
   (anomaly spikes), bands events onto the **9-stage intrusion timeline**, and
4. scores an **overall risk 0–100**.

Watch the dashboard refresh: key counters, the **risk gauge**, the **phase band**, **campaign
clusters** and the **surge chart**.

## 4. Reading the views

- **Dashboard** — headline KPIs + posture at a glance.
- **Attack Timeline** — chronological, colour-coded kill-chain phases; use the phase filter chips
  to isolate e.g. only `credential_access` or `lateral_movement`.
- **MITRE ATT&CK** — technique/tactic heat map showing where the tool detected activity.
- **Incidents** — every rule hit with time, phase, host, source IP, account and detail; live filter box.
- **Events** — the normalized event log with paging and a message/ID/channel filter.
- **Compliance** — ISO 27001 / NIST CSF / OWASP mapping and evidence coverage.
- **Reports & Audit** — downloads + chain-of-custody.

## 5. Reports & evidence

From **Reports & Audit** you can download:

| Download | Filename | Notes |
|---|---|---|
| **Executive HTML Report** | `intrusion_report_<case>.html` | Risk gauge, phase band, MITRE grid, clusters, incident + event tables, compliance matrices, audit chain, SHA-256 integrity footer. Print → PDF for official use. |
| **Events CSV** | `events_<case>.csv` | Every normalized event, UTF-8 BOM (opens cleanly in Excel). |
| **Timeline CSV** | `timeline_<case>.csv` | Phase-band timeline rows. |
| **Case JSON** | `case_<case>.json` | Full machine-readable case: events, incidents, analysis, compliance, audit, integrity. |

Every generated artefact is **SHA-256-hashed and logged**, and a `.sha256` sidecar is written next
to it in the workspace/exe data folder (`report.html.sha256`, `events.csv.sha256`, `case.json.sha256`)
— verify your copy: `certutil -hashfile "intrusion_report_C-....html" SHA256`.

### Audit trail

Every action — start, collect, import, analyze, downloads, denied requests, exit — is an entry in a
**hash-chained, append-only JSONL log** (`audit/audit.jsonl` in the workspace). The Reports tab shows
the live chain badge (`chain valid` / `chain broken`). Any tampering breaks the SHA-256 chain and is
flagged.

## 6. Interpreting risk

The composite risk score aggregates: severity of rule hits, number of incidents, distinct phases
observed, campaign breadth, and surge activity. Use it as a prioritizer, not a verdict — always
drill into **Incidents** and the **Timeline** for the actual evidence chain before acting.

## 7. Troubleshooting

| Symptom | Fix |
|---|---|
| "import rejected - unsupported file type" | Extension must be `.evtx`, `.csv`, `.json` (`.txt` accepted as JSON text). |
| 0 events from Collect | Current account may lack read access to some channels; check source info panel / audit for per-channel errors. |
| 403 forbidden | You're hitting the port without the session token — re-open the dashboard URL from the exe's browser launch. |
| Browser didn't open | Start the exe from Explorer and launch the printed URL; source mode: console prints the URL. |
| Port busy (source mode) | Set `WELICS_PORT` to a free port. |

## 8. Demo in 60 seconds

```powershell
# from the project root:
python tests\make_dataset.py        # (re)creates the synthetic case dataset
python tests\make_sample_report.py  # writes samples\intrusion_report_sample.html
# open the sample HTML to see an example executive report without touching your logs
```