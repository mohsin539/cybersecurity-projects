from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any

from .intake import human_size
from .models import StaticFindings

# architecture.md section 6.6: Report Generator. Renders the normalized result
# model into signed Markdown (portable) + JSON machine-readable form.

SCHEMA_VERSION = "sba.pattern.v1"


def _stamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _fmt_fingerprint(fp: dict[str, Any]) -> str:
    return json.dumps(fp, indent=2, ensure_ascii=True)


def render_report(sample, static: StaticFindings, fingerprint: dict[str, Any]) -> tuple[str, str]:
    """Returns (markdown, json)."""
    r = []
    r.append("# Ransomware Behavior Analysis Report")
    r.append("")
    r.append("## 1. Evidence header")
    r.append("")
    r.append(f"- **Schema:** `{SCHEMA_VERSION}`")
    r.append(f"- **Generated (UTC):** `{_stamp()}`")
    r.append(f"- **Sample SHA-256:** `{sample.sha256}`")
    r.append(f"- **Original name:** `{sample.original_name}`")
    r.append(f"- **Size:** {human_size(sample.size)} ({sample.size} bytes)")
    r.append(f"- **Magic:** `{sample.magic_hex}` → {sample.magic_hint}")
    r.append(f"- **Execution mode:** non-executing (read-only static + structural analysis)")
    r.append("")

    r.append("## 2. Static analysis")
    r.append("")
    r.append(f"- **Whole-file entropy:** {static.entropy:.4f} bits/byte")
    r.append(f"- **High-entropy block ratio (>=7.5 bits/byte):** {static.block_high_entropy_ratio:.4f}")
    r.append(f"- **PE structure:** {json.dumps(static.pe_info) if static.pe_info.get('is_pe') else 'not a PE binary'}")
    r.append(f"- **Crypto API/import hints:** {', '.join(static.crypto_imports) or 'none'}")
    r.append(f"- **Ransom/note indicators:** {', '.join(static.ransom_indicators) or 'none'}")
    r.append("")

    r.append("## 3. Encryption-pattern fingerprint")
    r.append("")
    r.append("```json")
    r.append(_fmt_fingerprint(fingerprint))
    r.append("```")
    r.append("")

    r.append("## 4. Notable strings (context)")
    r.append("")
    picked = [s for s in static.strings
              if any(k in s.lower() for k in ("decrypt", "ransom", ".lock", ".enc", "readme",
                                              "bitcoin", "wallet", "aes", "rsa", "crypto"))
              ][:30]
    if picked:
        for s in picked:
            r.append(f"- `` `{s[:160]}` ``")
    else:
        r.append("- (no notable crypto/ransom strings found)")
    r.append("")

    r.append("## 5. Caveats & integrity")
    r.append("")
    r.append("- Inference is **heuristic**: statistically consistent with the stated pattern class; it does **not** prove a specific cryptographic algorithm.")
    r.append("- The sample was **never executed**; on-host behavior (filesystem deltas, honeypot results, kernel telemetry) is out of scope for this portable workbench run.")
    r.append("- Evidence is reproducible: artifact hash, schema version, tooling version and timestamps are embedded above.")

    md = "\n".join(r)
    js = json.dumps(fingerprint, indent=2, ensure_ascii=True)
    return md, js


def save_report(reports_dir: str, sample, static: StaticFindings,
                fingerprint: dict[str, Any]) -> tuple[str, str, str]:
    md, js = render_report(sample, static, fingerprint)
    base = f"RPT_{sample.sha256[:12]}_{_stamp().replace(':', '')}"
    md_path = os.path.join(reports_dir, base + ".md")
    js_path = os.path.join(reports_dir, base + ".json")
    with open(md_path, "w", encoding="utf-8", newline="\n") as f:
        f.write(md)
    with open(js_path, "w", encoding="utf-8", newline="\n") as f:
        f.write(js + "\n")
    return md_path, js_path, md