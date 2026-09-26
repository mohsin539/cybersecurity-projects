"""TTPProfiler :: report generation (HTML / ATT&CK Navigator / STIX 2.1 / JSON).
All outputs are self-contained artifacts suitable for sharing in CTI pipelines.
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

from . import data as D
from .models import ActorProfile
from .security import json_dumps_safe, sha256_text

TACTIC_LABELS = {t["short"]: t["name"] for t in D.TACTICS}


def _colors(score: float) -> str:
    if score >= 0.8:
        return "#FF2E97"          # magenta pulse — critical
    if score >= 0.6:
        return "#FFB800"          # amber signal
    if score >= 0.35:
        return "#00E5FF"          # cyan byte
    return "#7C4DFF"              # violet quantum


def render_html(profile: ActorProfile, set_name: str = "", samples: list | None = None) -> str:
    samples = samples or []
    tactics = sorted(profile.tactic_scores.items(), key=lambda kv: -kv[1])
    techs = sorted(profile.techniques, key=lambda t: -t.score)

    tactic_rows = "\n".join(
        f"<tr><td>{TACTIC_LABELS.get(k, k)}</td><td>{v:.2f}</td>"
        f"<td><div class='bar'><i style='width:{min(100, int(v * 22))}%;"
        f"background:{_colors(v)}'></i></div></td></tr>"
        for k, v in tactics if v > 0)

    tech_rows = "\n".join(
        f"<tr><td><b>{t.technique_id}</b></td><td>{D.TECHNIQUES.get(t.technique_id, {}).get('name', '')}</td>"
        f"<td>{', '.join(TACTIC_LABELS.get(x, x) for x in D.TECHNIQUE_TACTICS.get(t.technique_id, []))}</td>"
        f"<td>{t.sample_coverage:.0%}</td><td>{t.score:.2f}</td></tr>"
        for t in techs)

    actor_cards = "\n".join(
        f"<div class='actor'><h3>{a.name} <span class='chip'>{a.confidence:.0f}%</span></h3>"
        f"<p class='alias'>{a.aliases}</p><p><b>Matched:</b> {', '.join(a.matched_techniques)}</p>"
        f"{('<p><b>Software:</b> ' + ', '.join(a.software_hits) + '</p>') if a.software_hits else ''}"
        f"</div>" for a in profile.actor_ranking[:5])

    top = profile.top_actor
    header = f"{top.name} ({top.confidence:.0f}% confidence)" if top else "No confident attribution"
    grade_badge = f"<span class='grade g{profile.intel_grade}'>Intel grade {profile.intel_grade}</span>"

    return f"""<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<title>TTP Profiler — {set_name}</title>
<style>
:root{{--bg:#0B0F19;--panel:#111827;--elev:#1B2436;--cyan:#00E5FF;--mag:#FF2E97;
--amber:#FFB800;--lime:#A6FF00;--violet:#7C4DFF;--txt:#E8F0FE;}}
*{{box-sizing:border-box;margin:0;padding:0}}
body{{background:var(--bg);color:var(--txt);font:14px/1.5 Inter,'Segoe UI',sans-serif;padding:32px}}
h1{{font-size:26px;letter-spacing:.5px;background:linear-gradient(90deg,var(--cyan),var(--mag));
-webkit-background-clip:text;background-clip:text;color:transparent}}
.badge{{display:inline-block;padding:3px 12px;border-radius:20px;font-size:12px;margin:6px 6px 0 0}}
.bb{{background:rgba(0,229,255,.12);color:var(--cyan);border:1px solid var(--cyan)}}
.gr{{background:rgba(164,255,0,.12);color:var(--lime);border:1px solid var(--lime)}}
.panel{{background:var(--panel);border:1px solid #223;border-radius:14px;padding:20px;margin:16px 0}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px}}
.metric{{background:var(--elev);padding:16px;border-radius:12px;text-align:center;
border-top:3px solid var(--cyan)}}
.metric b{{display:block;font-size:30px;font-family:'JetBrains Mono',monospace;color:var(--cyan)}}
table{{width:100%;border-collapse:collapse}}
th{{text-align:left;color:var(--cyan);font-size:12px;text-transform:uppercase;letter-spacing:1px}}
td,th{{padding:8px 10px;border-bottom:1px solid #1e2a3f}}
.bar{{height:10px;background:#0d1420;border-radius:6px;overflow:hidden}}
.bar i{{display:block;height:100%;border-radius:6px}}
.actor{{background:var(--elev);border:1px solid #26334b;border-radius:12px;padding:14px;margin:10px 0}}
.actor h3{{color:var(--lime)}}
.chip{{float:right;color:var(--amber);font-family:'JetBrains Mono',monospace}}
.alias{{color:#8fa3c9;font-size:12px;margin-bottom:8px}}
.grade{{display:inline-block;padding:4px 12px;border-radius:20px;font-weight:700}}
.gA{{background:var(--lime);color:#102200}} .gB{{background:var(--cyan);color:#001018}}
.gC{{background:var(--amber);color:#231a00}} .gD{{background:var(--mag);color:#fff}}
.hdr{{display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap}}
.foot{{color:#5b6b8c;font-size:11px;text-align:center;margin-top:20px}}
</style></head><body>
<h1>🛡️ Threat Actor TTP Profile</h1>
<div class="hdr"><div>
<span class="badge bb">MITRE ATT&CK™</span><span class="badge gr">Set: {set_name or profile.sample_set_id}</span>{grade_badge}
</div><div style="font-family:'JetBrains Mono',monospace;color:#8fa3c9;font-size:12px">{profile.id}</div></div>

<div class="panel"><div class="grid">
<div class="metric"><b>{profile.sample_count}</b>Samples analyzed</div>
<div class="metric"><b>{len(profile.techniques)}</b>Techniques mapped</div>
<div class="metric"><b>{len(profile.tactic_scores)}</b>Tactics engaged</div>
<div class="metric"><b>{profile.confidence:.0f}%</b>Profile confidence</div>
</div></div>

<div class="panel"><h2>🎯 Attribution target</h2>
<p style="font-size:18px;margin:8px 0;color:var(--lime)">{header}</p>{actor_cards}</div>

<div class="panel"><h2>🗺️ Tactic coverage</h2><table>{tactic_rows}</table></div>
<div class="panel"><h2>🔬 Technique evidence ranking</h2>
<table><tr><th>ID</th><th>Technique</th><th>Tactics</th><th>Coverage</th><th>Score</th></tr>{tech_rows}</table></div>
<div class="foot">Generated by TTPProfiler · {datetime.now(timezone.utc).isoformat(timespec='seconds')}Z · offline + local</div>
</body></html>"""


def render_navigator_layer(profile: ActorProfile) -> dict:
    """MITRE ATT&CK Navigator heatmap layer JSON."""
    techniques = []
    for t in profile.techniques:
        tech = D.TECHNIQUES.get(t.technique_id, {})
        score = min(100, int(t.score * 100 * 0.25 + t.sample_coverage * 75))
        techniques.append({
            "techniqueID": t.technique_id,
            "score": score,
            "color": _colors(t.score),
            "comment": f"score={t.score:.2f} coverage={t.sample_coverage:.0%} "
                       f"evidence={len(t.evidence_ids)}",
            "enabled": True,
        })
    return {
        "name": f"TTP Profiler — {profile.sample_set_id}",
        "versions": {"attack": "v15", "navigator": "4.9.0", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": "Generated offline by TTP Profiler. Confidence-weighted heatmap.",
        "techniques": techniques,
        "gradient": {"colors": ["#7C4DFF", "#00E5FF", "#FFB800", "#FF2E97"], "min": 0, "max": 100},
    }


def render_stix_bundle(profile: ActorProfile) -> dict:
    """Emissions-friendly STIX 2.1 bundle (profile + techniques + actor)."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    objects: list[dict] = []
    for tm in profile.techniques:
        tech = D.TECHNIQUES.get(tm.technique_id, {})
        objects.append({
            "type": "indicator", "id": f"indicator--{uuid.uuid4()}",
            "created": now, "modified": now, "name": tech.get("name", tm.technique_id),
            "pattern": f"[x-ttp-technique = '{tm.technique_id}']",
            "labels": ["ttp"],
            "confidence": int(min(99, tm.score * 100)),
            "external_references": [{"source_name": "mitre-attack",
                                     "external_id": tm.technique_id}],
        })
    for a in profile.actor_ranking[:3]:
        objects.append({
            "type": "threat-actor", "id": f"threat-actor--{uuid.uuid4()}",
            "created": now, "modified": now, "name": a.name,
            "aliases": [x.strip() for x in a.aliases.split(",") if x.strip()],
            "labels": ["threat-actor-group", "attributed"],
            "confidence": int(min(99, a.confidence)),
        })
    return {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": objects}


def render_json(profile: ActorProfile) -> dict:
    return profile.summary()


def write_all(profile: ActorProfile, out_dir, set_name: str = "", samples: list | None = None) -> dict:
    """Persist every artifact; return manifest with integrity hashes."""
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
    except Exception:
        out_dir = out_dir.parent
    artifacts = {
        "executive_report.html": render_html(profile, set_name, samples).encode("utf-8"),
        "navigator_layer.json": json.dumps(render_navigator_layer(profile), indent=2).encode("utf-8"),
        "stix_bundle.json": json.dumps(render_stix_bundle(profile), indent=2).encode("utf-8"),
        "profile.json": json_dumps_safe(render_json(profile)).encode("utf-8"),
    }
    manifest = {"profile": profile.id, "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"), "files": {}}
    for name, data in artifacts.items():
        (out_dir / name).write_bytes(data)
        manifest["files"][name] = {"bytes": len(data), "sha256": sha256_text(data.decode("utf-8", errors="replace"))}
    (out_dir / "MANIFEST.sha256.json").write_text(
        json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest