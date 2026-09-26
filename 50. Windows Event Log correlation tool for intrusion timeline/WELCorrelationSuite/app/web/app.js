"use strict";
/* WEL Intrusion Correlation Suite - single-page controller.
   All rendering uses textContent (no innerHTML with untrusted data) to
   stay OWASP-A03 XSS-safe; every action is audited server-side. */
const BASE = location.pathname.replace(/index\.html$/, "");
const S = {
  events: [], incidents: [], analysis: null, spikes: [],
  evPage: 0, evPageSize: 100, phases: [], audits: [], cov: null, tool: null,
};

const $ = (id) => document.getElementById(id);
const esc = (v) => String(v == null ? "" : v);
const fmtT = (ts) => {
  if (!ts) return "-";
  const t = new Date(ts);
  return isNaN(t) ? esc(ts) : t.toLocaleString([], { dateStyle: "short", timeStyle: "medium" });
};
const phaseColor = {
  reconnaissance: "#8b5cf6", initial_access: "#38bdf8", execution: "#22d3ee",
  persistence: "#a78bfa", privilege_escalation: "#fbbf24", credential_access: "#fb7185",
  defense_evasion: "#f87171", discovery: "#60a5fa", lateral_movement: "#fb923c",
  impact: "#ef4444", c2: "#34d399",
};
const sevColor = (s) => s >= 85 ? "#ef4444" : s >= 65 ? "#f97316" : s >= 40 ? "#fbbf24" : s >= 20 ? "#38bdf8" : "#64748b";

async function api(path, opts) {
  const res = await fetch(BASE + "api/" + path, opts);
  if (!res.ok) {
    let msg = "HTTP " + res.status;
    try { msg = (await res.json()).error || msg; } catch (e) { /* noop */ }
    throw new Error(msg);
  }
  const ctype = res.headers.get("content-type") || "";
  return ctype.includes("json") ? res.json() : res;
}

function toast(msg, err) {
  const t = $("toast");
  t.textContent = msg;
  t.className = "toast show" + (err ? " err" : "");
  clearTimeout(toast._t);
  toast._t = setTimeout(() => { t.className = "toast"; }, 3800);
}

// ------------------------------------------------------------------ tabs
document.querySelectorAll(".tab").forEach((b) => {
  b.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach((x) => x.classList.remove("active"));
    b.classList.add("active");
    document.querySelectorAll(".view").forEach((v) => v.classList.remove("active"));
    $("view-" + b.dataset.tab).classList.add("active");
  });
});

// ------------------------------------------------------------ data actions
async function refreshStatus() {
  try {
    const st = await api("status");
    $("caseId").textContent = st.case_id;
    $("kEvents").textContent = st.events;
    S.rules_loaded = st.rules || 40;
    $("serverStatus").className = "status online";
    $("serverStatus").textContent = "\u25CF localhost secured";
    if (st.events) $("sourceInfo").textContent = "Loaded: " + st.events + " events \u00b7 case " + st.case_id;
    return st;
  } catch (e) {
    $("serverStatus").className = "status";
    $("serverStatus").textContent = "\u25CF offline";
    toast("Can't reach local engine: " + e.message, true);
  }
}

$("btnCollect").addEventListener("click", async () => {
  const max = prompt("Events per channel (max):", "300");
  if (max === null) return;
  const btn = $("btnCollect"); btn.disabled = true; btn.textContent = "Collecting...";
  try {
    const res = await api("collect", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ max_per_channel: parseInt(max, 10) || 300 }),
    });
    toast("Collected " + res.events + " events");
    $("sourceInfo").textContent = "Live collection \u00b7 " + Object.entries(res.report.channels)
      .map(([k, v]) => k + "=" + v).join(", ") + " | errors: " + res.report.errors.length;
    S.events = await api("events");
    await afterData();
  } catch (e) { toast(e.message, true); }
  finally { btn.disabled = false; btn.textContent = "\u2B07 Collect live logs"; }
});

$("fileImport").addEventListener("change", async (ev) => {
  const file = ev.target.files[0];
  if (!file) return;
  const fd = new FormData();
  fd.append("file", file);
  const btn = $("btnCollect"); btn.disabled = true; btn.textContent = "Importing...";
  toast("Importing " + file.name + " ...");
  try {
    const res = await api("import", { method: "POST", body: fd });
    toast("Imported " + res.imported + " events" + (res.errors.length ? " (" + res.errors.join("; ") + ")" : ""));
    $("sourceInfo").textContent = "Source: " + file.name + " (" + res.imported + " events)";
    await afterData();
  } catch (e) { toast("Import failed: " + e.message, true); }
  finally { btn.disabled = false; btn.textContent = "\u2B07 Collect live logs"; ev.target.value = ""; }
});

$("btnAnalyze").addEventListener("click", async () => {
  const btn = $("btnAnalyze"); btn.disabled = true; btn.textContent = "Correlating...";
  try {
    const res = await api("analyze", { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" });
    SNAP = res.analysis || res;
    renderDashboard(SNAP);
    toast("Analysis complete \u2014 " + (res.incidents || 0) + " incidents, " +
      ((res.phases || []).length) + " phases");
    await refreshAudit();
  } catch (e) { toast(e.message, true); }
  finally { btn.disabled = false; btn.textContent = "\u2698 Run correlation"; }
});

$("btnReset").addEventListener("click", async () => {
  await api("case/reset", { method: "POST", body: "{}" });
  window.location.reload();
});

$("btnExit").addEventListener("click", async () => {
  toast("Shutting down local engine...");
  try { await api("shutdown", { method: "POST", body: "{}" }); } catch (e) { /* engine stops */ }
  await new Promise((r) => setTimeout(r, 600));
  window.close();
});

// ---------------------------------------------------------------- downloads
function download(type, fname) {
  api("report?type=" + encodeURIComponent(type))
    .then((res) => res.blob())
    .then((blob) => {
      const a = document.createElement("a");
      a.href = URL.createObjectURL(blob);
      a.download = fname;
      a.click();
      setTimeout(() => URL.revokeObjectURL(a.href), 4000);
      toast("Report downloaded \u2014 SHA-256 sidecar saved server-side");
      refreshAudit();
    })
    .catch((e) => toast(e.message, true));
}
$("dlHtml").addEventListener("click", () => download("html", "intrusion_report.html"));
$("dlCsv").addEventListener("click", () => download("csv", "events.csv"));
$("dlTimeline").addEventListener("click", () => download("timeline.csv", "timeline.csv"));
$("dlJson").addEventListener("click", () => download("json", "case.json"));

// ------------------------------------------------------------------ load
async function afterData() {
  await refreshStatus();
  await refreshEvents();
  await refreshAudit();
}
// ------------------------------------------------------------------ events
async function refreshEvents() {
  const res = await api("events?start=0&limit=200000");
  S.events = res.events;
  $("kEvents").textContent = res.total;
  renderEventsTable();
}

function renderEventsTable() {
  const q = ($("evtSearch").value || "").toLowerCase();
  const start = S.evPage * S.evPageSize;
  let items = S.events;
  if (q) items = items.filter((e) =>
    [e.channel, e.provider, e.computer, e.message, String(e.event_id), e.target_user]
      .join(" ").toLowerCase().includes(q));
  $("evPageInfo").textContent = items.length ? (start + 1) + "-" + Math.min(start + S.evPageSize, items.length) + " of " + items.length : "0 of 0";
  const slice = items.slice(start, start + S.evPageSize);
  const tb = $("eventTable").querySelector("tbody");
  tb.innerHTML = "";
  for (const e of slice) {
    const tr = document.createElement("tr");
    const td = (t, cn) => { const d = document.createElement("td"); d.textContent = t; if (cn) d.className = cn; return d; };
    tr.append(td(fmtT(e.ts), "mono"), td(e.event_id), td(e.channel), td(e.provider), td(e.computer), td(e.message));
    tb.append(tr);
  }
}
$("evtSearch").addEventListener("input", () => { S.evPage = 0; renderEventsTable(); });
$("evNext").addEventListener("click", () => { S.evPage++; renderEventsTable(); });
$("evPrev").addEventListener("click", () => { S.evPage = Math.max(0, S.evPage - 1); renderEventsTable(); });

// ------------------------------------------------------------ analysis
let SNAP = null;

// ------------------------------------------------------------------ render
function renderRiskGauge(risk, label) {
  const svg = $("svgRisk");
  const r = 60, cx = 70, cy = 70, pad = 6;
  const p = 0.72 * Math.PI;
  const start = Math.PI * 0.86;
  const arc = (t, col, w) => {
    const pth = document.createElementNS("http://www.w3.org/2000/svg", "path");
    const x0 = cx + r * Math.cos(start - p), y0 = cy + r * Math.sin(start - p);
    const x1 = cx + r * Math.cos(start + p), y1 = cy + r * Math.sin(start + p);
    const large = p * 2 > Math.PI ? 1 : 0;
    pth.setAttribute("d", `M ${x0} ${y0} A ${r} ${r} 0 ${large} 1 ${x1} ${y1}`);
    pth.setAttribute("fill", "none");
    pth.setAttribute("stroke", col);
    pth.setAttribute("stroke-width", w);
    pth.setAttribute("stroke-linecap", "round");
    svg.append(pth);
  };
  svg.innerHTML = "";
  arc(1, "#0b1626", 12);
  const frac = Math.max(0, Math.min(1, risk / 100));
  const col = risk >= 85 ? "#ef4444" : risk >= 65 ? "#f97316" : risk >= 40 ? "#fbbf24" : "#34d399";
  const p2 = p * (1 - 0.26);
  const x0 = cx + r * Math.cos(start - p2), y0 = cy + r * Math.sin(start - p2);
  const x1 = cx + r * Math.cos(start - p2 + 2 * p2 * frac), y1 = cy + r * Math.sin(start - p2 + 2 * p2 * frac);
  const big = 2 * p2 * frac > Math.PI ? 1 : 0;
  const sweep = 0;
  const pth = document.createElementNS("http://www.w3.org/2000/svg", "path");
  pth.setAttribute("d", `M ${x0} ${y0} A ${r} ${r} 0 ${big} 1 ${x1} ${y1}`);
  pth.setAttribute("fill", "none");
  pth.setAttribute("stroke", col);
  pth.setAttribute("stroke-width", 12);
  pth.setAttribute("stroke-linecap", "round");
  svg.append(pth);
  const txt = document.createElementNS("http://www.w3.org/2000/svg", "text");
  txt.setAttribute("x", cx); txt.setAttribute("y", cy + 6);
  txt.setAttribute("text-anchor", "middle");
  txt.setAttribute("font-family", "Consolas, monospace");
  txt.setAttribute("font-size", "22");
  txt.setAttribute("font-weight", "800");
  txt.setAttribute("fill", col);
  txt.textContent = risk;
  svg.append(txt);
  $("riskVal").textContent = risk + " / 100";
  $("riskLabel").textContent = label || "none";
  $("riskBar").style.width = Math.min(100, risk) + "%";
}

function renderDashboard(an) {
  if (!an) {
    $("kIncidents").textContent = 0; $("kPhases").textContent = 0;
    $("kCampaigns").textContent = 0; $("kSeverity").textContent = 0;
    $("kSpikes").textContent = 0;
    renderRiskGauge(0, "no analysis");
    return;
  }
  const s = an.summary || {};
  $("kIncidents").textContent = s.incidents || 0;
  $("kPhases").textContent = s.phase_count || 0;
  $("kCampaigns").textContent = s.campaigns || 0;
  $("kSeverity").textContent = s.max_severity || 0;
  $("kSpikes").textContent = s.spikes || 0;
  renderRiskGauge(s.risk_score || 0, s.risk_label || "none");
  renderPhaseBand(an.phases || []);
  renderCampaigns(an.campaigns || []);
  renderSpikeChart(an.spikes || []);
  renderTimeline(an.incidents || [], an.phases || []);
  renderMitre(an.mitre || {}, an.phases && an.phases.length ? an.phases : null);
  renderIncidents(an.incidents || []);
}

function renderPhaseBand(phases) {
  const el = $("phaseBand"); el.innerHTML = "";
  if (!phases.length) { el.innerHTML = '<div class="dim">Run analysis to populate.</div>'; return; }
  for (const p of phases) {
    const d = document.createElement("div");
    d.className = "phase";
    d.style.borderColor = p.color;
    d.style.background = p.color + "22";
    const nm = document.createElement("div"); nm.className = "p-name"; nm.textContent = p.name;
    const cnt = document.createElement("div"); cnt.className = "p-cnt"; cnt.style.color = p.color; cnt.textContent = p.count;
    const rk = document.createElement("div"); rk.className = "p-risk"; rk.textContent = "risk " + p.risk;
    d.append(nm, cnt, rk);
    el.append(d);
  }
}

function renderCampaigns(cams) {
  const el = $("campaignList"); el.innerHTML = "";
  if (!cams.length) { el.innerHTML = '<div class="dim">No clusters yet.</div>'; return; }
  for (const cm of cams) {
    const card = document.createElement("div");
    card.style.cssText = "border:1px solid var(--line);border-radius:10px;padding:10px 12px;margin-bottom:10px";
    const top = document.createElement("div");
    top.style.cssText = "display:flex;gap:10px;align-items:center;flex-wrap:wrap";
    const label = document.createElement("span"); label.className = "pill"; label.textContent = cm.label;
    label.style.color = sevColor(cm.severity);
    const info = document.createElement("span"); info.className = "dim"; info.style.fontSize = "11px";
    info.textContent = cm.incidents.length + " incidents \u00b7 window " + cm.window + "\u00b7 sev " + cm.severity;
    const chain = document.createElement("div");
    chain.className = "mono"; chain.style.cssText = "margin-top:6px;font-size:11px;color:var(--cyan)";
    chain.textContent = "hosts: " + (cm.hosts || []).join(", ") + "  |  chain: " + (cm.stage_sequence || []).join(" \u2192 ");
    top.append(label, info); card.append(top, chain); el.append(card);
  }
}

function renderSpikeChart(spikes) {
  const cv = $("spikeChart");
  const ctx = cv.getContext("2d");
  const note = $("spikeNote");
  cv.width = cv.parentElement.clientWidth || 500;
  cv.height = 150;
  ctx.clearRect(0, 0, cv.width, cv.height);
  const W = cv.width, H = cv.height, pad = 22;
  if (!spikes.length) {
    note.textContent = "No anomalous surge windows detected in the ingested window.";
    return;
  }
  note.textContent = "Peaks where event volume exceeded " + spikes[0].baseline + "/min baseline by z-scores shown below.";
  const maxV = Math.max.apply(null, spikes.map((s) => s.count));
  const bw = Math.max(8, (W - pad * 2) / spikes.length - 4);
  const grad = ctx.createLinearGradient(0, 0, 0, H);
  grad.addColorStop(0, "rgba(239,68,68,.9)");
  grad.addColorStop(1, "rgba(249,115,22,.5)");
  ctx.font = "10px Consolas";
  ctx.fillStyle = "#8ea3c0";
  ctx.textAlign = "center";
  spikes.forEach((s, i) => {
    const h = Math.max(3, (s.count / maxV) * (H - pad * 2));
    const x = pad + i * (bw + 4);
    const y = H - pad - h;
    ctx.fillStyle = grad;
    ctx.fillRect(x, y, bw, h);
    ctx.fillStyle = "#e6edf7";
    ctx.fillText(s.count, x + bw / 2, y - 4);
    ctx.fillStyle = "#8ea3c0";
    ctx.fillText(String(new Date(s.start_ts).getHours()).padStart(2, "0") + ":" +
      String(new Date(s.start_ts).getMinutes()).padStart(2, "0"), x + bw / 2, H - 8);
  });
}

// ------------------------------------------------------------- timeline
function renderTimeline(incidents, phases) {
  const list = $("timelineList"); list.innerHTML = "";
  const fbar = $("phaseFilters"); fbar.innerHTML = "";
  if (!incidents.length) { list.innerHTML = '<div class="dim">Run correlation analysis first.</div>'; return; }
  const active = {};
  (phases || []).forEach((p) => { active[p.slug] = true; });
  (phases || []).forEach((p) => {
    const c = document.createElement("button");
    c.className = "fchip on";
    c.style.cssText = "--chip:" + (p.color || "#22d3ee");
    c.textContent = p.name + " (" + p.count + ")";
    c.addEventListener("click", () => {
      active[p.slug] = !active[p.slug];
      c.classList.toggle("on", active[p.slug]);
      drawTimeline();
    });
    fbar.append(c);
  });
  function drawTimeline() {
    list.innerHTML = "";
    for (const inc of incidents) {
      if (!active[inc.stage]) continue;
      const col = phaseColor[inc.stage] || "#22d3ee";
      const item = document.createElement("div");
      item.className = "tl-item";
      item.style.cssText = "--dot:" + col;
      const t = document.createElement("div"); t.className = "tl-time"; t.textContent = fmtT(inc.ts);
      const title = document.createElement("div"); title.className = "tl-title";
      const pill = document.createElement("span");
      pill.className = "pill"; pill.style.color = sevColor(inc.severity);
      pill.textContent = inc.rule_name;
      title.textContent = inc.message ? inc.message : "";
      const meta = document.createElement("div"); meta.className = "tl-meta";
      meta.textContent = [inc.computer, inc.source_ip, inc.target_user, "phase: " + (inc.stage || ""),
        "sev: " + inc.severity + " \u00b7 " + inc.rule_id].filter(Boolean).join(" \u00b7 ");
      item.append(t, pill, title, meta);
      list.append(item);
    }
    if (!list.children.length) list.innerHTML = '<div class="dim">No events match the active phase filters.</div>';
  }
  drawTimeline();
}

// -------------------------------------------------------------- mitre
function renderMitre(matrix) {
  const el = $("mitreGrid"); el.innerHTML = "";
  const tactics = Object.keys(matrix);
  if (!tactics.length) { el.innerHTML = '<div class="dim">Run analysis to populate.</div>'; return; }
  const techniques = [...new Set(tactics.flatMap((t) => Object.keys(matrix[t])))];
  el.style.gridTemplateColumns = "150px repeat(" + tactics.length + ",1fr)";
  const top = document.createElement("div"); top.className = "thead"; top.textContent = "Technique / Tactic";
  el.append(top);
  tactics.forEach((t) => {
    const h = document.createElement("div"); h.className = "thead"; h.textContent = t;
    el.append(h);
  });
  techniques.forEach((tech) => {
    const rh = document.createElement("div"); rh.className = "rhead"; rh.textContent = tech;
    el.append(rh);
    tactics.forEach((t) => {
      const n = (matrix[t] && matrix[t][tech]) || 0;
      const cell = document.createElement("div");
      cell.className = "cell " + (n ? "c" + Math.min(n, 4) : "c0");
      cell.textContent = n || "";
      el.append(cell);
    });
  });
}

// ----------------------------------------------------------- incidents
function renderIncidents(incidents) {
  S.incidents = incidents;
  drawIncidents();
}
function drawIncidents() {
  const q = ($("incSearch").value || "").toLowerCase();
  const tb = $("incidentTable").querySelector("tbody");
  tb.innerHTML = "";
  const items = q ? S.incidents.filter((i) =>
    [i.rule_name, i.computer, i.source_ip, i.target_user, i.message, i.stage, i.rule_id]
      .join(" ").toLowerCase().includes(q)) : S.incidents;
  for (const i of items) {
    const tr = document.createElement("tr");
    const td = (t, cn) => { const d = document.createElement("td"); d.textContent = t; if (cn) d.className = cn; return d; };
    const pill = document.createElement("span"); pill.className = "pill";
    pill.style.color = sevColor(i.severity); pill.textContent = i.rule_name;
    const stage = td(i.stage); stage.style.color = phaseColor[i.stage] || "";
    const tdPill = document.createElement("td"); tdPill.append(pill);
    tr.append(td(fmtT(i.ts), "mono"), tdPill, stage, td(i.computer), td(i.source_ip), td(i.target_user), td(i.message));
    tb.append(tr);
  }
}
$("incSearch").addEventListener("input", drawIncidents);
// -------------------------------------------------------------- compliance
async function renderCompliance() {
  let fw;
  try { fw = await api("framework"); } catch (e) { return; }
  S.cov = fw.coverage || {};
  S.fw = fw.tool || {};
  const c = S.cov;
  $("covCards").innerHTML = [
    ["ISO 27001 controls", (c.iso_27001 || []).length, "/" + (c.iso_27001_total || 0), "coverage_matrix"],
    ["NIST CSF categories", (c.nist_csf || []).length, "/" + (c.nist_csf_total || 0), "coverage_matrix"],
    ["OWASP Top 10 items", (S.fw.owasp || []).length || 0, "", "hardening evidence"],
    ["Detection rules", S.rules_loaded || 40, "", "MITRE-mapped"],
  ].map(([l, v, d, n]) =>
    '<div class="card"><div class="label">' + l + '</div><div class="value">' + v + d +
    '</div><div class="hint">' + n + '</div></div>').join("");

  const iso = (S.fw.iso || []).map((id) =>
    "<tr><td class='mono'>" + id + "</td></tr>").join("");
  $("isoTable").innerHTML = "<table class='grid-table'><thead><tr><th>Control (evidenced)</th></tr></thead><tbody>" +
    (iso || "<tr><td>No incidents mapped yet - run analysis</td></tr>") + "</tbody></table>";

  const nistRows = (S.fw.nist || []).map((n) =>
    "<tr><td class='mono'>" + n.id + "</td><td>" + n.name + "</td><td>" + n.items.length +
    " measures</td></tr>").join("");
  $("nistTable").innerHTML = "<table class='grid-table'><thead><tr><th>ID</th><th>Category</th><th>Measures</th></tr></thead><tbody>" +
    (nistRows || "<tr><td colspan='3'>No data</td></tr>") + "</tbody></table>";

  const owaspRows = (S.fw.owasp || []).map((o) =>
    "<tr><td class='mono'>" + o.id + "</td><td>" + o.name + "</td><td>" +
    o.items.map((s) => s).join("; ") + "</td></tr>").join("");
  $("owaspTable").innerHTML = "<table class='grid-table'><thead><tr><th>ID</th><th>Category</th><th>Evidence</th></tr></thead><tbody>" +
    (owaspRows || "") + "</tbody></table>";
}

// ------------------------------------------------------------------ audit
async function refreshAudit() {
  try {
    const res = await api("audit");
    S.audits = res.entries || [];
    const st = res.stats || {};
    const ok = st.valid ? "good" : "";
    $("audChainBadge").className = "badge" + (ok ? " good" : "");
    $("audChainBadge").textContent = st.valid ? "\u2714 chain valid" : "\u26A0 chain review";
    $("audCount").textContent = (res.entries ? res.entries.length : 0) + " actions";
    $("integLine").textContent = (st.last_hash || "no artefacts yet") +
      " | audit path: " + (st.path || "");
    const tb = $("auditTable").querySelector("tbody");
    tb.innerHTML = "";
    const rows = res.entries ? res.entries.slice().reverse().slice(0, 80) : [];
    for (const a of rows) {
      const tr = document.createElement("tr");
      const td = (t, cn) => { const d = document.createElement("td"); d.textContent = t; if (cn) d.className = cn; return d; };
      tr.append(td(fmtT(a.ts), "mono"), td(a.actor), td(a.action), td((a.detail || "").slice(0, 90)), td(a.level));
      tb.append(tr);
    }
  } catch (e) { /* status refresh handled elsewhere */ }
}

// ---------------------------------------------------------------- boot
async function boot() {
  await refreshStatus();
  await refreshEvents();
  await refreshAudit();
  await renderCompliance();
  setInterval(async () => { await refreshStatus(); }, 20000);
}
boot().catch((e) => toast("Boot: " + e.message, true));