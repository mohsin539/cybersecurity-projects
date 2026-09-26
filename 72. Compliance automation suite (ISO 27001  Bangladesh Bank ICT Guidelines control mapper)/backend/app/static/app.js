/* Compliance Automation Suite — SPA logic (vanilla JS, no external CDNs) */
"use strict";

const state = { token: null, user: null, view: "dashboard" };
const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => [...document.querySelectorAll(sel)];

const ROLE_PERMS = {
  SUPER_ADMIN: ["*"],
  CISO: ["map:write", "assess:write", "risk:write", "evidence:write", "remediation:write", "report:write", "report:read", "dashboard:read", "audit:read", "asset:write", "user:read"],
  CONTROL_OWNER: ["evidence:write", "assess:read", "report:read", "dashboard:read", "remediation:write"],
  ASSESSOR: ["assess:write", "evidence:read", "report:read", "dashboard:read", "audit:read"],
  REGULATOR: ["dashboard:read", "report:read", "evidence:read"],
  VIEWER: ["dashboard:read", "report:read"],
};
const can = (perm) => {
  const p = ROLE_PERMS[state.user?.role] || [];
  return p.includes("*") || p.includes(perm);
};

/* ---------------- API helpers ---------------- */
async function api(path, opts = {}) {
  const headers = { ...(opts.headers || {}) };
  if (state.token) headers.Authorization = `Bearer ${state.token}`;
  if (opts.json) headers["Content-Type"] = "application/json";
  const res = await fetch(path, {
    method: opts.method || "GET",
    headers,
    body: opts.json ? JSON.stringify(opts.json) : opts.body,
  });
  if (res.status === 401) {
    toast("Session expired — sign in again", "err");
    logout();
    throw new Error("unauthorized");
  }
  if (res.status === 403) {
    const detail = await res.text();
    toast(`Forbidden: ${detail}`, "err");
    throw new Error("forbidden");
  }
  if (!res.ok) {
    const txt = await res.text();
    toast(`API error ${res.status}: ${txt.slice(0, 200)}`, "err");
    throw new Error(txt);
  }
  return res.json();
}

async function downloadFile(path, filename) {
  const res = await fetch(path, { headers: state.token ? { Authorization: `Bearer ${state.token}` } : {} });
  if (!res.ok) { toast(`Download failed (${res.status})`, "err"); return; }
  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url; a.download = filename || "download";
  a.click();
  URL.revokeObjectURL(url);
}

function toast(msg, kind = "ok") {
  const t = $("#toast");
  t.textContent = msg;
  t.className = `toast ${kind}`;
  t.hidden = false;
  clearTimeout(t._h);
  t._h = setTimeout(() => (t.hidden = true), 3600);
}

const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({
  "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
}[c]));
const badge = (s) => `<span class="badge has-${esc(s)}">${esc(s).replace(/_/g, " ")}</span>`;

/* ---------------- Auth ---------------- */
$("#login-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const username = $("#login-user").value.trim();
  const password = $("#login-pass").value;
  try {
    const r = await fetch("/auth/login", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password }),
    });
    if (!r.ok) { toast("Invalid credentials", "err"); return; }
    const data = await r.json();
    state.token = data.token;
    state.user = data.user;
    localStorage.setItem("cas_token", data.token);
    localStorage.setItem("cas_user", JSON.stringify(data.user));
    enterApp();
  } catch (err) { toast("Login failed", "err"); }
});

$("#btn-logout").addEventListener("click", logout);

function logout() {
  state.token = null; state.user = null;
  localStorage.removeItem("cas_token");
  localStorage.removeItem("cas_user");
  $("#app-shell").hidden = true;
  $(".app-body").dataset.view = "login";
  $("#login-screen").style.display = "flex";
}

function enterApp() {
  $("#login-screen").style.display = "none";
  $("#app-shell").hidden = false;
  $("#user-name").textContent = state.user.display_name;
  $("#user-role").textContent = state.user.role.replace(/_/g, " ");
  $("#user-avatar").textContent = (state.user.display_name || "U")[0].toUpperCase();
  $("#nav-admin").hidden = state.user.role !== "SUPER_ADMIN";
  switchView("dashboard");
  refreshVeracity();
}

/* ---------------- Navigation ---------------- */
$$(".nav-item").forEach((el) =>
  el.addEventListener("click", () => switchView(el.dataset.view)));

function switchView(view) {
  state.view = view;
  $$(".nav-item").forEach((n) => n.classList.toggle("active", n.dataset.view === view));
  $$(".view").forEach((v) => v.classList.remove("active"));
  const target = $(`#view-${view}`);
  if (target) target.classList.add("active");
  const meta = {
    dashboard: ["Dashboard", "Real-time compliance posture across 4+ frameworks"],
    controls: ["Controls & Mapping", "Canonical control mapper — ISO ⟷ BB ⟷ NIST ⟷ OWASP"],
    assessments: ["Assessments", "Auto & hybrid assessments across frameworks"],
    risk: ["Risk & Remediation", "CVSS-weighted risk register and SLA-tracked tickets"],
    evidence: ["Evidence Vault", "WORM storage, SHA-256 chains, overlap dedupe"],
    findings: ["Findings / Assets", "Scanner ingestion and asset inventory"],
    reports: ["Reports & Downloads", "PDF · DOCX · XLSX · CSV · JSON · Evidence ZIP"],
    audit: ["Audit Log", "Append-only, tamper-evident hash chain"],
    admin: ["Users & Roles", "RBAC user management (SUPER_ADMIN)"],
  }[view] || ["", ""];
  $("#page-title").textContent = meta[0];
  $("#page-sub").textContent = meta[1];
  ({ dashboard: renderDashboard, controls: renderControls, assessments: renderAssessments,
    risk: renderRisk, evidence: renderEvidence, findings: renderFindings,
    reports: renderReports, audit: renderAudit, admin: renderAdmin }[view] || (() => {}))();
}

async function refreshVeracity() {
  try {
    const r = await api("/evidence/integrity");
    const ok = r.vault.verified && r.audit_chain.verified;
    const pill = $("#veracity-pill");
    pill.className = `pill ${ok ? "pill-green" : "pill-red"}`;
    pill.textContent = ok ? "● Vault + audit chain verified" : "● TAMPER DETECTED";
  } catch { /* ignore */ }
}

$("#btn-download-soa").addEventListener("click", () => {
  downloadFileWithToken("/evidence/pack", "evidence_pack.zip");
});

async function downloadFileWithToken(path, name) {
  try {
    const res = await fetch(path, { headers: { Authorization: `Bearer ${state.token}` } });
    if (!res.ok) { toast("Download failed", "err"); return; }
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a"); a.href = url; a.download = name; a.click();
    URL.revokeObjectURL(url);
    toast("Evidence pack downloaded");
  } catch { toast("Download failed", "err"); }
}

/* ===================================================================
   DASHBOARD
=================================================================== */
async function renderDashboard() {
  const el = $("#view-dashboard");
  el.innerHTML = "<div class='empty'>Loading posture…</div>";
  let d;
  try { d = await api("/dashboard/summary"); } catch { return; }
  const k = d.kpis;
  const m = d.matrix;
  const colorOf = { COMPLIANT: "#34d399", PARTIAL: "#fbbf24", NON_COMPLIANT: "#f87171", NOT_ASSESSED: "#3b4a63", NOT_APPLICABLE: "#60a5fa" };
  const bars = m.frameworks.map((f) => `
    <div class="bar-row">
      <span class="lbl">${esc(f.code)}</span>
      <div class="bar-track"><div class="bar-fill" style="width:${f.compliance_score}%;background:linear-gradient(90deg,#22d3ee,#34d399)"></div></div>
      <span style="text-align:right;font-weight:700">${f.compliance_score}%</span>
    </div>`).join("");

  const riskLegend = [["CRITICAL", "#f87171"], ["HIGH", "#fbbf24"], ["MEDIUM", "#60a5fa"], ["LOW", "#8fa3c8"]]
    .map(([k2, c]) => `<div class="lg"><span class="sw" style="background:${c}"></span>${k2}
        <b style="margin-left:auto">${d.risk.by_tier[k2] || 0}</b></div>`).join("");

  const statusColors = ["COMPLIANT", "PARTIAL", "NON_COMPLIANT", "NOT_ASSESSED", "NOT_APPLICABLE"];
  const statusBars = (row) => statusColors.map((s) =>
    `<span style="background:${colorOf[s]};flex:${row.status[s] || 0}"></span>`).join("");

  const findings = d.assessments.recent.slice(0, 5).map((a) => `<tr>
    <td class="mono">#${a.id}</td><td>${esc(a.name)}</td>
    <td><span class="badge has-${a.framework_code}">${esc(a.framework_code)}</span></td>
    <td>${badge(a.status)}</td>
    <td>${a.score ?? "—"}%</td><td>${a.findings ?? 0}</td></tr>`).join("");

  el.innerHTML = `
    <div class="grid cols-4 mb">
      ${kpi("Overall compliance", `${k.overall_compliance}%`, "#22d3ee")}
      ${kpi("Controls tracked", k.controls_total, "#60a5fa", `${k.frameworks} frameworks`)}
      ${kpi("Evidence artefacts", k.evidence_total, "#34d399", `overlap savings ${k.overlap_savings}`)}
      ${kpi("Open critical/high", k.critical_findings, k.critical_findings ? "#f87171" : "#34d399", `${k.open_tickets} tickets open`)}
    </div>
    <div class="grid cols-2 mb">
      <div class="card"><h3>Compliance score per framework</h3>${bars}</div>
      <div class="card"><h3>Risk register distribution</h3>
        <div class="donut">
          <div class="donut-ring" style="--p:${Math.min(100, d.risk.total ? (d.risk.by_tier.CRITICAL + d.risk.by_tier.HIGH) / d.risk.total * 100 : 0)}"><b>${d.risk.total}</b></div>
          <div class="legend">${riskLegend}</div>
        </div>
        <div class="status-bars">
          ${["CRITICAL", "HIGH", "MEDIUM", "LOW"].map((s) => `<span style="background:${({CRITICAL:"#f87171",HIGH:"#fbbf24",MEDIUM:"#60a5fa",LOW:"#8fa3c8"})[s]};flex:${d.risk.by_tier[s] || 0}"></span>`).join("")}
        </div>
      </div>
    </div>
    <div class="grid cols-2 mb">
      <div class="card"><h3>Framework status heatmap</h3>
        <div class="table-wrap" style="overflow:hidden">
        <table><thead><tr><th>Framework</th><th>Controls</th><th>Compliant</th><th>Partial</th><th>Non-compliant</th><th>Not assessed</th></tr></thead>
        <tbody>${m.frameworks.map((f) => `<tr>
          <td><b>${esc(f.name)}</b></td><td>${f.total}</td>
          <td style="color:#34d399">${f.status.COMPLIANT || 0}</td>
          <td style="color:#fbbf24">${f.status.PARTIAL || 0}</td>
          <td style="color:#f87171">${f.status.NON_COMPLIANT || 0}</td>
          <td>${f.status.NOT_ASSESSED || 0}</td></tr>`).join("")}</tbody></table>
        <div class="status-bars mt">${m.frameworks.map((f) => statusBars(f)).join("<span style='width:12px'></span>")}</div>
        </div>
      </div>
      <div class="card"><h3>Recent assessments</h3>
        <div class="table-wrap"><table><thead>
        <tr><th>ID</th><th>Name</th><th>Framework</th><th>Status</th><th>Score</th><th>Findings</th></tr></thead>
        <tbody>${findings || "<tr><td colspan=6 class='empty'>Run your first assessment</td></tr>"}</tbody></table></div>
        <div class="flex-between mt">
          <span class="detail-line">Mean remediation: <b>${d.sla.avg_resolution_hours ?? "—"}h</b> · SLA breaches: <b>${d.sla.sla_breaches}</b></span>
          <button class="btn btn-primary btn-xs" onclick="quickAssess('ISO27001')" ${can("assess:write") ? "" : "disabled"}>Run ISO assessment</button>
        </div>
      </div>
    </div>`;
}

function kpi(label, value, color, cap = "") {
  return `<div class="card"><div class="card-cap">${esc(label)}</div>
    <div class="card-num" style="color:${color}">${esc(value)}</div>
    <div class="kpi-trend" style="color:var(--muted)">${esc(cap)}</div></div>`;
}

async function quickAssess(fw) {
  try {
    await api("/assessments", { method: "POST", json: { framework_code: fw, method: "AUTO", scope: "QUARTERLY" } });
    toast("Assessment completed");
    renderAssessments();
    switchView("assessments");
  } catch (e) { /* handled */ }
}

/* ===================================================================
   CONTROLS & MAPPING
=================================================================== */
async function renderControls() {
  const el = $("#view-controls");
  el.innerHTML = "<div class='empty'>Loading matrix…</div>";
  let [fw, controls, overlaps] = await Promise.all([
    api("/controls/frameworks"), api("/controls"), api("/controls/overlaps"),
  ]);
  const fwOpts = `<option value="">All frameworks</option>` + fw.map((f) => `<option value="${f.code}">${f.code}</option>`).join("");
  const catSel = ["ASSET_INVENTORY","ACCESS_CONTROL","CRYPTOGRAPHY","DATA_PROTECTION","IDENTITY","INCIDENT","LOG_AND_MONITOR","NETWORK","SECURE_CODING","TRAINING","VULNERABILITY"]
    .map((c) => `<option>${c}</option>`).join("");

  el.innerHTML = `
    <div class="bar-controls">
      <select id="ctl-fw">${fwOpts}</select>
      <select id="ctl-cat"><option value="">All categories</option>${catSel}</select>
      <button class="btn" onclick="loadControls()">Filter</button>
      <button class="btn btn-primary ${can("map:write") ? "" : "hidden"}" onclick="showMapper()">Open Control Mapper</button>
      <span class="detail-line">Evidence overlap savings: <b>${overlaps.overlap_savings}</b> · max frameworks per evidence: <b>${overlaps.max_frameworks_per_evidence}</b></span>
    </div>
    <div class="table-wrap"><table id="ctl-table"><thead><tr>
      <th>Framework</th><th>Code</th><th>Title</th><th>Category</th><th>Intent</th>
      <th>Status</th><th>Evidence</th><th>Owner</th></tr></thead>
      <tbody id="ctl-tbody"></tbody></table></div>`;
  window._controls = controls;
  renderControlRows(controls);
}

async function loadControls() {
  const fwSel = $("#ctl-fw").value, catSel = $("#ctl-cat").value;
  const q = new URLSearchParams();
  if (fwSel) q.set("framework", fwSel);
  if (catSel) q.set("category", catSel);
  const controls = await api(`/controls?${q}`);
  window._controls = controls;
  renderControlRows(controls);
}

function renderControlRows(controls) {
  const tb = $("#ctl-tbody");
  const rows = controls.map((c) => `<tr>
    <td><span class="badge has-${c.framework}">${esc(c.framework)}</span></td>
    <td class="mono">${esc(c.code)}</td>
    <td>${esc(c.title)}</td>
    <td><span class="pill pill-blue">${esc(c.category)}</span></td>
    <td>${badge(c.intent)}</td>
    <td>${badge(c.status)}</td>
    <td>${c.evidence_count}</td>
    <td>${esc(c.owner)}</td></tr>`).join("");
  tb.innerHTML = rows || "<tr><td colspan=8 class='empty'>No controls</td></tr>";
}

async function showMapper() {
  const overlapped = await api("/controls/overlaps");
  const brush = overlapped.breakdown || [];
  const topEv = brush.slice(0, 5);
  const list = await api("/controls");
  const opts = list.map((c) => `<option value="${c.id}">${c.framework} · ${c.code} — ${esc(c.title).slice(0, 40)}</option>`).join("");
  const suggestTarget = (s, picked) => s.map((x) => `<option value="${x.target_id}">${x.framework} · ${x.code} — ${esc(x.title).slice(0, 40)}${x.mapped ? " ✓" : ""}</option>`).join("");

  const modal = document.createElement("div");
  modal.style.cssText = "position:fixed;inset:0;background:rgba(2,8,23,.75);z-index:50;display:flex;align-items:center;justify-content:center;padding:20px";
  modal.innerHTML = `<div class="card" style="width:760px;max-height:86vh;overflow:auto">
    <h3 style="color:var(--brand)">Canonical Control Mapper</h3>
    <p class="detail-line mb">Pick a source control, then map it (EQUIVALENT / RELATED / IMPLEMENTS) to a target in another framework. "One evidence point in → compliant across every framework out."</p>
    <div class="field"><label>Source control</label><select id="map-src">${opts}</select></div>
    <div class="field"><label>Suggested targets (auto)</label><select id="map-sugg" disabled><option>—</option></select></div>
    <div class="field" style="display:grid;grid-template-columns:1fr 1fr;gap:10px">
      <div><label>Map type</label><select id="map-type"><option>EQUIVALENT</option><option>RELATED</option><option>IMPLEMENTS</option></select></div>
      <div><label>To target framework</label>${""}</div>
    </div>
    <div class="field"><label>Rationale</label><input id="map-why" placeholder="Optional note"></div>
    <div class="flex-between">
      <span class="detail-line">Evidence overlap winners (top de-dup):</span>
      <div class="flex">
        <button class="btn" onclick="this.closest('div').closest('.card').parentElement.remove()">Close</button>
        <button class="btn btn-primary" id="map-apply" onclick="applyMapping()">Apply mapping</button>
      </div>
    </div>
    <div class="mt">
      ${topEv.map((e) => `<div class="detail-line" style="padding:6px 0;border-bottom:1px solid var(--line)">
        <b>#${e.evidence_id}</b> ${esc(e.title)} → covers ${e.frameworks.join(" + ")} (${e.count} frameworks)</div>`).join("")}
    </div>
  </div>`;
  document.body.appendChild(modal);

  const src = modal.querySelector("#map-src");
  const sugg = modal.querySelector("#map-sugg");
  async function refreshSuggest() {
    const r = await api(`/controls/mapping/suggest/${src.value}`);
    if (r.suggestions.length) {
      sugg.disabled = false;
      sugg.innerHTML = `<option>—select suggestion—</option>` + suggestTarget(r.suggestions);
    } else {
      sugg.disabled = true;
      sugg.innerHTML = `<option>All controls in other frameworks listed below</option>`;
    }
  }
  // Simpler: always suggest + show full target list to be usable
  const fullOpts = `<option value="">—</option>` + list.filter((c) => String(c.id) !== src.value)
    .map((c) => `<option value="${c.id}">${c.framework} · ${c.code} — ${esc(c.title).slice(0, 40)}</option>`).join("");
  sugg.outerHTML = `<select id="map-tgt" class="field" style="width:100%">${fullOpts}</select>`;
  await refreshSuggest();

  window._applyMapping = async () => {
    try {
      const payload = { mappings: [{ source_id: +src.value, target_id: +$("#map-tgt").value, map_type: $("#map-type").value, rationale: $("#map-why").value }] };
      await api("/controls/mapping", { method: "POST", json: payload });
      toast("Mapping applied");
      modal.remove();
      renderControls();
    } catch { /* handled */ }
  };
}

async function applyMapping() {
  if (window._applyMapping) await window._applyMapping();
}

/* ===================================================================
   ASSESSMENTS
=================================================================== */
async function renderAssessments() {
  const el = $("#view-assessments");
  el.innerHTML = "<div class='empty'>Loading…</div>";
  const d = await api("/assessments");
  el.innerHTML = `
    <div class="grid cols-3 mb">
      ${kpi("Assessments total", d.total, "#60a5fa")}
      ${kpi("Completed", d.completed, "#34d399")}
      ${kpi("Best score", `${d.best_score}%`, "#22d3ee")}
    </div>
    <div class="card mb">
      <h3>Run new assessment</h3>
      <div class="flex">
        <div class="field" style="flex:1"><label>Name</label><input id="as-name" placeholder="Q4 BB ICT return prep"></div>
        <div class="field"><label>Framework</label><select id="as-fw">
          <option value="ISO27001">ISO 27001</option><option value="BBICT2015">BB ICT 2015</option>
          <option value="NISTCSF">NIST CSF 2.0</option><option value="OWASP2021">OWASP Top 10</option></select></div>
        <div class="field"><label>Method</label><select id="as-method"><option>AUTO</option><option>HYBRID</option><option>QUESTIONNAIRE</option></select></div>
        <div class="field"><label>Scope</label><select id="as-scope"><option>ANNUAL</option><option>QUARTERLY</option><option>RELEASE</option><option>CONTINUOUS</option></select></div>
        <div class="field" style="align-self:end"><button class="btn btn-primary" ${can("assess:write") ? "onclick='runAssessment()'" : "disabled"}>Run</button></div>
      </div>
    </div>
    <div class="card"><h3>Assessment history</h3>
      <div class="table-wrap"><table><thead><tr><th>ID</th><th>Name</th><th>Framework</th><th>Method</th>
        <th>Status</th><th>Score</th><th>Findings</th><th>Completed</th><th></th></tr></thead>
      <tbody>${d.recent.map((a) => `<tr>
        <td class="mono">#${a.id}</td><td>${esc(a.name)}</td>
        <td><span class="badge has-${a.framework_code}">${esc(a.framework_code)}</span></td>
        <td>${esc(a.method)}</td><td>${badge(a.status)}</td>
        <td style="font-weight:700;color:${(a.score ?? 0) >= 80 ? "#34d399" : (a.score ?? 0) >= 50 ? "#fbbf24" : "#f87171"}">${a.score ?? "—"}%</td>
        <td>${a.findings ?? 0}</td><td class="mono-sm" style="color:var(--muted)">${esc(a.completed_at ? a.completed_at.slice(0,16).replace("T"," ") : "—")}</td>
        <td><button class="btn btn-xs" onclick='openAssessmentDetail(${a.id})' ${can("assess:read") ? "" : "disabled"}>Detail</button></td></tr>`).join("")}</tbody></table></div>
    </div>`;
}

async function runAssessment() {
  const body = { framework_code: $("#as-fw").value, method: $("#as-method").value, scope: $("#as-scope").value, name: $("#as-name").value };
  const r = await api("/assessments", { method: "POST", json: body });
  toast(`Completed — score ${r.score}%`);
  renderAssessments();
}

async function openAssessmentDetail(id) {
  const d = await api(`/assessments/${id}`);
  const modal = document.createElement("div");
  modal.style.cssText = "position:fixed;inset:0;background:rgba(2,8,23,.75);z-index:50;display:flex;align-items:center;justify-content:center;padding:20px";
  const rows = d.decisions.map((x) => `<tr><td class="mono">${esc(x.code)}</td>
    <td>${esc(x.title).slice(0, 46)}</td><td>${badge(x.decision)}</td>
    <td>${x.evidence_count}</td>
    <td>${can("assess:write")
      ? `<select class="inline-dec" data-cid="${x.control_id}" onchange="setDecision(${d.id}, ${x.control_id}, this.value)"
           style="padding:5px 8px;border-radius:8px;background:#0a1526;color:var(--text);border:1px solid var(--line)">
           ${["COMPLIANT","PARTIAL","NON_COMPLIANT","NOT_APPLICABLE","NOT_ASSESSED"].map((s) => `<option ${s === x.decision ? "selected" : ""}>${s}</option>`).join("")}</select>` : badge(x.decision)}
    </td></tr>`).join("");
  modal.innerHTML = `<div class="card" style="width:900px;max-height:86vh;overflow:auto">
    <div class="flex-between"><div><h3 style="color:var(--brand)">${esc(d.name)}</h3>
      <p class="detail-line">${esc(d.framework_code)} · ${esc(d.method)} · score <b>${d.result_score ?? "—"}%</b> · findings <b>${d.findings_count}</b></p></div>
      <button class="btn" onclick="this.closest('.card').parentElement.remove()">Close</button></div>
    <div class="table-wrap mt"><table><thead><tr><th>Code</th><th>Control</th><th>Decision</th><th>Evidence</th><th>Adjust</th></tr></thead>
      <tbody>${rows}</tbody></table></div>
    <div class="mt"><button class="btn btn-primary btn-xs" onclick="downloadReportFor('controls','json','${esc(d.framework_code)}')">Export decisions (JSON)</button></div>
  </div>`;
  document.body.appendChild(modal);
}

async function setDecision(aid, cid, status) {
  try {
    await api(`/assessments/${aid}/decisions/${cid}`, { method: "POST", json: { status, note: "Updated from console" } });
    toast("Decision updated");
    openAssessmentDetail(aid);
    renderAssessments();
  } catch { /* handled */ }
}

/* ===================================================================
   RISK & REMEDIATION
=================================================================== */
async function renderRisk() {
  const el = $("#view-risk");
  el.innerHTML = "<div class='empty'>Loading…</div>";
  const [risk, tickets, sla] = await Promise.all([api("/risk"), api("/risk/tickets"), api("/risk/sla")]);
  const tierCount = risk.by_tier || {};
  el.innerHTML = `
    <div class="grid cols-4 mb">
      ${kpi("Open risks", risk.total, "#60a5fa")}
      ${kpi("Critical", tierCount.CRITICAL || 0, tierCount.CRITICAL ? "#f87171" : "#34d399")}
      ${kpi("High", tierCount.HIGH || 0, tierCount.HIGH ? "#fbbf24" : "#34d399")}
      ${kpi("Open tickets", sla.open, "#22d3ee", `${sla.overdue} overdue · ${sla.sla_breaches} breaches`)}
    </div>
    <div class="grid cols-2 mb">
      <div class="card"><h3>Risk register</h3><div class="table-wrap"><table><thead>
        <tr><th>ID</th><th>Risk</th><th>Tier</th><th>CVSS</th><th>Raw</th><th>Status</th></tr></thead><tbody>
        ${(risk.top || []).map((r) => `<tr><td class="mono">#${r.id}</td><td>${esc(r.title)}</td>
          <td>${badge(r.tier)}</td><td class="mono">${r.cvss}</td><td class="mono">${r.raw ?? "—"}</td>
          <td>${badge(r.status)}</td></tr>`).join("") || "<tr><td colspan=6 class='empty'>No risks</td></tr>"}
        </tbody></table></div>
        <div class="flex-between mt">
          <button class="btn btn-xs ${can("risk:write") ? "" : "hidden"}" onclick="escalateAll()">Auto-escalate high/critical → tickets</button>
          <button class="btn btn-xs" onclick="downloadReportFor('risk','pdf')">Risk register PDF</button>
        </div>
      </div>
      <div class="card"><h3>Remediation tickets</h3><div class="table-wrap"><table><thead>
        <tr><th>ID</th><th>Title</th><th>Priority</th><th>Status</th><th>Due</th><th>Assignee</th><th></th></tr></thead><tbody>
        ${tickets.map((t) => `<tr><td class="mono">#${t.id}</td><td>${esc(t.title).slice(0, 40)}</td>
          <td>${badge(t.priority)}</td><td>${badge(t.status)}</td>
          <td class="mono-sm" style="color:var(--muted)">${t.due_at ? esc(t.due_at.slice(0,16).replace("T"," ")) : "—"}</td>
          <td>${esc(t.assignee || "—")}</td>
          <td>${["IN_PROGRESS","IN_REVIEW","RESOLVED"].map((s) => `<button class="btn btn-xs" ${can("remediation:write") ? "" : "disabled"} onclick="setTicketStatus(${t.id},'${s}')">${s.replace("_"," ")}</button>`).join(" ")}</td></tr>`).join("") ||
          "<tr><td colspan=7 class='empty'>No tickets — run auto-escalation</td></tr>"}
        </tbody></table></div>
      </div>
    </div>
    <div class="card"><h3>New risk</h3>
      <div class="flex">
        <div class="field" style="flex:2"><label>Title</label><input id="rk-title" placeholder="e.g. Unpatched middleware exposes admin console"></div>
        <div class="field"><label>Likelihood (1-5)</label><input id="rk-like" type="number" min="1" max="5" value="3"></div>
        <div class="field"><label>Impact (1-5)</label><input id="rk-imp" type="number" min="1" max="5" value="3"></div>
        <div class="field"><label>CVSS</label><input id="rk-cvss" type="number" min="0" max="10" step="0.1" value="5"></div>
        <div class="field" style="align-self:end"><button class="btn btn-primary" ${can("risk:write") ? "onclick='createRisk()'" : "disabled"}>Add</button></div>
      </div>
    </div>`;
}

async function createRisk() {
  const title = $("#rk-title").value || "Untitled risk";
  await api("/risk", { method: "POST", json: { title, likelihood: +$("#rk-like").value, impact: +$("#rk-imp").value, cvss: +$("#rk-cvss").value } });
  toast("Risk added");
  renderRisk();
}

async function escalateAll() {
  const r = await api("/risk/escalate", { method: "POST", json: {} });
  toast(`${r.tickets_created.length} tickets auto-created`);
  renderRisk();
}

async function setTicketStatus(id, status) {
  await api(`/risk/tickets/${id}/status`, { method: "POST", json: { status } });
  toast(`Ticket #${id} → ${status}`);
  renderRisk();
}

/* ===================================================================
   EVIDENCE VAULT
=================================================================== */
async function renderEvidence() {
  const el = $("#view-evidence");
  el.innerHTML = "<div class='empty'>Loading…</div>";
  const evs = await api("/evidence");
  const controls = await api("/controls");
  const ctrlOpts = controls.map((c) => `<option value="${c.id}">${c.framework} · ${c.code} — ${esc(c.title).slice(0, 36)}</option>`).join("");
  el.innerHTML = `
    <div class="card mb">
      <h3>Upload evidence (WORM vault)</h3>
      <div class="flex">
        <div class="field" style="flex:1"><label>Title</label><input id="ev-title" placeholder="e.g. Annual pentest report 2026"></div>
        <div class="field"><label>Type</label><select id="ev-type">
          ${["POLICY","LOG_EXPORT","SCAN_REPORT","CONFIG_BASELINE","SCREENSHOT","AUDIT"].map((t) => `<option>${t}</option>`).join("")}</select></div>
        <div class="field"><label>Source</label><input id="ev-src" placeholder="Nessus / AWS / SIEM"></div>
      </div>
      <div class="field"><label>Link to controls (multi-select via Ctrl+Click)</label>
        <select id="ev-controls" multiple size="4" style="width:100%">${ctrlOpts}</select></div>
      <div class="field"><label>Artefact file (≤25MB · pdf/docx/xlsx/csv/json/txt/png/jpg/log/zip)</label>
        <input id="ev-file" type="file" style="padding:6px"></div>
      <div class="field"><label>Description</label><input id="ev-desc"></div>
      <button class="btn btn-primary" onclick="uploadEvidence()" ${can("evidence:write") ? "" : "disabled"}>Store to vault</button>
      <button class="btn" onclick="downloadFileWithToken('/evidence/pack','evidence_pack.zip')">Download evidence pack (ZIP)</button>
      <span class="pill pill-green" style="margin-left:8px" id="ev-pill">vault verified</span>
    </div>
    <div class="card"><h3>Vault ledger</h3><div class="table-wrap"><table><thead>
      <tr><th>ID</th><th>Artefact</th><th>Type</th><th>Controls linked</th><th>SHA-256</th><th>Chain</th><th>By</th><th>At</th></tr></thead><tbody>
      ${evs.map((e) => `<tr><td class="mono">#${e.id}</td><td>${esc(e.title)}</td>
        <td><span class="pill pill-blue">${esc(e.artefact_type)}</span></td>
        <td>${e.controls.map((c) => `<span class="badge has-${c.framework}">${esc(c.code)}</span>`).join(" ")}</td>
        <td class="mono-sm hashcell" title="${e.sha256}">${esc(e.sha256.slice(0, 12))}…</td>
        <td class="mono-sm hashcell" title="${e.chain_hash}">${esc(e.chain_hash.slice(0, 12))}…</td>
        <td>${esc(e.uploaded_by)}</td><td class="mono-sm" style="color:var(--muted)">${esc(e.created_at.slice(0,16).replace("T"," "))}</td></tr>`).join("") ||
        "<tr><td colspan=8 class='empty'>Vault empty</td></tr>"}
      </tbody></table></div></div>`;
  refreshVeracity();
}

async function uploadEvidence() {
  const file = $("#ev-file").files[0];
  if (!file) { toast("Choose a file first", "err"); return; }
  const selIds = [...$("#ev-controls").selectedOptions].map((o) => o.value);
  const fd = new FormData();
  fd.append("title", $("#ev-title").value || file.name);
  fd.append("artefact_type", $("#ev-type").value);
  fd.append("source_system", $("#ev-src").value || "MANUAL");
  fd.append("description", $("#ev-desc").value || "");
  fd.append("control_ids", JSON.stringify(selIds.map(Number)));
  fd.append("file", file);
  try {
    const res = await fetch("/evidence/upload", {
      method: "POST", headers: { Authorization: `Bearer ${state.token}` }, body: fd,
    });
    if (!res.ok) { toast(`Upload failed ${res.status}`, "err"); return; }
    const r = await res.json();
    toast(`Stored #${r.id} · sha256 ${r.sha256.slice(0, 12)}…`);
    renderEvidence();
  } catch { toast("Upload failed", "err"); }
}

/* ===================================================================
   FINDINGS / ASSETS
=================================================================== */
async function renderFindings() {
  const el = $("#view-findings");
  el.innerHTML = "<div class='empty'>Loading…</div>";
  const [assets, findings] = await Promise.all([api("/assets"), api("/assets/findings")]);
  const sevCount = findings.reduce((m, f) => (m[f.severity] = (m[f.severity] || 0) + 1, m), {});
  el.innerHTML = `
    <div class="grid cols-4 mb">
      ${kpi("Assets", assets.length, "#60a5fa")}
      ${kpi("Critical findings", sevCount.CRITICAL || 0, sevCount.CRITICAL ? "#f87171" : "#34d399")}
      ${kpi("High", sevCount.HIGH || 0, sevCount.HIGH ? "#fbbf24" : "#34d399")}
      ${kpi("Open total", findings.filter((f) => f.status === "OPEN").length, "#22d3ee")}
    </div>
    <div class="grid cols-2 mb">
      <div class="card"><h3>Asset inventory</h3>
        <div class="table-wrap"><table><thead><tr><th>Name</th><th>Type</th><th>Env</th><th>Classification</th><th>Criticality</th><th>Open</th></tr></thead><tbody>
        ${assets.map((a) => `<tr><td><b>${esc(a.name)}</b></td><td>${esc(a.asset_type)}</td><td>${esc(a.environment)}</td>
          <td><span class="pill pill-blue">${esc(a.classification)}</span></td>
          <td>${"★".repeat(Math.round(a.criticality))}</td><td>${a.open_findings}</td></tr>`).join("")}
        </tbody></table></div>
        <div class="flex-between mt">
          <span class="detail-line">New asset</span>
          <input id="as-name2" placeholder="Asset name" style="padding:7px 10px;border-radius:8px;border:1px solid var(--line);background:#0a1526;color:var(--text)">
          <button class="btn btn-xs __" onclick="addAsset()" ${can("asset:write") ? "" : "disabled"}>Add</button>
          <button class="btn btn-xs" onclick="downloadReportFor('scans','pdf')">Findings PDF</button>
        </div>
      </div>
      <div class="card"><h3>Scanner findings</h3>
        <div class="table-wrap"><table><thead><tr><th>Severity</th><th>Finding</th><th>Asset</th><th>Scanner</th><th>CVSS</th><th>Status</th></tr></thead><tbody>
        ${findings.slice(0, 80).map((f) => `<tr><td>${badge(f.severity)}</td>
          <td>${esc(f.title).slice(0, 46)}</td><td>${esc(f.asset)}</td><td>${esc(f.scanner)}</td>
          <td class="mono">${f.cvss}</td><td>${badge(f.status)}</td></tr>`).join("") || "<tr><td colspan=6 class='empty'>No findings</td></tr>"}
        </tbody></table></div>
      </div>
    </div>`;
}

async function addAsset() {
  const name = $("#as-name2").value;
  if (!name) return;
  await api("/assets", { method: "POST", json: { name } });
  toast("Asset added");
  renderFindings();
}

/* ===================================================================
   REPORTS
=================================================================== */
async function renderReports() {
  const el = $("#view-reports");
  el.innerHTML = "<div class='empty'>Loading catalogue…</div>";
  const r = await api("/reports/formats");
  const fmtChip = (table) => table.formats
    .map((f) => `<button class="btn btn-xs" onclick="downloadReportFor('${table.scope}','${f}')">⬇ ${f.toUpperCase()}</button>`).join(" ");
  el.innerHTML = `
    <div class="card mb">
      <h3>On-demand export (raw engine)</h3>
      <div class="flex">
        <select id="rep-type">${r.types.map((t) => `<option value="${t}">${t}</option>`).join("")}</select>
        <select id="rep-fmt">${r.formats.filter((f) => f !== "zip").map((f) => `<option value="${f}">${f.toUpperCase()}</option>`).join("")}</select>
        <select id="rep-fw"><option value="">All frameworks</option><option>ISO27001</option><option>BBICT2015</option><option>NISTCSF</option><option>OWASP2021</option></select>
        <button class="btn btn-primary" onclick="customExport()">Export</button>
      </div>
    </div>
    <div class="card"><h3>Regulator-ready report catalogue</h3>
      <div class="table-wrap"><table><thead><tr><th>Report</th><th>Scope</th><th>Cadence</th><th>Export</th></tr></thead><tbody>
      ${r.report_catalogue.map((t) => `<tr><td><b>${esc(t.name)}</b></td>
        <td><span class="pill pill-blue">${esc(t.scope)}</span></td><td>${esc(t.cadence)}</td><td>${fmtChip(t)}</td></tr>`).join("")}
      </tbody></table></div>
    </div>`;
}

async function customExport() {
  const type = $("#rep-type").value, fmt = $("#rep-fmt").value, fw = $("#rep-fw").value;
  downloadReportFor(type, fmt, fw || undefined);
}

async function downloadReportFor(type, fmt, fw) {
  const q = new URLSearchParams({ report: type, fmt });
  if (fw) q.set("framework", fw);
  try {
    const res = await fetch(`/reports/download?${q}`, { headers: { Authorization: `Bearer ${state.token}` } });
    if (!res.ok) { toast(`Export failed ${res.status}`, "err"); return; }
    const disp = res.headers.get("content-disposition") || "";
    const m = disp.match(/filename="?([^";]+)"?/);
    const blob = await res.blob();
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = m ? m[1] : `report.${fmt}`;
    a.click();
    URL.revokeObjectURL(a.href);
    toast(`Exported ${fmt.toUpperCase()}`);
  } catch { toast("Export failed", "err"); }
}

/* ===================================================================
   AUDIT LOG
=================================================================== */
async function renderAudit() {
  const el = $("#view-audit");
  el.innerHTML = "<div class='empty'>Loading…</div>";
  const rows = await api("/audit");
  const ver = await api("/audit/verify");
  el.innerHTML = `
    <div class="flex-between mb">
      <span class="pill ${ver.verified ? "pill-green" : "pill-red"}">Hash chain: ${ver.verified ? `verified (${ver.checked} rows)` : "TAMPERED"}</span>
      <button class="btn btn-xs" onclick="downloadReportFor('mapping','csv')">Export mapping CSV</button>
    </div>
    <div class="card"><h3>Append-only audit trail</h3>
      <div class="table-wrap"><table><thead><tr><th>ID</th><th>Actor</th><th>Role</th><th>Action</th><th>Entity</th><th>Detail</th><th>Row hash</th><th>At</th></tr></thead><tbody>
      ${rows.map((r) => `<tr><td class="mono">#${r.id}</td><td>${esc(r.actor)}</td>
        <td><span class="badge has-LOW">${esc(r.actor_role)}</span></td>
        <td><b style="color:var(--brand)">${esc(r.action)}</b></td>
        <td class="mono-sm">${esc(r.entity_type || "—")} ${r.entity_id ?? ""}</td>
        <td class="mono-sm">${esc(JSON.stringify(r.detail)).slice(0, 70)}</td>
        <td class="mono-sm hashcell" title="${r.row_hash}">${esc(r.row_hash.slice(0, 14))}…</td>
        <td class="mono-sm" style="color:var(--muted)">${esc(r.created_at.slice(0,16).replace("T"," "))}</td></tr>`).join("") || "<tr><td colspan=8 class='empty'>No audit rows</td></tr>"}
      </tbody></table></div>
    </div>`;
}

/* ===================================================================
   ADMIN
=================================================================== */
async function renderAdmin() {
  const el = $("#view-admin");
  el.innerHTML = "<div class='empty'>Loading…</div>";
  const users = await api("/auth/users");
  el.innerHTML = `
    <div class="card mb"><h3>Create user</h3>
      <div class="flex">
        <div class="field"><label>Username</label><input id="nu-user"></div>
        <div class="field"><label>Email</label><input id="nu-email"></div>
        <div class="field"><label>Display name</label><input id="nu-name"></div>
        <div class="field"><label>Role</label><select id="nu-role">
          ${["SUPER_ADMIN","CISO","CONTROL_OWNER","ASSESSOR","REGULATOR","VIEWER"].map((r) => `<option>${r}</option>`).join("")}</select></div>
        <div class="field"><label>Password</label><input id="nu-pass" type="password"></div>
        <div class="field" style="align-self:end"><button class="btn btn-primary" onclick="createUser()">Create</button></div>
      </div>
    </div>
    <div class="card"><h3>Users</h3><div class="table-wrap"><table><thead>
      <tr><th>Username</th><th>Email</th><th>Role</th><th>MFA</th><th>Active</th><th>Last login</th></tr></thead><tbody>
      ${users.map((u) => `<tr><td><b>${esc(u.display_name)}</b> <span class="mono-sm">@${esc(u.username)}</span></td>
        <td>${esc(u.email)}</td><td><span class="badge has-LOW">${esc(u.role)}</span></td>
        <td>${u.mfa_enabled ? "🔒" : "—"}</td><td>${u.is_active ? badge("COMPLIANT") : badge("NON_COMPLIANT")}</td>
        <td class="mono-sm" style="color:var(--muted)">${u.last_login ? esc(u.last_login.slice(0,16).replace("T"," ")) : "never"}</td></tr>`).join("")}
      </tbody></table></div></div>`;
}

async function createUser() {
  const d = { username: $("#nu-user").value, email: $("#nu-email").value, display_name: $("#nu-name").value, role: $("#nu-role").value, password: $("#nu-pass").value };
  if (!d.username || !d.email || !d.password) { toast("Fill all fields", "err"); return; }
  await api("/auth/users", { method: "POST", json: d });
  toast("User created");
  renderAdmin();
}

/* ---------------- Boot ---------------- */
(async function boot() {
  const tok = localStorage.getItem("cas_token");
  if (tok) {
    try {
      const me = await fetch("/auth/me", { headers: { Authorization: `Bearer ${tok}` } });
      if (me.ok) {
        const u = await me.json();
        state.token = tok;
        state.user = u;
        enterApp();
        return;
      }
    } catch { /* continue to login */ }
  }
  $("#login-screen").style.display = "flex";
})();