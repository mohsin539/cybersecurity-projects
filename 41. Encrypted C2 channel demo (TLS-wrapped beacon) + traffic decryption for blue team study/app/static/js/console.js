let TOKEN = sessionStorage.getItem("lab_token") || "";

const $ = (id) => document.getElementById(id);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

async function api(path, opts = {}) {
  const headers = { "Content-Type": "application/json", ...(opts.headers || {}) };
  if (TOKEN && !path.startsWith("/api/admin/hello") && !path.startsWith("/api/v1/beacon")) headers["X-Lab-Token"] = TOKEN;
  const res = await fetch(path, { ...opts, headers });
  if (res.status === 401) { toast("Unauthorized — refresh token", true); return null; }
  return res.json();
}

function toast(msg, isErr = false) {
  const t = $("toast");
  t.textContent = msg;
  t.className = "toast show" + (isErr ? " err" : "");
  clearTimeout(t._h);
  t._h = setTimeout(() => { t.className = "toast"; }, 3000);
}

function statusPill(s) {
  const map = { active: "pill-active", dead: "pill-dead", flagged: "pill-flagged", resumed: "pill-resumed", registered: "pill-active", queued: "pill-m", sent: "pill-m", executed: "pill-l", new: "pill-new", triaged: "pill-triaged", resolved: "pill-resolved" };
  return `<span class="pill ${map[s] || ""}">${esc(s)}</span>`;
}

function riskBar(score) {
  const s = Number(score || 0);
  const color = s >= 66 ? "#f87171" : s >= 33 ? "#fbbf24" : "#4ade80";
  return `<span class="riskbar"><i style="width:${s}%;background:${color}"></i></span>${s.toFixed ? s.toFixed(0) : s}`;
}

/* ---------- nav ---------- */
document.querySelectorAll(".nav-btn").forEach((b) => {
  b.addEventListener("click", () => {
    document.querySelectorAll(".nav-btn").forEach((x) => x.classList.remove("active"));
    b.classList.add("active");
    document.querySelectorAll(".view").forEach((v) => v.classList.remove("active"));
    $("view-" + b.dataset.view).classList.add("active");
    refreshView(b.dataset.view);
  });
});

function refreshView(v) {
  if (v === "dashboard") loadDashboard();
  if (v === "beacons") refreshSessions();
  if (v === "traffic") loadTraffic();
  if (v === "detections") loadDetections();
  if (v === "reports") loadReports();
  if (v === "compliance") loadCompliance();
  if (v === "security") loadSecurity();
}

/* ---------- dashboard ---------- */
async function loadDashboard() {
  const s = await api("/api/blue/stats");
  if (!s) return;
  const cards = [
    { n: s.sessions_total, l: "Beacon Sessions", ic: "🖥️", g: "glow-blue" },
    { n: s.sessions_active, l: "Active", ic: "🟢", g: "glow-green" },
    { n: s.sessions_flagged, l: "Flagged", ic: "🚩", g: "glow-red" },
    { n: s.traffic_records, l: "TLS Records", ic: "🌐", g: "glow-blue" },
    { n: s.traffic_decrypted, l: "Decrypted", ic: "🔓", g: "glow-green" },
    { n: s.alerts_open, l: "Open Alerts", ic: "🚨", g: "glow-amb" },
    { n: s.highest_risk, l: "Peak Risk", ic: "🎚️", g: "glow-red" },
    { n: s.active_rules, l: "Rules Live", ic: "🧬", g: "glow-green" },
  ];
  $("stats").innerHTML = cards.map((c) =>
    `<div class="card ${c.g}"><div class="ic">${c.ic}</div><div class="num">${c.n}</div><div class="lab">${c.l}</div></div>`).join("");

  const alerts = await api("/api/blue/alerts");
  $("dash-alerts").innerHTML = (alerts || []).slice(0, 6).map((a) => `
    <tr><td>${esc(a.rule_name)}</td><td>${statusPill(a.severity)}</td><td>${a.score}</td><td>${statusPill(a.status)}</td></tr>`).join("");
  const sessions = await api("/api/panel/sessions");
  $("dash-sessions").innerHTML = (sessions || []).map((s) => `
    <tr><td>${esc(s.agent_name)}</td><td>${statusPill(s.status)}</td><td>${riskBar(s.risk_score)}</td><td>${s.beacon_interval}s</td></tr>`).join("");
}

/* ---------- beacons ---------- */
async function refreshSessions() {
  const sessions = await api("/api/panel/sessions");
  if (!sessions) return;
  const f = ($("filter-sessions")?.value || "").toLowerCase();
  const rows = sessions.filter((s) => !f || (s.agent_name + s.uuid + (s.sni || "")).toLowerCase().includes(f));
  $("session-rows").innerHTML = rows.map((s) => `
    <tr>
      <td><b>${esc(s.agent_name)}</b><br><code>${esc((s.uuid || "").slice(0, 8))}</code></td>
      <td>${statusPill(s.status)}</td>
      <td>${riskBar(s.risk_score)}</td>
      <td>${esc(s.os)}</td>
      <td>${s.beacon_interval}s ± ${Math.round(s.jitter * 100)}%</td>
      <td><code>${esc(s.ja3)}</code></td>
      <td>${esc(s.sni || "-")}</td>
      <td>${esc(s.tls_version)}</td>
      <td>${esc(s.last_seen)}</td>
      <td>
        <button class="btn btn-sm" onclick="sessionDetail('${s.uuid}')">detail</button>
        <button class="btn btn-sm btn-danger" onclick="toggleKill('${s.uuid}')">${s.kill_switch ? "revive" : "kill"}</button>
      </td>
    </tr>`).join("") || `<tr><td colspan="10" class="hint">No sessions yet — start a demo beacon.</td></tr>`;
}

async function sessionDetail(uuid) {
  const d = await api(`/api/panel/sessions/${uuid}`);
  if (!d) return;
  $("beacon-detail").style.display = "block";
  $("bd-title").textContent = `Session ${d.agent_name} · ${uuid}`;
  $("bd-body").innerHTML = `
    <div class="two-col">
      <div class="panel">
        <div class="panel-title">Identity &amp; transport</div>
        <dl class="kv">
          <dt>UUID</dt><dd>${uuid}</dd>
          <dt>OS / IP</dt><dd>${esc(d.os)} @ ${esc(d.ip)}</dd>
          <dt>Interval / Jitter</dt><dd>${d.beacon_interval}s ± ${Math.round(d.jitter * 100)}%</dd>
          <dt>Risk</dt><dd>${d.risk_score}</dd>
          <dt>JA3</dt><dd>${esc(d.ja3)}</dd>
          <dt>JA3S</dt><dd>${esc(d.ja3s)}</dd>
          <dt>SNI</dt><dd>${esc(d.sni)}</dd>
          <dt>Cipher</dt><dd>${esc(d.cipher)}</dd>
          <dt>Auth</dt><dd>${esc(d.auth_method)}</dd>
        </dl>
      </div>
      <div class="panel">
        <div class="panel-title">Issue a task</div>
        <div class="toolbar">
          <input class="inp" id="task-cmd" style="min-width:220px" placeholder="e.g. whoami / dir / hostname" value="hostname">
        </div>
        <button class="btn btn-primary" onclick="issueTask('${uuid}')">Issue task</button>
        <div class="panel-title" style="margin-top:14px">Tasks</div>
        <table class="tbl">
          <thead><tr><th>ID</th><th>Command</th><th>Status</th><th>Result</th></tr></thead>
          <tbody>${(d.tasks || []).map((t) =>
            `<tr><td><code>${esc(t.task_id)}</code></td><td>${esc(t.command)}</td><td>${statusPill(t.status)}</td><td>${esc((t.result_data || "").slice(0, 80))}</td></tr>`).join("")}
          </tbody>
        </table>
      </div>
    </div>
    <div class="panel"><div class="panel-title">Key escrow (simulated SSLKEYLOG)</div>
      ${(d.keys || []).map((k) => `<code>${esc(k.key_type)}</code> · ${esc(k.label)} · ${esc(k.status)}<br>`).join("") || "none"}
    </div>`;
}

async function issueTask(uuid) {
  const cmd = $("task-cmd").value.trim();
  if (!cmd) return toast("Task command is empty", true);
  const r = await api("/api/panel/tasks", { method: "POST", body: JSON.stringify({ session_uuid: uuid, command: cmd }) });
  toast(r?.task_id ? `Task ${r.task_id} queued` : "failed", !r);
  sessionDetail(uuid);
}

async function toggleKill(uuid) {
  const sessions = await api("/api/panel/sessions");
  const s = sessions.find((x) => x.uuid === uuid);
  const kill = !(s && s.kill_switch);
  await api(`/api/panel/sessions/${uuid}`, { method: "PATCH", body: JSON.stringify({ status: kill ? "flagged" : "active", kill_switch: kill ? 1 : 0 }) });
  toast(kill ? "Kill switch engaged" : "Session revived");
  refreshSessions();
}

async function demoBeacon() {
  toast("Spawning simulated beacon agent on 127.0.0.1…");
  const res = await fetch("/api/v1/beacon/register", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ agent_name: "lab-beacon-x" + Math.floor(Math.random() * 900 + 100) }),
  });
  const r = await res.json();
  if (r.uuid) {
    await runBeacon(r);
    toast("Beacon ran one cycle — session registered");
    refreshSessions();
  } else {
    toast("register failed", true);
  }
}

async function runBeacon(r) {
  const keyHex = r.key_escrow_hex;
  await fetch("/api/v1/beacon/ping?uuid=" + r.uuid, { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" });
  await api("/api/panel/tasks", { method: "POST", body: JSON.stringify({ session_uuid: r.uuid, command: "ipconfig /all" }) });
  await api("/api/panel/tasks", { method: "POST", body: JSON.stringify({ session_uuid: r.uuid, command: "whoami" }) });
  for (let i = 0; i < 3; i++) {
    await fetch("/api/v1/beacon/ping?uuid=" + r.uuid, { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" });
  }
  const taskList = await fetch("/api/v1/beacon/tasks/" + r.uuid).then((x) => x.json());
  for (const t of taskList.tasks || []) {
    const plain = "ok|" + r.agent_name + "|" + t.task_id + "|LEGACY-LAB-CMD";
    const payload = await encAes(keyHex, plain);
    await fetch("/api/v1/beacon/result?uuid=" + r.uuid, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ task_id: t.task_id, payload }),
    });
  }
}

function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}

function bytesToB64(bytes) {
  let bin = "";
  const CHUNK = 0x8000;
  for (let i = 0; i < bytes.length; i += CHUNK) {
    bin += String.fromCharCode.apply(null, bytes.subarray(i, i + CHUNK));
  }
  return btoa(bin);
}

async function encAes(keyHex, text) {
  const rawKey = await crypto.subtle.importKey("raw", hexToBytes(keyHex), { name: "AES-GCM" }, false, ["encrypt"]);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encoded = new TextEncoder().encode(text);
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, rawKey, encoded);
  const buf = new Uint8Array(iv.length + ct.byteLength);
  buf.set(iv, 0);
  buf.set(new Uint8Array(ct), iv.length);
  return bytesToB64(buf);
}

/* ---------- traffic ---------- */
async function loadTraffic() {
  const rows = await api("/api/blue/traffic");
  if (!rows) return;
  const total = rows.length;
  const dec = rows.filter((r) => r.decrypted).length;
  $("traffic-stats").innerHTML = [
    { n: total, l: "Records", ic: "🧾", g: "glow-blue" },
    { n: dec, l: "Decrypted", ic: "🔓", g: "glow-green" },
    { n: new Set(rows.map((r) => r.session_uuid)).size, l: "Sessions", ic: "🖥️", g: "glow-blue" },
    { n: rows.filter((r) => r.event === "ping").length, l: "Heartbeats", ic: "💓", g: "glow-amb" },
  ].map((c) => `<div class="card ${c.g}"><div class="ic">${c.ic}</div><div class="num">${c.n}</div><div class="lab">${c.l}</div></div>`).join("");

  $("traffic-rows").innerHTML = rows.slice(0, 120).map((r) => {
    const meta = r.meta ? JSON.parse(r.meta || "{}") : {};
    const show = r.plaintext || Object.entries(meta).map(([k, v]) => `${k}=${v}`).join(" ") || "";
    return `<tr>
      <td>${r.id}</td>
      <td><b>${esc(r.event)}</b></td>
      <td><code>${esc((r.session_uuid || "").slice(0, 8))}</code></td>
      <td>${esc(r.src_ip)}:${r.src_port} → ${esc(r.dst_ip)}:${r.dst_port || 443}</td>
      <td>${r.record_len}</td>
      <td>${r.decrypted ? '<span class="pill pill-l">YES</span>' : '<span class="pill pill-dead">no</span>'}</td>
      <td class="hint">${esc(show.slice(0, 70))}</td>
      <td>${r.decrypted ? "" : `<button class="btn btn-sm" onclick="decryptOne(${r.id})">decrypt</button>`}</td>
    </tr>`;
  }).join("") || `<tr><td colspan="8" class="hint">No traffic captured yet.</td></tr>`;
}

async function decryptOne(id) {
  const r = await api("/api/blue/decrypt/record?record_id=" + id, { method: "POST" });
  toast(r?.ok ? "Record decrypted (escrowed key applied)" : r?.reason || "failed", !r?.ok);
  loadTraffic();
}

async function loadTlsPolicy() {
  const t = await api("/api/admin/tls");
  if (t) $("tls-policy").textContent = `TLS ${t.policy.min_version} · ${t.policy.cipher} · ${t.policy.lab_mode ? "lab" : "prod"} profile`;
}

/* ---------- detections ---------- */
async function loadDetections() {
  const rules = await api("/api/blue/rules");
  $("rules-rows").innerHTML = (rules || []).map((r) => `
    <tr>
      <td><b>${esc(r.rule_id)}</b> · ${esc(r.name)}<br><span class="hint">${esc(r.description || "")}</span></td>
      <td>${statusPill(r.severity)}</td>
      <td><code>${esc(r.mitre_id)}</code></td>
      <td><input type="checkbox" ${r.enabled ? "checked" : ""} onchange="toggleRule('${r.rule_id}', this.checked)"></td>
    </tr>`).join("");
  const alerts = await api("/api/blue/alerts");
  $("alerts-rows").innerHTML = (alerts || []).slice(0, 50).map((a) => `
    <tr>
      <td><b>${esc(a.rule_name)}</b><br><span class="hint">${esc(a.detail || "")}</span></td>
      <td>${statusPill(a.severity)}</td>
      <td>${a.score}</td>
      <td><code>${esc((a.session_uuid || "").slice(0, 8))}</code></td>
      <td>${statusPill(a.status)}
        ${a.status === "new" ? `<button class="btn btn-sm" onclick="triage(${a.id},'triaged')">triage</button>
        <button class="btn btn-sm btn-primary" onclick="triage(${a.id},'resolved')">resolve</button>` : ""}
      </td>
    </tr>`).join("") || `<tr><td colspan="5" class="hint">No alerts fired yet.</td></tr>`;
}

async function toggleRule(id, on) {
  await api("/api/blue/rules", { method: "POST", body: JSON.stringify({ rule_id: id, enabled: on }) });
  toast(`Rule ${id} ${on ? "enabled" : "disabled"}`);
}
async function triage(id, st) {
  await api("/api/blue/alerts/action", { method: "POST", body: JSON.stringify({ alert_id: id, status: st }) });
  loadDetections();
}

/* ---------- reports ---------- */
async function generateReport() {
  const formats = ["fmt-xlsx", "fmt-csv", "fmt-html"].filter((id) => $(id).checked).map((id) => id.replace("fmt-", ""));
  if (!formats.length) return toast("Select at least one format", true);
  const r = await api("/api/reports/generate", { method: "POST", body: JSON.stringify({ formats, scope: "all" }) });
  if (!r) return;
  for (const f of r.files) { window.location = "/api/reports/download/" + f.file_name + "?token=" + encodeURIComponent(TOKEN); }
  toast("Evidence bundle generated — downloads started");
  loadReports();
}

async function loadReports() {
  const list = await api("/api/reports/list");
  $("reports-rows").innerHTML = (list || []).map((r) => `
    <tr>
      <td>${esc(r.created_at)}</td>
      <td><code>${esc(r.scope)}</code></td>
      <td>${esc(r.formats)}</td>
      <td>${esc(r.file_name)}</td>
      <td><button class="btn btn-sm btn-primary" onclick="window.location='/api/reports/download/${esc(r.file_name)}?token=${encodeURIComponent(TOKEN)}'">⬇ ${r.file_size ? (r.file_size / 1024).toFixed(0) + " KB" : ""}</button></td>
    </tr>`).join("") || `<tr><td colspan="5" class="hint">No bundles yet — generate one above.</td></tr>`;
}

/* ---------- compliance ---------- */
async function loadCompliance() {
  const c = await api("/api/admin/compliance");
  if (!c) return;
  const labels = { owasp: "🟢 OWASP Top 10 (2021)", nist: "🟠 NIST CSF 2.0 + SP 800-53", iso: "🔵 ISO/IEC 27001:2022 Annex A" };
  $("compliance-body").innerHTML = Object.entries(c.matrix).map(([fw, rows]) => `
    <div class="complaince-cat"><h3>${labels[fw] || fw}</h3>
    <table class="tbl"><thead><tr><th>ID</th><th>Area</th><th>Architecture Response</th></tr></thead><tbody>
    ${rows.map(([rid, area, map]) => `<tr><td><code>${rid}</code></td><td>${esc(area)}</td><td>${esc(map)}</td></tr>`).join("")}
    </tbody></table></div>`).join("");
}

/* ---------- security ---------- */
async function loadSecurity() {
  const t = await api("/api/admin/tls");
  $("tls-body").innerHTML = `<dl class="kv">
    <dt>Min version</dt><dd>${t.policy.min_version}</dd>
    <dt>Cipher</dt><dd>${t.policy.cipher}</dd>
    <dt>Profile</dt><dd>${t.policy.lab_mode ? "lab" : "production"}</dd>
    <dt>KEYLOG path</dt><dd>${esc(t.policy.keylog_path)}</dd>
    <dt>Server cert</dt><dd>${esc(t.cert)}</dd>
  </dl>`;
  const keys = await api("/api/admin/keys");
  $("keys-body").innerHTML = (keys || []).slice(0, 30).map((k) =>
    `<code>${esc(k.key_type)}</code> · ${esc(k.label)} · <span class="hint">${esc(k.status)}</span> · <code>${esc((k.key_value || "").slice(0, 16))}…</code><br>`).join("") || "none";
  const audit = await api("/api/admin/audit");
  $("audit-rows").innerHTML = (audit || []).slice(0, 200).map((a) => `
    <tr><td>${esc(a.ts)}</td><td><b>${esc(a.actor)}</b></td><td>${esc(a.action)}</td><td>${esc(a.zone)}</td><td class="hint">${esc(a.detail)}</td></tr>`).join("");
}

/* ---------- meta ---------- */
function tick() {
  $("clock").textContent = new Date().toLocaleTimeString();
}
setInterval(tick, 1000);
tick();
document.getElementById("banner-close").addEventListener("click", () => (document.getElementById("banner").style.display = "none"));
document.getElementById("filter-sessions")?.addEventListener("input", refreshSessions);

(async function init() {
  try {
    const h = await api("/api/admin/hello");
    if (h?.token) { TOKEN = h.token; sessionStorage.setItem("lab_token", h.token); }
  } catch (e) { /* token not ready */ }
  await loadTlsPolicy();
  loadDashboard();
  setInterval(() => { const v = document.querySelector(".nav-btn.active")?.dataset.view; if (v === "dashboard") loadDashboard(); }, 8000);
})();