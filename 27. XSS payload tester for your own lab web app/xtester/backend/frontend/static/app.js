"use strict";

const API = "/api";
let accessToken = null;
let currentUser = null;

function $(sel) { return document.querySelector(sel); }

async function api(path, opts = {}) {
  const headers = Object.assign(
    { "Content-Type": "application/json" },
    opts.headers || {}
  );
  if (accessToken) headers["Authorization"] = "Bearer " + accessToken;
  const res = await fetch(API + path, Object.assign({}, opts, { headers }));
  if (res.status === 401 && !path.startsWith("/auth/login")) {
    const refreshed = await tryRefresh();
    if (!refreshed) { showLogin(); throw new Error("session expired"); }
    return api(path, opts);
  }
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.detail || "request failed");
  return data;
}

async function tryRefresh() {
  try {
    const res = await fetch(API + "/auth/refresh", { method: "POST", credentials: "include" });
    if (!res.ok) return false;
    const data = await res.json();
    accessToken = data.access_token;
    return true;
  } catch (e) { return false; }
}

function showLogin() {
  accessToken = null;
  $("#loginView").hidden = false;
  $("#appView").hidden = true;
  $("#scanDetailView").hidden = true;
  $("#userbox").hidden = true;
}

function escapeHTML(s) {
  return String(s == null ? "" : s)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}

function severityBadge(sev) {
  return `<span class="badge ${escapeHTML(sev)}">${escapeHTML(sev)}</span>`;
}
function verdictBadge(v) {
  return `<span class="badge ${v === "EXECUTED" ? "executed" : "info"}">${escapeHTML(v)}</span>`;
}

async function enterApp(user) {
  currentUser = user;
  $("#username").textContent = user.username;
  $("#roleBadge").textContent = user.role;
  $("#userbox").hidden = false;
  $("#loginView").hidden = true;
  $("#appView").hidden = false;
  $("#scanDetailView").hidden = true;
  document.querySelectorAll(".admin-only").forEach((el) => {
    el.style.display = user.role === "admin" ? "" : "none";
  });
  await refreshSessionDashboard();
}

async function refreshSessionDashboard() {
  const [scans] = await Promise.all([api("/scans?limit=30")]);
  renderScans(scans);
  if (currentUser && currentUser.role === "admin") { renderAdminPanels(); }
}

function renderScans(scans) {
  const pane = $("#tab-scans");
  if (!scans.length) {
    pane.innerHTML = `<div class="card"><p class="muted">No scans yet. Open the "New scan" tab to test a lab endpoint.</p></div>`;
    return;
  }
  let rows = scans.map((s) => `
    <tr>
      <td><a href="#" data-scan="${escapeHTML(s.id)}">${escapeHTML(s.id.slice(0, 8))}</a></td>
      <td class="muted">${escapeHTML(s.url)}</td>
      <td>${severityBadge(s.max_severity)}</td>
      <td>${escapeHTML(s.executed_count)}</td>
      <td>${escapeHTML(s.status)}</td>
      <td>${escapeHTML(new Date(s.created_at).toLocaleString())}</td>
    </tr>`).join("");
  pane.innerHTML = `
    <table>
      <thead><tr><th>Id</th><th>Target</th><th>Severity</th><th>Executed</th><th>Status</th><th>Created</th></tr></thead>
      <tbody>${rows}</tbody>
    </table>`;
  pane.querySelectorAll("a[data-scan]").forEach((a) =>
    a.addEventListener("click", (e) => { e.preventDefault(); openScan(a.dataset.scan); })
  );
}

async function openScan(id) {
  const s = await api("/scans/" + id);
  $("#appView").hidden = true;
  $("#scanDetailView").hidden = false;
  let findings = "";
  (s.findings || []).forEach((f) => {
    findings += `
      <div class="finding">
        <div class="row">
          <strong>${escapeHTML(f.vector_name)}</strong>
          ${severityBadge(f.severity)}
          ${verdictBadge(f.verdict)}
          <span class="pill">${escapeHTML(f.context)}</span>
          <span class="pill">${escapeHTML(f.evasion)}</span>
          <span class="pill">CVSS ${escapeHTML(f.cvss_score)}</span>
        </div>
        <p class="muted">${escapeHTML(f.vector_category)} &middot; ${escapeHTML(f.poc || f.url)}</p>
        <pre>${escapeHTML(f.payload)}</pre>
        <p><strong>Evidence:</strong> ${escapeHTML(f.evidence || "n/a")}</p>
        <p><strong>Remediation:</strong> ${escapeHTML(f.remediation || "n/a")}</p>
      </div>`;
  });
  if (!findings) findings = `<div class="card"><p class="muted">No findings — the target reflected nothing exploitable under these candidates.</p></div>`;
  $("#scanDetail").innerHTML = `
    <div class="card" style="max-width:none">
      <h2>Scan ${escapeHTML(s.id.slice(0, 8))}</h2>
      <p class="muted">${escapeHTML(s.url)}</p>
      <div class="row">
        <span>status: <b>${escapeHTML(s.status)}</b></span>
        <span>payloads: <b>${escapeHTML(s.payload_count)}</b></span>
        <span>executed: <b>${escapeHTML(s.executed_count)}</b></span>
        ${s.error ? `<span style="color:var(--danger)">error: ${escapeHTML(s.error)}</span>` : ""}
      </div>
      ${s.findings.length ? `<p class="muted">${s.findings.length} finding(s) — strongest probe per vector kept.</p>` : ""}
    </div>
    ${findings}`;
}

async function renderAdminPanels() {
  const [targets, users, keys, audit] = await Promise.all([
    api("/admin/targets"), api("/admin/users"), api("/admin/api-keys"), api("/admin/audit?limit=100")
  ]);
  $("#tab-targets").innerHTML = `
    <form id="targetForm" class="card" style="max-width:none">
      <div class="row">
        <input id="tLabel" placeholder="Label" style="max-width:200px" required>
        <input id="tUrl" placeholder="http://localhost:5001" style="flex:1" required>
        <button class="primary" type="submit">Register target</button>
      </div>
      <p class="muted">Registered agains the host allowlist; only admin-approved hosts become first-class targets.</p>
      <p class="err" id="targetErr"></p>
    </form>
    <table>
      <thead><tr><th>Label</th><th>Base URL</th><th>Host</th><th>Approved by</th><th></th></tr></thead>
      <tbody>${targets.map((t) => `
        <tr>
          <td>${escapeHTML(t.label)}</td><td>${escapeHTML(t.base_url)}</td>
          <td>${escapeHTML(t.host)}</td><td>${escapeHTML(t.approved_by || "")}</td>
          <td><button class="del-target" data-id="${t.id}">delete</button></td>
        </tr>`).join("")}</tbody>
    </table>`;
  $("#tab-users").innerHTML = `
    <form id="userForm" class="card">
      <input id="uName" placeholder="username" required>
      <input id="uPass" placeholder="password (min 12 chars)" type="password" minlength="12" required>
      <select id="uRole"><option value="viewer">viewer</option><option value="engineer">engineer</option><option value="admin">admin</option></select>
      <button class="primary" type="submit">Create user</button>
      <p class="err" id="userErr"></p>
    </form>
    <div class="row">
      <select id="kRole"><option value="engineer">engineer</option><option value="admin">admin</option><option value="viewer">viewer</option></select>
      <input id="kDays" type="number" value="30" min="1" max="365" style="max-width:90px">
      <button id="kCreate" class="primary" type="button">Issue API key</button>
      <span id="kOut" class="muted"></span>
    </div>
    <table>
      <thead><tr><th>ID</th><th>Owner</th><th>Prefix</th><th>Role</th><th>Expires</th><th>Last used</th><th></th></tr></thead>
      <tbody>${keys.map((k) => `
        <tr>
          <td>${k.id}</td><td>${escapeHTML(k.username || "?")}</td>
          <td>${escapeHTML(k.prefix)}</td><td>${escapeHTML(k.role_binding)}</td>
          <td>${escapeHTML(k.expires_at ? new Date(k.expires_at).toLocaleString() : "-")}</td>
          <td>${escapeHTML(k.last_used_at ? new Date(k.last_used_at).toLocaleString() : "never")}</td>
          <td>${k.enabled ? `<button class="revoke-key" data-id="${k.id}">revoke</button>` : "revoked"}</td>
        </tr>`).join("")}</tbody>
    </table>`;
  $("#tab-audit").innerHTML = `
    <table>
      <thead><tr><th>When</th><th>Actor</th><th>Action</th><th>Outcome</th><th>Resource</th><th>IP</th></tr></thead>
      <tbody>${audit.map((a) => `
        <tr>
          <td>${escapeHTML(new Date(a.ts).toLocaleString())}</td>
          <td>${escapeHTML(a.actor || "-")}</td><td>${escapeHTML(a.action)}</td>
          <td>${escapeHTML(a.outcome)}</td><td>${escapeHTML(a.resource || "-")}</td>
          <td>${escapeHTML(a.ip || "-")}</td>
        </tr>`).join("")}</tbody>
    </table>`;
  $("#targetForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    try {
      await api("/admin/targets", {
        method: "POST",
        body: JSON.stringify({ label: $("#tLabel").value, base_url: $("#tUrl").value })
      });
      await renderAdminPanels();
    } catch (err) { $("#targetErr").textContent = err.message; }
  });
  $("#userForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    try {
      await api("/admin/users", {
        method: "POST",
        body: JSON.stringify({ username: $("#uName").value, password: $("#uPass").value, role: $("#uRole").value })
      });
      $("#uName").value = ""; $("#uPass").value = ""; $("#userErr").textContent = "user created";
      await renderAdminPanels();
    } catch (err) { $("#userErr").textContent = err.message; }
  });
  $("#kCreate").addEventListener("click", async () => {
    try {
      const data = await api("/admin/api-keys", {
        method: "POST",
        body: JSON.stringify({ role_binding: $("#kRole").value, expires_days: parseInt($("#kDays").value, 10) })
      });
      $("#kOut").textContent = "Key (copy now): " + data.api_key;
      await renderAdminPanels();
    } catch (err) { $("#kOut").textContent = err.message; }
  });
  document.querySelectorAll(".del-target").forEach((b) =>
    b.addEventListener("click", async () => { await api("/admin/targets/" + b.dataset.id, { method: "DELETE" }); await renderAdminPanels(); })
  );
  document.querySelectorAll(".revoke-key").forEach((b) =>
    b.addEventListener("click", async () => { await api("/admin/api-keys/" + b.dataset.id, { method: "DELETE" }); await renderAdminPanels(); })
  );
}

function bindStaticEvents() {
  $("#loginForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    $("#loginErr").textContent = "";
    try {
      const res = await fetch(API + "/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({ username: $("#loginUser").value, password: $("#loginPass").value })
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || "login failed");
      accessToken = data.access_token;
      await enterApp(data.user);
    } catch (err) { $("#loginErr").textContent = err.message; }
  });
  $("#logoutBtn").addEventListener("click", async () => {
    try { await fetch(API + "/auth/logout", { method: "POST", credentials: "include" }); } catch (e) {}
    showLogin();
  });
  $("#scanForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    $("#scanErr").textContent = "";
    try {
      const s = await api("/scans", {
        method: "POST",
        body: JSON.stringify({ url: $("#scanUrl").value, context: $("#scanContext").value })
      });
      $("#scanErr").style.color = "var(--ok)";
      $("#scanErr").textContent = "queued: " + s.id;
      await refreshSessionDashboard();
    } catch (err) { $("#scanErr").textContent = err.message; }
  });
  $("#backBtn").addEventListener("click", () => {
    $("#scanDetailView").hidden = true;
    $("#appView").hidden = false;
    refreshSessionDashboard();
  });
  document.querySelectorAll(".tab").forEach((b) =>
    b.addEventListener("click", () => {
      document.querySelectorAll(".tab").forEach((x) => x.classList.remove("active"));
      b.classList.add("active");
      document.querySelectorAll(".tabpane").forEach((p) => (p.hidden = true));
      $("#tab-" + b.dataset.tab).hidden = false;
    })
  );
}

(async function init() {
  bindStaticEvents();
  showLogin();
  if (await tryRefresh()) {
    try { await enterApp((await api("/auth/me")).user); } catch (e) { showLogin(); }
  }
})();