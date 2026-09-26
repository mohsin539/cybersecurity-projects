/* NTM single-page client. Talks only to same-origin /api/* with the httpOnly
 * session cookie set server-side; no secrets stored in the browser (token
 * never leaves the cookie jar, localStorage never used for credentials).
 * Viewer role: server already redacts MAC addresses; UI just renders 403s.
 */
"use strict";

const $ = (sel, el = document) => el.querySelector(sel);
const $$ = (sel, el = document) => [...el.querySelectorAll(sel)];

const state = { view: "dashboard", poll: null };

async function api(path, opts = {}) {
  const res = await fetch(path, {
    method: opts.method || "GET",
    headers: { "content-type": "application/json", ...(opts.headers || {}) },
    credentials: "same-origin",
    body: opts.body ? JSON.stringify(opts.body) : undefined,
  });
  let data = null;
  try { data = await res.json(); } catch (_) { /* non-json */ }
  if (!res.ok) {
    const msg = (data && data.detail) || res.statusText;
    const err = new Error(msg); err.status = res.status; throw err;
  }
  return data;
}

function flash(el, text, kind = "err") {
  const t = $(el);
  if (!t) return;
  t.textContent = text || "";
  t.className = kind;
}

function show(screen) {
  $("#screen-login").classList.toggle("hidden", screen !== "login");
  $("#screen-app").classList.toggle("hidden", screen !== "app");
}
function showView(name) {
  state.view = name;
  $$(".view").forEach((v) => v.classList.toggle("hidden", v.id !== "view-" + name));
  $$(".nv").forEach((b) => b.classList.toggle("active", b.dataset.view === name));
}

/* ---------- login ---------- */
$("#form-login").addEventListener("submit", async (e) => {
  e.preventDefault();
  flash("#login-err", "");
  const fd = new FormData(e.target);
  try {
    const r = await api("/api/login", { method: "POST", body: {
      username: fd.get("username"), password: fd.get("password"),
      code: fd.get("code"),
    }});
    $("#who").textContent = r.username + " (" + r.role + ")";
    show("app"); showView("dashboard");
    me().catch(() => {});
  } catch (err) {
    flash("#login-err", "Login failed: " + err.message);
  }
});

async function me() {
  try {
    const r = await api("/api/me");
    $("#who").textContent = r.username + " (" + r.role + ")";
    show("app");
    return r;
  } catch (_) { return null; }
}

/* ---------- logout ---------- */
$("#btn-logout").addEventListener("click", async () => {
  try { await api("/api/logout", { method: "POST" }); } catch (_) {}
  show("login");
});

/* ---------- scan launch + job poll ---------- */
$("#form-scan").addEventListener("submit", async (e) => {
  e.preventDefault();
  flash("#scan-err", "");
  const fd = new FormData(e.target);
  try {
    const r = await api("/api/scan/sim", { method: "POST", body: {
      scope: fd.get("scope"), budget: Number(fd.get("budget")) || 6000,
    }});
    flash("#scan-info", "Job launched: " + r.job, "dim");
    await pollJob(r.job);
  } catch (err) {
    flash("#scan-err", "Scan failed: " + err.message);
  }
});

async function pollJob(jobId, times = 220) {
  clearInterval(state.poll);
  state.poll = setInterval(async () => {
    try {
      const r = await api("/api/jobs/" + jobId);
      const j = r.job;
      $("#job-status").textContent =
        `state=${j.state}  scanned=${j.counts ? j.counts.scanned : "?"}`;
      $("#job-bar").value = j.progress || 0;
      if (j.state === "done" || j.state === "error") {
        clearInterval(state.poll);
        $("#job-status").textContent += times > 0 ? "  (finished)" : "";
        loadDashboard();
        return;
      }
      if (--times <= 0) clearInterval(state.poll);
    } catch (_) {}
  }, 550);
}

/* ---------- viewers ---------- */
async function loadDashboard() {
  try {
    const t = await api("/api/topology");
    const n = t.nodes ? t.nodes.length : 0;
    const l = t.links ? t.links.length : 0;
    $("#topo-note").textContent = `${n} devices, ${l} links${t.redacted ? " (MACs redacted)" : ""}`;
  } catch (_) {}
}

async function loadTopology() {
  try {
    const t = await api("/api/topology");
    $("#topo-note").textContent =
      `${t.nodes.length} nodes, ${t.links.length} links` +
      (t.redacted ? " (viewer: MACs redacted)" : "");
    drawTopo(t);
  } catch (err) {
    flash("#topo-note", err.message);
  }
}

function drawTopo(t) {
  const box = $("#topo");
  const w = box.clientWidth || 900, h = box.clientHeight || 560;
  box.innerHTML = "";
  const svgns = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(svgns, "svg");
  svg.setAttribute("width", w); svg.setAttribute("height", h);
  const nodes = t.nodes || [], links = t.links || [];
  const pos = grid(nodes, w, h);
  for (const l of links) {
    const a = pos.get(l.source), b = pos.get(l.target);
    if (!a || !b) continue;
    const line = document.createElementNS(svgns, "line");
    line.setAttribute("x1", a.x); line.setAttribute("y1", a.y);
    line.setAttribute("x2", b.x); line.setAttribute("y2", b.y);
    line.setAttribute("stroke", "#667"); line.setAttribute("stroke-width", 1.5);
    line.setAttribute("stroke-opacity", l.confidence);
    svg.appendChild(line);
  }
  for (const n of nodes) {
    const p = pos.get(n.id) || pos.get(n.name) || { x: w/2, y: h/2 };
    const g = document.createElementNS(svgns, "g");
    const c = document.createElementNS(svgns, "circle");
    c.setAttribute("cx", p.x); c.setAttribute("cy", p.y); c.setAttribute("r", 9);
    c.setAttribute("fill", colorOf(n.kind)); c.setAttribute("stroke", "#111");
    const txt = document.createElementNS(svgns, "text");
    txt.setAttribute("x", p.x + 12); txt.setAttribute("y", p.y + 4);
    txt.textContent = n.name || n.ip;
    g.appendChild(c); g.appendChild(txt);
    g.appendChild(clickable(svg, () => showDevice(n)));
    svg.appendChild(g);
  }
  box.appendChild(svg);
}

function grid(nodes, w, h) {
  const map = new Map();
  const cols = Math.ceil(Math.sqrt(nodes.length)) || 1;
  nodes.forEach((n, i) => {
    const cx = (i % cols) * (w / cols) + w / (cols * 2);
    const cy = Math.floor(i / cols) * (h / cols) + h / (cols * 2);
    map.set(n.id, { x: cx, y: cy }); map.set(n.name, { x: cx, y: cy });
  });
  return map;
}
function clickable(svg, fn) {
  const r = document.createElementNS("http://www.w3.org/2000/svg", "rect");
  r.setAttribute("fill", "transparent"); r.setAttribute("width", "100%"); r.setAttribute("height", "100%");
  r.setAttribute("style", "pointer-events:all");
  return r;
}
function colorOf(kind) {
  return { switch: "#3d7", router: "#48f", server: "#fa3", printer: "#d6f",
           unknown: "#999" }[kind] || "#999";
}

async function loadInventory() {
  try {
    const r = await api("/api/inventory");
    $("#inv-note").textContent = r.redacted ? `${r.devices.length} devices (viewer: MACs redacted)` :
      `${r.devices.length} devices`;
    const tb = $("#inv-table tbody");
    tb.innerHTML = "";
    for (const d of r.devices) {
      const tr = document.createElement("tr");
      for (const k of ["ip", "name", "mac", "vendor", "kind", "last_seen"]) {
        const td = document.createElement("td");
        td.textContent = d[k] != null ? d[k] : "";
        tr.appendChild(td);
      }
      tb.appendChild(tr);
    }
  } catch (err) { flash("#inv-note", err.message); }
}

async function loadAudit() {
  try {
    const r = await api("/api/audit");
    const badge = $("#audit-ok");
    badge.textContent = r.chain_ok ? "chain OK" : "CHAIN BROKEN";
    badge.className = "badge " + (r.chain_ok ? "ok" : "bad");
    const tb = $("#audit-body");
    tb.innerHTML = "";
    for (const rec of (r.records || [])) {
      const tr = document.createElement("tr");
      for (const k of ["idx", "at", "actor", "action", "target", "result"]) {
        const td = document.createElement("td");
        const v = rec[k];
        td.textContent = typeof v === "object" && v ? JSON.stringify(v) : (v != null ? v : "");
        tr.appendChild(td);
      }
      tb.appendChild(tr);
    }
  } catch (err) { flash("#audit-body", err.message); }
}

/* ---------- nav wiring ---------- */
$$(".nv").forEach((b) => b.addEventListener("click", () => {
  showView(b.dataset.view);
  if (b.dataset.view === "topology") loadTopology();
  if (b.dataset.view === "inventory") loadInventory();
  if (b.dataset.view === "audit") loadAudit();
}));
$("#btn-refresh-topo").addEventListener("click", loadTopology);
$("#btn-refresh-inv").addEventListener("click", loadInventory);

/* ---------- init ---------- */
(async () => {
  const who = await me();
  if (who) { show("app"); showView("dashboard"); loadDashboard(); }
  else show("login");
})();

/* device drill-down kept minimal (functional stub hooked to /api/inventory) */
function showDevice(n) { loadInventory(); }
