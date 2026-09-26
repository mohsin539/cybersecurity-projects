"use strict";

const $ = (s) => document.querySelector(s);
const $$ = (s) => Array.from(document.querySelectorAll(s));
const STATE_CLR = { BOOTING: "#6e7681", HEALTHY: "#3fb950", DEGRADED: "#d29922",
  DRAINING: "#58a6ff", UNHEALTHY: "#f85149", QUARANTINED: "#bc8cff", REMOVED: "#333333" };

let lastCursor = 0;
let snap = null;
const chartCache = {};

function toast(msg, kind) {
  const t = $("#toast");
  t.textContent = msg;
  t.className = "toast " + (kind || "");
  setTimeout(() => t.classList.add("hidden"), 2600);
}

function key() { return $("#inKey").value.trim(); }

async function api(method, path, body) {
  const opts = { method, headers: {} };
  if (body !== undefined) { opts.headers["Content-Type"] = "application/json"; opts.body = JSON.stringify(body); }
  const k = key();
  if (k) opts.headers["X-Aegis-Key"] = k;
  try {
    const r = await fetch(path, opts);
    const j = await r.json().catch(() => ({}));
    if (!r.ok) { toast((j.error || j.detail) + " (" + r.status + ")", "err"); return null; }
    return j;
  } catch (e) { toast("network error: " + e.message, "err"); return null; }
}

function setRunBadge(s) {
  const el = $("#runStatus");
  el.className = "badge st-" + (s.running ? (s.paused ? "BOOTING" : "HEALTHY") : "off");
  el.textContent = s.paused ? "paused" : (s.running ? "running" : "stopped");
}

function render(s) {
  snap = s;
  setRunBadge(s.run);
  $("#runId").textContent = "run:" + s.run.id;
  $("#simTime").textContent = "t=" + s.run.sim_time + "s  policy=" + s.run.policy +
    "  sources=" + s.run.sources;
  $("#inRps").value = s.run.rps;
  $("#inSpeed").value = s.run.speed;
  $("#inPolicy").value = s.run.policy;
  $("#inModel").value = s.run.arrival_model;

  const m = s.metrics;
  $("#mRps").textContent = m.rps_now;
  $("#mSessions").textContent = m.sessions_total;
  $("#mErrors").textContent = m.errors_total;
  $("#mRejects").textContent = m.rejects_total;
  $("#mProbesOk").textContent = m.probes_ok;
  $("#mProbesFail").textContent = m.probes_fail;
  $("#mDecisions").textContent = m.decisions_total;
  $("#mEligible").textContent = s.backends.filter((b) =>
    (b.state === "HEALTHY" || b.state === "DEGRADED") && b.breaker !== "OPEN").length;

  const alerts = $("#alertList");
  if (alerts.dataset.n !== s.alerts.length + ":" + (s.alerts[0] || {}).id) {
    alerts.dataset.n = s.alerts.length + ":" + (s.alerts[0] || {}).id;
    alerts.innerHTML = s.alerts.length ? s.alerts.map((a) =>
      `<span class="alert-chip ${a.sev}">${a.t}s · ${a.type} — ${a.text}</span>`).join("") :
      '<span class="alert-chip">no alerts</span>';
  }

  renderCards(s.backends);
}

function renderCards(backends) {
  const host = $("#backendCards");
  const wanted = new Set(backends.map((b) => b.id));
  $$(".card", host).forEach((el) => {
    if (!wanted.has(el.dataset.id)) el.remove();
  });
  for (const b of backends) {
    let el = host.querySelector('.card[data-id="' + b.id + '"]');
    if (!el) { el = buildCard(b); host.appendChild(el); }
    updateCard(el, b);
  }
}

function buildCard(b) {
  const el = document.createElement("div");
  el.className = "card";
  el.dataset.id = b.id;
  el.innerHTML = `
    <div class="card-head">
      <span class="name"></span>
      <span class="badge"></span>
      <span class="gave mono small"></span>
    </div>
    <div class="csub mono"></div>
    <canvas class="spark"></canvas>
    <div class="stats">
      <div class="statrow"><span>active conns</span><b></b></div>
      <div class="statrow"><span>weight (eff)</span><b></b></div>
      <div class="statrow"><span>capacity (eff)</span><b></b></div>
      <div class="statrow"><span>ewma latency</span><b></b></div>
      <div class="statrow"><span>error rate</span><b></b></div>
      <div class="statrow"><span>sessions / errors</span><b></b></div>
      <div class="statrow"><span>probes ok/fail</span><b></b></div>
      <div class="statrow"><span>breaker</span><b></b></div>
    </div>
    <div class="card-actions">
      <button class="btn btnq" data-act="drain">Drain</button>
      <button class="btn btnq" data-act="cancel">CancelDrain</button>
      <button class="btn btnq" data-act="rearm">Rearm</button>
      <button class="btn btnq" data-act="remove">Remove</button>
      <select data-act="failure">
        <option value="NONE">no failure</option>
        <option value="CRASH">crash</option>
        <option value="LAG">lag</option>
        <option value="SLOW_CPU">slow cpu</option>
        <option value="PROBE_NO_TOKEN">probe no-token</option>
        <option value="FLAP">flap</option>
      </select>
    </div>`;
  el.addEventListener("click", (ev) => {
    const t = ev.target;
    if (!t.dataset.act) return;
    const id = el.dataset.id;
    const acts = {
      drain: ["POST", "/api/v1/backends/" + id + "/drain", "ops"],
      cancel: ["POST", "/api/v1/backends/" + id + "/cancel-drain", "ops"],
      rearm: ["POST", "/api/v1/backends/" + id + "/rearm", "ops"],
      remove: ["DELETE", "/api/v1/backends/" + id, "ops"],
    };
    const a = acts[t.dataset.act];
    if (a) { api(a[0], a[1]).then((r) => { if (r) toast(t.dataset.act + " ok", "ok"); }); }
  });
  el.querySelector('select[data-act="failure"]').addEventListener("change", (ev) => {
    const id = el.dataset.id;
    const profile = ev.target.value;
    const untilBox = profile === "NONE" ? null : 30;
    api("POST", "/api/v1/backends/" + id + "/failures", { profile, until: untilBox })
      .then((r) => { if (r) toast("failure -> " + profile, "ok"); });
  });
  return el;
}

function updateCard(el, b) {
  el.className = "card st-" + b.state;
  el.querySelector(".name").textContent = b.name;
  const badge = el.querySelector(".badge");
  badge.className = "badge st-" + b.state;
  badge.textContent = b.state;
  const fuse = el.querySelector(".gave");
  fuse.innerHTML = '<span class="bk-' + b.breaker + '">cb:' + b.breaker + "</span>";
  el.querySelector(".csub").textContent =
    b.id + " · " + b.latency_model + " base=" + b.latency_base_ms + "ms · " +
    (b.failure_profile === "NONE" ? "no failure" : "failure=" + b.failure_profile) +
    (b.quarantine_count ? " · q=" + b.quarantine_count : "");
  const fsel = el.querySelector('select[data-act="failure"]');
  if (fsel.value !== b.failure_profile) fsel.value = b.failure_profile;

  const rows = el.querySelectorAll(".statrow b");
  rows[0].textContent = b.active_conns;
  rows[1].textContent = b.weight + " (" + b.effective_weight + ")";
  rows[2].textContent = b.capacity + " (" + b.effective_capacity + ")";
  rows[3].textContent = b.ewma_ms + " ms";
  rows[4].textContent = (b.errors_rate * 100).toFixed(1) + "%";
  rows[5].textContent = b.total_sessions + " / " + b.total_errors;
  rows[6].textContent = b.probes_ok + " / " + b.probes_fail + " (sent " + b.probes_sent + ")";
  rows[7].textContent = b.breaker + (b.consecutive_fail ? " cf=" + b.consecutive_fail : "");

  const canvas = el.querySelector(".spark");
  const ck = chartCache[b.id];
  const cur = b.history.length;
  if (!ck || ck.len !== cur) {
    chartCache[b.id] = { len: cur };
    drawSpark(canvas, b.history);
  }
}

function drawSpark(canvas, points) {
  const w = canvas.clientWidth || 300, h = 52;
  const dpr = window.devicePixelRatio || 1;
  canvas.width = w * dpr; canvas.height = h * dpr;
  const ctx = canvas.getContext("2d");
  ctx.scale(dpr, dpr); ctx.clearRect(0, 0, w, h);
  if (!points.length) return;
  const vals = points.map((p) => p[0]);
  const min = Math.min(...vals), max = Math.max(...vals);
  const span = max - min || 1;
  const px = (i) => (points.length === 1 ? 0 : (i / (points.length - 1)) * (w - 2)) + 1;
  const py = (v) => h - 4 - ((v - min) / span) * (h - 8);
  ctx.beginPath();
  points.forEach((p, i) => { const x = px(i), y = py(p[0]); i ? ctx.lineTo(x, y) : ctx.moveTo(x, y); });
  ctx.strokeStyle = STATE_CLR[points[points.length - 1][1]] || "#58a6ff";
  ctx.lineWidth = 1.8; ctx.stroke();
  ctx.lineTo(px(points.length - 1), h); ctx.lineTo(px(0), h); ctx.closePath();
  ctx.fillStyle = "rgba(88,166,255,.12)"; ctx.fill();
}

function appendLog(e) {
  const host = $("#eventLog");
  const p = e.payload || {};
  const detail = p.backend ? "backend=" + p.backend + " " : "";
  const line = document.createElement("div");
  line.className = "line";
  line.innerHTML = `<span class="lt">${e.t}s</span>` +
    `<span class="sev-${e.sev}">[${e.type}]</span>` +
    `<span class="lp">${detail}${p.detail || p.reason || p.profile || p.action || p.policy || ""}` +
    `${p.to ? " -> " + p.to : ""}${p.latency_ms ? " lat=" + p.latency_ms + "ms" : ""}</span>`;
  host.appendChild(line);
  while (host.children.length > 300) host.removeChild(host.firstChild);
  host.scrollTop = host.scrollHeight;
}

function connectEvents() {
  const src = new EventSource("/api/v1/events/stream?cursor=" + lastCursor);
  src.onmessage = (ev) => {
    try {
      const e = JSON.parse(ev.data);
      lastCursor = e.id;
      appendLog(e);
    } catch (_) {}
  };
  src.onerror = () => {
    src.close();
    setTimeout(connectEvents, 2000);
  };
}

async function refresh() {
  const s = await api("GET", "/api/v1/snapshot");
  if (s) render(s);
}

async function loadSecurity() {
  const s = await api("GET", "/api/v1/security/status");
  if (s) {
    $("#secStatus").textContent = JSON.stringify({
      hardened: s.hardened, roles: s.roles,
      tokens: s.tokens, rate_limit_per_min: s.rate_limit_per_min,
      audit_entries: s.audit_entries, chain_tail: s.chain_tail,
    }, null, 1);
  }
}

async function loadNotes() {
  const s = await api("GET", "/api/v1/memory/notes");
  if (s && s.notes) $("#notesBox").value = s.notes;
}

function wireControls() {
  $("#btnStart").addEventListener("click", async () => {
    const body = {
      seed: parseInt($("#inSeed").value, 10) || 1,
      rps: parseFloat($("#inRps").value) || 0,
      speed: parseFloat($("#inSpeed").value) || 1,
      policy: $("#inPolicy").value,
      arrival_model: $("#inModel").value,
    };
    const r = await api("POST", "/api/v1/runs/start", body);
    if (r) toast("run started", "ok");
  });
  $("#btnApply").addEventListener("click", async () => {
    const body = {
      rps: parseFloat($("#inRps").value) || 0,
      speed: parseFloat($("#inSpeed").value) || 1,
      policy: $("#inPolicy").value,
      arrival_model: $("#inModel").value,
    };
    const r = await api("PATCH", "/api/v1/run", body);
    if (r) toast("applied: " + JSON.stringify(r.changed), "ok");
  });
  $("#btnPause").addEventListener("click", async () => {
    const pause = $("#btnPause").textContent !== "Resume";
    const r = await api("POST", "/api/v1/runs/pause", { paused: pause });
    if (r) { $("#btnPause").textContent = pause ? "Resume" : "Pause"; }
  });
  $("#btnStop").addEventListener("click", async () => {
    const r = await api("POST", "/api/v1/runs/stop");
    if (r) toast("run stopped", "ok");
  });
  $("#btnAdd").addEventListener("click", async () => {
    const body = {
      name: ($("#inName").value || "web-n").trim(),
      weight: parseInt($("#inWeight").value, 10) || 100,
      capacity: parseInt($("#inCap").value, 10) || 800,
      latency_base_ms: parseInt($("#inLat").value, 10) || 45,
      latency_model: $("#inLatModel").value,
    };
    const r = await api("POST", "/api/v1/backends", body);
    if (r) toast("backend added " + r.id, "ok");
  });
  $("#btnNotes").addEventListener("click", async () => {
    const r = await api("POST", "/api/v1/memory/notes", { text: $("#notesBox").value });
    if (r) toast("notes persisted to memory.md", "ok");
  });
  $("#inKey").addEventListener("change", () => {
    try { localStorage.setItem("aegis_key", $("#inKey").value); } catch (_) {}
  });
  try { const k = localStorage.getItem("aegis_key"); if (k) $("#inKey").value = k; } catch (_) {}
}

wireControls();
loadSecurity();
loadNotes();
refresh().then(() => connectEvents());
setInterval(refresh, 650);