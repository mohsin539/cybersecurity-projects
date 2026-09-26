/**
 * server.js — Network Traffic Monitor (on-device, per-app bandwidth)
 *
 * Zero-dependency Node HTTP server:
 *   - Scheduler spawns `collector.ps1` every INT_MS and parses JSON snapshots
 *   - Aggregates into a per-app rollup and a ring-buffer of history
 *   - Serves the web dashboard from /public and a small REST API
 *
 * Run:  node server/server.js   →   http://127.0.0.1:8070
 */
'use strict';

const http = require('http');
const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');

const ROOT = path.join(__dirname, '..');
const PUBLIC = path.join(ROOT, 'public');
const COLLECTOR = path.join(__dirname, 'collector.ps1');

const HOST = '127.0.0.1';
const PORT = 8070;
const INT_MS = 2000;          // sample interval
const HISTORY = 300;          // ring buffer size (~10 min)
const ADAPTERS_CAP = 6;

// ---------------------------------------------------------------- state
const state = {
  mode: 'live',           // 'live' | 'sim'
  startedAt: Date.now(),
  lastSampleAt: 0,
  lastError: null,
  failedTicks: 0,
  last: { ts: 0, totalRx: 0, totalTx: 0, adapters: [], apps: [] },
  history: { labels: [], rx: [], tx: [] },
  appTotals: new Map(),   // name -> {pid, cat, color, rxSum, txSum, peak, count}
};

// ----------------------------------------------------------- simulation
const SIM_APPS = [
  { name: 'chrome.exe',     cat: 'browser',   color: '#4fc3f7', rx: 0.9, tx: 0.4, conns: 34 },
  { name: 'Spotify.exe',    cat: 'streaming', color: '#7c4dff', rx: 6.2, tx: 0.2, conns: 3 },
  { name: 'steam.exe',      cat: 'gaming',    color: '#fb7185', rx: 3.8, tx: 1.5, conns: 8 },
  { name: 'svchost.exe',    cat: 'system',    color: '#fbbf24', rx: 0.4, tx: 0.3, conns: 22 },
  { name: 'Discord.exe',    cat: 'messaging', color: '#34d399', rx: 1.1, tx: 0.6, conns: 5 },
  { name: 'Teams.exe',      cat: 'messaging', color: '#22d3ee', rx: 0.8, tx: 0.7, conns: 4 },
  { name: 'vlc.exe',        cat: 'streaming', color: '#a78bfa', rx: 2.4, tx: 0.1, conns: 2 },
  { name: 'msedge.exe',     cat: 'browser',   color: '#60a5fa', rx: 1.6, tx: 0.9, conns: 18 },
];

function simSample(t) {
  const noise = (factor) => 0.65 + 0.65 * Math.sin(t / 4700 * factor) + Math.random() * 0.5;
  const apps = SIM_APPS.map((a, i) => {
    const rx = a.rx * noise(i + 1) * 1024;
    const tx = a.tx * noise(i + 3) * 1024;
    return {
      pid: 1000 + i, name: a.name, category: a.cat, color: a.color,
      rx: Math.round(rx), tx: Math.round(tx),
      conns: Math.round(a.conns * (0.9 + Math.random() * 0.2)),
    };
  });
  const totalRx = apps.reduce((s, a) => s + a.rx, 0);
  const totalTx = apps.reduce((s, a) => s + a.tx, 0);
  return {
    ts: t, totalRx, totalTx,
    adapters: [{ name: 'Ethernet', rxBps: Math.round(totalRx), txBps: Math.round(totalTx) }],
    apps,
  };
}

// ---------------------------------------------------------- ring buffer
function pushHistory(sample) {
  const { history } = state;
  const time = new Date(sample.ts * 1000).toTimeString().slice(0, 8);
  history.labels.push(time);
  history.rx.push(sample.totalRx);
  history.tx.push(sample.totalTx);
  const overflow = history.labels.length - HISTORY;
  if (overflow > 0) {
    history.labels.splice(0, overflow);
    history.rx.splice(0, overflow);
    history.tx.splice(0, overflow);
  }
}

function rollAppTotals(apps) {
  for (const a of apps) {
    let t = state.appTotals.get(a.name);
    if (!t) {
      t = { pid: a.pid, cat: a.category, color: a.color, rxSum: 0, txSum: 0, peak: 0, count: 0 };
      state.appTotals.set(a.name, t);
    }
    t.rxSum += a.rx;
    t.txSum += a.tx;
    const total = a.rx + a.tx;
    if (total > t.peak) t.peak = total;
    t.count += 1;
  }
}

function ingest(sample) {
  state.last = sample;
  state.lastSampleAt = Date.now();
  pushHistory(sample);
  rollAppTotals(sample.apps);
}

// ------------------------------------------------------------ collector
function runCollector(cb) {
  const ps = spawn('powershell.exe', [
    '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
    '-File', COLLECTOR,
  ], { windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });

  let out = '';
  let err = '';
  ps.stdout.on('data', (d) => { out += d.toString(); });
  ps.stderr.on('data', (d) => { err += d.toString(); });
  ps.on('error', (e) => cb(e));
  ps.on('close', (code) => {
    if (code !== 0) return cb(new Error(`collector exit ${code}: ${err.slice(0, 300)}`));
    const line = out.split('\n').map((s) => s.trim()).filter(Boolean).join('');
    if (!line) return cb(new Error('collector produced no output'));
    try { cb(null, JSON.parse(line)); } catch (e) { cb(new Error(`bad JSON: ${e.message}`)); }
  });
}

function tick() {
  const now = Math.floor(Date.now() / 1000);
  runCollector((err, sample) => {
    if (err) {
      state.failedTicks += 1;
      state.lastError = err.message;
      if (state.failedTicks >= 2 && state.mode === 'live') {
        state.mode = 'sim';
        console.log(`[sim] live collection unavailable (${err.message})`);
      }
      if (state.mode === 'sim') ingest(simSample(now));
      return;
    }
    state.failedTicks = 0;
    state.lastError = null;
    if (state.mode !== 'live') state.mode = 'live';
    ingest(validate(sample));
  });
}

// ------------------------------------------------------------- validation
const clamp = (n, lo, hi) => Math.min(hi, Math.max(lo, Number(n) || 0));

function validate(s) {
  const now = Math.floor(Date.now() / 1000);
  const apps = (Array.isArray(s.apps) ? s.apps : [])
    .filter((a) => a && typeof a === 'object' && a.name)
    .slice(0, 25)
    .map((a) => ({
      pid: clamp(a.pid, 0, 1e9),
      name: String(a.name).slice(0, 64),
      category: String(a.category || 'other').slice(0, 20),
      color: /^#[0-9a-f]{6}$/i.test(String(a.color)) ? a.color : '#8b96b8',
      rx: clamp(a.rx, 0, 1e15),
      tx: clamp(a.tx, 0, 1e15),
      conns: clamp(a.conns, 0, 1e6),
    }))
    .sort((x, y) => (y.rx + y.tx) - (x.rx + x.tx));
  const totalRx = clamp(s.totalRx, 0, 1e15);
  const totalTx = clamp(s.totalTx, 0, 1e15);
  const adapters = (Array.isArray(s.adapters) ? s.adapters : []).slice(0, ADAPTERS_CAP).map((a) => ({
    name: String(a.name || 'Unknown').slice(0, 64),
    rxBps: clamp(a.rxBps, 0, 1e15),
    txBps: clamp(a.txBps, 0, 1e15),
  }));
  return { ts: clamp(s.ts, 0, now), totalRx, totalTx, adapters, apps };
}

// ------------------------------------------------------------------ API
function json(res, code, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(code, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
  });
  res.end(body);
}

function apiStats() {
  const now = Math.floor(Date.now() / 1000);
  return {
    ts: now,
    mode: state.mode,
    totalRx: state.last.totalRx,
    totalTx: state.last.totalTx,
    adapters: state.last.adapters,
    apps: state.last.apps,
    lastError: state.lastError,
  };
}

function apiApps() {
  const out = [];
  for (const [name, t] of state.appTotals) {
    out.push({
      name,
      pid: t.pid,
      category: t.cat,
      color: t.color,
      rxSum: Math.round(t.rxSum),
      txSum: Math.round(t.txSum),
      peak: Math.round(t.peak),
      count: t.count,
    });
  }
  out.sort((a, b) => (b.rxSum + b.txSum) - (a.rxSum + a.txSum));
  return { apps: out.slice(0, 25) };
}

// ------------------------------------------------------------- static
const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
  '.png': 'image/png',
  '.json': 'application/json; charset=utf-8',
};

function serveStatic(res, urlPath) {
  let p = decodeURIComponent(urlPath.split('?')[0]);
  if (p === '/' || p === '') p = '/index.html';
  const file = path.normalize(path.join(PUBLIC, p));
  if (!file.startsWith(PUBLIC)) return json(res, 403, { ok: false, error: 'forbidden' });
  fs.readFile(file, (err, data) => {
    if (err) return json(res, 404, { ok: false, error: 'not found' });
    res.writeHead(200, {
      'Content-Type': MIME[path.extname(file).toLowerCase()] || 'application/octet-stream',
      'Cache-Control': 'no-cache',
    });
    res.end(data);
  });
}

const server = http.createServer((req, res) => {
  const { pathname } = new URL(req.url, 'http://localhost');
  Object.defineProperty(req, 'pathname', { value: pathname });

  if (req.method === 'GET' && pathname === '/api/health') {
    return json(res, 200, {
      ok: true, mode: state.mode, uptime: Math.floor((Date.now() - state.startedAt) / 1000),
      samples: state.history.labels.length, lastSampleAt: state.lastSampleAt,
      failedTicks: state.failedTicks, lastError: state.lastError,
    });
  }
  if (req.method === 'GET' && pathname === '/api/stats') return json(res, 200, apiStats());
  if (req.method === 'GET' && pathname === '/api/history') return json(res, 200, state.history);
  if (req.method === 'GET' && pathname === '/api/apps') return json(res, 200, apiApps());
  if (pathname.startsWith('/api/')) return json(res, 404, { ok: false, error: 'unknown api' });
  if (req.method !== 'GET') return json(res, 405, { ok: false, error: 'method not allowed' });
  return serveStatic(res, pathname);
});

server.listen(PORT, HOST, () => {
  console.log(`📡 Network Traffic Monitor → http://${HOST}:${PORT}`);
  console.log(`   mode: ${state.mode} · interval ${INT_MS}ms · history ${HISTORY}`);
  if (state.mode === 'live') {
    runCollector((err, sample) => {
      if (!err) ingest(validate(sample));
      tick();
    });
  } else {
    tick();
  }
});

// warm-up so the very first /api/health has data
setInterval(tick, INT_MS);
process.on('SIGINT', () => { console.log('\nbye'); process.exit(0); });