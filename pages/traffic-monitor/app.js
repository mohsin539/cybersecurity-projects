/* app.js — Network Traffic Monitor dashboard */
'use strict';

const $ = (id) => document.getElementById(id);

const fmtBps = (n) => {
  const v = Number(n) || 0;
  if (v >= 1e9) return (v / 1e9).toFixed(2) + ' GB/s';
  if (v >= 1e6) return (v / 1e6).toFixed(2) + ' MB/s';
  if (v >= 1e3) return (v / 1e3).toFixed(1) + ' KB/s';
  return v + ' B/s';
};

let lastStats = { apps: [], totalRx: 0, totalTx: 0 };
let selectedApp = null;
const POLL = 2000;

/* ---------------- charts ---------------- */

function initCanvas(id) {
  const c = $(id);
  const ratio = Math.min(window.devicePixelRatio || 1, 2);
  c.width = c.clientWidth * ratio;
  c.height = c.clientHeight * ratio;
  const ctx = c.getContext('2d');
  ctx.setTransform(ratio, 0, 0, ratio, 0, 0);
  return { ctx, c };
}

function drawArea(chart, series, defaultColor) {
  const { ctx, c } = chart;
  const W = c.clientWidth, H = c.clientHeight;
  const pad = { l: 8, r: 8, t: 12, b: 6 };
  ctx.clearRect(0, 0, W, H);

  const max = Math.max(100, ...series.rx, ...series.tx) * 1.15;
  const n = series.labels.length;
  const iw = W - pad.l - pad.r, ih = H - pad.t - pad.b;
  const x = (i) => pad.l + (n <= 1 ? iw / 2 : (i / (n - 1)) * iw);
  const y = (v) => pad.t + ih - (Math.min(v, max) / max) * ih;

  // grid
  ctx.strokeStyle = 'rgba(255,255,255,.06)';
  ctx.lineWidth = 1;
  for (let g = 0; g <= 3; g++) {
    const gy = pad.t + (ih / 3) * g;
    ctx.beginPath(); ctx.moveTo(pad.l, gy); ctx.lineTo(W - pad.r, gy); ctx.stroke();
  }

  const drawSeries = (arr, color) => {
    if (n < 2) return;
    ctx.beginPath();
    arr.forEach((v, i) => (i === 0 ? ctx.moveTo(x(i), y(v)) : ctx.lineTo(x(i), y(v))));
    ctx.strokeStyle = color;
    ctx.lineWidth = 2;
    ctx.lineJoin = 'round';
    ctx.stroke();
    ctx.lineTo(x(n - 1), H - pad.b);
    ctx.lineTo(x(0), H - pad.b);
    ctx.closePath();
    const g = ctx.createLinearGradient(0, pad.t, 0, H - pad.b);
    g.addColorStop(0, color + '55');
    g.addColorStop(1, color + '00');
    ctx.fillStyle = g;
    ctx.fill();
  };

  drawSeries(series.rx, defaultColor === undefined ? '#22d3ee' : defaultColor);
  if (series.tx && series.tx.length) drawSeries(series.tx, '#a78bfa');

  // labels
  if (n) {
    ctx.fillStyle = '#8b96b8';
    ctx.font = '10px Segoe UI';
    ctx.textAlign = 'left';
    ctx.fillText(series.labels[n - 1], pad.l + 4, H - 3);
  }
}

/* ---------------- render ---------------- */

function renderKpis(data) {
  $('kTotalRx').textContent = fmtBps(data.totalRx);
  $('kTotalTx').textContent = fmtBps(data.totalTx);
  $('kTotal').textContent = fmtBps(data.totalRx + data.totalTx);
  $('kApps').textContent = data.apps.length + ' apps';
  const peak = data.apps.reduce((m, a) => Math.max(m, a.rx + a.tx), 0);
  $('kPeak').textContent = fmtBps(peak);
  $('modeBadge').className = 'badge ' + (data.mode === 'sim' ? 'sim' : 'live');
  $('modeBadge').textContent = '● ' + data.mode;

  const spark = (id, rx, tx) => {
    const el = $(id);
    const tot = rx + tx || 1;
    el.innerHTML = '<i></i>';
    el.firstChild.style.width = Math.min(100, (rx / tot) * 100) + '%';
  };
  spark('sparkRx', data.totalRx, data.totalTx);
  spark('sparkTx', data.totalTx, data.totalRx);
}

function renderTopApps(apps) {
  const el = $('topApps');
  const top = [...apps].sort((a, b) => (b.rx + b.tx) - (a.rx + a.tx)).slice(0, 6);
  const max = Math.max(1, ...top.map((a) => a.rx + a.tx));
  if (!top.length) { el.innerHTML = '<div class="empty">no activity yet…</div>'; return; }
  el.innerHTML = top.map((a) => `
    <div class="row">
      <div class="lbl"><b><span class="chip" style="background:${a.color}"></span>${a.name}</b>
      <span class="stotal">${fmtBps(a.rx + a.tx)}</span></div>
      <div class="bar"><i style="background:${a.color}" data-w="${Math.round((a.rx + a.tx) / max * 100)}"></i></div>
    </div>`).join('');
  requestAnimationFrame(() => el.querySelectorAll('i[data-w]').forEach((i) => {
    i.style.width = i.dataset.w + '%';
  }));
}

function renderTable(apps) {
  const tbody = $('appRows');
  const max = Math.max(1, ...apps.map((a) => a.rx + a.tx));
  tbody.innerHTML = apps.map((a) => {
    const sel = selectedApp === a.name ? ' class="selected"' : '';
    const share = Math.round((a.rx + a.tx) / max * 100);
    const pct = Math.round((a.rx + a.tx) / Math.max(1, apps[0] ? apps.reduce((s, x) => s + x.rx + x.tx, 0) : 1) * 100);
    return `<tr data-name="${a.name.replace(/"/g, '&quot;')}"${sel}>
      <td><div class="appcell"><span class="chip" style="background:${a.color}"></span>
        <div><div class="name">${a.name}</div><div class="cat">${a.category}</div></div></div></td>
      <td><b>${fmtBps(a.rx)}</b></td>
      <td><b>${fmtBps(a.tx)}</b></td>
      <td><b style="color:${a.color}">${fmtBps(a.rx + a.tx)}</b></td>
      <td><b>${a.conns}</b></td>
      <td><div class="barwrap"><i style="background:${a.color}" data-w="${share}"></i></div><div style="font-size:10px;color:var(--muted)">${pct}%</div></td>
    </tr>`;
  }).join('');
  requestAnimationFrame(() => tbody.querySelectorAll('i[data-w]').forEach((i) => {
    i.style.width = i.dataset.w + '%';
  }));

  tbody.onclick = (e) => {
    const tr = e.target.closest('tr');
    if (!tr) return;
    selectedApp = tr.dataset.name;
    renderDrawer();
    renderTable(lastStats.apps);
    $('drawer').classList.add('open');
  };
}

function renderAdapters(adapters) {
  const el = $('adapters');
  if (!adapters || !adapters.length) { el.innerHTML = '<div class="empty">no adapters sampled</div>'; return; }
  el.innerHTML = adapters.map((a) => `
    <div class="adapter">
      <div class="nm">${a.name}</div>
      <div class="rt"><span>rx</span><b>${fmtBps(a.rxBps)}</b></div>
      <div class="rt"><span>tx</span><b>${fmtBps(a.txBps)}</b></div>
      <div class="rt"><span>total</span><b style="color:var(--green)">${fmtBps(a.rxBps + a.txBps)}</b></div>
    </div>`).join('');
}

/* ---------------- drawer ---------------- */

const drawerMeta = new Map(); // name -> {rx:[], tx:[], total:[]}

function renderDrawer() {
  if (!selectedApp) return;
  const s = lastStats.apps.find((a) => a.name === selectedApp);
  const m = drawerMeta.get(selectedApp) || { rx: [], tx: [], total: [] };
  const avg = m.total.length ? m.total.reduce((a, b) => a + b, 0) / m.total.length : 0;
  const peak = m.total.length ? Math.max(...m.total) : 0;
  $('drawerName').textContent = selectedApp;
  $('drawerName').style.color = s ? s.color : '';
  $('drawerMeta').textContent = `${s ? s.category : '—'} · pid ${s ? s.pid : '—'} · ${s ? s.conns : 0} connections`;
  $('dRx').textContent = fmtBps(s ? s.rx : 0);
  $('dTx').textContent = fmtBps(s ? s.tx : 0);
  $('dAvg').textContent = fmtBps(avg);
  $('dPeak').textContent = fmtBps(peak);
  $('dConns').textContent = s ? s.conns : '-';
  $('dCount').textContent = m.total.length;
  drawArea(drawerChart, { labels: m.rx.map((_, i) => i), rx: m.total, tx: [] }, s ? s.color : '#22d3ee');
}
const drawerChart = initCanvas('drawerChart');

function trackApp(name, a) {
  if (!drawerMeta.has(name)) drawerMeta.set(name, { rx: [], tx: [], total: [] });
  const m = drawerMeta.get(name);
  m.rx.push(a.rx); m.tx.push(a.tx); m.total.push(a.rx + a.tx);
  if (m.total.length > 80) { m.rx.shift(); m.tx.shift(); m.total.shift(); }
  if (selectedApp === name) renderDrawer();
}

/* ---------------- data ---------------- */

async function fetchJSON(url) {
  const r = await fetch(url, { cache: 'no-store' });
  if (!r.ok) throw new Error(url + ' → ' + r.status);
  return r.json();
}

async function loop() {
  try {
    const [stats] = await Promise.all([fetchJSON('/api/stats')]);
    lastStats = stats;
    $('health').textContent = '● connected · ' + new Date().toLocaleTimeString();
    $('health').style.color = 'var(--green)';
    renderKpis(stats);
    renderTopApps(stats.apps);
    renderTable(stats.apps);
    renderAdapters(stats.adapters);
    stats.apps.forEach((a) => trackApp(a.name, a));
  } catch (e) {
    $('health').textContent = '● offline: ' + e.message;
    $('health').style.color = 'var(--pink)';
  }
  try {
    const hist = await fetchJSON('/api/history');
    if (hist.rx.length) {
      drawArea(mainChart, hist);
      $('chartDelta').textContent = fmtBps(hist.rx[hist.rx.length - 1]) + ' down';
    }
  } catch (e) { /* keep last chart */ }
}

const mainChart = initCanvas('chart');

$('closeDrawer').onclick = () => { $('drawer').classList.remove('open'); selectedApp = null; };

window.addEventListener('resize', () => {
  const main = initCanvas('chart');
  const dr = initCanvas('drawerChart');
  loop().catch(() => {});
});

setInterval(() => { $('clock').textContent = new Date().toLocaleTimeString(); }, 1000);
setInterval(() => loop().catch(() => {}), POLL);
loop().catch(() => {});