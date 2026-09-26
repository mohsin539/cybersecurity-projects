/* SOC Alert Triage Dashboard — SPA client (strict CSP: no inline, no eval) */
'use strict';

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => document.querySelectorAll(sel);

// SECURITY (XSS / OWASP A03): text-only rendering — no innerHTML anywhere.
function el(tag, attrs = {}, ...children) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === 'class') n.className = v;
    else if (k.startsWith('on')) n.addEventListener(k.slice(2), v);
    else n.setAttribute(k, v);
  }
  for (const c of children) if (c != null) n.append(c);
  return n;
}

function toast(msg, ok = true) {
  const t = $('#toast');
  t.textContent = msg;
  t.className = 'toast' + (ok ? '' : ' err');
  setTimeout(() => t.classList.add('hidden'), 3500);
}

// ─── API client ───
let CSRF = null;
let me = null;

async function api(path, opts = {}) {
  const headers = { ...(opts.headers || {}) };
  if (opts.body) headers['Content-Type'] = 'application/json';
  if (CSRF) headers['X-CSRF-Token'] = CSRF;
  const r = await fetch(path, {
    method: opts.method || 'GET',
    headers,
    body: opts.body ? JSON.stringify(opts.body) : undefined,
    credentials: 'same-origin',
  });
  if (r.status === 401) { setAuth(null); showView('login'); throw new Error('session expired'); }
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(data.error || r.statusText);
  return data;
}

function setAuth(session) {
  CSRF = session ? session.csrf : null;
  me = session ? session.user : null;
}

// ─── views ───
const VIEWS = ['login', 'queue', 'alert', 'audit', 'config'];
function showView(name) {
  for (const v of VIEWS) {
    const node = $(`#view-${v}`);
    if (node) node.classList.toggle('hidden', v !== name);
  }
  const authed = name !== 'login';
  $('#nav').classList.toggle('hidden', !authed);
  $$('#nav .navbtn').forEach((b) => b.classList.toggle('active', b.dataset.view === name));
  if (authed) {
    $('#who').textContent = `${me ? me.id : ''} · ${me ? me.role : ''}`;
    $('#btn-ingest').classList.toggle('hidden', !(me && (me.role === 'soc.lead' || me.role === 'platform.admin')));
    $$('#nav [data-requires="config"]').forEach((b) => {
      b.classList.toggle('hidden', !(me && (me.role === 'soc.lead' || me.role === 'platform.admin')));
    });
  }
}

// ─── queue ───
async function loadQueue(band = '') {
  const q = band ? `?band=${encodeURIComponent(band)}` : '';
  const data = await api(`/api/queue${q}`);
  const body = $('#queue-body');
  body.replaceChildren();
  if (data.crossTenantStats) {
    $('#queue-meta').textContent = 'Auditor cross-tenant oversight (counts only)';
    for (const [t, n] of Object.entries(data.crossTenantStats)) {
      body.append(el('tr', {},
        el('td', {}, '—'),
        el('td', {}, '—'),
        el('td', {}, `tenant ${t}: ${n} canonical alerts`),
        el('td', {}, '(payload data withheld)'),
        el('td', {}, '—'), el('td', {}, '—'), el('td', {}, '—')));
    }
    $('#queue-empty').classList.add('hidden');
    return;
  }
  $('#queue-meta').textContent = `${data.alerts.length} canonical alerts`;
  for (const a of data.alerts) {
    const tr = el('tr', { class: 'row' });
    tr.addEventListener('click', () => openAlert(a.id));
    tr.append(
      el('td', {}, String(a.currentScore ?? '—')),
      el('td', {}, el('span', { class: `band ${a.currentBand}` }, a.currentBand || '—')),
      el('td', {}, a.title),
      el('td', {}, (a.entities || []).map((e) => `${e.type}:${e.id}`).join(', ')),
      el('td', {}, String(a.occurrenceCount || 1)),
      el('td', {}, a.status),
      el('td', {}, new Date(a.lastSeen).toLocaleString()),
    );
    body.append(tr);
  }
  $('#queue-empty').classList.toggle('hidden', data.alerts.length > 0);
}

// ─── alert detail ───
async function openAlert(id) {
  let data;
  try { data = await api(`/api/alerts/${id}`); }
  catch (e) { toast(e.message, false); return; }
  const d = $('#alert-detail');
  d.replaceChildren();
  const a = data.alert;

  d.append(el('h2', {}, a.title));
  d.append(el('p', { class: 'muted' },
    `${a.source} / ${a.ruleId} · tactic: ${a.tactic || 'n/a'} · status: ${a.status} · assigned: ${a.assignedTo || '—'}`));
  d.append(el('p', { class: 'muted' },
    `occurred ${new Date(a.occurredAt).toLocaleString()} · occurrences ${a.occurrenceCount || 1} · entities ${(a.entities || []).map((e) => `${e.type}:${e.id}`).join(', ')}`));

  const s = (data.scores || []).slice(-1)[0] || {};
  d.append(renderScore(a, s));

  // dedup tree
  d.append(el('h3', {}, `Deduplication — ${(data.duplicates || []).length} linked duplicate(s)`));
  if ((data.duplicates || []).length === 0) {
    d.append(el('p', { class: 'muted' }, 'No linked duplicates.'));
  }
  for (const dup of data.duplicates || []) {
    const row = el('div', { class: 'dup' });
    row.append(el('span', {}, `${dup.id.slice(0, 8)}… · seen ${new Date(dup.occurredAt).toLocaleString()}`));
    if (me && (me.role === 'soc.lead' || me.role === 'analyst.tier2')) {
      const splitBtn = el('button', { class: 'btn subtle' }, 'split → own canonical');
      splitBtn.addEventListener('click', () => splitDup(dup.id));
      row.append(splitBtn);
    }
    d.append(row);
  }

  // disposition actions
  const actions = el('div', { class: 'actions' });
  const mk = (label, status) => {
    const b = el('button', { class: 'btn' }, label);
    b.addEventListener('click', () => doDisposition(a.id, status));
    return b;
  };
  actions.append(mk('Investigating', 'investigating'), mk('False positive', 'false_positive'),
    mk('Benign', 'benign'), mk('Resolve', 'resolved'));
  const assignBtn = el('button', { class: 'btn subtle' }, 'Assign to me');
  assignBtn.addEventListener('click', () => doAssign(a.id));
  actions.append(assignBtn);
  d.append(actions);

  // score history
  if ((data.scores || []).length > 1) {
    d.append(el('h3', {}, 'Score history'));
    for (const sc of data.scores) {
      d.append(el('p', { class: 'muted' },
        `${sc.computedAt} → ${sc.score} (${sc.band}) · version ${sc.scoreVersion}`));
    }
  }
  showView('alert');
}

function renderScore(a, s) {
  const box = el('div', { class: 'card score' });
  box.append(el('h3', {}, `Score ${a.currentScore ?? '—'} · band ${a.currentBand ?? '—'} · version ${s.scoreVersion || '—'}`));
  if (a.degradedContext) {
    box.append(el('p', { class: 'error' }, '⚠ degraded context — score may be understated'));
  }
  const fb = s.factorBreakdown && s.factorBreakdown.factors ? s.factorBreakdown.factors : null;
  if (fb) {
    const tbl = el('table', { class: 'factors' });
    tbl.append(el('tr', {}, el('th', {}, 'factor'), el('th', {}, 'value'), el('th', {}, 'weight'), el('th', {}, 'contribution')));
    for (const [k, v] of Object.entries(fb)) {
      tbl.append(el('tr', {},
        el('td', {}, k),
        el('td', {}, String(v.value)),
        el('td', {}, String(v.weight)),
        el('td', {}, String(v.contribution))));
    }
    const m = s.factorBreakdown.contextMultiplier;
    const ml = s.factorBreakdown.mlAdjustment;
    tbl.append(el('tr', {},
      el('td', {}, 'context multiplier'), el('td', {}, '×' + String(m)),
      el('td', {}, 'mlAdjustment'), el('td', {}, String(ml))));
    box.append(tbl);
  } else {
    box.append(el('p', { class: 'muted' }, 'No factor breakdown available.'));
  }
  return box;
}

async function doDisposition(alertId, status) {
  try {
    await api(`/api/alerts/${alertId}/disposition`, { method: 'POST', body: { status, reason: 'analyst action' } });
    toast('dispositioned: ' + status);
    openAlert(alertId);
  } catch (e) { toast(e.message, false); }
}

async function doAssign(alertId) {
  try {
    await api(`/api/alerts/${alertId}/assign`, { method: 'POST', body: { assignee: me ? me.id : '' } });
    toast('assigned');
    openAlert(alertId);
  } catch (e) { toast(e.message, false); }
}

async function splitDup(dupId) {
  try {
    const r = await api(`/api/alerts/${dupId}/split-duplicate`, { method: 'POST', body: {} });
    toast('split — new canonical ' + r.newCanonicalId.slice(0, 8));
    openAlert(r.newCanonicalId);
  } catch (e) { toast(e.message, false); }
}

// ─── audit ───
async function loadAudit() {
  const data = await api('/api/audit');
  const body = $('#audit-body');
  body.replaceChildren();
  for (const ev of data.events || []) {
    body.append(el('tr', {},
      el('td', {}, String(ev.seq)),
      el('td', {}, new Date(ev.ts).toLocaleString()),
      el('td', {}, ev.actorId),
      el('td', {}, ev.action),
      el('td', {}, `${ev.objectType || ''}${ev.objectId ? ':' + ev.objectId.slice(0, 8) : ''}`),
      el('td', {}, ev.before || ev.after ? JSON.stringify(ev.before) + ' → ' + JSON.stringify(ev.after) : '')));
  }
  const chip = $('#chain-status');
  chip.textContent = 'chain: ' + (data.chainValid ? 'valid' : 'INVALID');
  chip.className = 'chip ' + (data.chainValid ? 'ok' : 'err');
}

// ─── config ───
async function loadConfig() {
  const data = await api('/api/config');
  $('#score-version').textContent = 'score version ' + data.scoreVersion;
  const wEd = $('#weights-editor');
  wEd.replaceChildren();
  for (const [k, v] of Object.entries(data.weights)) {
    const row = el('div', { class: 'cfg-row' });
    const lab = el('label', {}, k);
    const inp = el('input', { type: 'number', min: '0', max: '100', step: '1', value: String(v), 'data-w': k });
    row.append(lab, inp);
    wEd.append(row);
  }
  const tEd = $('#thresholds-editor');
  tEd.replaceChildren();
  for (const [k, v] of Object.entries(data.thresholds)) {
    const row = el('div', { class: 'cfg-row' });
    row.append(el('label', {}, k),
      el('input', { type: 'number', min: '0', max: '100', value: String(v), 'data-t': k }));
    tEd.append(row);
  }
  const sEd = $('#switches-editor');
  sEd.replaceChildren();
  const dedupRow = el('div', { class: 'cfg-row' });
  dedupRow.append(el('label', {}, 'dedup mode'));
  const sel = el('select', { 'data-s': 'dedup' });
  for (const m of ['full', 'exact_only', 'off']) {
    const opt = el('option', { value: m }, m);
    if (m === data.dedup.mode) opt.setAttribute('selected', 'selected');
    sel.append(opt);
  }
  dedupRow.append(sel);
  sEd.append(dedupRow);
  for (const k of ['ml_overlay', 'export_enabled']) {
    const row = el('div', { class: 'cfg-row' });
    const cb = el('input', { type: 'checkbox', 'data-s': k });
    if (data.switches[k]) cb.setAttribute('checked', 'checked');
    row.append(cb, el('label', {}, k));
    sEd.append(row);
  }
  updateWeightSum();
}

function readWeights() {
  const out = {};
  $$('#weights-editor input').forEach((i) => { out[i.getAttribute('data-w')] = Number(i.value); });
  return out;
}

function updateWeightSum() {
  const sum = Object.values(readWeights()).reduce((a, b) => a + (Number.isFinite(b) ? b : 0), 0);
  $('#weight-sum').textContent = String(sum);
  $('#weight-sum').className = sum === 100 ? 'ok' : 'err';
}

async function saveWeights() {
  try {
    const r = await api('/api/config', { method: 'POST', body: { weights: readWeights() } });
    toast('weights applied — rescored ' + r.rescored + ' alerts, version ' + r.scoreVersion);
    loadConfig();
  } catch (e) { toast(e.message, false); }
}

async function saveConfig() {
  try {
    const body = { switches: {} };
    const t = {};
    $$('#thresholds-editor input').forEach((i) => { t[i.getAttribute('data-t')] = Number(i.value); });
    body.thresholds = t;
    $$('#switches-editor [data-s]').forEach((n) => {
      const k = n.getAttribute('data-s');
      if (k === 'dedup') body.dedup = { mode: n.value };
      else body.switches[k] = n.checked;
    });
    await api('/api/config', { method: 'POST', body });
    toast('configuration applied');
    loadConfig();
  } catch (e) { toast(e.message, false); }
}

// ─── auth flows ───
async function loginAs(userId) {
  try {
    const data = await api('/api/auth/login', { method: 'POST', body: { userId } });
    setAuth({ csrf: data.csrf, user: data.user });
    $('#login-error').classList.add('hidden');
    showView('queue');
    loadQueue();
  } catch (e) {
    const err = $('#login-error');
    err.textContent = e.message;
    err.classList.remove('hidden');
  }
}

async function logout() {
  try { await api('/api/auth/logout', { method: 'POST', body: {} }); } catch (e) { /* session already gone */ }
  setAuth(null);
  showView('login');
}

// ─── wiring ───
function wire() {
  $$('.login-as').forEach((b) => b.addEventListener('click', () => loginAs(b.getAttribute('data-user'))));
  $('#logout').addEventListener('click', logout);
  $('#back-to-queue').addEventListener('click', () => { showView('queue'); loadQueue(currentBand); });
  $$('#band-filters .chip').forEach((c) => c.addEventListener('click', () => {
    $$('#band-filters .chip').forEach((x) => x.classList.remove('active'));
    c.classList.add('active');
    currentBand = c.getAttribute('data-band');
    loadQueue(currentBand);
  }));
  $('#nav').addEventListener('click', (ev) => {
    const btn = ev.target.closest('.navbtn');
    if (!btn) return;
    const v = btn.getAttribute('data-view');
    showView(v);
    if (v === 'queue') loadQueue(currentBand);
    if (v === 'audit') loadAudit();
    if (v === 'config') loadConfig();
  });
  $('#btn-ingest').addEventListener('click', simulateIngest);
  $('#btn-verify').addEventListener('click', loadAudit);
  $('#btn-export').addEventListener('click', () => { window.location.href = '/api/audit/export'; });
  $('#btn-save-weights').addEventListener('click', saveWeights);
  $('#btn-save-config').addEventListener('click', saveConfig);
  $('#weights-editor').addEventListener('input', updateWeightSum);
}

let currentBand = '';

async function simulateIngest() {
  const base = Date.now() - 60000;
  try {
    const r = await api('/api/ingest', {
      method: 'POST',
      body: {
        source: 'edr', ruleId: 'EDR-CRED-DUMP-01', ruleFamily: 'credential-access',
        tactic: 'credential-access', title: 'Credential dumping tool detected on FIN-DB-001',
        summary: 'LSASS handle access by unsigned binary',
        entities: [{ type: 'host', id: 'FIN-DB-001' }, { type: 'user', id: 'svc_backup@t1' }],
        occurredAt: new Date(base).toISOString(),
        confidence: 0.75, assetTier: 0, tiMatch: 1.0, identityRisk: 0.6,
        kevListed: true, epss: 0.61, anomalyZ: 0.8,
      },
    });
    toast(r.deduped
      ? 'ingested — deduplicated into canonical ' + r.canonicalId.slice(0, 8)
      : 'ingested — new canonical, score ' + r.score + ' (' + r.band + ')');
    loadQueue(currentBand);
  } catch (e) { toast(e.message, false); }
}

wire();
showView('login');
