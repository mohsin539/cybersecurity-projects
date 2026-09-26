/**
 * Client controller.
 *
 * Rules this file obeys without exception:
 *  - never compute, adjust or invent a score (SEC-SCORE-01);
 *  - never trust the first frame - always reconcile against a full snapshot;
 *  - every number on screen is traceable to a `seq` and a `state_hash`;
 *  - if the stream dies, keep the last known board and say so out loud.
 */

import { LeaderboardScene } from './scene.js';

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => Array.from(document.querySelectorAll(sel));

const state = {
  board: null,
  stream: null,
  retries: 0,
  stale: false,
  lastSeq: 0,
  lastHash: null,
  view: 'board',
  me: null,
  config: {},
  scores: { asOf: new Date().toISOString() },
};

const els = {
  canvas: $('#view'),
  labels: $('#labels'),
  eventName: $('#event-name'),
  phase: $('#phase-chip'),
  model: $('#model-chip'),
  seq: $('#seq-chip'),
  hash: $('#hash-chip'),
  solves: $('#solves-chip'),
  health: $('#health-chip'),
  tableBody: $('#leaderboard-table tbody'),
  notifications: $('#notifications'),
};

// ------------------------------------------------------------------ helpers --
function errorMessage(payload, response) {
  if (typeof payload === 'string' && payload) return payload;
  if (payload && typeof payload === 'object') {
    // FastAPI wraps handler errors as {"detail": {...}} while pydantic sends
    // {"detail": [{loc, msg}]}; both shapes must reach the operator as text.
    const detail = payload.detail !== undefined ? payload.detail : payload;
    if (typeof detail === 'string') return detail;
    if (Array.isArray(detail)) {
      const joined = detail.map((d) => (d && d.msg) || JSON.stringify(d)).join('; ');
      if (joined) return joined;
    } else if (detail && typeof detail === 'object') {
      if (typeof detail.message === 'string') return detail.message;
      if (typeof detail.detail === 'string') return detail.detail;
      if (typeof detail.error === 'string') return detail.error;
    }
    if (typeof payload.message === 'string') return payload.message;
    if (typeof payload.error === 'string') return payload.error;
  }
  return response.statusText || 'Request failed';
}

async function api(path, options = {}) {
  const { body, headers, ...rest } = options;
  const response = await fetch(path, {
    credentials: 'same-origin',
    ...rest,
    headers: {
      ...(body !== undefined && !(body instanceof FormData)
        ? { 'Content-Type': 'application/json' }
        : {}),
      ...(headers || {}),
    },
    ...(body === undefined ? {} : { body: typeof body === 'string' ? body : JSON.stringify(body) }),
  });
  if (response.status === 204) return null;
  const contentType = response.headers.get('content-type') || '';
  const payload = contentType.includes('application/json')
    ? await response.json()
    : await response.text();
  if (!response.ok) {
    const error = new Error(errorMessage(payload, response));
    error.status = response.status;
    error.payload = payload;
    throw error;
  }
  return payload;
}

function toast(message, kind = 'info', ttl = 5200) {
  const node = document.createElement('div');
  node.className = `toast ${kind}`;
  node.setAttribute('role', kind === 'danger' ? 'alert' : 'status');
  node.textContent = message;
  els.notifications.appendChild(node);
  setTimeout(() => node.remove(), ttl);
}

function fmt(value, digits = 0) {
  if (value === null || value === undefined) return '—';
  return Number(value).toLocaleString(undefined, {
    minimumFractionDigits: digits,
    maximumFractionDigits: digits,
  });
}

function ago(iso) {
  if (!iso) return '—';
  const seconds = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
  if (seconds < 60) return `${Math.floor(seconds)}s ago`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  return `${Math.floor(seconds / 3600)}h ago`;
}

// -------------------------------------------------------------------- board --
function applyBoard(board) {
  if (!board) return;
  state.board = board;
  state.lastSeq = board.last_seq ?? state.lastSeq;
  state.lastHash = board.state_hash ?? state.lastHash;
  state.stale = false;

  if (board.event) {
    els.eventName.textContent = board.event.name || 'CTF Scoreboard';
    document.title = `${board.event.name || 'CTF'} — 3D Scoreboard`;
  }
  if (board.event && board.event.phase) {
    els.phase.textContent = `phase: ${board.event.phase}`;
    els.phase.dataset.phase = board.event.phase;
  }
  if (board.scoring_model) els.model.textContent = `model: ${board.scoring_model}`;
  els.seq.textContent = `seq: ${state.lastSeq}`;
  els.hash.textContent = `hash: ${(state.lastHash || '—').slice(0, 10)}`;
  const solveCount = (board.teams || []).reduce((sum, t) => sum + (t.solves || 0), 0);
  els.solves.textContent = `solves: ${solveCount}`;

  scene.update(board);
  renderTable(board);
  updateHealth();
}

const TREND = { rising: '▲', steady: '■', falling: '▼' };

function renderTable(board) {
  const rows = (board.teams || [])
    .map(
      (t) => `<tr>
        <td>${t.rank}</td>
        <td><span class="swatch" style="background:${escapeHtml(t.accent)}"></span> ${escapeHtml(t.name)}</td>
        <td>${escapeHtml(t.country || '')}</td>
        <td>${fmt(t.score, 1)}</td>
        <td>${fmt(t.raw_score)}</td>
        <td>${t.solves ?? 0}</td>
        <td>${t.challenges_solved ?? 0}</td>
        <td>${TREND[t.trend] || '■'} ${escapeHtml(t.trend || 'steady')}</td>
        <td>${ago(t.last_solve_at)}</td>
      </tr>`,
    )
    .join('');
  els.tableBody.innerHTML =
    rows || '<tr><td colspan="9">No teams registered yet.</td></tr>';
}

function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
}

function updateHealth() {
  const health = scene.health();
  const bits = [`fps: ${health.fps}`];
  if (health.state === 'no-webgl2') bits.push('3d: unavailable');
  if (state.stale) bits.push('stream: stale');
  els.health.textContent = `health: ${bits.join(' · ')}`;
}

// -------------------------------------------------------------------- views --
function setView(view) {
  state.view = view;
  $('#panel-admin').hidden = view !== 'admin';
  $('#panel-integrity').hidden = view !== 'integrity';
  $('#fallback-table').hidden = view === 'board';
  $$('nav .btn[data-view]').forEach((b) =>
    b.setAttribute('aria-pressed', String(b.dataset.view === view)),
  );
  scene.setQuality(view === 'board' ? 'auto' : 'low');
  if (view === 'board') scene.start();
}

async function loadIntegrity() {
  const [invariants, integrity] = await Promise.all([
    api('/api/invariants'),
    api('/api/integrity'),
  ]);
  $('#integrity-json').textContent = JSON.stringify({ invariants, integrity }, null, 2);
}

// -------------------------------------------------------------------- stream --
function connect() {
  if (state.stream) state.stream.close();
  const stream = new EventSource('/api/stream');
  state.stream = stream;

  stream.addEventListener('open', () => {
    state.retries = 0;
    state.stale = false;
    updateHealth();
  });

  stream.addEventListener('snapshot', (event) => {
    try {
      applyBoard(JSON.parse(event.data).board);
    } catch (error) {
      console.error('bad snapshot', error);
    }
  });

  stream.addEventListener('board', (event) => {
    try {
      const payload = JSON.parse(event.data);
      applyBoard(payload.board);
      if (payload.reason === 'solve') {
        const team = (payload.board.teams || []).find((t) => t.rank === 1);
        if (team && state.view === 'board') {
          toast(`${team.name} is leading with ${fmt(team.score, 0)} pts`, 'success', 3600);
        }
      }
    } catch (error) {
      console.error('bad board frame', error);
    }
  });

  stream.addEventListener('solve', (event) => {
    try {
      const solve = JSON.parse(event.data);
      if (solve.by !== 'simulator') {
        toast(`${solve.team} solved ${solve.challenge} (+${fmt(solve.points, 1)})`, 'info', 4200);
      }
    } catch (error) {
      console.error('bad solve frame', error);
    }
  });

  stream.addEventListener('notice', (event) => {
    try {
      const notice = JSON.parse(event.data);
      toast(notice.message || notice.text || 'Board updated', notice.level || 'info');
    } catch (error) {
      console.error('bad notice frame', error);
    }
  });

  stream.addEventListener('resync', () => {
    // The gap is larger than the replay buffer: refetch instead of guessing.
    state.stale = true;
    api('/api/leaderboard')
      .then(applyBoard)
      .catch((error) => toast(`Resync failed: ${error.message}`, 'danger'));
  });

  stream.addEventListener('error', () => {
    state.stale = true;
    updateHealth();
    if (stream.readyState === EventSource.CLOSED) {
      state.retries += 1;
      const delay = Math.min(15000, 750 * 2 ** Math.min(5, state.retries));
      toast(`Live stream lost. Retrying in ${Math.round(delay / 1000)}s (table still valid).`, 'warn');
      setTimeout(connect, delay);
    }
  });
}

// --------------------------------------------------------------------- admin --
async function refreshMe() {
  try {
    const me = await api('/api/auth/me');
    if (!me.authenticated) {
      state.me = null;
      $('#me').textContent = 'not signed in';
      $('#solve-form').hidden = true;
      $('#adjust-propose').hidden = true;
      $('#phase-form').hidden = true;
      $('#pending-adjustments').hidden = true;
      $('#custody').hidden = true;
      return;
    }
    state.me = me;
    $('#me').textContent = `${me.display_name || me.handle} · ${me.role}${
      me.step_up ? ' · step-up active' : ''
    }`;
    $('#solve-form').hidden = !me.is_staff;
    $('#adjust-propose').hidden = !me.is_staff;
    $('#phase-form').hidden = !me.is_admin;
    $('#custody').hidden = !me.is_staff;
    $('#seal-log').hidden = !me.is_admin;
    $('#step-up').hidden = !me.is_staff || me.step_up;
  } catch (error) {
    state.me = null;
    $('#me').textContent = 'not signed in';
  }
}

async function refreshPending() {
  if (!state.me) return;
  try {
    const admin = await api('/api/admin/state');
    const pending = admin.pending_adjustments || [];
    $('#pending-adjustments').hidden = pending.length === 0;
    $('#pending-list').innerHTML = pending
      .map(
        (a) => `<li>#${a.id} — ${escapeHtml(a.team_slug || a.team_name)} ${
          a.delta > 0 ? '+' : ''
        }${fmt(a.delta, 0)} · by ${escapeHtml(a.proposed_by)} · ${escapeHtml(a.reason)}
          <button class="btn" data-approve="${a.id}">Approve</button>
          <button class="btn warn" data-reject="${a.id}">Reject</button></li>`,
      )
      .join('');
  } catch (error) {
    /* non-fatal: the panel simply stays as it was */
  }
}

// ---------------------------------------------------------------------- boot --
const scene = new LeaderboardScene(els.canvas, els.labels);

function wire() {
  $$('nav .btn[data-view]').forEach((button) =>
    button.addEventListener('click', () => setView(button.dataset.view)),
  );
  $('#refresh-integrity').addEventListener('click', () => loadIntegrity().catch((e) => toast(e.message, 'danger')));

  $('#login-form').addEventListener('submit', async (event) => {
    event.preventDefault();
    const data = new FormData(event.target);
    try {
      await api('/api/auth/login', {
        method: 'POST',
        body: JSON.stringify({ handle: data.get('handle'), password: data.get('password') }),
      });
      await refreshMe();
      await refreshPending();
      toast('Signed in.', 'success');
    } catch (error) {
      toast(error.message, 'danger');
    }
  });

  $('#logout').addEventListener('click', async () => {
    await api('/api/auth/logout', { method: 'POST' }).catch(() => {});
    await refreshMe();
    toast('Signed out.');
  });

  // Step-up: destructive or export operations re-verify the password (SEC-IAM-07).
  $('#step-up').addEventListener('click', async () => {
    const password = window.prompt('Re-enter your password to continue (valid for 10 minutes):');
    if (!password) return;
    try {
      await api('/api/auth/step-up', { method: 'POST', body: JSON.stringify({ password }) });
      await refreshMe();
      toast('Step-up verified.', 'success');
    } catch (error) {
      toast(error.message, 'danger');
    }
  });

  $('#solve-form').addEventListener('submit', async (event) => {
    event.preventDefault();
    const data = new FormData(event.target);
    try {
      const result = await api('/api/admin/solves', {
        method: 'POST',
        body: JSON.stringify({ team: data.get('team'), challenge: data.get('challenge') }),
      });
      $('#solve-result').textContent = `Awarded ${fmt(result.points, 1)} pts.`;
      toast(`Solve recorded for ${result.team}.`, 'success');
      await refreshPending();
    } catch (error) {
      $('#solve-result').textContent = error.message;
      toast(error.message, 'danger');
    }
  });

  $('#adjust-propose').addEventListener('submit', async (event) => {
    event.preventDefault();
    const data = new FormData(event.target);
    try {
      await api('/api/admin/adjustments', {
        method: 'POST',
        body: JSON.stringify({
          team: data.get('team'),
          delta: Number(data.get('delta')),
          reason: data.get('reason'),
        }),
      });
      $('#adjust-result').textContent = 'Proposal submitted for second approval.';
      toast('Proposal submitted. A second staff member must approve it.', 'info');
      await refreshPending();
    } catch (error) {
      $('#adjust-result').textContent = error.message;
      toast(error.message, 'danger');
    }
  });

  $('#pending-list').addEventListener('click', async (event) => {
    const approve = event.target.dataset.approve;
    const reject = event.target.dataset.reject;
    const id = approve || reject;
    if (!id) return;
    try {
      await api(`/api/admin/adjustments/${encodeURIComponent(id)}/decision`, {
        method: 'POST',
        body: JSON.stringify({ approve: Boolean(approve) }),
      });
      toast(approve ? 'Adjustment applied.' : 'Proposal rejected.', 'success');
      await refreshPending();
    } catch (error) {
      toast(error.message, 'danger');
    }
  });

  $('#phase-form').addEventListener('submit', async (event) => {
    event.preventDefault();
    const data = new FormData(event.target);
    try {
      await api('/api/admin/phase', {
        method: 'POST',
        body: JSON.stringify({ phase: data.get('phase') }),
      });
      toast(`Phase set to ${data.get('phase')}.`, 'success');
    } catch (error) {
      toast(error.message, 'danger');
    }
  });

  // Sealing is irreversible, so it asks first and then reports the new root.
  $('#seal-log').addEventListener('click', async () => {
    if (!window.confirm('Seal the event log? Sealing is permanent and stamps a Merkle root.')) return;
    try {
      const result = await api('/api/admin/seal', { method: 'POST' });
      const root = result.merkle_root || result.sealed_root || 'unknown';
      $('#custody-result').textContent = `Sealed ${result.from_seq}–${result.to_seq} · root ${String(root).slice(0, 16)}…`;
      toast('Event log sealed.', 'success');
    } catch (error) {
      $('#custody-result').textContent = error.message;
      toast(error.message, 'danger');
    }
  });

  // The export is behind a normal link, but a 403 must not download a login page.
  $('#export-audit').addEventListener('click', async (event) => {
    if (!state.me || !state.me.step_up) {
      event.preventDefault();
      toast('Re-verify with step-up before exporting the audit trail.', 'warn');
    }
  });

  window.addEventListener('resize', () => scene.resize());
  document.addEventListener('visibilitychange', () => {
    if (document.hidden) scene.stop();
    else if (state.view === 'board') scene.start();
  });
}

async function boot() {
  wire();
  if (scene.init()) {
    scene.start();
  } else {
    toast('WebGL2 unavailable — showing the accessible table instead.', 'warn', 9000);
    setView('table');
  }
  try {
    const [board, config] = await Promise.all([api('/api/leaderboard'), api('/api/config')]);
    state.config = config;
    applyBoard(board);
  } catch (error) {
    toast(`Cannot reach the scoreboard API: ${error.message}`, 'danger', 12000);
  }
  await refreshMe();
  connect();
  setInterval(() => {
    if (state.view === 'board') updateHealth();
    if (state.me) refreshPending();
  }, 30000);
}

boot();
