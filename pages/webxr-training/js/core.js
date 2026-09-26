/* eslint-env browser */
/**
 * core.js — GUI foundation: safe DOM helpers, API client, session store,
 * toasts, modals and dependency-free canvas charts.
 *
 * Security posture (OWASP A03 / ASVS V5, architecture.md §6):
 *  - every DOM write goes through `el()` using textContent — never innerHTML
 *  - bearer token lives in sessionStorage only (destroyed with the tab)
 *  - a 401 clears the token and returns to the welcome screen (no stuck state)
 */
'use strict';

window.XR = window.XR || {};

/* ─── DOM helpers ─────────────────────────────────────────────────────── */

const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];

/**
 * Create an element. `text` is assigned via textContent so no attacker- or
 * content-supplied string can ever be parsed as markup.
 */
function el(tag, attrs = {}, children = []) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === null || v === undefined || v === false) continue;
    if (k === 'class') node.className = v;
    else if (k === 'text') node.textContent = String(v);
    else if (k === 'html') throw new Error('innerHTML is forbidden (CSP A03)');
    else if (k === 'dataset') for (const [dk, dv] of Object.entries(v)) node.dataset[dk] = String(dv);
    else if (k.startsWith('on') && typeof v === 'function') node.addEventListener(k.slice(2), v);
    else if (v === true) node.setAttribute(k, '');
    else node.setAttribute(k, String(v));
  }
  for (const c of [].concat(children)) {
    if (c === null || c === undefined || c === false) continue;
    node.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return node;
}

const frag = (children) => {
  const f = document.createDocumentFragment();
  for (const c of [].concat(children)) if (c) f.append(c instanceof Node ? c : document.createTextNode(String(c)));
  return f;
};

const clear = (node) => {
  while (node.firstChild) node.removeChild(node.firstChild);
  return node;
};

/* ─── Formatting ──────────────────────────────────────────────────────── */

const fmt = {
  pct: (v) => (v === null || v === undefined ? '—' : `${v}%`),
  num: (v) => (v === null || v === undefined ? '—' : String(v)),
  date: (ts) => (ts ? new Date(ts).toLocaleDateString(undefined, { day: '2-digit', month: 'short' }) : '—'),
  time: (ts) => (ts ? new Date(ts).toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' }) : '—'),
  stamp: (ts) => (ts ? new Date(ts).toLocaleString() : '—'),
  ago(ts) {
    if (!ts) return '—';
    const s = Math.max(0, Math.round((Date.now() - ts) / 1000));
    if (s < 60) return `${s}s ago`;
    if (s < 3600) return `${Math.round(s / 60)}m ago`;
    if (s < 86400) return `${Math.round(s / 3600)}h ago`;
    return `${Math.round(s / 86400)}d ago`;
  },
  dur(sec) {
    if (sec === null || sec === undefined) return '—';
    if (sec < 60) return `${sec}s`;
    const m = Math.floor(sec / 60);
    return `${m}m ${sec % 60}s`;
  },
  cls: (score) => (score === null || score === undefined ? '' : score >= 80 ? 'good' : score >= 50 ? 'warn' : 'bad'),
};

/* ─── Session store ───────────────────────────────────────────────────── */

const Store = {
  user: null,
  token: sessionStorage.getItem('xr.token') || null,
  modules: [],
  categories: [],
  capabilities: {},
  run: null, // { session, module, idx, results }

  get role() {
    return this.user ? this.user.role : null;
  },
  isAdmin() {
    return this.role === 'admin';
  },
  setToken(t) {
    this.token = t;
    if (t) sessionStorage.setItem('xr.token', t);
    else sessionStorage.removeItem('xr.token');
  },
};

/* ─── API client ──────────────────────────────────────────────────────── */

const API = {
  async call(path, { method = 'GET', body } = {}) {
    let res;
    try {
      res = await fetch(path, {
        method,
        cache: 'no-store',
        headers: {
          'Content-Type': 'application/json',
          ...(Store.token ? { Authorization: `Bearer ${Store.token}` } : {}),
        },
        body: body === undefined ? undefined : JSON.stringify(body),
      });
    } catch {
      throw Object.assign(new Error('network_unreachable'), { status: 0 });
    }
    const data = await res.json().catch(() => ({}));
    if (res.status === 401 && Store.token) {
      Store.setToken(null);
      Store.user = null;
      App.onSignedOut();
    }
    if (!res.ok) {
      throw Object.assign(new Error(data.error || 'request_failed'), { status: res.status, data });
    }
    return data;
  },
  get: (p) => API.call(p),
  post: (p, body) => API.call(p, { method: 'POST', body }),
};

const FRIENDLY = {
  invalid_credentials: 'Invalid email or password.',
  too_many_attempts: 'Too many attempts — wait for the timer, then try again.',
  rate_limited: 'Rate limit reached — slow down and retry shortly.',
  unauthorized: 'Your session expired. Please sign in again.',
  forbidden: 'Forbidden — that action needs a different role.',
  not_found: 'Not found.',
  already_completed: 'This session was already submitted (replay rejected).',
  invalid_results: 'Answers could not be validated.',
  payload_too_large: 'Payload too large.',
  network_unreachable: 'Cannot reach the service — is the server running?',
};

const friendlyError = (err) => FRIENDLY[err && err.message] || (err && err.message) || 'Unexpected error';

/* ─── Toasts ──────────────────────────────────────────────────────────── */

const Toast = {
  show(message, kind = 'info', ms = 4200) {
    const host = $('#toast-host');
    if (!host) return;
    const node = el('div', { class: `toast ${kind}`, text: message, role: 'status' });
    host.append(node);
    setTimeout(() => {
      node.style.opacity = '0';
      setTimeout(() => node.remove(), 200);
    }, ms);
  },
  ok: (m) => Toast.show(m, 'good'),
  err: (m) => Toast.show(m, 'error', 6000),
  warn: (m) => Toast.show(m, 'warn', 5000),
};

/* ─── Modal ───────────────────────────────────────────────────────────── */

const Modal = {
  close() {
    const host = $('#modal-host');
    if (!host) return;
    clear(host);
    host.hidden = true;
  },
  open(title, bodyNodes, actions = []) {
    const host = $('#modal-host');
    if (!host) return;
    clear(host);
    const box = el('div', { class: 'modal', role: 'dialog', 'aria-modal': 'true', 'aria-label': title });
    box.append(el('h2', { text: title }));
    for (const n of [].concat(bodyNodes)) if (n) box.append(n);
    const bar = el('div', { class: 'row spread mt' });
    for (const a of actions) {
      bar.append(el('button', { class: `btn ${a.kind || ''}`.trim(), text: a.label, onclick: a.onClick }));
    }
    bar.append(el('button', { class: 'btn ghost', text: 'Close', onclick: () => Modal.close() }));
    box.append(bar);
    clear(host).append(box);
    host.hidden = false;
    const first = box.querySelector('input, select, textarea, button');
    if (first) first.focus();
  },
};

/* ─── Reusable components ─────────────────────────────────────────────── */

const UI = {
  stat(value, label, { tone = '', sub = '' } = {}) {
    return el('div', { class: 'stat' }, [
      el('div', { class: `num ${tone}`, text: fmt.num(value) }),
      el('div', { class: 'lbl', text: label }),
      sub ? el('div', { class: 'sub', text: sub }) : null,
    ]);
  },

  meter(value, { tone = '', label = '', valueText = '' } = {}) {
    const pct = Math.max(0, Math.min(100, Number(value) || 0));
    return el('div', { class: 'stack', style: 'gap:6px' }, [
      label
        ? el('div', { class: 'metric-row' }, [
            el('span', { class: 'metric-label', text: label }),
            el('span', { class: 'metric-val', text: valueText || fmt.pct(pct) }),
          ])
        : null,
      el('div', { class: `meter ${tone}` }, el('i', { style: `width:${pct}%` })),
    ]);
  },

  table(headers, rows) {
    if (!rows.length) return el('p', { class: 'empty', text: 'No records yet.' });
    const thead = el('tr', {}, headers.map((h) => el('th', { class: h.num ? 'num' : '', text: h.label ?? h })));
    const tbody = rows.map((cells) =>
      el(
        'tr',
        { class: cells.trClass || '' },
        cells.cells.map((c) => {
          const cell = el(c.num ? 'td' : 'td', { class: c.num ? 'num' : '' });
          if (c instanceof Node) cell.append(c);
          else cell.textContent = c === null || c === undefined ? '—' : String(c);
          return cell;
        })
      )
    );
    return el('div', { class: 'table-wrap' }, el('table', {}, [el('thead', {}, thead), el('tbody', {}, tbody)]));
  },

  card(title, children, { actions = [], badge = null, flush = false } = {}) {
    const head = title
      ? el('div', { class: 'card-head' }, [
          el('h2', { text: title }),
          el('div', { class: 'row' }, [badge, ...actions].filter(Boolean)),
        ])
      : null;
    return el('section', { class: `card ${flush ? 'card-flush' : ''}` }, [head, ...[].concat(children).filter(Boolean)]);
  },

  tabs(items) {
    // items: [{id, label, render: () => Node}]
    const panel = el('div', { class: 'tabpanel' });
    const bar = el('div', { class: 'tabs', role: 'tablist' });
    const buttons = items.map((item) => {
      const b = el('button', {
        type: 'button',
        role: 'tab',
        text: item.label,
        'aria-selected': item.id === items[0].id ? 'true' : 'false',
        onclick: () => {
          for (const other of buttons) other.setAttribute('aria-selected', 'false');
          b.setAttribute('aria-selected', 'true');
          clear(panel).append(item.render());
        },
      });
      bar.append(b);
      return b;
    });
    panel.append(items[0].render());
    return el('div', {}, [bar, panel]);
  },

  loading(n = 3) {
    return el('div', { class: 'grid' }, Array.from({ length: n }, () => el('div', { class: 'skeleton' })));
  },

  /** Score dial with conic-gradient meter (no canvas, no images). */
  dial(score) {
    const pct = Math.max(0, Math.min(100, Number(score) || 0));
    const tone = pct >= 80 ? '' : pct >= 50 ? 'mid' : 'low';
    return el('div', { class: `dial ${tone}`, style: `--pct:${pct}`, role: 'img', 'aria-label': `Security score ${pct} of 100` }, [
      el('div', { class: 'dial-val', text: String(pct) }),
      el('div', { class: 'dial-lbl', text: 'score' }),
    ]);
  },
};

/* ─── Canvas charts (dependency-free, DPR-aware) ──────────────────────── */

const Chart = {
  base(canvas, height) {
    const dpr = window.devicePixelRatio || 1;
    const w = canvas.clientWidth || canvas.parentElement.clientWidth || 600;
    const h = height || canvas.clientHeight || 180;
    canvas.width = Math.max(1, Math.round(w * dpr));
    canvas.height = Math.max(1, Math.round(h * dpr));
    canvas.style.height = `${h}px`;
    const ctx = canvas.getContext('2d');
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, w, h);
    return { ctx, w, h };
  },

  /** Line chart of score history. points: [{label, value|null}] */
  line(canvas, points, { height = 190, yLabel = '' } = {}) {
    const { ctx, w, h } = Chart.base(canvas, height);
    const pad = { l: 34, r: 12, t: 14, b: 26 };
    const iw = w - pad.l - pad.r;
    const ih = h - pad.t - pad.b;

    ctx.strokeStyle = 'rgba(120,145,220,0.18)';
    ctx.lineWidth = 1;
    ctx.font = '11px system-ui, sans-serif';
    ctx.fillStyle = '#7d8db8';
    for (let g = 0; g <= 4; g++) {
      const y = pad.t + (ih * g) / 4;
      ctx.beginPath();
      ctx.moveTo(pad.l, y);
      ctx.lineTo(pad.l + iw, y);
      ctx.stroke();
      ctx.textAlign = 'right';
      ctx.fillText(String(100 - g * 25), pad.l - 6, y + 4);
    }
    if (!points.length) {
      ctx.textAlign = 'center';
      ctx.fillText('No completed sessions yet', w / 2, h / 2);
      return;
    }

    const xAt = (i) => pad.l + (points.length === 1 ? iw / 2 : (iw * i) / (points.length - 1));
    const yAt = (v) => pad.t + ih * (1 - Math.max(0, Math.min(100, v)) / 100);

    const vals = points.map((p) => p.value).filter((v) => v !== null && v !== undefined);
    if (vals.length > 1) {
      const grad = ctx.createLinearGradient(0, pad.t, 0, pad.t + ih);
      grad.addColorStop(0, 'rgba(92,179,255,0.35)');
      grad.addColorStop(1, 'rgba(92,179,255,0)');
      ctx.beginPath();
      ctx.moveTo(xAt(0), yAt(vals[0]));
      vals.forEach((v, i) => ctx.lineTo(xAt(i), yAt(v)));
      ctx.lineTo(xAt(vals.length - 1), pad.t + ih);
      ctx.lineTo(xAt(0), pad.t + ih);
      ctx.closePath();
      ctx.fillStyle = grad;
      ctx.fill();
    }

    ctx.beginPath();
    let started = false;
    points.forEach((p, i) => {
      if (p.value === null || p.value === undefined) return;
      const x = xAt(i);
      const y = yAt(p.value);
      if (!started) { ctx.moveTo(x, y); started = true; } else ctx.lineTo(x, y);
    });
    ctx.strokeStyle = '#5cb3ff';
    ctx.lineWidth = 2.5;
    ctx.lineJoin = 'round';
    ctx.stroke();

    points.forEach((p, i) => {
      if (p.value === null || p.value === undefined) return;
      ctx.beginPath();
      ctx.arc(xAt(i), yAt(p.value), 3.5, 0, Math.PI * 2);
      ctx.fillStyle = '#5cb3ff';
      ctx.fill();
    });

    ctx.fillStyle = '#7d8db8';
    ctx.textAlign = 'center';
    const every = Math.ceil(points.length / 6);
    points.forEach((p, i) => {
      if (i % every !== 0 && i !== points.length - 1) return;
      ctx.fillText(p.label, xAt(i), h - 8);
    });
    if (yLabel) {
      ctx.textAlign = 'left';
      ctx.fillText(yLabel, 4, 12);
    }
  },

  /** Horizontal funnel bars: [{label, value, color}] */
  funnel(canvas, rows, { height = 0 } = {}) {
    const h = height || Math.max(70, rows.length * 34 + 14);
    const { ctx, w } = Chart.base(canvas, h);
    const max = Math.max(1, ...rows.map((r) => r.value));
    const labelW = 132;
    rows.forEach((r, i) => {
      const y = 8 + i * 34;
      ctx.font = '12px system-ui, sans-serif';
      ctx.fillStyle = '#a6b6e0';
      ctx.textAlign = 'left';
      ctx.fillText(r.label, 0, y + 12);
      const bw = (w - labelW - 46) * (r.value / max);
      ctx.fillStyle = 'rgba(120,145,220,0.14)';
      ctx.fillRect(labelW, y, w - labelW - 46, 20);
      ctx.fillStyle = r.color || '#5cb3ff';
      ctx.fillRect(labelW, y, Math.max(2, bw), 20);
      ctx.fillStyle = '#eef2ff';
      ctx.textAlign = 'right';
      ctx.fillText(String(r.value), w, y + 14);
    });
  },
};

/* ─── Capability + integrity helpers (WebXR / security) ───────────────── */

const Capability = {
  /**
   * Feature-detect WebXR. Never prompts for permissions (architecture.md §6).
   * @returns {Promise<{supported:boolean, mode:string, reasons:string[]}>}
   */
  async detectXR() {
    const reasons = [];
    if (!('xr' in navigator) || typeof navigator.xr.isSessionSupported !== 'function') {
      reasons.push('navigator.xr unavailable');
      return { supported: false, vr: false, ar: false, mode: 'desktop', reasons };
    }
    let vr = false;
    let ar = false;
    try {
      vr = await navigator.xr.isSessionSupported('immersive-vr');
    } catch (err) {
      reasons.push('vr check failed');
    }
    try {
      ar = await navigator.xr.isSessionSupported('immersive-ar');
    } catch (err) {
      reasons.push('ar check failed');
    }
    const coarse = window.matchMedia('(pointer: coarse)').matches;
    return {
      supported: vr || ar,
      vr,
      ar,
      mode: vr ? 'vr' : ar ? 'ar' : coarse ? 'mobile' : 'desktop',
      secure: window.isSecureContext,
      reasons,
    };
  },

  /**
   * Verify a scenario bundle's SHA-256 integrity before rendering (SI-7).
   * WebCrypto requires a secure context; on plain-HTTP LAN access we report
   * "unverified" instead of silently pretending the check passed.
   */
  async verifyIntegrity(bundle) {
    if (!bundle || typeof bundle.integrity !== 'string') return { state: 'absent' };
    if (!window.crypto || !window.crypto.subtle || !window.isSecureContext) {
      return { state: 'unavailable', reason: 'non-secure context' };
    }
    try {
      const bytes = new TextEncoder().encode(JSON.stringify(bundle.nodes));
      const digest = await window.crypto.subtle.digest('SHA-256', bytes);
      const hex = [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('');
      return hex === bundle.integrity
        ? { state: 'verified', hash: hex }
        : { state: 'failed', expected: bundle.integrity, actual: hex };
    } catch (err) {
      return { state: 'error', reason: err.message };
    }
  },
};

/* ─── Aggregate-only telemetry (architecture.md §6, GDPR Art.25) ──────── */

const Telemetry = {
  allowed: new Set(),
  buffer: [],
  sessionId: null,

  configure(allowed, sessionId) {
    this.allowed = new Set(Array.isArray(allowed) ? allowed : []);
    this.sessionId = sessionId;
    this.buffer = [];
  },

  /** Record an allow-listed event type. No free-text, no sensor data, ever. */
  record(type) {
    if (!this.allowed.has(type) || !this.sessionId) return;
    if (this.buffer.length >= 200) return;
    this.buffer.push({ type, at: Date.now() });
  },

  async flush() {
    if (!this.sessionId || this.buffer.length === 0) return;
    const events = this.buffer.splice(0, this.buffer.length);
    try {
      await API.post(`/api/sessions/${this.sessionId}/telemetry`, { events });
    } catch {
      // Telemetry is best-effort and never blocks the learning flow.
    }
  },
};

Object.assign(window.XR, {
  $, $$, el, frag, clear, fmt, Store, API, friendlyError, Toast, Modal, UI, Chart, Capability, Telemetry,
  FRIENDLY,
});
