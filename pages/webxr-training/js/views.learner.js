/* eslint-env browser */
/**
 * views.learner.js — Welcome, module catalog, immersive player, debrief,
 * personal dashboard and the simulated-threat inbox.
 *
 * All views are pure render functions returning DOM nodes. The server remains
 * the only authority for identity and scores (OWASP A04).
 */
'use strict';

(function () {
  const { $, $$, el, clear, frag, fmt, Store, API, UI, Toast, Modal, Chart, Capability, Telemetry, Stage, friendlyError } = window.XR;

  const Views = {};

  /* ─── Welcome / sign-in ─────────────────────────────────────────────── */

  Views.login = function login() {
    const wrap = el('div', { class: 'login-wrap' });
    const err = el('p', { class: 'alert error', id: 'login-error', hidden: true, role: 'alert' });
    const email = el('input', { type: 'email', id: 'login-email', autocomplete: 'username', required: true, placeholder: 'you@yourcompany.com' });
    const pass = el('input', { type: 'password', id: 'login-password', autocomplete: 'current-password', required: true });
    const submit = el('button', { type: 'submit', class: 'btn primary block', text: 'Sign in' });
    const demo = el('button', { type: 'button', class: 'btn ghost block', text: '🎓 Try demo (learner)' });

    const showErr = (msg) => {
      err.textContent = msg;
      err.hidden = false;
    };

    const doLogin = async (path, body) => {
      submit.disabled = true;
      demo.disabled = true;
      err.hidden = true;
      try {
        const r = await API.post(path, body);
        Store.setToken(r.token);
        Store.user = r.user;
        Toast.ok(`Welcome, ${r.user.name}`);
        window.App.afterLogin();
      } catch (e) {
        showErr(friendlyError(e));
        submit.disabled = false;
        demo.disabled = false;
      }
    };

    const form = el('form', {
      onsubmit: (e) => {
        e.preventDefault();
        doLogin('/api/auth/login', { email: email.value.trim(), password: pass.value });
      },
    }, [
      el('label', { text: 'Work email' }, email),
      el('label', { text: 'Password' }, pass),
      submit,
    ]);

    demo.addEventListener('click', () => doLogin('/api/auth/demo-login', {}));

    wrap.append(
      el('section', { class: 'card login-card' }, [
        el('div', { class: 'center' }, [
          el('div', { style: 'font-size:2.6rem', 'aria-hidden': 'true', text: '🥽' }),
          el('h1', { text: 'Security Awareness Training' }),
          el('p', { class: 'muted', text: 'Immersive, browser-native drills for phishing, vishing, tailgating, data handling and ransomware response. No install, no headset required.' }),
        ]),
        form,
        el('div', { class: 'divider', text: 'or' }),
        demo,
        err,
        el('p', { class: 'small muted mt', text: 'Access is rate-limited and every security event lands in a hash-chained audit log (ISO/IEC 27001 A.8.15). Telemetry is aggregate-only and opt-in at the device level — no camera, microphone or gaze data ever leaves your headset.' }),
      ])
    );
    return wrap;
  };

  /* ─── Home / command centre ─────────────────────────────────────────── */

  Views.home = async function home() {
    const root = el('div');
    const [xr, stats] = await Promise.all([
      Capability.detectXR(),
      API.get('/api/stats/risk').catch(() => null),
    ]);

    const hero = el('section', { class: 'hero' }, [
      el('h1', { text: `Welcome back, ${Store.user.name}` }),
      el('p', {
        class: 'lede',
        text: 'Six immersive micro-drills (5–12 min each) that turn security policy into muscle memory. Scores are computed server-side and recorded as xAPI evidence for ISO/IEC 27001 A.6.3.',
      }),
      el('div', { class: 'hero-actions' }, [
        el('a', { class: 'btn primary', href: '#/modules', text: '▶ Start a drill' }),
        el('a', { class: 'btn', href: '#/threats', text: '📬 Triage simulated threats' }),
        el('a', { class: 'btn ghost', href: '#/compliance', text: '🏛️ Framework alignment' }),
      ]),
      el('div', { class: 'xr-strip' }, [
        xrChip('Device mode', xr.mode.toUpperCase(), xr.mode !== 'desktop'),
        xrChip('Immersive VR', xr.vr ? 'available' : 'not available', xr.vr),
        xrChip('Immersive AR', xr.ar ? 'available' : 'not available', xr.ar),
        xrChip('Secure context', xr.secure ? 'yes (crypto available)' : 'no — integrity check limited', xr.secure),
        xrChip('Reduced motion', window.matchMedia('(prefers-reduced-motion: reduce)').matches ? 'on' : 'off', false),
      ]),
    ]);

    const tiles = el('div', { class: 'stat-grid' }, [
      UI.stat(fmt.num(stats && stats.completed), 'Modules completed', { sub: `${fmt.num(stats && stats.totalSessions)} sessions started` }),
      UI.stat(fmt.num(stats && stats.avgRiskScore), 'Average security score', { tone: fmt.cls(stats && stats.avgRiskScore), sub: 'server-computed' }),
      UI.stat(fmt.num(stats && stats.totalTrapHits), 'Traps triggered', { tone: (stats && stats.totalTrapHits > 0) ? 'warn' : 'good' }),
      UI.stat(fmt.num(Store.modules.length || 6), 'Modules in catalog', { sub: 'architecture.md §6' }),
    ]);

    const nextUp = el('section', { class: 'card' }, [
      el('div', { class: 'card-head' }, [
        el('h2', { text: 'Recommended next' }),
        el('a', { class: 'btn sm ghost', href: '#/modules', text: 'All modules →' }),
      ]),
    ]);
    const list = el('div', { class: 'grid' });
    const weakest = stats && stats.weakestModule;
    const suggestions = Store.modules.filter((m) => m.id === weakest).concat(Store.modules.filter((m) => m.id !== weakest));
    for (const m of suggestions.slice(0, 3)) list.append(moduleCard(m, { compact: true }));
    nextUp.append(list);

    const posture = el('section', { class: 'card' }, [
      el('h2', { text: '🔐 Platform security posture' }),
      el('div', { class: 'grid-3' }, [
        postureItem('Strict CSP', "script-src 'self' · no inline, no eval", 'A03'),
        postureItem('Hash-chained audit', 'every auth/session/admin event', 'A.8.15'),
        postureItem('Server-side scoring', 'client scores are ignored', 'A04'),
        postureItem('PII encrypted at rest', 'AES-256-GCM per field', 'A.8.24'),
        postureItem('Rate limiting', '5 login attempts / min / IP', 'A07'),
        postureItem('Object-level authz', 'no cross-user session reads', 'A01'),
      ]),
    ]);

    root.append(hero, el('div', { class: 'card' }, [el('h2', { text: 'Your standing' }), tiles]), nextUp, posture);
    return root;
  };

  const xrChip = (label, value, on) =>
    el('span', { class: `xr-chip ${on ? 'on' : ''}` }, [el('b', { text: value }), ' ', label]);

  const postureItem = (title, detail, ref) =>
    el('div', { class: 'principle' }, [
      el('div', { class: 'row spread' }, [el('h4', { text: title }), el('span', { class: 'badge plain mono', text: ref })]),
      el('p', { text: detail }),
    ]);

  /* ─── Module catalog ────────────────────────────────────────────────── */

  function moduleCard(m, { compact = false, progress = null } = {}) {
    const done = progress && progress.completed > 0;
    const card = el('article', { class: `card module-card ${done ? 'done' : ''}` }, [
      el('div', { class: 'row spread' }, [
        el('span', { class: 'badge', text: m.category }),
        el('span', { class: 'small faint mono', text: m.ref }),
      ]),
      el('h3', {}, [el('span', { class: 'visual', 'aria-hidden': 'true', text: m.visual }), el('span', { text: m.title.replace(/^\S+\s/, '') })]),
      el('p', { class: 'muted small mb0', text: m.description }),
      el('div', { class: 'meta' }, [
        el('span', { text: `⏱ ${m.durationMin} min` }),
        el('span', { text: `🧩 ${m.nodeCount} decisions` }),
        el('span', { text: `⚠ ${m.trapCount} traps` }),
        el('span', { text: `⚖ weight ×${m.riskWeight}` }),
        el('span', { text: `🏅 ${m.xp} XP` }),
      ]),
      compact
        ? null
        : el('ul', { class: 'objectives' }, m.objectives.map((o) => el('li', { text: o }))),
      el('div', { class: 'card-foot' }, [
        el('span', { class: 'progress-note', text: progress ? (done ? `Best ${progress.best}% · ${progress.completed} run(s)` : 'Not attempted') : '' }),
        el('button', { class: 'btn primary', text: done ? 'Run again' : 'Start drill', onclick: () => Views.startModule(m.id) }),
      ]),
    ]);
    return card;
  }
  Views.moduleCard = moduleCard;

  Views.modules = async function modules() {
    const root = el('div');
    const head = el('div', { class: 'page-head' }, [
      el('div', {}, [
        el('h1', { text: 'Training Modules' }),
        el('p', { class: 'lede', text: 'Immersive scenario drills mapped to ISO/IEC 27001 A.6.3 awareness objectives. Every drill ends with a server-computed debrief you can export.' }),
      ]),
      el('div', { class: 'page-head-actions' }, [el('a', { class: 'btn sm', href: '#/threats', text: '📬 Simulated threats' })]),
    ]);
    const grid = el('div', { class: 'grid' });
    const filters = el('div', { class: 'chip-row mb0' });

    let sessions = [];
    try {
      sessions = (await API.get('/api/sessions')).sessions || [];
    } catch { /* non-fatal: progress hints simply stay empty */ }

    const progressFor = (id) => {
      const rel = sessions.filter((s) => s.moduleId === id && s.status === 'completed' && s.riskScore !== null);
      if (!rel.length) return null;
      return { completed: rel.length, best: Math.max(...rel.map((s) => s.riskScore)) };
    };

    const render = (cat) => {
      clear(grid);
      const items = Store.modules.filter((m) => cat === 'all' || m.category === cat);
      if (!items.length) {
        grid.append(el('p', { class: 'empty', text: 'No modules in this category.' }));
        return;
      }
      for (const m of items) grid.append(moduleCard(m, { progress: progressFor(m.id) }));
    };

    const cats = Store.categories.length ? Store.categories : [{ id: 'all', label: 'All modules' }];
    for (const c of cats) {
      const count = c.id === 'all' ? Store.modules.length : Store.modules.filter((m) => m.category === c.id).length;
      const b = el('button', {
        class: 'chip',
        type: 'button',
        'aria-pressed': c.id === 'all' ? 'true' : 'false',
        text: `${c.visual || ''} ${c.label} (${count})`.trim(),
        onclick: () => {
          for (const other of $$('.chip', filters)) other.setAttribute('aria-pressed', 'false');
          b.setAttribute('aria-pressed', 'true');
          render(c.id);
        },
      });
      filters.append(b);
    }
    render('all');

    root.append(head, el('section', { class: 'card' }, [filters]), grid);
    return root;
  };

  /* ─── Immersive player ──────────────────────────────────────────────── */

  Views.startModule = async function startModule(moduleId) {
    try {
      const xr = await Capability.detectXR();
      const r = await API.post('/api/sessions/start', { moduleId, deviceClass: xr.mode });
      Store.run = { session: r.session, module: r.module, idx: 0, results: [], integrity: null, xr };
      Telemetry.configure(r.module.telemetry || [], r.session.id);
      location.hash = '#/play';
    } catch (e) {
      Toast.err(friendlyError(e));
    }
  };

  Views.play = async function play() {
    const run = Store.run;
    if (!run || !run.module) {
      location.hash = '#/modules';
      return el('div');
    }
    const { module: mod, session } = run;
    const root = el('div');
    const stageBox = el('div', { class: 'stage' });
    const body = el('div', { class: 'player-body' });
    root.append(el('section', { class: 'card player-shell' }, [stageBox, body]));

    // Integrity verification happens BEFORE the first frame (NIST SI-7).
    run.integrity = await Capability.verifyIntegrity(mod);
    if (run.integrity.state === 'failed') {
      Toast.err('Bundle integrity check FAILED — refusing to render this scenario.');
      return el('div', {}, UI.card('🛑 Integrity failure', el('p', {
        class: 'error',
        text: 'The scenario bundle did not match its signed SHA-256 hash. The run has been aborted (OWASP A08 — software & data integrity). Contact your administrator.',
      })));
    }
    Telemetry.record('integrity.checked');

    const stage = new Stage(stageBox);
    stage.setScene(mod.nodes[run.idx] ? mod.nodes[run.idx].scene || mod.scene : mod.scene);
    stage.start();

    const hud = el('div', { class: 'hud' });
    const integrityBadge =
      run.integrity.state === 'verified'
        ? el('span', { class: 'hud-chip good', text: '✓ bundle integrity verified (SHA-256)' })
        : el('span', { class: 'hud-chip', text: `⚠ integrity ${run.integrity.state}` });
    hud.append(
      el('span', { class: 'hud-chip', text: `🧩 ${mod.ref} ${mod.scene}` }),
      el('span', { class: 'hud-chip', text: '◉ interactive-3D fallback' }),
      el('span', { class: 'hud-chip', text: `🎮 ${session.deviceClass}` }),
      el('span', { class: 'spacer' }),
      integrityBadge,
      el('span', { class: 'hud-chip', id: 'hud-progress', text: 'Node 1' })
    );
    stage.overlay.insertBefore(hud, stage.overlay.firstChild);

    let xrActive = false;
    if (run.xr && (run.xr.vr || run.xr.ar)) {
      const vrBtn = el('button', { class: 'hud-chip', type: 'button', text: `🥽 Enter ${run.xr.vr ? 'VR' : 'AR'}` });
      vrBtn.addEventListener('click', async () => {
        try {
          await stage.enterXR(run.xr.vr ? 'immersive-vr' : 'immersive-ar');
          xrActive = true;
          vrBtn.textContent = '⏹ Exit immersive';
          vrBtn.addEventListener('click', async () => { await stage.exitXR(); xrActive = false; vrBtn.textContent = '🥽 Re-enter'; });
          Toast.ok('Immersive session started — use your headset or hand controllers.');
        } catch (e) {
          Toast.warn(`Immersive mode unavailable (${e.message}) — continuing in interactive 3D.`);
        }
      });
      hud.insertBefore(vrBtn, integrityBadge);
    }

    const progressBar = el('i', { style: 'width:0%' });
    const prompt = el('p', { class: 'prompt' });
    const feedback = el('div', { class: 'feedback', hidden: true });
    const options = el('div', { class: 'options' });

    body.append(
      el('div', { class: 'progress-track' }, progressBar),
      prompt,
      feedback,
      options,
      el('div', { class: 'row spread mt' }, [
        el('span', { class: 'small faint', id: 'hud-telemetry', text: 'Aggregate telemetry: 0 events buffered (no sensor data collected)' }),
        el('button', {
          class: 'btn ghost sm',
          text: 'Abandon run',
          onclick: async () => {
            await Telemetry.flush();
            stage.destroy();
            Store.run = null;
            location.hash = '#/modules';
          },
        }),
      ])
    );

    const telemetryNote = $('#hud-telemetry', body);

    function renderNode() {
      const node = mod.nodes[run.idx];
      stage.setScene(node.scene || mod.scene);
      Telemetry.record('scene.enter');
      const pct = Math.round(((run.idx) / mod.nodes.length) * 100);
      progressBar.style.width = `${pct}%`;
      $('#hud-progress', hud).textContent = `Node ${run.idx + 1}/${mod.nodes.length}`;
      prompt.textContent = node.prompt;
      feedback.hidden = true;
      clear(options);
      for (const opt of node.options) {
        options.append(
          el('button', {
            class: 'option',
            type: 'button',
            onclick: () => choose(node, opt),
          }, [el('span', { class: 'key', text: opt.id }), el('span', { text: opt.text })])
        );
      }
    }

    function choose(node, opt) {
      const good = opt.id === node.correct;
      run.results.push({ nodeId: node.id, choice: opt.id });
      Telemetry.record('choice.make');
      Telemetry.record('feedback.view');
      if (telemetryNote) telemetryNote.textContent = `Aggregate telemetry: ${Telemetry.buffer.length} events buffered (no sensor data collected)`;

      // Mark the chosen option and lock the set (single answer per node).
      for (const b of $$('.option', options)) {
        b.disabled = true;
        b.classList.add('locked');
        if (b.firstChild && b.firstChild.textContent === opt.id) {
          b.classList.add('chosen', good ? 'correct' : 'wrong');
          if (!good) b.classList.add('trap-flash');
        }
      }
      feedback.className = `feedback ${good ? 'good' : 'bad'}`;
      clear(feedback);
      feedback.append(
        el('b', { text: good ? '✅ Correct decision' : '⚠️ Weak spot identified' }),
        el('span', { text: node.explain })
      );
      feedback.hidden = false;
      if (!good) stage.alertPulse();

      const last = run.idx + 1 >= mod.nodes.length;
      options.append(
        el('div', { class: 'row mt' }, [
          el('button', {
            class: 'btn primary',
            type: 'button',
            text: last ? 'Finish & debrief →' : 'Next scene →',
            onclick: () => {
              run.idx += 1;
              if (run.idx < mod.nodes.length) renderNode();
              else finish();
            },
          }),
          el('span', { class: 'small faint', text: good ? '+1 secure decision' : 'Server re-validates every answer at submit' }),
        ])
      );
    }

    async function finish() {
      clear(options);
      options.append(el('p', { class: 'muted', text: 'Submitting decisions for server-side scoring…' }));
      try {
        await Telemetry.flush();
        const r = await API.post(`/api/sessions/${session.id}/complete`, { results: run.results });
        Store.run = null;
        stage.destroy();
        App.pendingDebrief = r;
        if (location.hash === '#/debrief') App.render();
        else location.hash = '#/debrief';
      } catch (e) {
        Toast.err(friendlyError(e));
        options.append(el('button', { class: 'btn', text: 'Retry submit', onclick: finish }));
      }
    }

    renderNode();
    return root;
  };

  /* ─── Debrief ───────────────────────────────────────────────────────── */

  Views.debrief = function debrief() {
    const data = App.pendingDebrief;
    if (!data) {
      location.hash = '#/dashboard';
      return el('div');
    }
    const { score, debrief: db, session } = data;
    const root = el('div');
    const modTitle = (Store.modules.find((m) => m.id === session.moduleId) || {}).title || session.moduleId;

    const headline =
      score.riskScore >= 80 ? 'Excellent — strong security instincts' :
      score.riskScore >= 50 ? 'Passable — review the weak spots below' :
      'High risk — repeat this drill after reviewing the debrief';

    root.append(
      el('div', { class: 'page-head' }, [
        el('div', {}, [
          el('h1', { text: 'Session debrief' }),
          el('p', { class: 'lede', text: `${modTitle} · session ${session.id.slice(0, 12)} · device ${session.deviceClass} · completed ${fmt.stamp(session.completedAt)}` }),
        ]),
        el('div', { class: 'page-head-actions' }, [
          el('a', { class: 'btn sm', href: '#/modules', text: 'Back to modules' }),
          el('a', { class: 'btn sm primary', href: '#/dashboard', text: 'View dashboard' }),
        ]),
      ])
    );

    root.append(
      el('section', { class: 'card' }, [
        el('div', { class: 'score-hero' }, [
          UI.dial(score.riskScore),
          el('div', { style: 'flex:1;min-width:240px' }, [
            el('h2', { text: headline }),
            el('p', { class: 'muted', text: 'Scores are recomputed on the server from the signed scenario catalog — the browser never decides your result (OWASP A04: Insecure Design).' }),
            el('div', { class: 'stat-grid' }, [
              UI.stat(`${score.correct}/${score.total}`, 'Correct decisions', { tone: 'good' }),
              UI.stat(score.trapHits, 'Traps triggered', { tone: score.trapHits ? 'bad' : 'good' }),
              UI.stat(fmt.num((Store.modules.find((m) => m.id === session.moduleId) || {}).xp), 'XP awarded', { tone: 'good' }),
            ]),
          ]),
        ]),
      ])
    );

    const review = el('section', { class: 'card' }, [el('h2', { text: 'Decision-by-decision review' })]);
    for (const n of db.nodes) {
      review.append(
        el('article', { class: `review-item ${n.isCorrect ? 'correct' : n.trapped ? 'trapped' : 'wrong'}` }, [
          el('div', { class: 'row spread' }, [
            el('span', { class: 'badge ' + (n.isCorrect ? 'good' : n.trapped ? 'warn' : 'bad'), text: n.isCorrect ? 'Correct' : n.trapped ? 'Trap triggered' : 'Incorrect' }),
            el('span', { class: 'small faint mono', text: `${n.scene} · ${n.nodeId}` }),
          ]),
          el('div', { class: 'rq', text: n.prompt }),
          el('div', { class: 'ra' }, ['Your answer: ', el('b', { text: n.chosenText })]),
          n.isCorrect ? null : el('div', { class: 'rc', text: `Correct answer: ${n.correctText}` }),
          el('div', { class: 'rx', text: n.explain }),
        ])
      );
    }
    root.append(review);

    root.append(
      el('section', { class: 'card' }, [
        el('div', { class: 'card-head' }, [
          el('h2', { text: 'xAPI 1.0.3 learning record' }),
          el('span', { class: 'badge purple', text: 'LRS statement' }),
        ]),
        el('p', { class: 'small muted', text: 'Emitted server-side on completion — exportable to any LMS via LTI 1.3 / xAPI (ISO A.6.3 evidence, ADL xAPI 1.0.3).' }),
        el('pre', { class: 'xapi-block', text: JSON.stringify((session.xapi || [])[(session.xapi || []).length - 1] || {}, null, 2) }),
        el('p', { class: 'small faint mono mt', text: `Aggregate telemetry recorded: ${JSON.stringify(session.telemetry || {})}` }),
      ])
    );
    return root;
  };

  /* ─── Personal dashboard ────────────────────────────────────────────── */

  Views.dashboard = async function dashboard() {
    const root = el('div');
    const [stats, list] = await Promise.all([API.get('/api/stats/risk'), API.get('/api/sessions')]);
    const sessions = (list.sessions || []).slice().reverse();

    root.append(
      el('div', { class: 'page-head' }, [
        el('div', {}, [
          el('h1', { text: 'My training dashboard' }),
          el('p', { class: 'lede', text: 'Personal risk posture, module coverage and simulation resilience. Admins additionally see the organization-wide rollup in the Admin console.' }),
        ]),
        el('div', { class: 'page-head-actions' }, [
          el('a', { class: 'btn sm', href: '#/modules', text: 'Continue training' }),
          Store.isAdmin() ? el('a', { class: 'btn sm primary', href: '#/admin', text: 'Admin console →' }) : null,
        ]),
      ])
    );

    root.append(
      el('section', { class: 'card' }, [
        el('div', { class: 'stat-grid' }, [
          UI.stat(fmt.num(stats.avgRiskScore), 'Average security score', { tone: fmt.cls(stats.avgRiskScore) }),
          UI.stat(fmt.num(stats.completed), 'Completed drills', { sub: `${fmt.num(stats.active)} in progress` }),
          UI.stat(fmt.num(stats.totalTrapHits), 'Traps triggered', { tone: stats.totalTrapHits ? 'warn' : 'good' }),
          UI.stat(fmt.num(Object.keys(stats.byModule || {}).length), 'Modules covered', { sub: `of ${Store.modules.length || 6}` }),
        ]),
      ])
    );

    // Score trend
    const completed = sessions.filter((s) => s.status === 'completed' && s.riskScore !== null);
    const trendCard = el('section', { class: 'card' }, [el('h2', { text: 'Score trend' })]);
    const canvas = el('canvas', { 'aria-label': 'Security score over recent completed drills', role: 'img' });
    trendCard.append(canvas);
    root.append(trendCard);
    requestAnimationFrame(() => {
      Chart.line(
        canvas,
        completed.slice(-12).map((s, i) => ({ label: `#${i + 1}`, value: s.riskScore })),
        { yLabel: 'score 0–100' }
      );
    });

    // Module heat list
    const byModule = stats.byModule || {};
    const modCard = el('section', { class: 'card' }, [el('h2', { text: 'Module breakdown' })]);
    if (!Object.keys(byModule).length) {
      modCard.append(el('p', { class: 'empty', text: 'Complete a drill to populate your module breakdown.' }));
    } else {
      for (const m of Store.modules) {
        const rec = byModule[m.id];
        if (!rec) continue;
        modCard.append(
          el('div', { class: 'mb0' }, [
            UI.meter(rec.avgScore, { label: `${m.visual} ${m.title.replace(/^\S+\s/, '')}`, valueText: `${rec.avgScore}%`, tone: fmt.cls(rec.avgScore) }),
            el('p', { class: 'small faint mt', text: `${rec.count} attempt(s) · trap rate ${Math.round((rec.trapRate || 0) * 100)}%` }),
          ])
        );
      }
      if (stats.weakestModule) {
        const wm = Store.modules.find((m) => m.id === stats.weakestModule);
        modCard.append(
          el('div', { class: 'alert warn mt' }, [
            el('b', { text: 'Focus area: ' }),
            `${wm ? wm.title : stats.weakestModule} is your weakest module (${byModule[stats.weakestModule].avgScore}%). Re-run it to lift your average.`,
          ])
        );
      }
    }
    root.append(modCard);

    // Simulation resilience
    try {
      const inbox = await API.get('/api/campaigns/inbox');
      const m = inbox.metrics || {};
      root.append(
        el('section', { class: 'card' }, [
          el('div', { class: 'card-head' }, [
            el('h2', { text: '📬 Simulated-threat resilience' }),
            el('a', { class: 'btn sm ghost', href: '#/threats', text: 'Open inbox →' }),
          ]),
          el('div', { class: 'stat-grid' }, [
            UI.stat(fmt.num(m.delivered), 'Simulations delivered'),
            UI.stat(fmt.num(m.pending), 'Awaiting your triage', { tone: m.pending ? 'warn' : 'good' }),
            UI.stat(fmt.pct(m.resilience), 'Correct triage rate', { tone: fmt.cls(m.resilience === null ? null : m.resilience) }),
            UI.stat(fmt.dur(m.avgTimeToReportSec), 'Avg time to report', { tone: 'good' }),
          ]),
        ])
      );
    } catch { /* simulation service optional in this deployment */ }

    // History table
    const hist = el('section', { class: 'card' }, [el('h2', { text: 'Session history' })]);
    hist.append(
      UI.table(
        [
          { label: 'Session' }, { label: 'Module' }, { label: 'Device' },
          { label: 'Score', num: true }, { label: 'Traps', num: true }, { label: 'Status' }, { label: 'Started' },
        ],
        sessions.slice(0, 25).map((s) => ({
          cells: [
            el('span', { class: 'mono', text: s.id.slice(0, 10) }),
            (Store.modules.find((m) => m.id === s.moduleId) || {}).title || s.moduleId,
            s.deviceClass || '—',
            s.riskScore === null ? '—' : el('b', { class: fmt.cls(s.riskScore), text: String(s.riskScore) }),
            s.trapHits === null ? '—' : String(s.trapHits),
            el('span', { class: 'badge ' + (s.status === 'completed' ? 'good' : 'warn'), text: s.status }),
            fmt.stamp(s.startedAt),
          ],
        }))
      )
    );
    root.append(hist);
    return root;
  };

  /* ─── Simulated threats inbox ───────────────────────────────────────── */

  Views.threats = async function threats() {
    const root = el('div');
    root.append(
      el('div', { class: 'page-head' }, [
        el('div', {}, [
          el('h1', { text: '📬 Simulated Threats' }),
          el('p', { class: 'lede', text: 'Security-awareness simulations launched by your security team. Triage them exactly as you would a real message — report, delete, or engage — then read the red flags you missed. Nothing here is a real message and no data leaves this platform.' }),
        ]),
      ])
    );

    const data = await API.get('/api/campaigns/inbox');
    const m = data.metrics || {};

    root.append(
      el('section', { class: 'card' }, [
        el('div', { class: 'stat-grid' }, [
          UI.stat(fmt.num(m.delivered), 'Messages delivered'),
          UI.stat(fmt.num(m.pending), 'Untriaged', { tone: m.pending ? 'warn' : 'good' }),
          UI.stat(fmt.num(m.reported), 'Reported to SOC', { tone: 'good' }),
          UI.stat(fmt.pct(m.resilience), 'Triage accuracy', { tone: fmt.cls(m.resilience) }),
        ]),
      ])
    );

    const inbox = el('section', { class: 'card' }, [
      el('div', { class: 'card-head' }, [
        el('h2', { text: 'Simulation inbox' }),
        el('span', { class: 'badge warn', text: 'Training simulation — not real mail' }),
      ]),
    ]);

    const messages = data.messages || [];
    if (!messages.length) {
      inbox.append(el('p', { class: 'empty', text: 'No simulations delivered to you yet. Your security team can launch one from the Admin console.' }));
    } else {
      const list = el('div', { class: 'mail-list' });
      for (const msg of messages) list.append(mailItem(msg, () => App.render()));
      inbox.append(list);
    }
    root.append(inbox);
    return root;
  };

  function mailItem(msg, onDone) {
    const actions = el('div', { class: 'mail-actions' });
    const container = el('article', { class: `mail ${msg.triagedAt ? 'triaged' : 'unread'}` });

    const done = msg.triagedAt !== null;
    if (done) {
      actions.append(
        el('span', {
          class: 'badge ' + (msg.correct ? 'good' : msg.action === 'click' || msg.action === 'reply' ? 'bad' : 'warn'),
          text: msg.correct ? '✔ Correctly reported' : `✖ You chose “${msg.action}”`,
        }),
        el('span', { class: 'small faint', text: `triaged ${fmt.ago(msg.triagedAt)}` })
      );
    } else {
      for (const [action, label, kind] of [
        ['report', '🚩 Report to security', 'good'],
        ['delete', '🗑️ Delete', ''],
        ['click', '🔗 Open the link', 'danger'],
        ['reply', '↩️ Reply to sender', 'danger'],
      ]) {
        actions.append(
          el('button', {
            class: `btn sm ${kind}`,
            type: 'button',
            text: label,
            onclick: (e) => submitTriage(msg, action, e.currentTarget, onDone),
          })
        );
      }
    }

    container.append(
      el('div', { class: 'mail-icon', 'aria-hidden': 'true', text: '✉️' }),
      el('div', {}, [
        el('div', { class: 'mail-head' }, [
          el('span', { class: 'mail-from', text: msg.fromName }),
          el('span', { class: 'mail-addr', text: `<${msg.fromAddress}>` }),
          el('span', { class: 'spacer' }),
          el('span', { class: 'badge plain', text: msg.vector }),
        ]),
        el('div', { class: 'mail-subject', text: msg.subject }),
        el('div', { class: 'mail-preview', text: msg.preview }),
        el('div', { class: 'small faint mt', text: `Delivered ${fmt.stamp(msg.sentAt)} · simulation ${msg.id.slice(0, 8)}` }),
        actions,
      ])
    );
    return container;
  }

  async function submitTriage(msg, action, btn, onDone) {
    const buttons = $$(`.mail-actions .btn`);
    for (const b of buttons) b.disabled = true;
    btn.textContent = 'Working…';
    try {
      const r = await API.post(`/api/campaigns/${msg.campaignId}/triage`, { messageId: msg.id, action });
      showTriageResult(msg, r.result);
      onDone();
    } catch (e) {
      Toast.err(friendlyError(e));
      for (const b of buttons) b.disabled = false;
      btn.textContent = 'Retry';
    }
  }

  function showTriageResult(msg, result) {
    const body = el('div', {}, [
      el('div', { class: `alert ${result.correct ? 'success' : 'warn'}` }, [
        el('b', { text: result.correct ? 'Correct call — reporting is the control that works. ' : `Best action here was “${result.correctAction}”. ` }),
        result.guidance,
      ]),
      el('h3', { class: 'mt', text: 'Red flags you should have spotted' }),
      el('ul', { class: 'redflag-list' }, result.redFlags.map((f) => el('li', { text: f }))),
      el('div', { class: 'row spread mt' }, [
        el('span', { class: 'badge plain', text: `vector: ${result.vector}` }),
        el('span', { class: 'badge ' + (result.severity === 'high' ? 'bad' : 'warn'), text: `severity: ${result.severity}` }),
        el('span', { class: 'small faint', text: `time to action: ${fmt.dur(result.timeToActionSec)}` }),
      ]),
    ]);
    Modal.open('Triage debrief', body, [
      { label: 'Open compliance mapping', kind: 'ghost', onClick: () => { window.XR.Modal.close(); location.hash = '#/compliance'; } },
    ]);
  }

  window.XR.Views = Object.assign(window.XR.Views || {}, Views);
})();
