/* eslint-env browser */
/**
 * views.governance.js — Compliance view (framework alignment) and the
 * admin console (users, campaigns, organization analytics, audit log,
 * evidence export).
 *
 * Admin routes are gated client-side for UX only; the server re-checks the
 * role on every request (OWASP A01 — the real enforcement point is the API).
 */
'use strict';

(function () {
  const { el, clear, fmt, Store, API, UI, Toast, Modal, Chart, friendlyError } = window.XR;
  const Views = {};

  /* ─── Compliance / framework alignment ──────────────────────────────── */

  Views.compliance = async function compliance() {
    const root = el('div');
    const f = await API.get('/api/frameworks');

    root.append(
      el('div', { class: 'page-head' }, [
        el('div', {}, [
          el('h1', { text: '🏛️ Framework alignment' }),
          el('p', { class: 'lede', text: `Live control mapping for ${f.META.name} v${f.META.version} — the same material that auditors review, rendered from the server so it can never drift from the implementation.` }),
        ]),
        el('div', { class: 'page-head-actions' }, [
          el('span', { class: 'badge plain', text: f.META.classification }),
          Store.isAdmin() ? el('a', { class: 'btn sm primary', href: '#/admin', text: 'Admin console →' }) : null,
        ]),
      ])
    );

    // Principles
    root.append(
      el('section', { class: 'card' }, [
        el('h2', { text: 'Architectural principles' }),
        el('div', { class: 'principle-grid' }, f.META.principles.map((p) =>
          el('div', { class: 'principle' }, [
            el('div', { class: 'p-icon', 'aria-hidden': 'true', text: p.icon }),
            el('h4', { text: p.title }),
            el('p', { text: p.detail }),
          ])
        )),
      ])
    );

    root.append(
      UI.tabs([
        { id: 'iso', label: 'ISO/IEC 27001:2022', render: () => isoPanel(f) },
        { id: 'owasp', label: 'OWASP Top 10', render: () => owaspPanel(f) },
        { id: 'nist', label: 'NIST CSF + 800-53', render: () => nistPanel(f) },
        { id: 'zt', label: 'Zero Trust (SP 800-207)', render: () => ztPanel(f) },
        { id: 'standards', label: 'Industry standards', render: () => standardsPanel(f) },
        { id: 'threats', label: 'Threat model (STRIDE)', render: () => threatPanel(f) },
        { id: 'kpi', label: 'KPIs & roadmap', render: () => kpiPanel(f) },
      ])
    );
    return root;
  };

  function isoPanel(f) {
    return el('div', {}, [
      el('section', { class: 'card' }, [
        el('h2', { text: 'Annex A — statement of applicability (key controls)' }),
        el('p', { class: 'muted small', text: 'A.6.3 (awareness & training) is the control this platform operationalises for customer ISMS: the drills themselves generate the evidence.' }),
        el('div', {}, f.ISO27001.map((c) =>
          el('div', { class: 'map-row' }, [
            el('div', { class: 'map-key', text: c.id }),
            el('div', { class: 'map-val' }, [
              el('strong', { text: c.title }),
              el('span', { text: c.requirement }),
              el('span', { class: 'small faint', text: `Implementation: ${c.implementation}` }),
              el('span', { class: 'small faint', text: `Evidence: ${c.evidence}` }),
            ]),
          ])
        )),
      ]),
    ]);
  }

  function owaspPanel(f) {
    return el('section', { class: 'card' }, [
      el('h2', { text: 'OWASP Top 10:2021 — defense in depth' }),
      UI.table(
        [{ label: '#' }, { label: 'Risk' }, { label: 'Threat to platform' }, { label: 'Mitigations' }, { label: 'Verified by' }],
        f.OWASP.map((r) => ({
          cells: [
            el('b', { class: 'mono', text: r.id }),
            el('span', { text: r.risk }),
            el('span', { class: 'muted', text: r.threat }),
            el('span', { class: 'muted', text: r.mitigations }),
            el('span', { class: 'small faint', text: r.verifiedBy }),
          ],
        }))
      ),
      el('p', { class: 'small faint mt', text: 'Verification baseline: OWASP ASVS 4.0 Level 2, WSTG pen-test scope, SAMM secure-SDLC maturity, API Security Top 10 for the gateway.' }),
    ]);
  }

  function nistPanel(f) {
    return el('div', {}, [
      el('section', { class: 'card' }, [
        el('h2', { text: 'NIST Cybersecurity Framework 2.0 — six functions' }),
        el('div', { class: 'csf-flow' }, f.NIST_CSF.map((fn, i) => [
          el('div', { class: 'csf-step' }, [
            el('div', { class: 'fn', text: `${fn.fn} · ${fn.subcategories}` }),
            el('h4', { text: fn.name }),
            el('p', { text: fn.controls }),
          ]),
          i < f.NIST_CSF.length - 1 ? el('div', { class: 'center faint', text: '→' }) : null,
        ])),
      ]),
      el('section', { class: 'card' }, [
        el('h2', { text: 'NIST SP 800-53 Rev.5 — selected control families' }),
        el('div', {}, f.NIST_800_53.map((c) =>
          el('div', { class: 'map-row' }, [
            el('div', { class: 'map-key', text: c.family }),
            el('div', { class: 'map-val' }, el('span', { text: c.controls })),
          ])
        )),
      ]),
    ]);
  }

  function ztPanel(f) {
    return el('div', {}, [
      el('section', { class: 'card' }, [
        el('h2', { text: 'Zero Trust Architecture — tenet → implementation' }),
        el('p', { class: 'muted small', text: 'Every request is authenticated, authorised and evaluated — there is no implicit trust in network location (deny-by-default policy decision point).' }),
        el('div', {}, f.ZERO_TRUST.map((z) =>
          el('div', { class: 'map-row' }, [
            el('div', { class: 'map-key', text: 'TENET' }),
            el('div', { class: 'map-val' }, [el('strong', { text: z.tenet }), el('span', { text: z.impl })]),
          ])
        )),
      ]),
      el('section', { class: 'card' }, [
        el('h2', { text: 'Authentication & session model (SP 800-63B)' }),
        UI.table([{ label: 'Item' }, { label: 'Standard applied' }], [
          { cells: ['Learner login', 'Federated OIDC/SAML to enterprise IdP → AAL2 (TOTP or WebAuthn)'] },
          { cells: ['Admin / author login', 'AAL2+ enforced — FIDO2/passkeys mandatory, step-up re-auth for destructive actions'] },
          { cells: ['Service-to-service', 'mTLS + SPIFFE/SPIRE workload identity'] },
          { cells: ['Session', '8h idle learner / 30min admin · server-side revocable · device-bound'] },
          { cells: ['Machine tokens', 'Short-lived (≤15min) JWTs, audience-restricted, key rotation ≤24h'] },
        ]),
      ]),
    ]);
  }

  function standardsPanel(f) {
    return el('section', { class: 'card' }, [
      el('h2', { text: 'Worldwide standards matrix' }),
      UI.table([{ label: 'Domain' }, { label: 'Standard' }, { label: 'How this solution complies' }],
        f.STANDARDS.map((s) => ({ cells: [s.domain, el('b', { text: s.standard }), el('span', { class: 'muted', text: s.compliance })] }))
      ),
    ]);
  }

  function threatPanel(f) {
    return el('section', { class: 'card' }, [
      el('div', { class: 'card-head' }, [
        el('h2', { text: 'Threat model — STRIDE × MITRE ATT&CK' }),
        el('span', { class: 'badge purple', text: `${f.THREATS.length} threats modelled` }),
      ]),
      el('p', { class: 'muted small', text: 'Reviewed per epic and quarterly; purple-team validated twice a year; top risks tracked in the ISO 27001 risk register with named owners.' }),
      UI.table([{ label: 'STRIDE' }, { label: 'Attack scenario' }, { label: 'Component' }, { label: 'ATT&CK' }, { label: 'Countermeasure' }, { label: 'Residual' }],
        f.THREATS.map((t) => ({
          trClass: 'threat-row',
          cells: [
            el('b', { text: t.stride }),
            t.scenario,
            el('span', { class: 'muted', text: t.component }),
            el('span', { class: 'mono small', text: t.attack }),
            el('span', { class: 'muted', text: t.countermeasure }),
            el('span', { class: `residual ${t.residual.startsWith('Low') ? 'low' : 'medium'}`, text: t.residual }),
          ],
        }))
      ),
    ]);
  }

  function kpiPanel(f) {
    return el('div', {}, [
      el('section', { class: 'card' }, [
        el('h2', { text: 'Success metrics (KPIs)' }),
        el('div', { class: 'grid-3' }, f.KPIS.map((k) =>
          el('div', { class: 'principle' }, [
            el('div', { class: 'row spread' }, [el('span', { class: 'badge plain', text: k.category }), el('span', { 'aria-hidden': 'true', text: k.icon })]),
            el('h4', { class: 'mt', text: k.kpi }),
            el('p', { text: k.target }),
          ])
        )),
      ]),
      el('section', { class: 'card' }, [
        el('h2', { text: 'Compliance roadmap & certification path' }),
        el('div', { class: 'roadmap' }, f.ROADMAP.map((p) =>
          el('div', { class: `phase ${p.tone}` }, [
            el('div', { class: 'p-win', text: `${p.phase} · ${p.window}` }),
            el('h4', { text: p.title }),
            el('ul', {}, p.items.map((i) => el('li', { text: i }))),
          ])
        )),
      ]),
    ]);
  }

  /* ─── Admin console ─────────────────────────────────────────────────── */

  Views.admin = async function admin() {
    if (!Store.isAdmin()) {
      return el('section', { class: 'card' }, [
        el('h1', { text: 'Admin console' }),
        el('div', { class: 'alert error', text: 'Forbidden — the admin role is required for this view (RBAC, ISO/IEC 27001 A.5.15). The API independently rejects these calls with HTTP 403.' }),
      ]);
    }

    const root = el('div');
    root.append(
      el('div', { class: 'page-head' }, [
        el('div', {}, [
          el('h1', { text: '🛡️ Admin console' }),
          el('p', { class: 'lede', text: 'Campaign orchestration, organization risk analytics, user provisioning (SCIM-style) and tamper-evident audit evidence for ISO/IEC 27001 A.6.3 and SOC 2 CC7.2.' }),
        ]),
        el('div', { class: 'page-head-actions' }, [
          el('button', { class: 'btn sm', text: '⬇ Export evidence pack', onclick: exportEvidence }),
          el('button', { class: 'btn sm primary', text: '＋ Launch simulation', onclick: launchCampaignDialog }),
        ]),
      ])
    );

    const body = el('div');
    root.append(body);

    const [analytics, campaignData, usersData] = await Promise.all([
      API.get('/api/admin/analytics'),
      API.get('/api/admin/campaigns'),
      API.get('/api/admin/users'),
    ]);

    const org = analytics.organization;
    const sim = analytics.campaigns;
    const totals = org.totals;

    body.append(
      el('section', { class: 'card' }, [
        el('h2', { text: 'Organization risk posture' }),
        el('div', { class: 'stat-grid' }, [
          UI.stat(fmt.num(totals.users), 'Provisioned users'),
          UI.stat(fmt.pct(totals.completionRate), 'Session completion rate', { tone: fmt.cls(totals.completionRate), sub: `${fmt.num(totals.completed)}/${fmt.num(totals.sessions)}` }),
          UI.stat(fmt.num(totals.avgScore), 'Average score', { tone: fmt.cls(totals.avgScore) }),
          UI.stat(fmt.pct(totals.coveragePct), 'Module coverage', { tone: fmt.cls(totals.coveragePct) }),
          UI.stat(fmt.num(totals.atRiskUsers), 'At-risk learners (<60)', { tone: totals.atRiskUsers ? 'bad' : 'good' }),
          UI.stat(fmt.num(totals.untrainedUsers), 'Not yet trained', { tone: totals.untrainedUsers ? 'warn' : 'good' }),
        ]),
      ])
    );

    // Simulation funnel
    const funnelCard = el('section', { class: 'card' }, [
      el('div', { class: 'card-head' }, [
        el('h2', { text: '🎯 Phishing simulation funnel' }),
        el('span', { class: 'badge warn', text: 'KPI: click-rate ↓ 60%' }),
      ]),
      el('div', { class: 'stat-grid' }, [
        UI.stat(fmt.num(sim.delivered), 'Simulations delivered'),
        UI.stat(fmt.pct(sim.reportRate), 'Reported to SOC', { tone: 'good' }),
        UI.stat(fmt.pct(sim.clickRate), 'Clicked / replied', { tone: sim.clickRate ? 'bad' : 'good' }),
        UI.stat(fmt.num(sim.pending), 'Pending triage', { tone: sim.pending ? 'warn' : 'good' }),
      ]),
    ]);
    const funnelCanvas = el('canvas', { role: 'img', 'aria-label': 'Simulation triage funnel' });
    funnelCard.append(funnelCanvas);
    body.append(funnelCard);
    requestAnimationFrame(() => {
      Chart.funnel(funnelCanvas, [
        { label: 'Delivered', value: sim.delivered, color: '#5cb3ff' },
        { label: 'Triaged', value: sim.triaged, color: '#b197fc' },
        { label: 'Reported', value: sim.triaged - (sim.clickRate ? Math.round((sim.clickRate * sim.triaged) / 100) : sim.triaged), color: '#63e6be' },
        { label: 'Clicked / replied', value: sim.clickRate ? Math.round((sim.clickRate * sim.triaged) / 100) : 0, color: '#ff8787' },
      ]);
    });

    // Module heat
    body.append(
      el('section', { class: 'card' }, [
        el('h2', { text: '📚 Module heat' }),
        ...org.moduleHeat.map((m) =>
          el('div', { class: 'mb0' }, [
            UI.meter(m.avgScore === null ? 0 : m.avgScore, {
              label: `${m.visual} ${m.title.replace(/^\S+\s/, '')}`,
              valueText: m.avgScore === null ? 'no data' : `${m.avgScore}%`,
              tone: fmt.cls(m.avgScore),
            }),
            el('p', { class: 'small faint', text: `${m.completed} completion(s)` }),
          ])
        ),
      ])
    );

    // Campaign table + templates
    const tplRows = (campaignData.templates || []).map((t) => ({
      cells: [
        el('b', { text: t.vector }),
        el('span', { class: 'muted', text: t.subject }),
        el('span', { class: 'badge ' + (t.severity === 'high' ? 'bad' : 'warn'), text: t.severity }),
        el('button', { class: 'btn sm primary', text: 'Launch', onclick: () => launchCampaignDialog(t.id) }),
      ],
    }));
    const campCard = el('section', { class: 'card' }, [
      el('div', { class: 'card-head' }, [
        el('h2', { text: '✉️ Campaigns & lure library' }),
        el('span', { class: 'badge plain', text: `${(campaignData.campaigns || []).length} launched` }),
      ]),
      el('h3', { text: 'Lure templates' }),
      UI.table([{ label: 'Vector' }, { label: 'Subject' }, { label: 'Severity' }, { label: '' }], tplRows),
      el('h3', { class: 'mt', text: 'Launched campaigns' }),
      UI.table(
        [{ label: 'Campaign' }, { label: 'Vector' }, { label: 'Cohort' }, { label: 'Delivered', num: true }, { label: 'Reported', num: true }, { label: 'Clicked', num: true }, { label: 'Status' }],
        (campaignData.campaigns || []).map((c) => ({
          cells: [
            el('span', {}, [el('b', { text: c.name }), el('div', { class: 'small faint', text: fmt.ago(c.createdAt) })]),
            c.vector,
            c.targetRole,
            String(c.metrics.delivered),
            el('span', { class: 'good', text: c.metrics.reported === null ? '—' : String(c.metrics.reported) }),
            el('span', { class: c.metrics.clicked ? 'bad' : '', text: c.metrics.clicked === null ? '—' : String(c.metrics.clicked) }),
            el('span', { class: 'badge good', text: c.status }),
          ],
        }))
      ),
    ]);
    body.append(campCard);

    // Users
    const usersCard = el('section', { class: 'card' }, [
      el('div', { class: 'card-head' }, [
        el('h2', { text: '👥 Users & provisioning' }),
        el('button', { class: 'btn sm', text: '＋ Provision user', onclick: () => provisionDialog() }),
      ]),
      UI.table([{ label: 'Name' }, { label: 'Role' }, { label: 'Email' }, { label: 'MFA' }, { label: 'Score', num: true }, { label: 'Coverage', num: true }],
        (usersData.users || []).map((u) => {
          const row = org.users.find((x) => x.userId === u.id) || {};
          return {
            cells: [
              el('b', { text: u.name }),
              el('span', { class: 'badge ' + (u.role === 'admin' ? 'bad' : u.role === 'author' ? 'purple' : 'plain'), text: u.role }),
              el('span', { class: 'mono small', text: u.email }),
              el('span', { class: 'badge ' + (u.mfaEnrolled ? 'good' : 'warn'), text: u.mfaEnrolled ? 'enrolled' : 'pending' }),
              row.avgScore === null || row.avgScore === undefined ? '—' : el('b', { class: fmt.cls(row.avgScore), text: String(row.avgScore) }),
              String(row.coverage || 0),
            ],
          };
        })
      ),
      el('p', { class: 'small faint mt', text: 'Emails are stored AES-256-GCM encrypted at rest and decrypted only server-side for authentication (A.8.11 data masking). Provisioning mirrors SCIM 2.0 semantics.' }),
    ]);
    body.append(usersCard);

    // Audit log
    const auditCard = el('section', { class: 'card' }, [
      el('div', { class: 'card-head' }, [
        el('h2', { text: '📜 Audit log (hash-chained, append-only)' }),
        el('div', { class: 'row' }, [
          el('button', { class: 'btn sm', text: 'Verify chain integrity', onclick: verifyChain }),
          el('button', { class: 'btn sm ghost', text: 'Refresh', onclick: () => App.render() }),
        ]),
      ]),
      el('div', { class: 'audit-log' }, [el('p', { class: 'empty', text: 'Loading entries…' })]),
    ]);
    body.append(auditCard);

    try {
      const audit = await API.get('/api/admin/audit');
      const box = $('.audit-log', auditCard);
      clear(box);
      const entries = (audit.entries || []).slice(-60).reverse();
      if (!entries.length) box.append(el('p', { class: 'empty', text: 'No audit entries yet.' }));
      for (const e of entries) {
        box.append(
          el('div', { class: 'audit-line' }, [
            el('span', { class: 'ts', text: fmt.stamp(e.ts) }),
            el('span', { class: 'actor', text: e.actor }),
            el('span', { class: 'action', text: e.action }),
            el('span', { class: 'hash', text: `#${(e.hash || '').slice(0, 10)}` }),
          ])
        );
      }
    } catch (e) {
      clear($('.audit-log', auditCard)).append(el('p', { class: 'error', text: friendlyError(e) }));
    }

    return root;
  };

  /* ─── Admin actions ─────────────────────────────────────────────────── */

  function launchCampaignDialog(presetTemplate) {
    const nameInput = el('input', { type: 'text', id: 'c-name', placeholder: 'Q3 awareness wave 1' });
    const tplSelect = el('select', { id: 'c-tpl' });
    const roleSelect = el('select', { id: 'c-role' }, [
      el('option', { value: 'learner', text: 'learners' }),
      el('option', { value: 'author', text: 'authors' }),
      el('option', { value: 'admin', text: 'admins' }),
      el('option', { value: 'all', text: 'everyone' }),
    ]);

    fetchTemplates(tplSelect, presetTemplate);

    const body = el('div', {}, [
      el('p', { class: 'muted small', text: 'Each targeted learner receives one simulated message. Red flags are hidden until they triage it, so the decision is genuinely theirs (ISO A.6.3). Simulations are watermarked as training content.' }),
      el('label', { text: 'Campaign name' }, nameInput),
      el('label', { text: 'Lure template' }, tplSelect),
      el('label', { text: 'Target cohort' }, roleSelect),
    ]);

    Modal.open('Launch phishing simulation', body, [
      {
        label: 'Launch',
        kind: 'primary',
        onClick: async (e) => {
          const btn = e && e.currentTarget;
          if (btn) btn.disabled = true;
          try {
            const r = await API.post('/api/admin/campaigns', {
              name: nameInput.value.trim(),
              templateId: tplSelect.value,
              targetRole: roleSelect.value,
            });
            Modal.close();
            Toast.ok(`Simulation launched to ${r.campaign.targetCount} user(s).`);
            App.render();
          } catch (err) {
            Toast.err(friendlyError(err));
            if (btn) btn.disabled = false;
          }
        },
      },
    ]);
  }

  async function fetchTemplates(select, preset) {
    try {
      const data = await API.get('/api/admin/campaigns');
      for (const t of data.templates || []) {
        select.append(el('option', { value: t.id, text: `${t.vector} — ${t.subject}` }));
      }
      if (preset) select.value = preset;
    } catch (e) {
      select.append(el('option', { value: '', text: `Could not load templates (${friendlyError(e)})` }));
    }
  }

  function provisionDialog() {
    const email = el('input', { type: 'email', id: 'u-email', placeholder: 'new.user@yourcompany.com' });
    const name = el('input', { type: 'text', id: 'u-name', placeholder: 'Display name' });
    const role = el('select', { id: 'u-role' }, [
      el('option', { value: 'learner', text: 'learner' }),
      el('option', { value: 'author', text: 'author' }),
      el('option', { value: 'admin', text: 'admin' }),
    ]);
    const body = el('div', {}, [
      el('p', { class: 'muted small', text: 'Creates a local identity record with an idp_subject ready for OIDC/SAML/SCIM federation. In production this endpoint is driven by your IdP, not by humans.' }),
      el('label', { text: 'Email' }, email),
      el('label', { text: 'Display name' }, name),
      el('label', { text: 'Role' }, role),
    ]);
    Modal.open('Provision user', body, [
      {
        label: 'Create',
        kind: 'primary',
        onClick: async (e) => {
          const btn = e && e.currentTarget;
          if (btn) btn.disabled = true;
          try {
            await API.post('/api/admin/users', { email: email.value.trim(), name: name.value.trim(), role: role.value });
            Modal.close();
            Toast.ok('User provisioned and audit-logged.');
            App.render();
          } catch (err) {
            Toast.err(friendlyError(err));
            if (btn) btn.disabled = false;
          }
        },
      },
    ]);
  }

  async function verifyChain() {
    try {
      const r = await API.get('/api/admin/audit/verify');
      Modal.open('Audit chain integrity', el('div', {}, [
        el('div', { class: `alert ${r.valid ? 'success' : 'error'}` }, [
          el('b', { text: r.valid ? '✅ Chain intact — ' : '❌ CHAIN BROKEN — ' }),
          r.valid
            ? `${r.entries} entries verified. Every record binds the previous record's SHA-256, so any edit, deletion or reorder would be detected (ISO A.8.15, NIST AU-9, SOC 2 CC7.2).`
            : `Verification failed at entry index ${r.brokenAt}. Treat the audit trail as evidence of tampering and escalate immediately.`,
        ]),
        el('pre', { class: 'xapi-block', text: JSON.stringify(r, null, 2) }),
      ]));
    } catch (e) {
      Toast.err(friendlyError(e));
    }
  }

  async function exportEvidence() {
    try {
      const pack = await API.get('/api/admin/evidence');
      const blob = new Blob([JSON.stringify(pack, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = el('a', { href: url, download: `iso27001-a63-evidence-${new Date().toISOString().slice(0, 10)}.json` });
      document.body.append(a);
      a.click();
      a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 2000);
      Modal.open('Evidence pack exported', el('div', {}, [
        el('div', { class: 'alert success' }, [
          el('b', { text: 'Audit event recorded. ' }),
          `The pack contains ${pack.training.completed} completion record(s), module coverage, the simulation funnel and chain integrity (${pack.auditChain.valid ? 'valid' : 'BROKEN'}). Hand it to your ISO 27001 / SOC 2 auditor as A.6.3 awareness evidence.`,
        ]),
        el('pre', { class: 'xapi-block', text: JSON.stringify({ artifact: pack.artifact, generatedAt: pack.generatedAt, training: pack.training, auditChain: pack.auditChain, simulation: { reportRate: pack.simulation.reportRate, clickRate: pack.simulation.clickRate } }, null, 2) }),
      ]));
    } catch (e) {
      Toast.err(friendlyError(e));
    }
  }

  window.XR.Views = Object.assign(window.XR.Views || {}, Views);
})();
