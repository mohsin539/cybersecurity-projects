/* eslint-env browser */
/**
 * app.js — Router, auth bootstrap, navigation chrome and health probe.
 *
 * Route guards here are UX only; the API is the enforcement point
 * (state.md §7, OWASP A01).
 */
'use strict';

(function () {
  const { $, $$, el, clear, fmt, Store, API, Toast, Modal, UI, friendlyError } = window.XR;

  const ROUTES = {
    '#/login': { view: 'login', auth: 'none' },
    '#/home': { view: 'home', auth: 'any' },
    '#/modules': { view: 'modules', auth: 'any' },
    '#/play': { view: 'play', auth: 'any' },
    '#/debrief': { view: 'debrief', auth: 'any' },
    '#/threats': { view: 'threats', auth: 'any' },
    '#/dashboard': { view: 'dashboard', auth: 'any' },
    '#/compliance': { view: 'compliance', auth: 'any' },
    '#/admin': { view: 'admin', auth: 'admin' },
  };

  const App = {
    pendingDebrief: null,
    rendering: false,

    async render() {
      if (this.rendering) return;
      this.rendering = true;
      const root = $('#app');
      const hash = location.hash || (Store.user ? '#/home' : '#/login');
      const route = ROUTES[hash] || ROUTES[Store.user ? '#/home' : '#/login'];

      for (const a of $$('[data-nav]')) {
        if (a.getAttribute('href') === hash) a.setAttribute('aria-current', 'page');
        else a.removeAttribute('aria-current');
      }

      try {
        if (route.auth === 'none' && Store.user) {
          location.hash = '#/home';
          return;
        }
        if (route.auth !== 'none' && !Store.user) {
          location.hash = '#/login';
          return;
        }
        if (route.auth === 'admin' && !Store.isAdmin()) {
          clear(root).append(
            el('section', { class: 'card' }, [
              el('h1', { text: 'Access denied' }),
              el('div', { class: 'alert error', text: 'This view requires the admin role (ISO/IEC 27001 A.5.15). The API also rejects these requests with HTTP 403.' }),
              el('a', { class: 'btn mt', href: '#/dashboard', text: '← Back to my dashboard' }),
            ])
          );
          return;
        }
        const node = await window.XR.Views[route.view]();
        clear(root);
        if (node) root.append(node);
        root.scrollTop = 0;
        window.scrollTo({ top: 0, behavior: 'auto' });
      } catch (e) {
        clear(root).append(
          UI.card('⚠️ Something went wrong', [
            el('div', { class: 'alert error', text: friendlyError(e) }),
            el('div', { class: 'row mt' }, [
              el('button', { class: 'btn', text: 'Retry', onclick: () => App.render() }),
              el('a', { class: 'btn ghost', href: '#/login', text: 'Back to start' }),
            ]),
          ])
        );
      } finally {
        this.rendering = false;
      }
    },

    /** Refresh nav + chrome after a sign-in. */
    afterLogin() {
      this.renderChrome();
      this.loadCatalog();
      const target = Store.isAdmin() ? '#/admin' : '#/home';
      if (location.hash === target) this.render();
      else location.hash = target;
      this.refreshThreatBadge();
    },

    onSignedOut() {
      this.renderChrome();
      this.pendingDebrief = null;
      Store.run = null;
      Toast.warn('Session ended — please sign in again.');
      location.hash = '#/login';
    },

    renderChrome() {
      const box = $('#userbox');
      clear(box);
      for (const a of $$('[data-nav]')) {
        const need = a.dataset.auth;
        const show = need === 'any' ? Boolean(Store.user) : need === 'admin' ? Store.isAdmin() : true;
        a.hidden = !show;
      }
      if (Store.user) {
        box.append(
          el('span', { class: 'pill' }, [el('b', { text: Store.user.name }), ` · ${Store.user.role}`]),
          el('button', { class: 'btn sm ghost', text: 'Sign out', onclick: () => this.signOut() })
        );
      } else {
        box.append(el('span', { class: 'pill', text: 'guest' }));
      }
    },

    async loadCatalog() {
      try {
        const data = await API.get('/api/modules');
        Store.modules = data.modules || [];
        Store.categories = data.categories || [];
        Store.capabilities = data.capabilities || {};
      } catch (e) {
        Store.modules = Store.modules || [];
      }
    },

    async refreshThreatBadge() {
      const badge = $('#nav-threat-count');
      if (!badge) return;
      if (!Store.user) {
        badge.hidden = true;
        return;
      }
      try {
        const data = await API.get('/api/campaigns/inbox');
        const pending = (data.metrics || {}).pending || 0;
        badge.textContent = String(pending);
        badge.hidden = pending === 0;
      } catch {
        badge.hidden = true;
      }
    },

    signOut() {
      Store.setToken(null);
      Store.user = null;
      Store.run = null;
      this.pendingDebrief = null;
      this.renderChrome();
      location.hash = '#/login';
      this.render();
    },

    async health() {
      const status = $('#footer-status');
      const build = $('#footer-build');
      try {
        const h = await API.get('/api/health');
        if (status) {
          status.className = h.auditChainValid ? 'ok' : 'bad';
          status.textContent = `● ${h.status} · audit chain ${h.auditChainValid ? 'valid' : 'BROKEN'} · ${h.time.slice(11, 19)}Z`;
        }
        if (build) build.textContent = `v${h.version}`;
      } catch {
        if (status) {
          status.className = 'bad';
          status.textContent = '● api unreachable';
        }
      }
    },
  };

  window.App = App;

  window.addEventListener('hashchange', () => {
    App.render();
    App.refreshThreatBadge();
  });

  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') Modal.close();
  });

  (async function init() {
    App.renderChrome();
    if (Store.token) {
      try {
        const me = await API.get('/api/auth/me');
        Store.user = me.user;
        App.renderChrome();
        await App.loadCatalog();
        if (!location.hash || location.hash === '#/login') location.hash = '#/home';
      } catch {
        Store.setToken(null);
      }
    }
    await App.render();
    App.refreshThreatBadge();
    App.health();
    setInterval(() => App.health(), 30000);
  })();
})();
