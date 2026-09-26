/* eslint-env browser */
/**
 * xr.js — Immersive stage runtime (architecture.md §6 WEBXR CLIENT).
 *
 * Two rendering paths behind one API:
 *  1. **Immersive** — a dependency-free WebGL2 renderer driven by a real
 *     `navigator.xr` session (`immersive-vr` / `immersive-ar`) at headset
 *     refresh rate. Used only when the device advertises support.
 *  2. **Desktop / mobile fallback** — a stylised Canvas 2D stage with the same
 *     HUD, the same scene themes and identical interaction flow, so no learner
 *     is ever blocked from training (WCAG 2.2 non-VR fallback).
 *
 * Client-side guarantees (security.md §2.2, §2.6):
 *  - no camera, microphone or environment sensor data is ever read
 *  - bundle integrity is verified before the first frame renders
 *  - telemetry is aggregate-only via the allow-list in core.js
 */
'use strict';

(function () {
  const { el, Telemetry } = window.XR;
  const reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  /* ─── Scene themes ───────────────────────────────────────────────────── */

  const SCENES = {
    inbox: {
      sky: ['#1b2a5e', '#0b1230'],
      accent: '#5cb3ff',
      prop: 'mail',
      caption: 'Virtual inbox · three unread messages in view',
    },
    call: {
      sky: ['#241a4d', '#0d0a24'],
      accent: '#b197fc',
      prop: 'phone',
      caption: 'Incoming call · unknown number, executive pretext',
    },
    lobby: {
      sky: ['#12303f', '#08131c'],
      accent: '#63e6be',
      prop: 'door',
      caption: 'Reception lobby · secure door + badge reader',
    },
    desk: {
      sky: ['#2b2540', '#120f22'],
      accent: '#ffd43b',
      prop: 'desk',
      caption: 'Workstation · classified documents on screen',
    },
    ransomware: {
      sky: ['#3d1626', '#150610'],
      accent: '#ff8787',
      prop: 'lock',
      caption: 'Endpoint compromised · mass file encryption in progress',
    },
    office: {
      sky: ['#1c2a3f', '#0a1220'],
      accent: '#ffa94d',
      prop: 'office',
      caption: 'Open-plan floor · visitor without a badge',
    },
  };

  const sceneFor = (name) => SCENES[name] || SCENES.inbox;

  /* ─── Minimal matrix helpers (WebGL, column-major) ───────────────────── */

  const M4 = {
    identity: () => new Float32Array([1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1]),
    multiply(a, b) {
      const out = new Float32Array(16);
      for (let c = 0; c < 4; c++) {
        for (let r = 0; r < 4; r++) {
          out[c * 4 + r] =
            a[0 * 4 + r] * b[c * 4 + 0] +
            a[1 * 4 + r] * b[c * 4 + 1] +
            a[2 * 4 + r] * b[c * 4 + 2] +
            a[3 * 4 + r] * b[c * 4 + 3];
        }
      }
      return out;
    },
    /** translate * rotateY * scale */
    trs(tx, ty, tz, ry, sx, sy, sz) {
      const c = Math.cos(ry);
      const s = Math.sin(ry);
      return new Float32Array([
        c * sx, 0, -s * sx, 0,
        0, sy, 0, 0,
        s * sz, 0, c * sz, 0,
        tx, ty, tz, 1,
      ]);
    },
  };

  const VERT = `#version 300 es
    in vec3 aPos; in vec3 aColor;
    uniform mat4 uMVP; out vec3 vColor;
    void main() { gl_Position = uMVP * vec4(aPos, 1.0); vColor = aColor; }`;

  const FRAG = `#version 300 es
    precision mediump float; in vec3 vColor; out vec4 outColor;
    void main() { outColor = vec4(vColor, 1.0); }`;

  function cubeGeometry(color) {
    const c = color;
    const faces = [
      [[-0.5, -0.5, 0.5], [0.5, -0.5, 0.5], [0.5, 0.5, 0.5], [-0.5, 0.5, 0.5]], // front
      [[0.5, -0.5, -0.5], [-0.5, -0.5, -0.5], [-0.5, 0.5, -0.5], [0.5, 0.5, -0.5]], // back
      [[-0.5, 0.5, 0.5], [0.5, 0.5, 0.5], [0.5, 0.5, -0.5], [-0.5, 0.5, -0.5]], // top
      [[-0.5, -0.5, -0.5], [0.5, -0.5, -0.5], [0.5, -0.5, 0.5], [-0.5, -0.5, 0.5]], // bottom
      [[0.5, -0.5, 0.5], [0.5, -0.5, -0.5], [0.5, 0.5, -0.5], [0.5, 0.5, 0.5]], // right
      [[-0.5, -0.5, -0.5], [-0.5, -0.5, 0.5], [-0.5, 0.5, 0.5], [-0.5, 0.5, -0.5]], // left
    ];
    const pos = [];
    const col = [];
    for (const f of faces) {
      const [a, b, d, e] = f;
      pos.push(...a, ...b, ...d, ...a, ...d, ...e);
      for (let i = 0; i < 6; i++) col.push(c[0], c[1], c[2]);
    }
    return { pos: new Float32Array(pos), col: new Float32Array(col), count: pos.length / 3 };
  }

  function gridGeometry(size = 7, step = 0.75) {
    const pos = [];
    const col = [];
    const push = (x1, z1, x2, z2) => {
      pos.push(x1, 0, z1, x2, 0, z2);
      col.push(0.36, 0.5, 0.85, 0.36, 0.5, 0.85);
    };
    for (let i = -size; i <= size; i++) {
      const v = i * step;
      push(-size * step, v, size * step, v);
      push(v, -size * step, v, size * step);
    }
    return { pos: new Float32Array(pos), col: new Float32Array(col), count: pos.length / 3 };
  }

  const hexToRgb = (hex) => {
    const h = hex.replace('#', '');
    const n = parseInt(h.length === 3 ? h.split('').map((x) => x + x).join('') : h, 16);
    return [((n >> 16) & 255) / 255, ((n >> 8) & 255) / 255, (n & 255) / 255];
  };

  /** Rounded-rect path with a graceful fallback where roundRect is missing. */
  function rr(ctx, x, y, w, h, r) {
    if (typeof ctx.roundRect === 'function') {
      ctx.beginPath();
      ctx.roundRect(x, y, w, h, r);
      return;
    }
    ctx.beginPath();
    ctx.moveTo(x + r, y);
    ctx.arcTo(x + w, y, x + w, y + h, r);
    ctx.arcTo(x + w, y + h, x, y + h, r);
    ctx.arcTo(x, y + h, x, y, r);
    ctx.arcTo(x, y, x + w, y, r);
    ctx.closePath();
  }

  /* ─── Stage controller ───────────────────────────────────────────────── */

  class Stage {
    constructor(container) {
      this.container = container;
      this.scene = 'inbox';
      this.raf = 0;
      this.t0 = performance.now();
      this.pulse = 0; // trap / alert pulse intensity
      this.running = false;
      this.xrSession = null;
      this.xrRefSpace = null;
      this.gl = null;
      this.programs = null;

      this.canvas = el('canvas', { 'aria-hidden': 'true' });
      this.overlay = el('div', { class: 'stage-overlay' });
      container.append(this.canvas, this.overlay);
      this.renderOverlay();
      this.resize = () => this.onResize();
      window.addEventListener('resize', this.resize);
    }

    renderOverlay() {
      const s = sceneFor(this.scene);
      this.overlay.replaceChildren(
        el('div', { class: 'stage-bottom' }, [
          el('div', { class: 'stage-caption', text: s.caption }),
          el('div', { class: 'reticle', 'aria-hidden': 'true' }),
        ])
      );
    }

    setScene(name) {
      this.scene = SCENES[name] ? name : 'inbox';
      this.renderOverlay();
    }

    /**
     * Replace the canvas element with a fresh one. A canvas keeps whatever
     * context type it was created with for its whole life, so swapping the
     * element is the only way to move between the 2D fallback and WebGL2.
     * Also halts the fallback loop, since it is bound to the old element.
     */
    swapCanvas() {
      if (this.raf) cancelAnimationFrame(this.raf);
      this.raf = 0;
      const fresh = el('canvas', { 'aria-hidden': 'true' });
      this.canvas.replaceWith(fresh);
      this.canvas = fresh;
      this.ctx2d = null;
      this.container.append(this.overlay);
      this.onResize();
    }

    /** swapCanvas() plus re-acquiring the 2D context for the fallback path. */
    resetCanvas() {
      this.swapCanvas();
      if (this.running) this.ctx2d = this.canvas.getContext('2d');
    }

    /** Flash the stage red — used when a trap option is selected. */
    alertPulse() {
      this.pulse = 1;
    }

    onResize() {
      if (!this.running || this.xrSession) return;
      this.canvas.width = Math.max(1, Math.round(this.canvas.clientWidth * (window.devicePixelRatio || 1)));
      this.canvas.height = Math.max(1, Math.round(this.canvas.clientHeight * (window.devicePixelRatio || 1)));
    }

    /* ── Fallback renderer (Canvas 2D) ─────────────────────────────────── */

    start() {
      if (this.running) return;
      this.running = true;
      this.loop = this.loop.bind(this);
      this.onResize();
      this.ctx2d = this.canvas.getContext('2d');
      this.raf = requestAnimationFrame(this.loop);
    }

    stop() {
      this.running = false;
      if (this.raf) cancelAnimationFrame(this.raf);
      this.raf = 0;
      if (this.xrSession) this.exitXR().catch(() => {});
    }

    loop(now) {
      if (!this.running) return;
      this.pulse = Math.max(0, this.pulse - 0.02);
      this.drawFallback((now - this.t0) / 1000);
      this.raf = requestAnimationFrame(this.loop);
    }

    drawFallback(t) {
      const ctx = this.ctx2d;
      if (!ctx) return;
      const dpr = window.devicePixelRatio || 1;
      const w = this.canvas.width / dpr;
      const h = this.canvas.height / dpr;
      const s = sceneFor(this.scene);
      const accent = s.accent;
      const motion = reduceMotion ? 0 : 1;

      // Sky
      const sky = ctx.createLinearGradient(0, 0, 0, h);
      sky.addColorStop(0, s.sky[0]);
      sky.addColorStop(1, s.sky[1]);
      ctx.fillStyle = sky;
      ctx.fillRect(0, 0, w, h);

      // Perspective floor grid
      const horizon = h * 0.52;
      ctx.strokeStyle = 'rgba(92,179,255,0.16)';
      ctx.lineWidth = 1;
      for (let i = 0; i <= 16; i++) {
        const x = (w / 16) * i;
        ctx.beginPath();
        ctx.moveTo(x, h);
        ctx.lineTo(w / 2 + (x - w / 2) * 0.12, horizon);
        ctx.stroke();
      }
      for (let i = 1; i <= 9; i++) {
        const p = i / 9;
        const y = horizon + (h - horizon) * p * p;
        ctx.globalAlpha = 0.5 * (1 - p * 0.55);
        ctx.beginPath();
        ctx.moveTo(0, y);
        ctx.lineTo(w, y);
        ctx.stroke();
        ctx.globalAlpha = 1;
      }

      // Floating dust
      ctx.fillStyle = 'rgba(200,220,255,0.28)';
      for (let i = 0; i < 26; i++) {
        const seed = i * 137.5;
        const dx = ((seed * 7) % w) + Math.sin(t * 0.35 + i) * 14 * motion;
        const dy = ((seed * 13) % (h * 0.7)) + Math.cos(t * 0.28 + i * 1.7) * 10 * motion;
        ctx.globalAlpha = 0.1 + ((i % 5) / 12);
        ctx.fillRect(dx, dy, 2, 2);
      }
      ctx.globalAlpha = 1;

      // Scene prop
      const cx = w / 2;
      const cy = horizon + (h - horizon) * 0.42;
      ctx.save();
      ctx.translate(cx, cy);
      const bob = Math.sin(t * 1.1) * 8 * motion;
      ctx.translate(0, bob);
      ctx.shadowColor = accent;
      ctx.shadowBlur = 26;
      this.drawProp(ctx, s.prop, accent, t, w, motion);
      ctx.restore();

      // Trap / alert pulse
      if (this.pulse > 0) {
        ctx.fillStyle = `rgba(255, 90, 90, ${0.2 * this.pulse})`;
        ctx.fillRect(0, 0, w, h);
      }

      // Vignette
      const vig = ctx.createRadialGradient(cx, cy, Math.min(w, h) * 0.28, cx, cy, Math.max(w, h) * 0.72);
      vig.addColorStop(0, 'rgba(0,0,0,0)');
      vig.addColorStop(1, 'rgba(0,0,0,0.55)');
      ctx.fillStyle = vig;
      ctx.fillRect(0, 0, w, h);
    }

    drawProp(ctx, prop, accent, t, w, motion) {
      const S = Math.min(w, 520);
      ctx.lineWidth = 3;
      ctx.strokeStyle = accent;
      ctx.fillStyle = 'rgba(12,20,48,0.86)';
      const spin = Math.sin(t * 0.6) * 0.14 * motion;

      if (prop === 'mail') {
        for (let i = 0; i < 3; i++) {
          const off = (i - 1) * 92;
          const y = off * 0.36;
          ctx.save();
          ctx.rotate(spin * (i === 1 ? 0.4 : 1));
          ctx.fillStyle = i === 1 ? 'rgba(20,32,72,0.94)' : 'rgba(14,22,52,0.82)';
          rr(ctx, off - 74, y - 54, 148, 108, 12);
          ctx.fill();
          ctx.strokeStyle = i === 1 ? accent : 'rgba(120,145,220,0.5)';
          ctx.stroke();
          ctx.beginPath();
          ctx.moveTo(off - 70, y - 48);
          ctx.lineTo(off, y - 6);
          ctx.lineTo(off + 70, y - 48);
          ctx.strokeStyle = i === 1 ? accent : 'rgba(120,145,220,0.45)';
          ctx.stroke();
          if (i === 1) {
            ctx.fillStyle = '#ff8787';
            ctx.beginPath();
            ctx.arc(off + 52, y - 36, 7, 0, Math.PI * 2);
            ctx.fill();
          }
          ctx.restore();
        }
      } else if (prop === 'phone') {
        rr(ctx, -70, -120, 140, 240, 20);
        ctx.fill();
        ctx.stroke();
        ctx.fillStyle = accent;
        ctx.beginPath();
        ctx.arc(0, -60, 14, 0, Math.PI * 2);
        ctx.fill();
        ctx.strokeStyle = 'rgba(120,145,220,0.6)';
        ctx.lineWidth = 2;
        for (let i = 1; i <= 4; i++) {
          const r = 26 * i + Math.sin(t * 3 + i) * 4 * motion;
          ctx.beginPath();
          ctx.arc(0, -60, r, 0, Math.PI * 2);
          ctx.globalAlpha = 0.5 / i;
          ctx.stroke();
          ctx.globalAlpha = 1;
        }
        ctx.fillStyle = '#a6b6e0';
        ctx.fillRect(-46, 22, 92, 8);
        ctx.fillRect(-46, 44, 60, 8);
      } else if (prop === 'door') {
        rr(ctx, -92, -128, 184, 256, 10);
        ctx.fill();
        ctx.stroke();
        ctx.fillStyle = 'rgba(99,230,190,0.18)';
        ctx.fillRect(-92, -128, 92, 256);
        ctx.fillStyle = accent;
        rr(ctx, 46, -34, 30, 62, 6);
        ctx.fill();
        ctx.strokeStyle = accent;
        ctx.beginPath();
        ctx.arc(60, 64, 7, 0, Math.PI * 2);
        ctx.fill();
      } else if (prop === 'desk') {
        rr(ctx, -120, -92, 240, 150, 12);
        ctx.fill();
        ctx.stroke();
        ctx.fillStyle = 'rgba(255,212,59,0.2)';
        ctx.fillRect(-104, -76, 208, 84);
        ctx.fillStyle = accent;
        for (let i = 0; i < 4; i++) ctx.fillRect(-96, -64 + i * 18, 150 - i * 26, 7);
        ctx.strokeStyle = accent;
        rr(ctx, -150, 66, 300, 16, 8);
        ctx.stroke();
      } else if (prop === 'lock') {
        rr(ctx, -118, -70, 236, 132, 14);
        ctx.fill();
        ctx.stroke();
        ctx.beginPath();
        ctx.arc(0, -70, 46, Math.PI, 0);
        ctx.stroke();
        ctx.fillStyle = accent;
        ctx.beginPath();
        ctx.arc(0, 4, 18, 0, Math.PI * 2);
        ctx.fill();
        for (let i = 0; i < 3; i++) {
          const prog = ((t * 0.35 + i * 0.33) % 1);
          ctx.fillStyle = i === 0 ? '#ff8787' : i === 1 ? '#ffa94d' : '#ffd43b';
          ctx.fillRect(-92 + i * 66, 38, 58 * prog, 10);
        }
      } else {
        // office: open-plan desks + unbadged visitor
        for (let i = -1; i <= 1; i++) {
          rr(ctx, i * 108 - 44, -34, 88, 78, 8);
          ctx.fill();
          ctx.strokeStyle = 'rgba(120,145,220,0.5)';
          ctx.stroke();
        }
        ctx.fillStyle = accent;
        ctx.beginPath();
        ctx.arc(0, -96, 20, 0, Math.PI * 2);
        ctx.fill();
        rr(ctx, -22, -72, 44, 62, 12);
        ctx.fill();
        ctx.strokeStyle = accent;
        ctx.beginPath();
        ctx.arc(0, -58, 9, 0, Math.PI * 2);
        ctx.stroke();
      }
    }

    /* ── Immersive renderer (WebXR + WebGL2, no dependencies) ──────────── */

    async enterXR(mode = 'vr') {
      if (this.xrSession) return;
      if (!('xr' in navigator) || typeof navigator.xr.requestSession !== 'function') {
        throw new Error('WebXR not available');
      }
      const session = await navigator.xr.requestSession(mode, {
        optionalFeatures: ['local-floor', 'bounded-floor', 'hand-tracking'],
      });
      // A canvas keeps one context type for life: hand the immersive
      // renderer a brand-new element so getContext('webgl2') can succeed.
      this.swapCanvas();
      const gl = this.canvas.getContext('webgl2', { xrCompatible: true, antialias: true, alpha: true });
      if (!gl) {
        this.resetCanvas();
        if (this.running) this.raf = requestAnimationFrame(this.loop);
        await session.end();
        throw new Error('WebGL2 unavailable for immersive session');
      }
      this.xrSession = session;
      this.gl = gl;
      this.programs = this.buildPrograms(gl);

      const layer = new XRWebGLLayer(session, gl);
      await session.updateRenderState({ baseLayer: layer, depthNear: 0.05, depthFar: 60 });
      this.xrRefSpace =
        (await session.requestReferenceSpace('local-floor').catch(() => null)) ||
        (await session.requestReferenceSpace('local'));

      this.raf = 0;
      session.addEventListener('end', () => {
        this.xrSession = null;
        this.gl = null;
        this.programs = null;
        Telemetry.record('xr.session.end');
        // A canvas keeps one context type for life: swap in a fresh element so
        // the 2D fallback can resume after the immersive session ends.
        this.resetCanvas();
        if (this.running) this.raf = requestAnimationFrame(this.loop);
      });

      Telemetry.record('xr.session.start');
      this.xrLoop(session, this.xrRefSpace);
      return session;
    }

    async exitXR() {
      if (this.xrSession) await this.xrSession.end();
    }

    buildPrograms(gl) {
      const compile = (type, src) => {
        const sh = gl.createShader(type);
        gl.shaderSource(sh, src);
        gl.compileShader(sh);
        if (!gl.getShaderParameter(sh, gl.COMPILE_STATUS)) throw new Error('shader: ' + gl.getShaderInfoLog(sh));
        return sh;
      };
      const program = gl.createProgram();
      gl.attachShader(program, compile(gl.VERTEX_SHADER, VERT));
      gl.attachShader(program, compile(gl.FRAGMENT_SHADER, FRAG));
      gl.linkProgram(program);
      if (!gl.getProgramParameter(program, gl.LINK_STATUS)) throw new Error('link: ' + gl.getProgramInfoLog(program));

      return {
        program,
        uMVP: gl.getUniformLocation(program, 'uMVP'),
        aPos: gl.getAttribLocation(program, 'aPos'),
        aColor: gl.getAttribLocation(program, 'aColor'),
        cache: new Map(),
      };
    }

    /** Upload a CPU geometry into a VAO (memoised per colour+shape). */
    upload(gl, key, cpu) {
      if (this.programs.cache.has(key)) return this.programs.cache.get(key);
      const vao = gl.createVertexArray();
      gl.bindVertexArray(vao);
      const pb = gl.createBuffer();
      gl.bindBuffer(gl.ARRAY_BUFFER, pb);
      gl.bufferData(gl.ARRAY_BUFFER, cpu.pos, gl.STATIC_DRAW);
      gl.enableVertexAttribArray(this.programs.aPos);
      gl.vertexAttribPointer(this.programs.aPos, 3, gl.FLOAT, false, 0, 0);
      const cb = gl.createBuffer();
      gl.bindBuffer(gl.ARRAY_BUFFER, cb);
      gl.bufferData(gl.ARRAY_BUFFER, cpu.col, gl.STATIC_DRAW);
      gl.enableVertexAttribArray(this.programs.aColor);
      gl.vertexAttribPointer(this.programs.aColor, 3, gl.FLOAT, false, 0, 0);
      gl.bindVertexArray(null);
      const geo = { vao, count: cpu.count, lines: Boolean(cpu.lines) };
      this.programs.cache.set(key, geo);
      return geo;
    }

    xrLoop(session, refSpace) {
      const t0 = performance.now();
      const s = sceneFor(this.scene);
      const accent = hexToRgb(s.accent);
      // Prop cluster, themed per scenario: colour, size and placement.
      const boxes = [
        [0, 1.15, -1.9, 0.9, 0.62, 0.05, accent],
        [0, 1.52, -1.95, 0.7, 0.4, 0.03, [0.72, 0.86, 1]],
        [1.05, 1.0, -1.5, 0.34, 0.34, 0.34, [0.35, 0.55, 0.95]],
        [-1.05, 0.9, -1.55, 0.28, 0.28, 0.28, [0.45, 0.35, 0.8]],
      ];

      const frame = (now, xrFrame) => {
        const gl = this.gl;
        if (!gl || !this.programs || !session) return; // session ended → stop the loop
        const layer = xrFrame.session.renderState.baseLayer;
        const pose = xrFrame.getViewerPose(refSpace);
        gl.bindFramebuffer(gl.FRAMEBUFFER, layer.framebuffer);
        gl.enable(gl.DEPTH_TEST);
        gl.useProgram(this.programs.program);

        const gridGeo = this.upload(gl, 'grid', gridGeometry());
        const t = (now - t0) / 1000;
        const spin = reduceMotion ? 0 : t * 0.35;

        for (const view of pose ? pose.views : []) {
          const vp = layer.getViewport(view);
          if (!vp) continue;
          gl.viewport(vp.x, vp.y, vp.width, vp.height);
          gl.clear(gl.COLOR_BUFFER_BIT | gl.DEPTH_BUFFER_BIT);
          const viewMat = view.transform.inverse.matrix;
          const draw = (geo, model, mode) => {
            gl.bindVertexArray(geo.vao);
            gl.uniformMatrix4fv(this.programs.uMVP, false, M4.multiply(viewMat, model));
            gl.drawArrays(mode, 0, geo.count);
          };
          draw(gridGeo, M4.identity(), gl.LINES);
          for (const [x, y, z, sx, sy, sz, c] of boxes) {
            const key = `cube:${s.prop}:${c.map((n) => n.toFixed(2)).join(',')}`;
            draw(this.upload(gl, key, cubeGeometry(c)), M4.trs(x, y, z, spin * 0.35, sx, sy, sz), gl.TRIANGLES);
          }
        }
        gl.bindVertexArray(null);
        session.requestAnimationFrame(frame);
      };
      session.requestAnimationFrame(frame);
    }

    destroy() {
      this.stop();
      window.removeEventListener('resize', this.resize);
      this.canvas.remove();
    }
  }

  window.XR.Stage = Stage;
  window.XR.SCENES = SCENES;
  window.XR.sceneFor = sceneFor;
})();
