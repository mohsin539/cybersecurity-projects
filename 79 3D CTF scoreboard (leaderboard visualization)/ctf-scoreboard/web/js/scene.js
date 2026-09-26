/**
 * The leaderboard scene: bars, floor, particles, pulses and HTML labels.
 *
 * Design notes:
 *  - The bar for rank 1 is centred and slightly forward; the rest form a
 *    shallow arc so every bar stays visible from the default camera.
 *  - Bar height is a *deterministic* function of the projected score, so two
 *    clients with the same `state_hash` draw the same picture (INV-02).
 *  - All motion is cosmetic easing toward a target, never a source of truth.
 */

import {
  createDynamicBuffer,
  createFullscreenTriangle,
  createInstancedCube,
  createProgram,
  hexToRgb,
  mat4,
} from './gl.js';

const BAR_VS = `#version 300 es
precision highp float;

layout(location = 0) in vec3 aPosition;
layout(location = 1) in vec3 aNormal;
layout(location = 2) in vec3 iOffset;
layout(location = 3) in float iHeight;
layout(location = 4) in vec3 iColour;
layout(location = 5) in float iGlow;
layout(location = 6) in float iFade;

uniform mat4 uViewProj;
uniform float uWidth;
uniform float uDepth;

out vec3 vNormal;
out vec3 vColour;
out vec3 vWorld;
out float vGlow;
out float vFade;
out float vLocalY;

void main() {
  vec3 unit = aPosition;
  vec3 scaled = vec3(unit.x * uWidth, unit.y * iHeight, unit.z * uDepth);
  vec3 world = scaled + iOffset;
  world.y = aPosition.y * iHeight + iOffset.y;

  vNormal = aNormal;
  vColour = iColour;
  vWorld = world;
  vGlow = iGlow;
  vFade = iFade;
  vLocalY = aPosition.y + 0.5;

  gl_Position = uViewProj * vec4(world, 1.0);
}
`;

const BAR_FS = `#version 300 es
precision highp float;

in vec3 vNormal;
in vec3 vColour;
in vec3 vWorld;
in float vGlow;
in float vFade;
in float vLocalY;

uniform vec3 uCamera;
uniform float uTime;

out vec4 fragColour;

void main() {
  vec3 normal = normalize(vNormal);
  vec3 viewDir = normalize(uCamera - vWorld);

  // Hemispheric ambient: cool from above, warm bounce from the floor.
  vec3 sky = vec3(0.30, 0.36, 0.55);
  vec3 ground = vec3(0.10, 0.08, 0.16);
  float hemi = normal.y * 0.5 + 0.5;
  vec3 ambient = mix(ground, sky, hemi);

  // Key light from the front-left, plus a rim light to separate silhouettes.
  vec3 keyDir = normalize(vec3(-0.55, 0.8, 0.6));
  float key = max(dot(normal, keyDir), 0.0);
  float rim = pow(1.0 - max(dot(normal, viewDir), 0.0), 2.5);

  vec3 colour = vColour * (ambient + key * 0.75) + vec3(0.45, 0.62, 1.0) * rim * 0.35;

  // Vertical gradient plus an emissive cap so tall bars read as data.
  colour *= mix(0.45, 1.15, vLocalY);
  float cap = smoothstep(0.86, 1.0, vLocalY);
  colour += vColour * cap * 0.9;

  // Score-change pulse: a travelling band of light.
  float band = exp(-pow((vLocalY - fract(uTime * 0.55)) * 5.5, 2.0));
  colour += vColour * band * vGlow * 1.6;

  float alpha = mix(0.28, 1.0, vFade);
  fragColour = vec4(colour * alpha, alpha);
}
`;

const FLOOR_VS = `#version 300 es
precision highp float;
layout(location = 0) in vec2 aPosition;
out vec2 vUv;
void main() {
  vUv = aPosition;
  gl_Position = vec4(aPosition, 1.0, 1.0);
}
`;

const FLOOR_FS = `#version 300 es
precision highp float;
in vec2 vUv;
uniform mat4 uInvViewProj;
uniform float uTime;
out vec4 fragColour;

// Analytic ray/plane intersection: the floor is drawn by shading the world
// position the primary ray hits, which keeps the horizon and grid in one pass.
vec3 unproject(vec2 ndc, float z) {
  vec4 far = uInvViewProj * vec4(ndc, z, 1.0);
  return far.xyz / far.w;
}

void main() {
  vec3 near = unproject(vUv, -1.0);
  vec3 far = unproject(vUv, 1.0);
  vec3 dir = normalize(far - near);

  float t = (0.0 - near.y) / dir.y;
  if (t <= 0.0) {
    fragColour = vec4(0.027, 0.043, 0.086, 1.0);
    return;
  }
  vec3 hit = near + dir * t;

  vec2 grid = abs(fract(hit.xz * 0.5) - 0.5) / fwidth(hit.xz * 0.5);
  float line = 1.0 - min(min(grid.x, grid.y), 1.0);

  float radius = length(hit.xz);
  float fade = exp(-radius * 0.045);
  float pool = exp(-pow(length(hit.xz - vec2(0.0, -1.5)) * 0.11, 2.0));

  vec3 base = vec3(0.035, 0.05, 0.105);
  vec3 gridColour = mix(vec3(0.11, 0.20, 0.42), vec3(0.36, 0.83, 1.0), pool);
  vec3 colour = base + gridColour * line * (0.35 + pool * 0.9) * fade;

  // A slow scan pulse keeps the floor alive without distracting from the bars.
  float scan = exp(-pow((hit.z - fract(uTime * 0.08) * 40.0 - 20.0) * 0.5, 2.0));
  colour += gridColour * scan * 0.10 * fade;

  float alpha = clamp(0.55 + fade * 0.45, 0.0, 1.0);
  fragColour = vec4(colour, alpha);
}
`;

const PARTICLE_VS = `#version 300 es
precision highp float;
layout(location = 0) in vec3 aPosition;
layout(location = 1) in float aSize;
layout(location = 2) in vec3 aColour;
layout(location = 3) in float aAlpha;
uniform mat4 uViewProj;
uniform float uPixelRatio;
out vec3 vColour;
out float vAlpha;
void main() {
  vColour = aColour;
  vAlpha = aAlpha;
  vec4 clip = uViewProj * vec4(aPosition, 1.0);
  gl_Position = clip;
  gl_PointSize = max(1.0, aSize * uPixelRatio * (18.0 / max(clip.w, 0.1)));
}
`;

const PARTICLE_FS = `#version 300 es
precision highp float;
in vec3 vColour;
in float vAlpha;
out vec4 fragColour;
void main() {
  vec2 d = gl_PointCoord - vec2(0.5);
  float r = dot(d, d) * 4.0;
  float alpha = exp(-r * 2.6) * vAlpha;
  if (alpha < 0.01) discard;
  fragColour = vec4(vColour * alpha, alpha);
}
`;

const RING_VS = `#version 300 es
precision highp float;
layout(location = 0) in vec2 aPosition;
uniform mat4 uViewProj;
uniform float uRadius;
uniform float uWidth;
out vec2 vLocal;
void main() {
  vLocal = aPosition;
  vec3 world = vec3(aPosition.x * uRadius, 0.02, aPosition.y * uRadius);
  world.xz += vec2(uWidth, 0.0);
  gl_Position = uViewProj * vec4(world, 1.0);
}
`;

const RING_FS = `#version 300 es
precision highp float;
in vec2 vLocal;
uniform vec3 uColour;
uniform float uAlpha;
out vec4 fragColour;
void main() {
  float d = length(vLocal);
  float ring = exp(-pow((d - 0.86) * 12.0, 2.0));
  float glow = exp(-pow((d - 0.86) * 3.0, 2.0)) * 0.35;
  float alpha = (ring + glow) * uAlpha;
  if (alpha < 0.01) discard;
  fragColour = vec4(uColour * alpha, alpha);
}
`;

const MAX_BARS = 64;
const MAX_PARTICLES = 900;
const MAX_RINGS = 24;

function ease(current, target, rate, dt) {
  return current + (target - current) * (1 - Math.exp(-rate * dt));
}

export class LeaderboardScene {
  constructor(canvas, labelCanvas) {
    this.canvas = canvas;
    this.labelCanvas = labelCanvas;
    this.labelCtx = labelCanvas ? labelCanvas.getContext('2d') : null;
    this.gl = null;
    this.teams = [];
    this.bars = new Map();
    this.pulses = [];
    this.particles = [];
    this.rings = [];
    this.time = 0;
    this.lastFrame = 0;
    this.fps = 0;
    this.fpsSamples = [];
    this.quality = 'auto';
    this.reducedMotion =
      typeof matchMedia === 'function' &&
      matchMedia('(prefers-reduced-motion: reduce)').matches;
    this.camera = { azimuth: 0, elevation: 0.42, distance: 26, target: [0, 3.2, 0] };
    this.drag = null;
    this.projected = new Float32Array(4);
    this.viewProj = mat4.create();
    this.view = mat4.create();
    this.proj = mat4.create();
    this.eye = [0, 8, 26];
    this.status = { state: 'initialising', lastHash: null, lastSeq: 0 };
    this.frames = 0;
    this.running = false;
  }

  init() {
    const gl = this.canvas.getContext('webgl2', {
      alpha: false,
      antialias: true,
      powerPreference: 'high-performance',
      preserveDrawingBuffer: false,
    });
    if (!gl) {
      this.status = { ...this.status, state: 'no-webgl2' };
      return false;
    }
    this.gl = gl;
    this.barProgram = createProgram(gl, BAR_VS, BAR_FS);
    this.floorProgram = createProgram(gl, FLOOR_VS, FLOOR_FS);
    this.particleProgram = createProgram(gl, PARTICLE_VS, PARTICLE_FS);
    this.ringProgram = createProgram(gl, RING_VS, RING_FS);
    this.cube = createInstancedCube(gl, MAX_BARS);
    this.triangle = createFullscreenTriangle(gl);
    this.particleBuffer = createDynamicBuffer(gl, MAX_PARTICLES * 8);
    this.particleVao = this._createParticleVao(gl);
    this.ringVao = this._createRingVao(gl);
    this._seedParticles();
    this._attachInput();
    this.resize();
    this.status = { ...this.status, state: 'ready' };
    return true;
  }

  _createParticleVao(gl) {
    const vao = gl.createVertexArray();
    gl.bindVertexArray(vao);
    gl.bindBuffer(gl.ARRAY_BUFFER, this.particleBuffer);
    const stride = 8 * 4;
    gl.enableVertexAttribArray(0);
    gl.vertexAttribPointer(0, 3, gl.FLOAT, false, stride, 0);
    gl.enableVertexAttribArray(1);
    gl.vertexAttribPointer(1, 1, gl.FLOAT, false, stride, 12);
    gl.enableVertexAttribArray(2);
    gl.vertexAttribPointer(2, 3, gl.FLOAT, false, stride, 16);
    gl.enableVertexAttribArray(3);
    gl.vertexAttribPointer(3, 1, gl.FLOAT, false, stride, 28);
    gl.bindVertexArray(null);
    return vao;
  }

  _createRingVao(gl) {
    const vao = gl.createVertexArray();
    gl.bindVertexArray(vao);
    const buffer = gl.createBuffer();
    gl.bindBuffer(gl.ARRAY_BUFFER, buffer);
    gl.bufferData(
      gl.ARRAY_BUFFER,
      new Float32Array([-1, -1, 1, -1, 1, 1, -1, -1, 1, 1, -1, 1]),
      gl.STATIC_DRAW,
    );
    gl.enableVertexAttribArray(0);
    gl.vertexAttribPointer(0, 2, gl.FLOAT, false, 0, 0);
    gl.bindVertexArray(null);
    return vao;
  }

  _seedParticles() {
    for (let i = 0; i < 260; i += 1) {
      this.particles.push({
        x: (Math.random() - 0.5) * 70,
        y: Math.random() * 16,
        z: (Math.random() - 0.5) * 70 - 6,
        vx: (Math.random() - 0.5) * 0.25,
        vy: 0.12 + Math.random() * 0.35,
        vz: (Math.random() - 0.5) * 0.25,
        size: 0.6 + Math.random() * 1.8,
        r: 0.45,
        g: 0.62,
        b: 0.95,
        a: 0.12 + Math.random() * 0.3,
        life: 1,
      });
    }
  }

  _attachInput() {
    const canvas = this.canvas;
    const onDown = (event) => {
      if (event.button !== undefined && event.button !== 0) return;
      this.drag = { x: event.clientX, y: event.clientY, moved: 0 };
      canvas.setPointerCapture?.(event.pointerId);
    };
    const onMove = (event) => {
      if (!this.drag) return;
      const dx = event.clientX - this.drag.x;
      const dy = event.clientY - this.drag.y;
      this.drag.moved += Math.abs(dx) + Math.abs(dy);
      this.drag.x = event.clientX;
      this.drag.y = event.clientY;
      this.camera.azimuth -= dx * 0.006;
      this.camera.elevation = Math.min(
        1.35,
        Math.max(0.08, this.camera.elevation + dy * 0.004),
      );
    };
    const onUp = (event) => {
      this.drag = null;
      canvas.releasePointerCapture?.(event.pointerId);
    };
    canvas.addEventListener('pointerdown', onDown);
    window.addEventListener('pointermove', onMove);
    window.addEventListener('pointerup', onUp);
    canvas.addEventListener(
      'wheel',
      (event) => {
        event.preventDefault();
        this.camera.distance = Math.min(
          60,
          Math.max(12, this.camera.distance + event.deltaY * 0.02),
        );
      },
      { passive: false },
    );
  }

  /**
   * Push a fresh projection. `board.teams` comes straight from the server;
   * nothing here recomputes a score.
   */
  update(board) {
    if (!board || !Array.isArray(board.teams)) return;
    const previous = new Map(this.teams.map((t) => [t.team_id, t]));
    this.teams = board.teams.map((team) => ({
      team_id: team.team_id,
      name: team.name,
      slug: team.slug,
      accent: team.accent,
      country: team.country,
      score: team.score,
      raw_score: team.raw_score,
      solves: team.solves,
      rank: team.rank,
      challenges_solved: team.challenges_solved,
      trend: team.trend,
      last_solve_at: team.last_solve_at,
    }));
    this.status.lastHash = board.state_hash || this.status.lastHash;
    this.status.lastSeq = board.last_seq || 0;

    const leader = this.teams.length ? this.teams.reduce((a, b) => (b.score > a.score ? b : a)) : null;
    this.layout(this.teams, leader);

    for (const team of this.teams) {
      const before = previous.get(team.team_id);
      const bar = this.bars.get(team.team_id);
      const target = this._heightFor(team, leader);
      if (!bar) {
        this.bars.set(team.team_id, {
          team,
          x: team.layout.x,
          z: team.layout.z,
          height: 0.05,
          target,
          targetHeight: target,
          width: team.layout.width,
          depth: team.layout.depth,
          glow: 0,
          fade: 0,
          targetFade: 1,
          rgb: hexToRgb(team.accent),
          settle: 0,
        });
        continue;
      }
      bar.team = team;
      bar.x = team.layout.x;
      bar.z = team.layout.z;
      bar.width = team.layout.width;
      bar.depth = team.layout.depth;
      bar.rgb = hexToRgb(team.accent);
      bar.targetHeight = target;

      if (before && team.score > before.score) {
        this.celebrate(team, team.score - before.score);
        bar.settle = 1;
      } else if (before && team.score < before.score) {
        this.flash(team, 'score-revised');
      }
    }

    for (const [id, bar] of this.bars) {
      if (!this.teams.some((t) => t.team_id === id)) {
        bar.targetFade = 0;
      }
    }
  }

  /** Podium in front, then a shallow arc. Pure layout, no randomness. */
  layout(teams, leader) {
    const arcRadius = 9.5;
    const visible = teams.slice(0, MAX_BARS);
    visible.forEach((team, index) => {
      if (leader && team.team_id === leader.team_id) {
        team.layout = { x: 0, z: 0.5, width: 1.5, depth: 1.5 };
        return;
      }
      const t = index / Math.max(1, visible.length - 1);
      const angle = (t - 0.5) * Math.PI * 1.02;
      const x = Math.sin(angle) * arcRadius;
      const z = -Math.cos(angle) * arcRadius * 0.55 + 3.2;
      const width = 0.85;
      team.layout = { x, z, width, depth: width };
    });
  }

  _heightFor(team, leader) {
    const reference = Math.max(1, leader ? leader.score : 1);
    return 0.4 + (team.score / reference) * 9.5;
  }

  celebrate(team, delta) {
    const bar = this.bars.get(team.team_id);
    if (!bar) return;
    bar.glow = 1;
    this.rings.push({
      x: bar.x,
      z: bar.z,
      age: 0,
      life: this.reducedMotion ? 0.9 : 2.1,
      rgb: bar.rgb,
    });
    if (this.rings.length > MAX_RINGS) this.rings.shift();
    const burst = this.reducedMotion ? 12 : 46;
    for (let i = 0; i < burst; i += 1) {
      const angle = Math.random() * Math.PI * 2;
      const speed = 1.6 + Math.random() * 3.4;
      this.particles.push({
        x: bar.x,
        y: bar.targetHeight + 0.3,
        z: bar.z,
        vx: Math.cos(angle) * speed,
        vy: 1.6 + Math.random() * 3.6,
        vz: Math.sin(angle) * speed,
        size: 1.2 + Math.random() * 2.4,
        r: bar.rgb[0],
        g: bar.rgb[1],
        b: bar.rgb[2],
        a: 0.95,
        life: 1,
      });
    }
    if (this.particles.length > MAX_PARTICLES) {
      this.particles.splice(0, this.particles.length - MAX_PARTICLES);
    }
  }

  flash(team, reason) {
    const bar = this.bars.get(team.team_id);
    if (bar) bar.glow = Math.max(bar.glow, 0.5);
    this.status.lastFlash = reason;
  }

  resize() {
    if (!this.gl) return;
    const dpr = Math.min(window.devicePixelRatio || 1, this.quality === 'low' ? 1 : 2);
    const width = Math.floor(this.canvas.clientWidth * dpr);
    const height = Math.floor(this.canvas.clientHeight * dpr);
    if (width === 0 || height === 0) return;
    if (this.canvas.width !== width || this.canvas.height !== height) {
      this.canvas.width = width;
      this.canvas.height = height;
    }
    if (this.labelCanvas) {
      this.labelCanvas.width = Math.floor(this.labelCanvas.clientWidth * dpr);
      this.labelCanvas.height = Math.floor(this.labelCanvas.clientHeight * dpr);
    }
    this.gl.viewport(0, 0, width, height);
  }

  setQuality(level) {
    this.quality = level;
    this.resize();
  }

  start() {
    if (this.running || !this.gl) return;
    this.running = true;
    const loop = (now) => {
      if (!this.running) return;
      this.frame(now);
      this.raf = requestAnimationFrame(loop);
    };
    this.raf = requestAnimationFrame(loop);
  }

  stop() {
    this.running = false;
    if (this.raf) cancelAnimationFrame(this.raf);
  }

  frame(now) {
    const dt = Math.min(0.05, (now - (this.lastFrame || now)) / 1000);
    this.lastFrame = now;
    this.time += dt;
    this.resize();
    this._update(dt);
    this._render();
    this._drawLabels();

    this.frames += 1;
    if (dt > 0) {
      this.fpsSamples.push(1 / dt);
      if (this.fpsSamples.length > 60) this.fpsSamples.shift();
      this.fps =
        this.fpsSamples.reduce((a, b) => a + b, 0) / this.fpsSamples.length;
    }
    if (this.quality === 'auto' && this.frames === 240) {
      this.quality = this.fps < 24 ? 'low' : 'high';
    }
  }

  _update(dt) {
    for (const bar of this.bars.values()) {
      bar.height = ease(bar.height, bar.targetHeight, 4.5, dt);
      bar.fade = ease(bar.fade, bar.targetFade, 5, dt);
      bar.glow = Math.max(0, bar.glow - dt * 0.7);
      bar.settle = Math.max(0, bar.settle - dt * 0.9);
    }
    for (const ring of this.rings) ring.age += dt;
    this.rings = this.rings.filter((r) => r.age < r.life);

    for (const p of this.particles) {
      p.x += p.vx * dt;
      p.y += p.vy * dt;
      p.z += p.vz * dt;
      p.vy -= 2.4 * dt;
      p.life -= dt * (p.a > 0.5 ? 0.75 : 0.05);
      if (p.y < 0.05) {
        p.y = 0.05;
        p.vy = Math.abs(p.vy) * 0.28;
        p.vx *= 0.7;
        p.vz *= 0.7;
      }
    }
    this.particles = this.particles.filter((p) => p.life > 0 && p.a > 0.01);
    if (this.particles.length > MAX_PARTICLES) {
      this.particles.splice(0, this.particles.length - MAX_PARTICLES);
    }
  }

  _cameraMatrices() {
    const { azimuth, elevation, distance, target } = this.camera;
    const eye = [
      target[0] + Math.sin(azimuth) * Math.cos(elevation) * distance,
      target[1] + Math.sin(elevation) * distance,
      target[2] + Math.cos(azimuth) * Math.cos(elevation) * distance,
    ];
    this.eye = eye;
    const aspect = this.canvas.width / Math.max(1, this.canvas.height);
    mat4.perspective(this.proj, (50 * Math.PI) / 180, aspect, 0.1, 220);
    mat4.lookAt(this.view, eye, target, [0, 1, 0]);
    mat4.multiply(this.viewProj, this.proj, this.view);
  }

  _render() {
    const gl = this.gl;
    this._cameraMatrices();
    gl.clearColor(0.027, 0.043, 0.086, 1);
    gl.clear(gl.COLOR_BUFFER_BIT | gl.DEPTH_BUFFER_BIT);

    // floor (additive-free, drawn first with depth writes off)
    gl.disable(gl.DEPTH_TEST);
    gl.useProgram(this.floorProgram.program);
    const invViewProj = mat4.create();
    invertMat4(invViewProj, this.viewProj);
    gl.uniformMatrix4fv(this.floorProgram.uniforms.uInvViewProj, false, invViewProj);
    gl.uniform1f(this.floorProgram.uniforms.uTime, this.time);
    gl.bindVertexArray(this.triangle);
    gl.drawArrays(gl.TRIANGLES, 0, 3);
    gl.enable(gl.DEPTH_TEST);

    // bars
    const data = new Float32Array(MAX_BARS * 9);
    let count = 0;
    for (const bar of this.bars.values()) {
      if (bar.fade < 0.01 || count >= MAX_BARS) continue;
      const o = count * 9;
      data[o] = bar.x;
      data[o + 1] = 0;
      data[o + 2] = bar.z;
      data[o + 3] = Math.max(0.05, bar.height);
      data[o + 4] = bar.rgb[0];
      data[o + 5] = bar.rgb[1];
      data[o + 6] = bar.rgb[2];
      data[o + 7] = bar.glow;
      data[o + 8] = bar.fade;
      count += 1;
    }
    if (count > 0) {
      gl.bindBuffer(gl.ARRAY_BUFFER, this.cube.instanceBuffer);
      gl.bufferSubData(gl.ARRAY_BUFFER, 0, data.subarray(0, count * 9));
      gl.useProgram(this.barProgram.program);
      gl.uniformMatrix4fv(this.barProgram.uniforms.uViewProj, false, this.viewProj);
      gl.uniform1f(this.barProgram.uniforms.uWidth, 0.95);
      gl.uniform1f(this.barProgram.uniforms.uDepth, 0.95);
      gl.uniform3f(this.barProgram.uniforms.uCamera, this.eye[0], this.eye[1], this.eye[2]);
      gl.uniform1f(this.barProgram.uniforms.uTime, this.time);
      gl.enable(gl.BLEND);
      gl.blendFunc(gl.SRC_ALPHA, gl.ONE_MINUS_SRC_ALPHA);
      gl.bindVertexArray(this.cube.vao);
      gl.drawElementsInstanced(gl.TRIANGLES, 36, gl.UNSIGNED_SHORT, 0, count);
    }

    // pulses
    if (this.rings.length) {
      gl.useProgram(this.ringProgram.program);
      gl.uniformMatrix4fv(this.ringProgram.uniforms.uViewProj, false, this.viewProj);
      gl.enable(gl.BLEND);
      gl.blendFunc(gl.SRC_ALPHA, gl.ONE);
      gl.depthMask(false);
      gl.bindVertexArray(this.ringVao);
      for (const ring of this.rings) {
        const t = ring.age / ring.life;
        const alpha = Math.max(0, (1 - t) ** 2);
        gl.uniform1f(this.ringProgram.uniforms.uRadius, 0.4 + t * 3.4);
        gl.uniform1f(this.ringProgram.uniforms.uWidth, ring.x);
        gl.uniform3f(
          this.ringProgram.uniforms.uColour,
          ring.rgb[0],
          ring.rgb[1],
          ring.rgb[2],
        );
        gl.uniform1f(this.ringProgram.uniforms.uAlpha, alpha);
        gl.drawArrays(gl.TRIANGLES, 0, 6);
      }
      gl.depthMask(true);
    }

    // particles
    if (this.particles.length) {
      const n = Math.min(this.particles.length, MAX_PARTICLES);
      const pdata = new Float32Array(n * 8);
      for (let i = 0; i < n; i += 1) {
        const p = this.particles[i];
        const o = i * 8;
        pdata[o] = p.x;
        pdata[o + 1] = p.y;
        pdata[o + 2] = p.z;
        pdata[o + 3] = p.size;
        pdata[o + 4] = p.r;
        pdata[o + 5] = p.g;
        pdata[o + 6] = p.b;
        pdata[o + 7] = Math.max(0, Math.min(1, p.a * p.life));
      }
      gl.bindBuffer(gl.ARRAY_BUFFER, this.particleBuffer);
      gl.bufferSubData(gl.ARRAY_BUFFER, 0, pdata);
      gl.useProgram(this.particleProgram.program);
      gl.uniformMatrix4fv(this.particleProgram.uniforms.uViewProj, false, this.viewProj);
      gl.uniform1f(
        this.particleProgram.uniforms.uPixelRatio,
        Math.min(window.devicePixelRatio || 1, 2),
      );
      gl.enable(gl.BLEND);
      gl.blendFunc(gl.SRC_ALPHA, gl.ONE);
      gl.depthMask(false);
      gl.bindVertexArray(this.particleVao);
      gl.drawArrays(gl.POINTS, 0, n);
      gl.depthMask(true);
    }

    gl.bindVertexArray(null);
  }

  /** HTML labels are drawn on a 2D canvas: crisper text than SDF atlases. */
  _drawLabels() {
    const ctx = this.labelCtx;
    if (!ctx) return;
    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    const w = this.labelCanvas.clientWidth;
    const h = this.labelCanvas.clientHeight;
    ctx.setTransform(1, 0, 0, 1, 0, 0);
    ctx.clearRect(0, 0, this.labelCanvas.width, this.labelCanvas.height);
    ctx.scale(dpr, dpr);

    const ranked = this.teams.slice(0, 16);
    ctx.textAlign = 'center';
    ctx.textBaseline = 'bottom';
    for (const team of ranked) {
      const bar = this.bars.get(team.team_id);
      if (!bar || bar.fade < 0.2) continue;
      mat4.projectPoint(this.projected, this.viewProj, bar.x, bar.height + 0.35, bar.z);
      if (this.projected[3] <= 0) continue;
      const sx = (this.projected[0] / this.projected[3] * 0.5 + 0.5) * w;
      const sy = (1 - (this.projected[1] / this.projected[3] * 0.5 + 0.5)) * h;
      if (sx < -100 || sx > w + 100 || sy < -50 || sy > h + 50) continue;

      const scale = Math.max(0.72, Math.min(1.12, 14 / Math.max(1, this.projected[3]) * 8));
      ctx.font = `600 ${Math.round(13 * scale)}px Inter, system-ui, sans-serif`;
      ctx.fillStyle = 'rgba(232, 236, 248, 0.95)';
      ctx.fillText(`#${team.rank} ${team.name}`, sx, sy);

      ctx.font = `500 ${Math.round(11 * scale)}px Inter, system-ui, sans-serif`;
      const rgb = bar.rgb.map((c) => Math.round(c * 255));
      ctx.fillStyle = `rgba(${rgb[0]}, ${rgb[1]}, ${rgb[2]}, 0.9)`;
      ctx.fillText(`${team.score} pts`, sx, sy - 16 * scale);
    }
  }

  /** Compact health payload for the HUD. */
  health() {
    return {
      ...this.status,
      fps: Math.round(this.fps),
      bars: this.bars.size,
      particles: this.particles.length,
      quality: this.quality,
    };
  }
}

function invertMat4(out, m) {
  const a00 = m[0];
  const a01 = m[1];
  const a02 = m[2];
  const a03 = m[3];
  const a10 = m[4];
  const a11 = m[5];
  const a12 = m[6];
  const a13 = m[7];
  const a20 = m[8];
  const a21 = m[9];
  const a22 = m[10];
  const a23 = m[11];
  const a30 = m[12];
  const a31 = m[13];
  const a32 = m[14];
  const a33 = m[15];
  const b00 = a00 * a11 - a01 * a10;
  const b01 = a00 * a12 - a02 * a10;
  const b02 = a00 * a13 - a03 * a10;
  const b03 = a01 * a12 - a02 * a11;
  const b04 = a01 * a13 - a03 * a11;
  const b05 = a02 * a13 - a03 * a12;
  const b06 = a20 * a31 - a21 * a30;
  const b07 = a20 * a32 - a22 * a30;
  const b08 = a20 * a33 - a23 * a30;
  const b09 = a21 * a32 - a22 * a31;
  const b10 = a21 * a33 - a23 * a31;
  const b11 = a22 * a33 - a23 * a32;
  let det = b00 * b11 - b01 * b10 + b02 * b09 + b03 * b08 - b04 * b07 + b05 * b06;
  if (!det) return out;
  det = 1.0 / det;
  out[0] = (a11 * b11 - a12 * b10 + a13 * b09) * det;
  out[1] = (a02 * b10 - a01 * b11 - a03 * b09) * det;
  out[2] = (a31 * b05 - a32 * b04 + a33 * b03) * det;
  out[3] = (a22 * b04 - a21 * b05 - a23 * b03) * det;
  out[4] = (a12 * b08 - a10 * b11 - a13 * b07) * det;
  out[5] = (a00 * b11 - a02 * b08 + a03 * b07) * det;
  out[6] = (a32 * b02 - a30 * b05 - a33 * b01) * det;
  out[7] = (a20 * b05 - a22 * b02 + a23 * b01) * det;
  out[8] = (a10 * b10 - a11 * b08 + a13 * b06) * det;
  out[9] = (a01 * b08 - a00 * b10 - a03 * b06) * det;
  out[10] = (a30 * b04 - a31 * b02 + a33 * b00) * det;
  out[11] = (a21 * b02 - a20 * b04 - a23 * b00) * det;
  out[12] = (a11 * b07 - a10 * b09 - a12 * b06) * det;
  out[13] = (a00 * b09 - a01 * b07 + a02 * b06) * det;
  out[14] = (a31 * b01 - a30 * b03 - a32 * b00) * det;
  out[15] = (a20 * b03 - a21 * b01 + a22 * b00) * det;
  return out;
}
