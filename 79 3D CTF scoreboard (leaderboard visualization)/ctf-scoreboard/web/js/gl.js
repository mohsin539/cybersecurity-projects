/**
 * Minimal WebGL2 engine.
 *
 * No libraries, no CDN, no build step: the scoreboard must render on a venue
 * machine with no internet. This module provides just enough of an engine to
 * draw the scene - a mat4 math subset, program compilation with useful errors,
 * an instanced cube mesh, a procedural floor, point particles and additive
 * pulse rings - plus a screen-space projection helper for HTML text labels.
 */

export const VERTEX_SHADER_VERSION = '#version 300 es\n';

export function createShader(gl, type, source) {
  const shader = gl.createShader(type);
  gl.shaderSource(shader, source);
  gl.compileShader(shader);
  if (!gl.getShaderParameter(shader, gl.COMPILE_STATUS)) {
    const log = gl.getShaderInfoLog(shader);
    const numbered = source
      .split('\n')
      .map((line, i) => `${String(i + 1).padStart(3)} | ${line}`)
      .join('\n');
    gl.deleteShader(shader);
    throw new Error(`Shader compile failed:\n${log}\n${numbered}`);
  }
  return shader;
}

export function createProgram(gl, vertexSource, fragmentSource) {
  const program = gl.createProgram();
  const vs = createShader(gl, gl.VERTEX_SHADER, vertexSource);
  const fs = createShader(gl, gl.FRAGMENT_SHADER, fragmentSource);
  gl.attachShader(program, vs);
  gl.attachShader(program, fs);
  gl.linkProgram(program);
  gl.deleteShader(vs);
  gl.deleteShader(fs);
  if (!gl.getProgramParameter(program, gl.LINK_STATUS)) {
    const log = gl.getProgramInfoLog(program);
    gl.deleteProgram(program);
    throw new Error(`Program link failed: ${log}`);
  }
  const uniforms = {};
  const count = gl.getProgramParameter(program, gl.ACTIVE_UNIFORMS);
  for (let i = 0; i < count; i += 1) {
    const info = gl.getActiveUniform(program, i);
    if (info) uniforms[info.name.replace('[0]', '')] = gl.getUniformLocation(program, info.name);
  }
  return { program, uniforms };
}

// ------------------------------------------------------------------- mat4 ----
export const mat4 = {
  create() {
    return new Float32Array([1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1]);
  },

  identity(out) {
    out.set([1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1]);
    return out;
  },

  perspective(out, fovy, aspect, near, far) {
    const f = 1 / Math.tan(fovy / 2);
    const nf = 1 / (near - far);
    out[0] = f / aspect;
    out[1] = 0;
    out[2] = 0;
    out[3] = 0;
    out[4] = 0;
    out[5] = f;
    out[6] = 0;
    out[7] = 0;
    out[8] = 0;
    out[9] = 0;
    out[10] = (far + near) * nf;
    out[11] = -1;
    out[12] = 0;
    out[13] = 0;
    out[14] = 2 * far * near * nf;
    out[15] = 0;
    return out;
  },

  lookAt(out, eye, center, up) {
    let z0 = eye[0] - center[0];
    let z1 = eye[1] - center[1];
    let z2 = eye[2] - center[2];
    let len = Math.hypot(z0, z1, z2) || 1;
    z0 /= len;
    z1 /= len;
    z2 /= len;

    let x0 = up[1] * z2 - up[2] * z1;
    let x1 = up[2] * z0 - up[0] * z2;
    let x2 = up[0] * z1 - up[1] * z0;
    len = Math.hypot(x0, x1, x2);
    if (len) {
      x0 /= len;
      x1 /= len;
      x2 /= len;
    }

    const y0 = z1 * x2 - z2 * x1;
    const y1 = z2 * x0 - z0 * x2;
    const y2 = z0 * x1 - z1 * x0;

    out[0] = x0;
    out[1] = y0;
    out[2] = z0;
    out[3] = 0;
    out[4] = x1;
    out[5] = y1;
    out[6] = z1;
    out[7] = 0;
    out[8] = x2;
    out[9] = y2;
    out[10] = z2;
    out[11] = 0;
    out[12] = -(x0 * eye[0] + x1 * eye[1] + x2 * eye[2]);
    out[13] = -(y0 * eye[0] + y1 * eye[1] + y2 * eye[2]);
    out[14] = -(z0 * eye[0] + z1 * eye[1] + z2 * eye[2]);
    out[15] = 1;
    return out;
  },

  multiply(out, a, b) {
    for (let c = 0; c < 4; c += 1) {
      const b0 = b[c * 4];
      const b1 = b[c * 4 + 1];
      const b2 = b[c * 4 + 2];
      const b3 = b[c * 4 + 3];
      out[c * 4] = b0 * a[0] + b1 * a[4] + b2 * a[8] + b3 * a[12];
      out[c * 4 + 1] = b0 * a[1] + b1 * a[5] + b2 * a[9] + b3 * a[13];
      out[c * 4 + 2] = b0 * a[2] + b1 * a[6] + b2 * a[10] + b3 * a[14];
      out[c * 4 + 3] = b0 * a[3] + b1 * a[7] + b2 * a[11] + b3 * a[15];
    }
    return out;
  },

  /** Project a world point to normalised device coordinates; w <= 0 means behind the camera. */
  projectPoint(out, m, x, y, z) {
    const cx = m[0] * x + m[4] * y + m[8] * z + m[12];
    const cy = m[1] * x + m[5] * y + m[9] * z + m[13];
    const cz = m[2] * x + m[6] * y + m[10] * z + m[14];
    const cw = m[3] * x + m[7] * y + m[11] * z + m[15];
    out[0] = cx;
    out[1] = cy;
    out[2] = cz;
    out[3] = cw;
    return out;
  },
};

export function hexToRgb(hex) {
  const clean = String(hex || '#6c5ce7').replace('#', '');
  const full =
    clean.length === 3
      ? clean
          .split('')
          .map((c) => c + c)
          .join('')
      : clean.padEnd(6, '0').slice(0, 6);
  const int = parseInt(full, 16);
  return [((int >> 16) & 255) / 255, ((int >> 8) & 255) / 255, (int & 255) / 255];
}

// ------------------------------------------------------------------ meshes ----
const CUBE_POSITIONS = new Float32Array([
  // front
  -0.5, -0.5, 0.5, 0.5, -0.5, 0.5, 0.5, 0.5, 0.5, -0.5, 0.5, 0.5,
  // back
  0.5, -0.5, -0.5, -0.5, -0.5, -0.5, -0.5, 0.5, -0.5, 0.5, 0.5, -0.5,
  // top
  -0.5, 0.5, 0.5, 0.5, 0.5, 0.5, 0.5, 0.5, -0.5, -0.5, 0.5, -0.5,
  // bottom
  -0.5, -0.5, -0.5, 0.5, -0.5, -0.5, 0.5, -0.5, 0.5, -0.5, -0.5, 0.5,
  // right
  0.5, -0.5, 0.5, 0.5, -0.5, -0.5, 0.5, 0.5, -0.5, 0.5, 0.5, 0.5,
  // left
  -0.5, -0.5, -0.5, -0.5, -0.5, 0.5, -0.5, 0.5, 0.5, -0.5, 0.5, -0.5,
]);

const CUBE_NORMALS = new Float32Array([
  0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1,
  0, 0, -1, 0, 0, -1, 0, 0, -1, 0, 0, -1,
  0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0,
  0, -1, 0, 0, -1, 0, 0, -1, 0, 0, -1, 0,
  1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0,
  -1, 0, 0, -1, 0, 0, -1, 0, 0, -1, 0, 0,
]);

const CUBE_INDICES = new Uint16Array([
  0, 1, 2, 0, 2, 3, 4, 5, 6, 4, 6, 7,
  8, 9, 10, 8, 10, 11, 12, 13, 14, 12, 14, 15,
  16, 17, 18, 16, 18, 19, 20, 21, 22, 20, 22, 23,
]);

/**
 * Instanced unit cube. Per-instance attributes:
 *   0 vec3 offset, 1 float height, 2 vec3 colour, 3 vec2 (glow, fade)
 */
export function createInstancedCube(gl, capacity) {
  const vao = gl.createVertexArray();
  gl.bindVertexArray(vao);

  const positionBuffer = gl.createBuffer();
  gl.bindBuffer(gl.ARRAY_BUFFER, positionBuffer);
  gl.bufferData(gl.ARRAY_BUFFER, CUBE_POSITIONS, gl.STATIC_DRAW);
  gl.enableVertexAttribArray(0);
  gl.vertexAttribPointer(0, 3, gl.FLOAT, false, 0, 0);

  const normalBuffer = gl.createBuffer();
  gl.bindBuffer(gl.ARRAY_BUFFER, normalBuffer);
  gl.bufferData(gl.ARRAY_BUFFER, CUBE_NORMALS, gl.STATIC_DRAW);
  gl.enableVertexAttribArray(1);
  gl.vertexAttribPointer(1, 3, gl.FLOAT, false, 0, 0);

  const indexBuffer = gl.createBuffer();
  gl.bindBuffer(gl.ELEMENT_ARRAY_BUFFER, indexBuffer);
  gl.bufferData(gl.ELEMENT_ARRAY_BUFFER, CUBE_INDICES, gl.STATIC_DRAW);

  // interleaved: offset(3) height(1) colour(3) glow(1) fade(1) = 9 floats
  const stride = 9 * 4;
  const instanceBuffer = gl.createBuffer();
  gl.bindBuffer(gl.ARRAY_BUFFER, instanceBuffer);
  gl.bufferData(gl.ARRAY_BUFFER, capacity * stride, gl.DYNAMIC_DRAW);

  gl.enableVertexAttribArray(2);
  gl.vertexAttribPointer(2, 3, gl.FLOAT, false, stride, 0);
  gl.vertexAttribDivisor(2, 1);
  gl.enableVertexAttribArray(3);
  gl.vertexAttribPointer(3, 1, gl.FLOAT, false, stride, 12);
  gl.vertexAttribDivisor(3, 1);
  gl.enableVertexAttribArray(4);
  gl.vertexAttribPointer(4, 3, gl.FLOAT, false, stride, 16);
  gl.vertexAttribDivisor(4, 1);
  gl.enableVertexAttribArray(5);
  gl.vertexAttribPointer(5, 1, gl.FLOAT, false, stride, 28);
  gl.vertexAttribDivisor(5, 1);
  gl.enableVertexAttribArray(6);
  gl.vertexAttribPointer(6, 1, gl.FLOAT, false, stride, 32);
  gl.vertexAttribDivisor(6, 1);

  gl.bindVertexArray(null);
  return { vao, instanceBuffer, capacity, stride };
}

/** A single full-screen triangle used for the floor and background passes. */
export function createFullscreenTriangle(gl) {
  const vao = gl.createVertexArray();
  gl.bindVertexArray(vao);
  const buffer = gl.createBuffer();
  gl.bindBuffer(gl.ARRAY_BUFFER, buffer);
  gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-1, -1, 3, -1, -1, 3]), gl.STATIC_DRAW);
  gl.enableVertexAttribArray(0);
  gl.vertexAttribPointer(0, 2, gl.FLOAT, false, 0, 0);
  gl.bindVertexArray(null);
  return vao;
}

export function createDynamicBuffer(gl, capacityFloats) {
  const buffer = gl.createBuffer();
  gl.bindBuffer(gl.ARRAY_BUFFER, buffer);
  gl.bufferData(gl.ARRAY_BUFFER, capacityFloats * 4, gl.DYNAMIC_DRAW);
  gl.bindBuffer(gl.ARRAY_BUFFER, null);
  return buffer;
}
