#!/usr/bin/env node
/**
 * scripts/build-pages.mjs — assemble the static GitHub Pages site.
 *
 * Copies three self-contained, static dashboard front ends into /pages and
 * prefixes absolute asset paths with each project's sub-URL so they load
 * correctly when served from https://mohsin539.github.io/cybersecurity-projects/.
 *
 *   66 → /traffic-monitor/   (public/, pure static UI; data needs the local server)
 *   78 → /webxr-training/    (public/, pure static UI; API calls need the local server)
 *   79 → /ctf-scoreboard/    (web/, pure static UI; score data needs the FastAPI service)
 *
 * The dashboards are client/server apps: online they render fully against
 * their local backends. On Pages they serve as static previews — a yellow
 * banner injected into every index.html says exactly that.
 *
 * Usage:  node scripts/build-pages.mjs          # from the repository root
 */

import { cpSync, existsSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

const ROOT = process.cwd();

const SITES = [
  {
    id: 'traffic-monitor',
    title: 'Network Traffic Monitor',
    project: '66. Network traffic monitor app (on-device, per-app bandwidth)',
    src: 'public',
    rewrites: [], // already uses relative paths
  },
  {
    id: 'webxr-training',
    title: 'WebXR Security Awareness Training',
    project: '78. WebXR security awareness training module',
    src: 'public',
    rewrites: [
      [/href="\/(css|icons|manifest\.webmanifest)/g, 'href="$1'],
      [/src="\/(js)/g, 'src="$1'],
    ],
  },
  {
    id: 'ctf-scoreboard',
    title: '3D CTF Scoreboard',
    project: '79 3D CTF scoreboard (leaderboard visualization)',
    src: 'ctf-scoreboard/web',
    // The FastAPI app serves web/ under a /static/* URL alias; on Pages the
    // files sit at the site root, so strip the alias.
    rewrites: [
      [/href="\/(favicon\.svg)/g, 'href="$1'],
      [/href="\/static\//g, 'href="'],
      [/src="\/static\//g, 'src="'],
    ],
  },
];

const BANNER = (title, project) => `
<div style="background:#f59e0b;color:#1f2937;font:14px/1.5 system-ui,sans-serif;padding:10px 16px;text-align:center">
  ⚠️ <strong>Static preview</strong> of “${title}” (project ${project.split('.')[0].trim()}) from the
  <a href="https://github.com/mohsin539/cybersecurity-projects" style="color:#1f2937">cybersecurity-projects</a> portfolio.
  Live data (sampling, APIs) requires running the project locally — see its README.
  <a href="../../" style="color:#1f2937;font-weight:600">← All demos</a>
</div>`;

/** Recursively rewrite absolute asset refs in .html/.js/.css/.webmanifest files. */
function rewriteRefs(dir, rewrites) {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, entry.name);
    if (entry.isDirectory()) {
      rewriteRefs(p, rewrites);
    } else if (/\.(html|js|css|webmanifest|json)$/.test(entry.name)) {
      let text = readFileSync(p, 'utf8');
      const before = text;
      for (const [re, replacement] of rewrites) text = text.replace(re, replacement);
      if (text !== before) writeFileSync(p, text);
    }
  }
}

function main() {
  const outDir = join(ROOT, 'pages');
  rmSync(outDir, { recursive: true, force: true });
  mkdirSync(outDir, { recursive: true });

  const cards = [];

  for (const site of SITES) {
    const srcDir = join(ROOT, site.project, site.src);
    const destDir = join(outDir, site.id);
    if (!existsSync(srcDir)) {
      console.error(`✗ missing source dir for ${site.id}: ${srcDir}`);
      process.exitCode = 1;
      continue;
    }

    cpSync(srcDir, destDir, { recursive: true });
    rewriteRefs(destDir, site.rewrites);

    const indexCandidates = ['index.html', 'dashboard.html'];
    const indexPath = indexCandidates.map((f) => join(destDir, f)).find((f) => existsSync(f));
    if (indexPath) {
      const html = readFileSync(indexPath, 'utf8');
      const injected = html.replace(
        /(<body[^>]*>)/i,
        `$1\n${BANNER(site.title, site.project)}`
      );
      writeFileSync(indexPath, injected);
    }
    cards.push({ site, hasIndex: Boolean(indexPath) });
    console.log(`✓ ${site.id}/  ← ${site.project}/${site.src}`);
  }

  // Landing page listing all previews.
  const indexHtml = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Cybersecurity Projects — Live Demos</title>
<style>
  :root { color-scheme: dark; }
  body { font:16px/1.6 system-ui,sans-serif; margin:0; background:#0b1220; color:#e5e7eb; }
  main { max-width: 900px; margin: 0 auto; padding: 48px 24px; }
  h1 { font-size: 28px; margin: 0 0 4px; }
  p.sub { color: #94a3b8; margin-top: 0; }
  .grid { display: grid; gap: 16px; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); margin-top: 32px; }
  a.card { display:block; background:#111a2e; border:1px solid #1f2a44; border-radius:12px; padding:20px; text-decoration:none; color:inherit; transition:border-color .15s; }
  a.card:hover { border-color:#3b82f6; }
  .card h2 { margin:0 0 8px; font-size:18px; }
  .card p { margin:0; color:#94a3b8; font-size:14px; }
  footer { margin-top:48px; color:#64748b; font-size:14px; }
  footer a { color:#93c5fd; }
</style>
</head>
<body>
<main>
  <h1>🛡️ Cybersecurity Projects — Live Demos</h1>
  <p class="sub">Static previews of select dashboards from the portfolio. Most tools in the repo are lab agents/services — run them locally per each project's README.</p>
  <div class="grid">
${cards
  .map(
    ({ site }) => `    <a class="card" href="${site.id}/">
      <h2>${site.title}</h2>
      <p>Project ${site.project.split('.')[0].trim()} — static UI preview</p>
    </a>`
  )
  .join('\n')}
  </div>
  <footer>
    ⚠️ Educational use only — every tool is scoped to labs, owned systems, or authorized environments.<br>
    <a href="https://github.com/mohsin539/cybersecurity-projects">github.com/mohsin539/cybersecurity-projects</a>
  </footer>
</main>
</body>
</html>
`;
  writeFileSync(join(outDir, 'index.html'), indexHtml);
  console.log('✓ pages/index.html');
}

main();
