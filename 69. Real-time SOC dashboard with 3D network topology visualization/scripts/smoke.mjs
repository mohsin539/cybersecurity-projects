import { chromium } from 'playwright';
import { spawn } from 'node:child_process';
import { setTimeout as sleep } from 'node:timers/promises';

const PORT = 4173;
const url = `http://localhost:${PORT}/`;
let failures = 0;

const server = spawn('npx', ['vite', 'preview', '--port', String(PORT), '--strictPort'], {
  shell: true,
  stdio: 'pipe',
});

server.stdout.on('data', (d) => process.stdout.write(`[preview] ${d}`));
server.stderr.on('data', (d) => process.stderr.write(`[preview] ${d}`));

await sleep(3500);

const browser = await chromium.launch();
const page = await browser.newPage({ viewport: { width: 1600, height: 950 } });

const consoleErrors = [];
page.on('console', (msg) => {
  if (msg.type() === 'error') consoleErrors.push(msg.text());
});
page.on('pageerror', (err) => consoleErrors.push(`pageerror: ${err.message}`));

try {
  const resp = await page.goto(url, { waitUntil: 'networkidle', timeout: 30000 });
  if (!resp || !resp.ok()) {
    failures++;
    console.log(`✗ HTTP status ${resp ? resp.status() : 'none'}`);
  } else {
    console.log(`✓ HTTP ${resp.status()} ${url}`);
  }

  await sleep(2500);

  const checks = [
    ['.topbar', 'top bar'],
    ['.stats-bar', 'stats bar'],
    ['.legend', 'legend'],
    ['.side-panel', 'side panel'],
    ['.hop-list .hop', 'attack path hops rendered'],
    ['canvas', 'three.js canvas'],
    ['.bh-label', '3d node labels'],
    ['.statusbar', 'status bar'],
    ['.nav-rail', 'nav rail'],
    ['.stream-ticker', 'stream ticker'],
  ];
  for (const [sel, label] of checks) {
    const n = await page.locator(sel).count();
    if (n === 0) {
      failures++;
      console.log(`✗ missing: ${label} (${sel})`);
    } else {
      console.log(`✓ ${label}: ${n}`);
    }
  }

  // navigate every SOC module via the nav rail
  const modules = [
    ['3D Topology', '.topology-module'],
    ['Blanket Map', '.blanket-layout'],
    ['Alert Triage', '.alert-table'],
    ['Incidents', '.incident-grid'],
    ['Query Studio', '.query-editor'],
    ['Threat Intel', '.intel-layout'],
    ['Compliance', '.framework-grid'],
  ];
  for (const [title, root] of modules) {
    await page.locator(`.nav-item[title="${title}"]`).click();
    await sleep(400);
    const n = await page.locator(root).count();
    if (n === 0) {
      failures++;
      console.log(`✗ module missing: ${title} (${root})`);
    } else {
      console.log(`✓ module: ${title}`);
    }
  }

  // back to topology for the interaction + screenshot checks
  await page.locator('.nav-item[title="3D Topology"]').click();
  await sleep(1200);

  // verify canvas has non-trivial size
  const canvasBox = await page.locator('canvas').first().boundingBox();
  if (!canvasBox || canvasBox.width < 300 || canvasBox.height < 300) {
    failures++;
    console.log(`✗ canvas size invalid: ${JSON.stringify(canvasBox)}`);
  } else {
    console.log(`✓ canvas size ${Math.round(canvasBox.width)}x${Math.round(canvasBox.height)}`);
  }

  // select a hop focus button (interaction)
  await page.locator('.hop-from').first().click();
  await sleep(800);

  // toggle plan view
  await page.locator('.icon-btn.wide').first().click();
  await sleep(600);

  await page.screenshot({ path: 'smoke-screenshot.png' });
  console.log('✓ screenshot saved to smoke-screenshot.png');

  if (consoleErrors.length > 0) {
    failures++;
    console.log(`✗ console/page errors (${consoleErrors.length}):`);
    consoleErrors.slice(0, 10).forEach((e) => console.log(`   - ${e}`));
  } else {
    console.log('✓ no console/page errors');
  }
} catch (err) {
  failures++;
  console.log(`✗ exception: ${err.message}`);
} finally {
  await browser.close();
  server.kill();
}

console.log(failures === 0 ? '\nSMOKE PASS' : `\nSMOKE FAIL (${failures})`);
process.exit(failures === 0 ? 0 : 1);