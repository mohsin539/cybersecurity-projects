/* Headless-Chrome E2E verification for SentinelGraph UI.
 * Drives the installed Chrome (puppeteer-core): login, dashboard,
 * graph explorer + attack-path simulation, compliance, audit, screenshots.
 *
 * Usage: node verify.js  (server must be running at http://127.0.0.1:8015)
 */
const puppeteer = require('puppeteer-core')
const fs = require('fs')

const BASE = process.env.SG_BASE || 'http://127.0.0.1:8015'
const CHROME = process.env.CHROME_PATH ||
  'C:/Program Files/Google/Chrome/Application/chrome.exe'
const ART = __dirname + '/artifacts'

const results = []
const consoleErrors = []
const check = (name, ok, detail = '') => {
  results.push({ name, ok, detail })
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? ' — ' + detail : ''}`)
  return ok
}

const sleep = (ms) => new Promise(r => setTimeout(r, ms))

async function clickByText(page, selector, text) {
  const ok = await page.evaluate((sel, t) => {
    const els = [...document.querySelectorAll(sel)]
    const el = els.find(e => e.textContent.trim().includes(t))
    if (el) { el.click(); return true }
    return false
  }, selector, text)
  if (!ok) throw new Error(`no ${selector} containing "${text}"`)
}

async function bodyHas(page, text) {
  return page.evaluate(t =>
    document.body.innerText.toLowerCase().includes(t.toLowerCase()), text)
}

async function waitForText(page, text, timeout = 10000) {
  await page.waitForFunction(
    t => document.body.innerText.toLowerCase().includes(t.toLowerCase()),
    { timeout }, text)
}

;(async () => {
  fs.mkdirSync(ART, { recursive: true })
  const browser = await puppeteer.launch({
    executablePath: CHROME,
    headless: true,
    args: ['--no-sandbox', '--disable-gpu', '--window-size=1600,1000'],
    defaultViewport: { width: 1600, height: 1000 },
  })
  const page = await browser.newPage()
  page.on('console', m => { if (m.type() === 'error') consoleErrors.push(m.text()) })
  page.on('pageerror', e => consoleErrors.push('pageerror: ' + e.message))

  // ---------- 1. Login page renders ----------
  await page.goto(BASE, { waitUntil: 'networkidle2' })
  check('login form renders', await bodyHas(page, 'SentinelGraph')
    && await bodyHas(page, 'Password'))
  await page.screenshot({ path: ART + '/01-login.png' })

  // ---------- 2. Sign in as admin ----------
  await page.click('input:not([type="password"])', { clickCount: 3 })
  await page.type('input:not([type="password"])', 'admin')
  await page.type('input[type="password"]', 'ChangeMe!Lab2024')
  await clickByText(page, 'button', 'Sign in')
  await waitForText(page, 'Graph Explorer')
  check('login succeeds (admin role visible)',
    await bodyHas(page, 'admin'), 'role chip in header')
  await sleep(600) // let dashboard data land
  await page.screenshot({ path: ART + '/02-dashboard.png' })

  // ---------- 3. Dashboard content ----------
  check('dashboard: risk index present', await bodyHas(page, 'Risk index'))
  check('dashboard: choke points section', await bodyHas(page, 'Choke points'))
  check('dashboard: findings feed', await bodyHas(page, 'Findings'))
  const dashText = await page.evaluate(() => document.body.innerText)
  check('dashboard: ESC1 finding listed',
    /ESC1/.test(dashText), 'ADCS rule surfaces on dashboard')

  // ---------- 3b. What-if remediation simulator ----------
  const chipCount = await page.evaluate(() =>
    document.querySelectorAll('button.rounded-full').length)
  check('what-if: finding chips rendered', chipCount >= 10,
    `${chipCount} chips`)
  if (chipCount > 0) {
    await page.evaluate(() => {
      document.querySelectorAll('button.rounded-full')[0].click()
      document.querySelectorAll('button.rounded-full')[1]?.click()
    })
    await page.evaluate(() => {
      const b = [...document.querySelectorAll('button')]
        .find(x => /Simulate fix \(\d+\)/.test(x.textContent))
      if (b) b.click()
    })
    await waitForText(page, 'Remediation roadmap')
    const wiText = await page.evaluate(() => document.body.innerText)
    const arrow = wiText.includes('→')
    check('what-if: before/after metrics shown',
      /risk score/i.test(wiText) && arrow,
      'risk delta computed')
  }
  check('dashboard: PDF/CSV export buttons',
    await bodyHas(page, 'CSV'), 'findings section exports')
  check('dashboard: ticket exports (Jira/ServiceNow)',
    await bodyHas(page, 'ServiceNow') && await bodyHas(page, 'Jira'))

  // Scheduled re-scan: run once, expect diff panel
  await page.evaluate(() => {
    const b = [...document.querySelectorAll('button')]
      .find(x => x.textContent.trim() === 'Scan now')
    if (b) b.click()
  })
  await waitForText(page, 'New since last scan', 8000)
  const rescanText = await page.evaluate(() => document.body.innerText)
  check('rescan: diff panel renders',
    /Resolved/i.test(rescanText) && /Changed/i.test(rescanText))
  check('rescan: scheduler status shown',
    /scheduler:/i.test(rescanText))

  // ---------- 4. Graph Explorer ----------
  await clickByText(page, 'button', 'Graph Explorer')
  await page.waitForFunction(() => window.__sg_cy &&
    window.__sg_cy.nodes && window.__sg_cy.nodes().length > 30,
    { timeout: 15000 })
  const nodeCount = await page.evaluate(() => window.__sg_cy.nodes().length)
  const edgeCount = await page.evaluate(() => window.__sg_cy.edges().length)
  check('graph rendered', nodeCount > 30 && edgeCount > 35,
    `${nodeCount} nodes / ${edgeCount} edges`)

  // Select helpdesk user and simulate attack paths
  await page.evaluate(() => {
    window.__sg_cy.getElementById('user:helpdesk_bob').trigger('tap')
  })
  await sleep(300)
  await clickByText(page, 'button', 'Find attack paths')
  await waitForText(page, 'Blast radius')
  const explorerText = await page.evaluate(() => document.body.innerText)
  const t0reach = /domain compromise possible/i.test(explorerText)
  check('attack paths: helpdesk → Tier-0 flagged', t0reach)
  check('attack paths: path list rendered',
    /paths \(\d+\)/i.test(explorerText))
  const riskVal = (explorerText.match(/(\d+)\s*\/\s*100/) || [])[1]
  check('attack paths: blast radius score shown', !!riskVal, `risk=${riskVal}`)
  await page.screenshot({ path: ART + '/03-explorer-paths.png' })

  // CA + cert template nodes visible in graph
  const hasCA = await page.evaluate(() =>
    window.__sg_cy.getElementById('ca:corp-issuing-01').nonempty())
  const hasTmpl = await page.evaluate(() =>
    window.__sg_cy.getElementById('cert_template:esc1').nonempty())
  check('ADCS objects in graph', hasCA && hasTmpl, 'CA + ESC templates')

  // ---------- 5. Compliance tab ----------
  await clickByText(page, 'button', 'Compliance')
  await waitForText(page, 'Overall compliance posture')
  await sleep(400)
  const compText = await page.evaluate(() => document.body.innerText)
  for (const fw of ['OWASP Top 10 2021', 'ISO/IEC 27001:2022',
    'NIST CSF 2.0', 'NIST SP 800-53', 'PCI DSS 4.0', 'CIS Controls v8']) {
    check(`compliance: ${fw}`, compText.includes(fw))
  }
  const ringCount = await page.evaluate(() =>
    document.querySelectorAll('svg circle').length)
  check('compliance: score rings rendered', ringCount >= 14,
    `${ringCount} circle elements`)
  check('compliance: PDF/CSV export buttons',
    await bodyHas(page, 'Export PDF') && await bodyHas(page, 'Export CSV'))
  // expand first framework matrix
  await clickByText(page, 'button', 'Show control matrix')
  await sleep(300)
  const matrixText = await page.evaluate(() => document.body.innerText)
  check('compliance: control matrix expands',
    /pass|partial|fail/i.test(matrixText))
  await page.screenshot({ path: ART + '/04-compliance.png' })

  // ---------- 6. Audit trail (admin) ----------
  await clickByText(page, 'button', 'Audit Trail')
  await waitForText(page, 'Audit trail')
  await sleep(400)
  const auditRows = await page.evaluate(() =>
    document.querySelectorAll('tbody tr').length)
  check('audit trail rows visible', auditRows >= 3, `${auditRows} events`)
  await page.screenshot({ path: ART + '/05-audit.png' })

  // ---------- 7. Console hygiene ----------
  check('no console/page errors', consoleErrors.length === 0,
    consoleErrors.slice(0, 3).join(' | '))

  await browser.close()

  const failed = results.filter(r => !r.ok)
  console.log('\n' + JSON.stringify({
    total: results.length, passed: results.length - failed.length,
    failed: failed.length, artifacts: ART,
  }, null, 2))
  process.exit(failed.length ? 1 : 0)
})().catch(e => { console.error('E2E fatal:', e); process.exit(2) })
