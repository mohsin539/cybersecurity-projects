/**
 * AEGIS-SENTINEL — Report engine (architecture.md §11)
 *
 * Deterministic exports: CSV, JSON, STIX 2.1, HTML (print-to-PDF),
 * Audit Pack. Canonicalized, SHA-256 digested, Ed25519 signed.
 */
import { auditLedger } from '../security/auditLedger'
import { CATEGORY_LABELS, SEVERITY_ORDER } from '../domain/sources'
import type { ThreatEvent } from '../domain/types'
import { canonicalJson, sha256Hex, signPayload } from '../security/crypto'
import type { SignatureResult } from '../security/crypto'

export type ReportFormat = 'csv' | 'json' | 'stix' | 'html' | 'audit-pack'

export interface ReportOptions {
  format: ReportFormat
  events: ThreatEvent[]
  filtersSummary: Record<string, unknown>
  actor: string
  role: string
  asOf: Date
}

export interface ReportResult {
  blob: Blob
  filename: string
  mime: string
  digest: string
  signature: SignatureResult
}

const EVENT_FIELDS = [
  'event_id', 'title', 'category', 'severity', 'risk_score',
  'src_country', 'dst_country', 'records_impacted', 'pii_classes',
  'techniques', 'ioc_count', 'source_id', 'trust_tier',
  'occurred_at', 'ingested_at', 'content_hash',
]
function csvEscape(v: unknown): string {
  const s = String(v ?? '')
  return /[",\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s
}

function flatten(e: ThreatEvent): Record<string, string | number> {
  return {
    event_id: e.event_id,
    title: e.title,
    category: e.category,
    severity: e.severity,
    risk_score: e.risk_score,
    src_country: e.geo.src.country,
    dst_country: e.geo.dst.country,
    records_impacted: e.impact.records,
    pii_classes: e.impact.pii_classes.join(';'),
    techniques: e.techniques.join(';'),
    ioc_count: e.indicators.length,
    source_id: e.sources.map((s) => s.source_id).join(';'),
    trust_tier: e.sources.map((s) => s.trust_tier).join(';'),
    occurred_at: e.occurred_at,
    ingested_at: e.ingested_at,
    content_hash: e.content_hash,
  }
}

function buildCsv(events: ThreatEvent[]): string {
  const rows = events.map((e) => {
    const f = flatten(e)
    return EVENT_FIELDS.map((k) => csvEscape(f[k])).join(',')
  })
  return '\uFEFF' + [EVENT_FIELDS.join(','), ...rows].join('\r\n')
}
function buildStix(events: ThreatEvent[]): string {
  const objects: Record<string, unknown>[] = [
    {
      type: 'identity',
      spec_version: '2.1',
      id: 'identity--aegis-demo-export',
      name: 'AEGIS-SENTINEL Demo Export',
      identity_class: 'system',
    },
  ]
  for (const e of events) {
    const ip = e.indicators.find((i) => i.type === 'ip')?.value ?? '0.0.0.0'
    objects.push({
      type: 'indicator',
      spec_version: '2.1',
      id: e.stix_id,
      created: e.occurred_at,
      modified: e.occurred_at,
      name: e.title,
      labels: [e.category, e.severity],
      pattern: "[ipv4-addr:value = '" + ip + "']",
      pattern_type: 'stix',
      valid_from: e.occurred_at,
      custom_properties: {
        risk_score: e.risk_score,
        records_impacted: e.impact.records,
        techniques: e.techniques,
        src_country: e.geo.src.country,
        dst_country: e.geo.dst.country,
      },
    })
  }
  return JSON.stringify({ type: 'bundle', id: 'bundle--aegis-' + Date.now(), objects }, null, 2)
}
function escHtml(s: string): string {
  return s.replace(/[&<>"']/g, (ch) =>
    ch === '&' ? '&amp;' : ch === '<' ? '&lt;' : ch === '>' ? '&gt;' : ch === '"' ? '&quot;' : '&#39;')
}

function sevClass(s: string): string {
  return s === 'medium' ? 'med' : s === 'zero-day' ? 'zero' : s
}

function buildHtmlReport(opts: ReportOptions, digest: string, sig: SignatureResult): string {
  const events = opts.events
  const bySeverity = SEVERITY_ORDER.map((s) => [s, events.filter((e) => e.severity === s).length] as [string, number])
  const byCountry = new Map<string, number>()
  for (const e of events) byCountry.set(e.geo.src.country, (byCountry.get(e.geo.src.country) ?? 0) + 1)
  const topCountries = [...byCountry.entries()].sort((a, b) => b[1] - a[1]).slice(0, 10)
  const records = events.reduce((a, e) => a + e.impact.records, 0)
  const avgRisk = events.length ? Math.round((events.reduce((a, e) => a + e.risk_score, 0) / events.length) * 10) / 10 : 0
  const rows = events.slice(0, 60).map((e) => {
    const cells = [
      '<td class="' + sevClass(e.severity) + '">' + escHtml(e.severity) + '</td>',
      '<td>' + escHtml(e.title) + '</td>',
      '<td>' + escHtml(CATEGORY_LABELS[e.category]) + '</td>',
      '<td>' + e.risk_score + '</td>',
      '<td>' + e.impact.records.toLocaleString() + '</td>',
      '<td>' + escHtml(e.geo.src.country) + ' → ' + escHtml(e.geo.dst.country) + '</td>',
      '<td>' + escHtml(e.occurred_at.slice(0, 19).replace('T', ' ')) + '</td>',
    ]
    return '<tr>' + cells.join('') + '</tr>'
  }).join('\n')
  return htmlTemplate(opts, digest, sig, { bySeverity, topCountries, records, avgRisk, rows })
}
interface HtmlParts {
  bySeverity: [string, number][]
  topCountries: [string, number][]
  records: number
  avgRisk: number
  rows: string
}

function htmlTemplate(opts: ReportOptions, digest: string, sig: SignatureResult, p: HtmlParts): string {
  const gen = opts.asOf.toISOString()
  const sevSpans = p.bySeverity.map((s) => '<span class="' + sevClass(s[0]) + '">' + s[0] + ': ' + s[1] + '</span>').join(' · ')
  const countries = p.topCountries.map((c) => '<li>' + escHtml(c[0]) + ' — ' + c[1] + ' events</li>').join('')
  const css = [
    'body{font-family:Segoe UI,system-ui,sans-serif;color:#e8f6ff;background:#0b1226;margin:0;padding:40px}',
    'h1{font-size:22px;letter-spacing:.12em;margin:0 0 4px}.sub{color:#7f9cb5;font-size:12px}',
    '.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin:22px 0}',
    '.kpi{border:1px solid #233047;border-radius:10px;padding:12px}.kpi b{display:block;font-size:20px}',
    '.kpi span{font-size:10px;color:#7f9cb5;text-transform:uppercase;letter-spacing:.1em}',
    'table{width:100%;border-collapse:collapse;font-size:11px}',
    'th{text-align:left;color:#00b3c8;text-transform:uppercase;font-size:9px;padding:6px;border-bottom:1px solid #233047}',
    'td{padding:5px 6px;border-bottom:1px solid #16203a}',
    '.crit{color:#ff1e56}.high{color:#ff7b54}.med{color:#ffd32a}.low{color:#3ae374}.zero{color:#c084fc}',
    'footer{margin-top:28px;font-size:10px;color:#7f9cb5;word-break:break-all}',
    '@media print{body{padding:24px}}',
  ].join('\n')
  const parts = [
    '<!doctype html><html><head><meta charset="utf-8">',
    '<title>AEGIS-SENTINEL Threat Report</title><style>' + css + '</style></head><body>',
    '<h1>🌍 AEGIS-SENTINEL — Threat Report</h1>',
    '<div class="sub">Point-in-time snapshot · ' + escHtml(gen) + ' · ' + events_count(opts) + ' events</div>',
    '<div class="grid">',
    kpi(String(opts.events.length), 'Events'),
    kpi(p.records.toLocaleString(), 'Records impacted'),
    kpi(String(p.avgRisk), 'Avg risk'),
    kpi(p.topCountries[0]?.[0] ?? '—', 'Top source country'),
    '</div>',
    '<p>' + sevSpans + '</p><p>Top countries: </p><ul>' + countries + '</ul>',
    '<table><thead><tr><th>Severity</th><th>Title</th><th>Category</th><th>Risk</th><th>Records</th><th>Route</th><th>When</th></tr></thead>',
    '<tbody>' + p.rows + '</tbody></table>',
    '<footer>',
    '<b>Digest:</b> sha256:' + escHtml(digest) + '<br>',
    '<b>Signature (Ed25519):</b> ' + escHtml(sig.signature_hex.slice(0, 96)) + '…<br>',
    '<b>Public key:</b> ' + escHtml(sig.public_key_hex) + '<br>',
    '<b>Actor:</b> ' + escHtml(opts.actor) + ' (' + escHtml(opts.role) + ') · Generated ' + escHtml(gen) + '<br>',
    'Verify via the /verify portal with digest + signature + public key.',
    '</footer></body></html>',
  ]
  return parts.join('\n')
}

function events_count(opts: ReportOptions): string {
  return String(opts.events.length)
}

function kpi(value: string, label: string): string {
  return '<div class="kpi"><b>' + escHtml(value) + '</b><span>' + escHtml(label) + '</span></div>'
}
function buildAuditPack(opts: ReportOptions, digest: string, sig: SignatureResult): string {
  const entries = auditLedger.all()
  const v = auditLedger.verify()
  const status = v.ok ? 'VALID' : 'BROKEN at seq ' + v.first_broken_seq
  const rows = entries.slice(-120).map((en) => {
    const cells = [
      '<td>' + en.seq + '</td>',
      '<td>' + escHtml(en.ts) + '</td>',
      '<td>' + escHtml(en.actor) + '</td>',
      '<td>' + escHtml(en.role) + '</td>',
      '<td>' + escHtml(en.action) + '</td>',
      '<td>' + escHtml(en.resource) + '</td>',
      '<td>' + escHtml(en.entry_hash.slice(0, 24)) + '</td>',
    ]
    return '<tr>' + cells.join('') + '</tr>'
  }).join('\n')
  const parts = [
    '<!doctype html><html><head><meta charset="utf-8">',
    '<title>AEGIS-SENTINEL Audit Pack</title>',
    '<style>body{font-family:Consolas,monospace;background:#0b1226;color:#e8f6ff;padding:32px;font-size:12px}',
    'h1{font-size:18px;letter-spacing:.12em}table{border-collapse:collapse;width:100%;font-size:11px}',
    'td,th{border:1px solid #233047;padding:4px 6px;text-align:left}th{background:#101a33;color:#00b3c8}',
    '.ok{color:#3ae374}.bad{color:#ff1e56}</style></head><body>',
    '<h1>🧾 AEGIS-SENTINEL — Compliance Audit Pack</h1>',
    '<p>Generated ' + escHtml(opts.asOf.toISOString()) + ' · actor=' + escHtml(opts.actor) + ' · role=' + escHtml(opts.role) + '</p>',
    '<p><b>Chain verification:</b> ' + (v.ok ? '<span class="ok">VALID</span>' : '<span class="bad">' + escHtml(status) + '</span>') + ' · ' + v.length + ' entries · head=' + escHtml(v.head_hash.slice(0, 32)) + '</p>',
    '<table><tr><th>Seq</th><th>Timestamp</th><th>Actor</th><th>Role</th><th>Action</th><th>Resource</th><th>Entry hash</th></tr>',
    rows,
    '</table>',
    '<p><b>Report digest:</b> sha256:' + escHtml(digest) + '</p>',
    '<p><b>Pack signature (Ed25519):</b> ' + escHtml(sig.signature_hex.slice(0, 96)) + '</p>',
    '<p><b>Public key:</b> ' + escHtml(sig.public_key_hex) + '</p>',
    '<p><b>Framework tags:</b> ISO 27001 A.8.15 · NIST AU-2/AU-9 · OWASP A09 (evidence subset)</p>',
    '<p>Offline verifier: entry_hash = SHA256(canonical_json(entry minus hashes) + | + prev_hash)</p>',
    '</body></html>',
  ]
  return parts.join('\n')
}
function buildJsonPayload(events: ThreatEvent[], opts: ReportOptions): string {
  return JSON.stringify({
    report: {
      type: 'aegis.threat-report',
      version: '1.0.0',
      generated_at: opts.asOf.toISOString(),
      actor: opts.actor,
      role: opts.role,
      filters: opts.filtersSummary,
      count: events.length,
    },
    events,
  }, null, 2)
}

export async function generateReport(opts: ReportOptions): Promise<ReportResult> {
  let body: string
  let mime: string
  let ext: string
  switch (opts.format) {
    case 'csv':
      body = buildCsv(opts.events)
      mime = 'text/csv'
      ext = 'csv'
      break
    case 'json':
      body = buildJsonPayload(opts.events, opts)
      mime = 'application/json'
      ext = 'json'
      break
    case 'stix':
      body = buildStix(opts.events)
      mime = 'application/stix+json'
      ext = 'json'
      break
    case 'audit-pack':
      body = ''
      mime = 'text/html'
      ext = 'html'
      break
    case 'html':
    default:
      body = ''
      mime = 'text/html'
      ext = 'html'
      break
  }

  const provenance = {
    format: opts.format,
    event_count: opts.events.length,
    as_of: opts.asOf.toISOString(),
    filters: opts.filtersSummary,
    actor: opts.actor,
    role: opts.role,
  }
  const digest = await sha256Hex(canonicalJson(provenance) + '|' + body)
  const signature = signPayload({ digest, provenance })

  if (opts.format === 'html') body = buildHtmlReport(opts, digest, signature)
  if (opts.format === 'audit-pack') body = buildAuditPack(opts, digest, signature)

  const stamp = opts.asOf.toISOString().replace(/[:.]/g, '-')
  return {
    blob: new Blob([body], { type: mime }),
    filename: 'aegis-report_' + opts.format + '_' + stamp + '.' + ext,
    mime,
    digest,
    signature,
  }
}

export function downloadBlob(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  document.body.appendChild(a)
  a.click()
  a.remove()
  window.setTimeout(() => URL.revokeObjectURL(url), 1000)
}
