import { useMemo } from 'react';
import type { Severity, SocState } from '../../types';
import { MITRE_CATALOG } from '../../lib/sim/templates';

interface ComplianceReportsProps {
  state: SocState;
}

interface FrameworkRow {
  id: string;
  label: string;
  baseline: number;
  live: number;
  weight: number;
}

const CONTROL_MATRIX = [
  { domain: 'Access Control', iso: 'A.8.2 / A.8.3 / A.8.18', nist: 'AC-1..7, IA-2..5', csf: 'PR.AA', impl: 'OIDC + MFA, OPA, RBAC/ABAC, mTLS' },
  { domain: 'Encryption', iso: 'A.8.24 / A.8.25', nist: 'SC-8, SC-13', csf: 'PR.DS', impl: 'TLS 1.3, AES-256, KMS/HSM' },
  { domain: 'Logging & Audit', iso: 'A.8.15', nist: 'AU-2..12', csf: 'DE.CM, RS.CO', impl: 'Immutable log store, 7-y retention' },
  { domain: 'Vulnerability Mgmt', iso: 'A.8.8', nist: 'RA-5, SI-2', csf: 'ID.RA', impl: 'Trivy, SBOM, CVE watch, patch SLA' },
  { domain: 'Security Operations', iso: 'A.8.16', nist: 'SI-4', csf: 'DE.CM', impl: '24/7 SOC, playbooks, detection rules' },
  { domain: 'Incident Response', iso: 'A.5.24-28', nist: 'IR-1..8', csf: 'RS + RC', impl: 'Case/IR service, playbooks, DR tested' },
  { domain: 'Business Continuity', iso: 'A.5.29 / A.5.30', nist: 'CP-1..13', csf: 'RC', impl: 'Active-active, RTO ≤ 30m, RPO ≤ 60s' },
  { domain: 'Data Retention', iso: 'A.8.10', nist: 'SI-12, DM-1', csf: 'PR.DS', impl: 'ILM policies, legal hold, erasure' },
];

const RETENTION = [
  { type: 'Raw logs / flows', hot: '7 days', warm: '90 days', cold: '1–7 years', del: 'Irreversible' },
  { type: 'Alerts & cases', hot: '30 days', warm: '1 year', cold: '5 years', del: 'Verified' },
  { type: 'Audit logs', hot: '90 days', warm: '1 year', cold: '7 years', del: 'Immutable' },
  { type: '3D snapshots', hot: '24 h', warm: '90 days', cold: '1 year', del: '—' },
  { type: 'PII', hot: 'Minimized scope', warm: '—', cold: 'Pseudonymized', del: 'Right-to-erasure' },
];

function sevColor(s: Severity): string {
  return { critical: '#FF1744', high: '#FF6E40', medium: '#FFB300', low: '#3EC6FF', info: '#9aa7c7' }[s];
}

function frameworkScore(state: SocState): FrameworkRow[] {
  const openAlerts = state.alerts.filter((a) => a.status === 'new' || a.status === 'triaging').length;
  const totalAlerts = Math.max(1, state.alerts.length);
  const detection = 100 - (openAlerts / totalAlerts) * 100;
  const contained = state.incidents.filter((i) => ['contained', 'eradicated', 'recovered', 'closed'].includes(i.status)).length;
  const incPct = state.incidents.length ? (contained / state.incidents.length) * 100 : 100;

  return [
    { id: 'iso', label: 'ISO/IEC 27001:2022', baseline: 78, live: detection * 0.6 + incPct * 0.4, weight: 0.25 },
    { id: 'csf', label: 'NIST CSF 2.0', baseline: 84, live: detection * 0.5 + state.metrics.coverage * 0.5, weight: 0.25 },
    { id: 'sp80053', label: 'NIST SP 800-53 Rev.5', baseline: 82, live: detection * 0.55 + incPct * 0.45, weight: 0.2 },
    { id: 'owasp', label: 'OWASP ASVS L3 target', baseline: 90, live: state.metrics.coverage, weight: 0.2 },
    { id: 'zt', label: 'Zero Trust (800-207)', baseline: 74, live: state.metrics.coverage * 0.9, weight: 0.1 },
  ];
}

function topTechniques(state: SocState): { id: string; name: string; count: number }[] {
  const m = new Map<string, number>();
  for (const a of state.alerts) m.set(a.mitreId, (m.get(a.mitreId) ?? 0) + 1);
  return [...m.entries()]
    .map(([id, count]) => ({ id, name: MITRE_CATALOG[id]?.name ?? id, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 8);
}

function buildReport(state: SocState): string {
  const sevCount: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const a of state.alerts) sevCount[a.severity]++;
  const lines: string[] = [];
  lines.push(`# SOC Compliance Report — ${new Date().toISOString()}`);
  lines.push('');
  lines.push('## Executive summary');
  lines.push(`- Events scanned (window): ${state.logs.length}`);
  lines.push(`- Alerts captured: ${state.alerts.length} (${state.alerts.filter((a) => a.status === 'closed').length} closed, ${state.alerts.filter((a) => a.status === 'new').length} open)`);
  lines.push(`- Incidents: ${state.incidents.length} (${state.incidents.filter((i) => i.status === 'closed').length} closed)`);
  lines.push(`- Intelligence items: ${state.intel.length}`);
  lines.push('');
  lines.push('## Severity distribution');
  (['critical', 'high', 'medium', 'low', 'info'] as Severity[]).forEach((s) => lines.push(`- ${s}: ${sevCount[s]}`));
  lines.push('');
  lines.push('## Top detection techniques (MITRE ATT&CK)');
  topTechniques(state).forEach((t) => lines.push(`- ${t.id} ${t.name} — ${t.count}`));
  lines.push('');
  lines.push('## Framework posture');
  frameworkScore(state).forEach((f) => lines.push(`- ${f.label}: ${Math.round(Math.max(f.live, f.baseline))}%`));
  lines.push('');
  lines.push('## Retention compliance (ISO 27001 A.8.10 / GDPR)');
  RETENTION.forEach((r) => lines.push(`- ${r.type}: hot ${r.hot} / warm ${r.warm} / cold ${r.cold}`));
  return lines.join('\n');
}

function download(filename: string, text: string, mime: string) {
  const blob = new Blob([text], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}

export function ComplianceReports({ state }: ComplianceReportsProps) {
  const frameworks = useMemo(() => frameworkScore(state), [state]);

  const exportCsv = () => {
    const header = 'id,ts,severity,source,mitreId,title,status,assets';
    const rows = state.alerts.map((a) =>
      [a.id, new Date(a.ts).toISOString(), a.severity, a.source, a.mitreId, `"${a.title.replace(/"/g, '""')}"`, a.status, a.assets.join('|')].join(','),
    );
    download('soc-alerts-export.csv', [header, ...rows].join('\n'), 'text/csv');
  };

  const exportReport = () => {
    download(`soc-report-${Date.now()}.md`, buildReport(state), 'text/markdown');
  };

  const sevCount: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const a of state.alerts) sevCount[a.severity]++;

  return (
    <div className="module-page">
      <div className="module-head">
        <div>
          <h1>Compliance &amp; Report Engine</h1>
          <p className="module-sub">Continuous posture scoring mapped to ISO 27001, NIST CSF / 800-53, OWASP and Zero Trust</p>
        </div>
        <div className="module-head-actions">
          <button className="btn" onClick={exportCsv}>Export alerts CSV</button>
          <button className="btn btn-primary" onClick={exportReport}>Generate report (.md)</button>
        </div>
      </div>

      <div className="framework-grid">
        {frameworks.map((f) => {
          const score = Math.max(f.live, f.baseline);
          const color = score >= 85 ? 'var(--good)' : score >= 70 ? 'var(--warn)' : 'var(--danger)';
          return (
            <div className="card framework-card" key={f.id}>
              <h3>{f.label}</h3>
              <div className="framework-gauge">
                <div className="framework-ring" style={{ ['--pct' as string]: `${score}%`, ['--ring' as string]: color }}>
                  <span>{Math.round(score)}%</span>
                </div>
              </div>
              <div className="framework-meta">
                <span>baseline {Math.round(f.baseline)}%</span>
                <span>live {Math.round(Math.max(f.live, 0))}%</span>
              </div>
            </div>
          );
        })}
      </div>

      <div className="compliance-columns">
        <div className="card matrix-card">
          <div className="panel-head">
            <h2>Control mapping matrix</h2>
            <span className="section-title-right">ISO / NIST / CSF → implementation</span>
          </div>
          <div className="matrix-table">
            <div className="matrix-head">
              <span>Domain</span><span>ISO 27001</span><span>SP 800-53</span><span>CSF 2.0</span><span>Implementation</span>
            </div>
            {CONTROL_MATRIX.map((c) => (
              <div className="matrix-row" key={c.domain}>
                <b>{c.domain}</b><span>{c.iso}</span><span>{c.nist}</span><span>{c.csf}</span><span className="row-msg">{c.impl}</span>
              </div>
            ))}
          </div>
        </div>

        <div className="compliance-side">
          <div className="card retention-card">
            <div className="panel-head">
              <h2>Retention policy</h2>
            </div>
            <div className="panel-body">
              {RETENTION.map((r) => (
                <div className="retention-row" key={r.type}>
                  <b>{r.type}</b>
                  <span>hot {r.hot}</span>
                  <span>warm {r.warm}</span>
                  <span>cold {r.cold}</span>
                </div>
              ))}
            </div>
          </div>

          <div className="card severity-card">
            <div className="panel-head">
              <h2>Alert volume</h2>
            </div>
            <div className="panel-body">
              {(['critical', 'high', 'medium', 'low', 'info'] as Severity[]).map((s) => (
                <div className="volume-row" key={s}>
                  <span>
                    <i style={{ background: sevColor(s) }} /> {s}
                  </span>
                  <div className="progress-track">
                    <div
                      className="progress-fill"
                      style={{
                        width: `${Math.max(4, (sevCount[s] / Math.max(1, state.alerts.length)) * 100)}%`,
                        background: sevColor(s),
                      }}
                    />
                  </div>
                  <b>{sevCount[s]}</b>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}