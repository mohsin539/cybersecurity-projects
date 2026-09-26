// Minimal typed API client — bearer token kept in memory only (XSS-blast-radius
// reduction, OWASP A07). No localStorage persistence of tokens.
export type Role = 'admin' | 'analyst' | 'auditor'

export interface AuthMe { username: string; role: Role }
export interface LoginResponse { access_token: string; role: Role; full_name: string; expires_at: number }

export interface GraphNode { id: string; kind: string; label: string; domain: string; tier: number | null }
export interface GraphEdge { source: string; target: string; kind: string }
export interface GraphData { nodes: GraphNode[]; edges: GraphEdge[]; stats: Record<string, unknown> }

export interface AttackPath { nodes: string[]; edges: { source: string; target: string; kind: string }[]; hops: number; risk: number; target_tier0: boolean }
export interface BlastRadius { node_id: string; reachable_tier0: boolean; tier0_count: number; total_reachable: number; risk_score: number; frontier: string[] }
export interface PathResponse { source: string; paths: AttackPath[]; blast_radius: BlastRadius }

export interface Finding { id: string; title: string; severity: 'critical' | 'high' | 'medium' | 'low' | 'info'; category: string; description: string; affected: { id: string; label: string; why: string }[]; mitre: string[]; remediation: string }
export interface FindingSummary { total: number; by_severity: Record<string, number>; by_category: Record<string, number>; risk_index: number }

export interface ControlStatus { id: string; title: string; category: string; statement: string; status: 'pass' | 'partial' | 'fail'; criticality: string }
export interface FrameworkPosture { name: string; description: string; score: number; counts: { pass: number; partial: number; fail: number; total: number }; controls: ControlStatus[] }
export interface CompliancePosture { frameworks: Record<string, FrameworkPosture> }

export interface AuditEvent { id: string; ts: string; event: string; actor: string; outcome: string; severity: string }

export interface WhatIfMetrics { risk_index: number; findings_total: number; by_severity: Record<string, number>; tier0_exposed_principals: number; tier_distribution: Record<string, number> }
export interface WhatIfSingle { finding_id: string; title: string; severity: string; before: WhatIfMetrics; after: WhatIfMetrics; delta: Record<string, number> }
export interface WhatIfBatch { before: WhatIfMetrics; roadmap_steps: { finding_id: string; risk_index: number; findings_total: number; tier0_exposed: number }[]; final: WhatIfMetrics; total_delta: { risk_index: number; findings_total: number }; singles: WhatIfSingle[] }

export interface RescanHistoryEntry { ts: string; trigger: string; actor: string; new: number; resolved: number; changed: number; unchanged: number; total: number; critical_new: number }
export interface RescanFindingLite { id: string; title: string; severity: string; affected_count: number }
export interface RescanResult { ran_at: string; trigger: string; new: RescanFindingLite[]; resolved: RescanFindingLite[]; changed: { finding_id: string; old_severity: string; new_severity: string; old_affected: number; new_affected: number }[]; counts: { new: number; resolved: number; changed: number; unchanged: number; total: number }; critical_new: number }
export interface RescanStatus { enabled: boolean; interval_minutes: number; last_run: string | null; baseline_findings: number; history: RescanHistoryEntry[] }

let token: string | null = null
export const setToken = (t: string | null) => { token = t }
export const getToken = () => token

export class ApiError extends Error {
  status: number
  constructor(status: number, message: string) { super(message); this.status = status }
}

async function req<T>(path: string, init?: RequestInit): Promise<T> {
  const headers: Record<string, string> = { 'Content-Type': 'application/json', ...(init?.headers as object) }
  if (token) headers['Authorization'] = `Bearer ${token}`
  const res = await fetch(path, { ...init, headers })
  if (res.status === 401) { setToken(null); throw new ApiError(401, 'Session expired — sign in again') }
  if (!res.ok) {
    let msg = `HTTP ${res.status}`
    try { msg = (await res.json())?.error?.message ?? (await res.json())?.detail ?? msg } catch { /* keep default */ }
    throw new ApiError(res.status, msg)
  }
  return res.json() as Promise<T>
}

export const api = {
  login: async (username: string, password: string) => {
    const r = await req<LoginResponse>('/api/v1/auth/login',
      { method: 'POST', body: JSON.stringify({ username, password }) })
    setToken(r.access_token)
    return r
  },
  me: () => req<AuthMe>('/api/v1/auth/me'),
  logout: () => req<{ status: string }>('/api/v1/auth/logout', { method: 'POST' }),
  graph: () => req<GraphData>('/api/v1/graph'),
  summary: () => req<Record<string, unknown>>('/api/v1/analysis/summary'),
  paths: (source: string, maxHops = 5, limit = 10) =>
    req<PathResponse>('/api/v1/analysis/paths', { method: 'POST', body: JSON.stringify({ source, max_hops: maxHops, limit }) }),
  chokePoints: () => req<{ choke_points: { node_id: string; label: string; kind: string; tier0_reachable: number; reach: number; risk: number }[] }>('/api/v1/analysis/choke-points'),
  tier0Exposure: () => req<{ tier0: GraphNode[]; exposure: { target: string; label: string; kind: string; attacker_count: number; attackers: string[] }[] }>('/api/v1/analysis/tier0-exposure'),
  findings: () => req<{ findings: Finding[]; summary: FindingSummary }>('/api/v1/findings'),
  compliance: () => req<CompliancePosture>('/api/v1/compliance'),
  audit: (limit = 100) => req<{ events: AuditEvent[] }>(`/api/v1/audit?limit=${limit}`),
  whatIfCatalog: () => req<{ mitigations: Record<string, string> }>('/api/v1/analysis/what-if'),
  whatIf: (findingIds: string[]) =>
    req<WhatIfBatch>('/api/v1/analysis/what-if', { method: 'POST', body: JSON.stringify({ finding_ids: findingIds }) }),
  rescanStatus: () => req<RescanStatus>('/api/v1/analysis/rescan/status'),
  rescanRun: () => req<RescanResult>('/api/v1/analysis/rescan/run', { method: 'POST' }),
  rescanInterval: (minutes: number) =>
    req<RescanStatus>('/api/v1/analysis/rescan/interval', { method: 'POST', body: JSON.stringify({ minutes }) }),
  rescanReset: () => req<{ status: string }>('/api/v1/analysis/rescan/reset', { method: 'POST' }),
  meta: () => req<{ app: string; version: string; environment: string }>('/api/v1/meta'),
}

/** Authenticated file download (bearer in header, so no plain <a href>). */
export async function downloadApiFile(path: string, fallbackName: string): Promise<void> {
  const headers: Record<string, string> = {}
  if (token) headers['Authorization'] = `Bearer ${token}`
  const res = await fetch(path, { headers })
  if (!res.ok) throw new ApiError(res.status, `Download failed (HTTP ${res.status})`)
  const blob = await res.blob()
  const dispo = res.headers.get('Content-Disposition') || ''
  const m = /filename="?([^";]+)"?/.exec(dispo)
  const a = document.createElement('a')
  a.href = URL.createObjectURL(blob)
  a.download = m?.[1] ?? fallbackName
  document.body.appendChild(a)
  a.click()
  a.remove()
  setTimeout(() => URL.revokeObjectURL(a.href), 5000)
}

export const downloadReport = (
  report: 'findings' | 'compliance', format: 'pdf' | 'csv') =>
  downloadApiFile(`/api/v1/reports/${report}?format=${format}`,
    `sentinelgraph-${report}.${format}`)

export const downloadTickets = (system: 'jira' | 'servicenow') =>
  downloadApiFile(`/api/v1/reports/tickets/${system}?format=csv`,
    `sentinelgraph-tickets-${system}.csv`)
