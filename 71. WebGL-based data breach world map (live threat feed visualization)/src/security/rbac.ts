/**
 * AEGIS-SENTINEL — RBAC policy (security.md §6.2, architecture.md §10.1)
 * OPA-analog: authorization decisions as data, evaluated centrally.
 */
export type Role = 'viewer' | 'analyst' | 'auditor' | 'admin'

export type Permission =
  | 'globe.view'
  | 'threat.drilldown'
  | 'ioc.copy'
  | 'report.request'
  | 'report.download'
  | 'audit.view'
  | 'audit.export'
  | 'audit.verify'
  | 'admin.role'

export const ROLE_PERMISSIONS: Record<Role, Permission[]> = {
  viewer:  ['globe.view', 'threat.drilldown'],
  analyst: ['globe.view', 'threat.drilldown', 'ioc.copy', 'report.request', 'report.download', 'audit.verify'],
  auditor: ['globe.view', 'threat.drilldown', 'audit.view', 'audit.export', 'audit.verify'],
  admin:   ['globe.view', 'threat.drilldown', 'ioc.copy', 'report.request', 'report.download', 'audit.view', 'audit.export', 'audit.verify', 'admin.role'],
}

/** Central authorization decision point (OPA-analog, security.md §6.1). */
export function allow(role: Role, permission: Permission): boolean {
  return ROLE_PERMISSIONS[role]?.includes(permission) ?? false
}
