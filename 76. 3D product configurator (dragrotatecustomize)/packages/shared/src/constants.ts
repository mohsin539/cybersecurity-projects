/**
 * PrismForge shared domain constants.
 *
 * These values are the single source of truth for the product configurator and
 * are consumed by BOTH the web client and the API. The API re-validates every
 * inbound payload against the Zod contracts derived from these identifiers
 * (defence against tampered clients / mass-assignment - OWASP A01:2021).
 */

// ---------------------------------------------------------------------------
// Identifiers
// ---------------------------------------------------------------------------

/** Physical, individually configurable meshes of the product. */
export const PART_IDS = [
  'body',
  'grille',
  'cap',
  'ring',
  'base',
  'buttons',
  'strap',
] as const;
export type PartId = (typeof PART_IDS)[number];

/** Bolt-on modules that can be toggled on/off (also change the 3D scene graph). */
export const ACCESSORY_IDS = ['cap', 'ringLight', 'strap', 'handle', 'stand'] as const;
export type AccessoryId = (typeof ACCESSORY_IDS)[number];

/** Surface treatments mapped to physically-based material parameters. */
export const FINISH_IDS = [
  'matte',
  'satin',
  'gloss',
  'brushedMetal',
  'polishedMetal',
  'anodized',
  'carbonWeave',
  'translucent',
  'rubberized',
] as const;
export type FinishId = (typeof FINISH_IDS)[number];

/** Where engraved text is projected onto the mesh. */
export const ENGRAVING_POSITIONS = ['front', 'side', 'back'] as const;
export type EngravingPosition = (typeof ENGRAVING_POSITIONS)[number];

export const ENGRAVING_FONTS = ['grotesk', 'mono', 'serif', 'script'] as const;
export type EngravingFont = (typeof ENGRAVING_FONTS)[number];

// ---------------------------------------------------------------------------
// Access control (ISO/IEC 27001 A.5.15 / A.8.2 - least privilege)
// ---------------------------------------------------------------------------

export const ROLES = ['viewer', 'configurator', 'auditor', 'security_officer', 'admin'] as const;
export type Role = (typeof ROLES)[number];

/** Ordered privilege ladder. Index === privilege level. */
export const ROLE_RANK: Record<Role, number> = {
  viewer: 0,
  configurator: 1,
  auditor: 2,
  security_officer: 3,
  admin: 4,
};

export function hasAtLeast(role: Role, required: Role): boolean {
  return ROLE_RANK[role] >= ROLE_RANK[required];
}

// ---------------------------------------------------------------------------
// Audit trail vocabulary (ISO/IEC 27001 A.8.15 / A.8.16, NIST AU family)
// ---------------------------------------------------------------------------

export const AUDIT_ACTIONS = [
  'auth.login',
  'auth.login.failed',
  'auth.logout',
  'auth.token.refresh',
  'auth.token.reuse_detected',
  'auth.password.changed',
  'auth.account.locked',
  'auth.mfa.challenge',
  'auth.mfa.failed',
  'authz.denied',
  'catalog.read',
  'config.create',
  'config.read',
  'config.update',
  'config.delete',
  'config.share.created',
  'config.share.accessed',
  'report.generate',
  'report.download',
  'audit.read',
  'audit.verify',
  'audit.export',
  'admin.user.create',
  'admin.user.update',
  'admin.user.disable',
  'admin.role.change',
  'admin.integrity.check',
  'system.config.update',
  'system.startup',
  'system.shutdown',
] as const;
export type AuditAction = (typeof AUDIT_ACTIONS)[number];

export const AUDIT_OUTCOMES = ['SUCCESS', 'FAILURE', 'DENIED'] as const;
export type AuditOutcome = (typeof AUDIT_OUTCOMES)[number];

/** ISO/IEC 27001 A.8.15 logging guidance: severity drives alerting. */
export const AUDIT_SEVERITIES = ['INFO', 'NOTICE', 'WARNING', 'CRITICAL'] as const;
export type AuditSeverity = (typeof AUDIT_SEVERITIES)[number];

/** Actions that are always recorded at CRITICAL regardless of outcome. */
export const CRITICAL_ACTIONS: ReadonlySet<string> = new Set<string>([
  'auth.token.reuse_detected',
  'auth.account.locked',
  'authz.denied',
  'admin.role.change',
  'admin.user.disable',
  'audit.export',
  'system.config.update',
]);

// ---------------------------------------------------------------------------
// Reporting
// ---------------------------------------------------------------------------

export const REPORT_FORMATS = ['csv', 'xlsx', 'html', 'pdf', 'json'] as const;
export type ReportFormat = (typeof REPORT_FORMATS)[number];

export const REPORT_SUBJECTS = [
  'configuration', // single configuration spec sheet
  'configurations', // configuration register
  'pricing', // price breakdown / quote
  'audit', // audit trail extract
  'integrity', // hash-chain verification result
  'access-review', // user/role entitlement review (ISO A.5.18)
  'security-posture', // control coverage summary
] as const;
export type ReportSubject = (typeof REPORT_SUBJECTS)[number];

export const REPORT_FORMATS_MIME: Record<ReportFormat, string> = {
  csv: 'text/csv; charset=utf-8',
  xlsx: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  html: 'text/html; charset=utf-8',
  pdf: 'application/pdf',
  json: 'application/json; charset=utf-8',
};

export const REPORT_FORMATS_EXT: Record<ReportFormat, string> = {
  csv: 'csv',
  xlsx: 'xlsx',
  html: 'html',
  pdf: 'pdf',
  json: 'json',
};

// ---------------------------------------------------------------------------
// Domain limits (enforced server-side; mirrored client-side for UX only)
// ---------------------------------------------------------------------------

export const LIMITS = {
  /** Max characters in free-text fields (engraving, notes) - prevents log/DB bloat. */
  engravingMaxLength: 24,
  notesMaxLength: 500,
  /** Configurable physical envelope in millimetres. */
  dimensionMinMm: 60,
  dimensionMaxMm: 400,
  quantityMin: 1,
  quantityMax: 10000,
  /** Pagination */
  pageSizeDefault: 25,
  pageSizeMax: 200,
  /** Audit query window (days) - bounds the cost of a single extract. */
  auditWindowMaxDays: 366,
} as const;

/** Hard currency ceiling; guards against integer overflow in totals. */
export const PRICE_MAX = 1_000_000;
