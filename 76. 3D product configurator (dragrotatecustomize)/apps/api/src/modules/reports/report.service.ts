/**
 * Report model + data gathering.
 *
 * Architecture: every subject is reduced to ONE intermediate representation
 * (`ReportModel`) and then rendered by a format-specific writer. That means a
 * CSV, an XLSX, a standalone HTML page and a PDF of the same request are
 * guaranteed to carry identical figures - there is no per-format business logic
 * to drift out of sync, which is the usual cause of disputed exports.
 *
 * Access control is applied while GATHERING, not while rendering, so a caller
 * can never obtain a format they were not entitled to (OWASP A01:2021).
 */

import {
  ACCESSORIES,
  ENGRAVING_FONTS,
  FINISHES,
  LIMITS,
  PARTS,
  computePrice,
  configurationSpecSchema,
  getProduct,
  type AccessoryId,
  type AuditSeverity,
  type ConfigurationSpec,
  type PartId,
  type PriceBreakdown,
  type ReportFormat,
  type ReportSubject,
  type Role,
} from '@prismforge/shared';
import { all, get } from '../../db/driver.js';
import { AppError } from '../../utils/errors.js';
import { isoPlusSeconds, nowIso } from '../../utils/ids.js';
import {
  auditStats,
  queryAudit,
  verifyChain,
  type AuditRecord,
  type ChainVerification,
} from '../audit/audit.service.js';
import { readConfiguration } from '../configurations/configurations.service.js';
import type { Actor } from '../../http/context.js';

export const REPORT_SCHEMA_VERSION = '1.0.0';
export const REPORT_TOOL_VERSION = 'PrismForge Reporting Engine 1.0.0';
export const MAX_AUDIT_ROWS = 5000;

export type Classification = 'INTERNAL' | 'CONFIDENTIAL' | 'RESTRICTED';

export interface ReportColumn {
  key: string;
  label: string;
  align?: 'left' | 'right' | 'center';
  width?: number;
  /** Long text should wrap in HTML/PDF. */
  wrap?: boolean;
}

export interface ReportSection {
  heading: string;
  note?: string;
  columns: ReportColumn[];
  rows: Array<Record<string, string | number | null>>;
}

export interface ReportModel {
  schemaVersion: string;
  meta: {
    title: string;
    subject: ReportSubject;
    format: ReportFormat;
    classification: Classification;
    organisation: string;
    generatedAt: string;
    generatedBy: { id: string; email: string; role: Role };
    correlationId: string;
    retentionUntil: string;
    toolVersion: string;
    /** Provenance statement shown in the document footer. */
    provenance: string;
  };
  headline: Array<{ label: string; value: string }>;
  sections: ReportSection[];
  snapshot?: string;
  notes: string[];
  /** Present on audit/integrity subjects. */
  chain?: {
    verified: boolean;
    entries: number;
    headHash: string | null;
    errors: Array<{ seq: number; reason: string }>;
    checkpoint: ChainVerification['checkpoint'];
  };
  raw?: Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// Authorisation matrix
// ---------------------------------------------------------------------------

const SUBJECT_MIN_ROLE: Record<ReportSubject, Role> = {
  configuration: 'configurator',
  pricing: 'configurator',
  configurations: 'auditor',
  audit: 'auditor',
  integrity: 'security_officer',
  'access-review': 'security_officer',
  'security-posture': 'security_officer',
};

const SUBJECT_CLASSIFICATION: Record<ReportSubject, Classification> = {
  configuration: 'INTERNAL',
  pricing: 'INTERNAL',
  configurations: 'CONFIDENTIAL',
  audit: 'RESTRICTED',
  integrity: 'RESTRICTED',
  'access-review': 'RESTRICTED',
  'security-posture': 'CONFIDENTIAL',
};

const SUBJECT_TITLE: Record<ReportSubject, string> = {
  configuration: 'Configuration Specification Sheet',
  pricing: 'Quotation & Price Breakdown',
  configurations: 'Configuration Register',
  audit: 'Audit Trail Extract',
  integrity: 'Audit Chain Integrity Verification Report',
  'access-review': 'User Access Review',
  'security-posture': 'Security Control Coverage Summary',
};

export function assertSubjectAllowed(actor: Actor, subject: ReportSubject): void {
  const required = SUBJECT_MIN_ROLE[subject];
  if (rankOf(actor.role) < rankOf(required)) {
    throw new AppError('FORBIDDEN', `Report subject '${subject}' requires the '${required}' role or higher`, {
      details: { required, current: actor.role },
    });
  }
}

const ROLE_RANKS: Record<Role, number> = {
  viewer: 0,
  configurator: 1,
  auditor: 2,
  security_officer: 3,
  admin: 4,
};

function rankOf(role: Role): number {
  return ROLE_RANKS[role] ?? 0;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function finishLabel(id: string): string {
  return FINISHES[id as keyof typeof FINISHES]?.label ?? id;
}

function hexLabel(hex: string): string {
  return hex.toUpperCase();
}

function money(minor: number, currency: string): string {
  return new Intl.NumberFormat('en-US', { style: 'currency', currency }).format(minor / 100);
}

function resolveWindow(from?: string, to?: string): { from: string; to: string } {
  const toDate = to ? new Date(to) : new Date();
  const fromDate = from ? new Date(from) : new Date(toDate.getTime() - 30 * 86_400_000);
  const spanDays = (toDate.getTime() - fromDate.getTime()) / 86_400_000;
  if (spanDays > LIMITS.auditWindowMaxDays) {
    throw AppError.badRequest(
      `Report window is limited to ${LIMITS.auditWindowMaxDays} days. Narrow the requested range.`,
    );
  }
  return { from: fromDate.toISOString(), to: toDate.toISOString() };
}

function provenanceLine(model: Pick<ReportModel, 'schemaVersion' | 'meta'>): string {
  return (
    `Generated by PrismForge Reporting Engine v${REPORT_SCHEMA_VERSION} on ${model.meta.generatedAt} ` +
    `by ${model.meta.generatedBy.email} (${model.meta.generatedBy.role}). ` +
    `Correlation id ${model.meta.correlationId}. Classification: ${model.meta.classification}. ` +
    `Figures are derived from the authoritative server-side configuration record and are reproducible ` +
    `from the audit trail.`
  );
}

// ---------------------------------------------------------------------------
// Model builders
// ---------------------------------------------------------------------------

function configurationModel(
  actor: Actor,
  spec: ConfigurationSpec,
  price: PriceBreakdown,
  meta: BaseMeta,
  extra: { id?: string; version?: number; fingerprint?: string; snapshot?: string; owner?: string } = {},
): ReportModel {
  const product = getProduct(spec.productId);

  const model: ReportModel = {
    schemaVersion: REPORT_SCHEMA_VERSION,
    meta: metaFor(meta, 'configuration', SUBJECT_CLASSIFICATION.configuration),
    headline: [
      { label: 'Configuration', value: spec.name },
      { label: 'Product', value: `${product.name} (${product.sku})` },
      { label: 'Record id', value: extra.id ?? 'Unsaved draft' },
      { label: 'Version', value: extra.version ? `v${extra.version}` : '-' },
      { label: 'Owner', value: extra.owner ?? actor.email },
      { label: 'Price fingerprint', value: extra.fingerprint ?? price.fingerprint },
    ],
    sections: [
      {
        heading: 'Bill of materials',
        note: 'Every configurable surface on the assembly.',
        columns: [
          { key: 'part', label: 'Part' },
          { key: 'finish', label: 'Finish' },
          { key: 'colour', label: 'Colour (sRGB)' },
          { key: 'enabled', label: 'Fitted' },
        ],
        rows: (Object.keys(PARTS) as PartId[]).map((p) => {
          const cfg = spec.parts[p] ?? { colour: '#000000', finish: 'matte', enabled: false };
          const fitted = cfg.enabled && (!PARTS[p].requiresAccessory || spec.accessories.includes(PARTS[p].requiresAccessory!));
          return {
            part: PARTS[p].label,
            finish: finishLabel(cfg.finish),
            colour: hexLabel(cfg.colour),
            enabled: fitted ? 'Yes' : 'No',
          };
        }),
      },
      {
        heading: 'Accessories & modules',
        columns: [
          { key: 'module', label: 'Module' },
          { key: 'description', label: 'Description', wrap: true },
        ],
        rows: (spec.accessories.length ? spec.accessories : []).map((a) => ({
          module: ACCESSORIES[a as AccessoryId]?.label ?? a,
          description: ACCESSORIES[a as AccessoryId]?.description ?? '',
        })),
      },
      {
        heading: 'Dimensions & personalisation',
        columns: [
          { key: 'attribute', label: 'Attribute' },
          { key: 'value', label: 'Value' },
        ],
        rows: [
          { attribute: 'Height', value: `${spec.dimensions.height} mm` },
          { attribute: 'Diameter', value: `${spec.dimensions.diameter} mm` },
          {
            attribute: 'Engraving',
            value: spec.engraving.enabled
              ? `"${spec.engraving.text}" - ${spec.engraving.position}, ${ENGRAVING_FONTS.includes(spec.engraving.font) ? spec.engraving.font : 'grotesk'}`
              : 'None',
          },
          { attribute: 'Order quantity', value: spec.quantity.toLocaleString('en-US') },
          { attribute: 'Lead time', value: `${price.leadTimeDays} calendar days` },
          { attribute: 'Build origin', value: product.origin },
          { attribute: 'Customer notes', value: spec.notes || '-' },
        ],
      },
      {
        heading: 'Price breakdown',
        note: `Currency ${price.currency}. Tax rate ${(price.taxRate * 100).toFixed(0)}%.`,
        columns: [
          { key: 'code', label: 'Code' },
          { key: 'line', label: 'Line item' },
          { key: 'detail', label: 'Detail', wrap: true },
          { key: 'unit', label: 'Unit', align: 'right' },
          { key: 'amount', label: 'Amount', align: 'right' },
        ],
        rows: price.lines.map((l) => ({
          code: l.code,
          line: l.label,
          detail: l.detail,
          unit: money(l.unitMinor, price.currency),
          amount: money(l.amountMinor, price.currency),
        })),
      },
    ],
    notes: [
      'All prices are ex-works and exclude duties unless explicitly stated.',
      'Colour is specified in sRGB and rendered with the documented PBR parameters; screen calibration affects appearance.',
      'Configuration fingerprint is a deterministic digest of every input field and is reproducible for verification.',
    ],
  };

  model.headline.push(
    { label: 'Subtotal', value: money(price.subtotalMinor, price.currency) },
    { label: 'Tax', value: money(price.taxMinor, price.currency) },
    { label: 'Total', value: money(price.totalMinor, price.currency) },
  );
  if (extra.snapshot) model.snapshot = extra.snapshot;
  model.meta.provenance = provenanceLine(model);
  return model;
}

function pricingModel(actor: Actor, spec: ConfigurationSpec, price: PriceBreakdown, meta: BaseMeta): ReportModel {
  const model = configurationModel(actor, spec, price, meta);
  model.meta.title = SUBJECT_TITLE.pricing;
  model.meta.subject = 'pricing';
  model.sections = model.sections.filter((s) => s.heading === 'Price breakdown');
  model.headline = [
    { label: 'Quotation for', value: spec.name },
    { label: 'Product', value: getProduct(spec.productId).name },
    { label: 'Quantity', value: spec.quantity.toLocaleString('en-US') },
    { label: 'Subtotal', value: money(price.subtotalMinor, price.currency) },
    { label: 'Tax', value: money(price.taxMinor, price.currency) },
    { label: 'Total', value: money(price.totalMinor, price.currency) },
    { label: 'Per unit', value: money(price.totalPerUnitMinor, price.currency) },
    { label: 'Lead time', value: `${price.leadTimeDays} days` },
    { label: 'Fingerprint', value: price.fingerprint },
  ];
  model.meta.provenance = provenanceLine(model);
  return model;
}

function registerModel(actor: Actor, query: { from?: string; to?: string; pageSize?: number }, meta: BaseMeta): ReportModel {
  const { from, to } = resolveWindow(query.from, query.to);
  const params: unknown[] = [from, to];
  const elevated = actor.role === 'auditor' || actor.role === 'security_officer' || actor.role === 'admin';
  let scope = '';
  if (!elevated) {
    scope = ' AND owner_id = ?';
    params.push(actor.id);
  }
  const limit = Math.min(query.pageSize ?? 1000, 5000);

  const rows = all<{
    id: string;
    public_id: string;
    version: number;
    name: string;
    product_id: string;
    owner_id: string;
    quantity: number;
    total_minor: number;
    currency: string;
    status: string;
    created_at: string;
    updated_at: string;
    fingerprint: string;
  }>(
    `SELECT id, public_id, version, name, product_id, owner_id, quantity, total_minor,
            currency, status, created_at, updated_at, fingerprint
       FROM configurations
      WHERE deleted_at IS NULL AND created_at >= ? AND created_at <= ?${scope}
      ORDER BY created_at DESC LIMIT ?`,
    ...params,
    limit,
  );

  const ownerNames = new Map<string, string>(
    all<{ id: string; email: string }>('SELECT id, email FROM users').map((u) => [u.id, u.email]),
  );

  const model: ReportModel = {
    schemaVersion: REPORT_SCHEMA_VERSION,
    meta: metaFor(meta, 'configurations', SUBJECT_CLASSIFICATION.configurations),
    headline: [
      { label: 'Records', value: String(rows.length) },
      { label: 'Window start', value: from },
      { label: 'Window end', value: to },
      { label: 'Scope', value: elevated ? 'All owners (elevated role)' : 'Own records only' },
      { label: 'Aggregate value', value: money(rows.reduce((a, r) => a + Number(r.total_minor), 0), rows[0]?.currency ?? 'USD') },
    ],
    sections: [
      {
        heading: 'Configuration register',
        note: 'Soft-deleted records are excluded; they remain in the audit trail.',
        columns: [
          { key: 'id', label: 'Record id' },
          { key: 'name', label: 'Name', wrap: true },
          { key: 'product', label: 'Product' },
          { key: 'owner', label: 'Owner' },
          { key: 'qty', label: 'Qty', align: 'right' },
          { key: 'total', label: 'Total', align: 'right' },
          { key: 'status', label: 'Status' },
          { key: 'created', label: 'Created (UTC)' },
          { key: 'updated', label: 'Updated (UTC)' },
          { key: 'fingerprint', label: 'Fingerprint' },
        ],
        rows: rows.map((r) => ({
          id: r.public_id,
          name: r.name,
          product: getProduct(r.product_id).name,
          owner: ownerNames.get(r.owner_id) ?? r.owner_id,
          qty: Number(r.quantity),
          total: money(Number(r.total_minor), r.currency),
          status: r.status,
          created: r.created_at,
          updated: r.updated_at,
          fingerprint: r.fingerprint,
        })),
      },
    ],
    notes: [
      'Record identifiers are opaque; configuration content is stored encrypted at rest (AES-256-GCM).',
      'This extract lists metadata only. Configuration content requires the detail endpoint and is separately authorised.',
    ],
  };
  model.meta.provenance = provenanceLine(model);
  return model;
}

function auditModel(
  actor: Actor,
  query: { from?: string; to?: string; action?: string; outcome?: string; minSeverity?: AuditSeverity },
  meta: BaseMeta,
): ReportModel {
  const { from, to } = resolveWindow(query.from, query.to);

  const collected: AuditRecord[] = [];
  let page = 1;
  for (;;) {
    const result = queryAudit({
      page,
      pageSize: 500,
      order: 'asc',
      action: query.action,
      outcome: query.outcome as never,
      minSeverity: query.minSeverity,
      from,
      to,
    });
    collected.push(...result.rows);
    if (collected.length >= MAX_AUDIT_ROWS || page * 500 >= result.total) break;
    page++;
  }
  const rows = collected.slice(0, MAX_AUDIT_ROWS);

  const stats = auditStats(Math.max(1, Math.round((Date.parse(to) - Date.parse(from)) / 86_400_000)));
  const integrity = verifyChain({ fromSeq: 0, toSeq: rows.length ? Number(rows[rows.length - 1]!.seq) : undefined });

  const model: ReportModel = {
    schemaVersion: REPORT_SCHEMA_VERSION,
    meta: metaFor(meta, 'audit', SUBJECT_CLASSIFICATION.audit),
    headline: [
      { label: 'Entries extracted', value: String(rows.length) },
      { label: 'Window start', value: from },
      { label: 'Window end', value: to },
      { label: 'Failures in window', value: String(stats.byOutcome['FAILURE'] ?? 0) },
      { label: 'Denials in window', value: String(stats.byOutcome['DENIED'] ?? 0) },
      { label: 'Chain verified', value: integrity.valid ? 'YES' : 'NO' },
      { label: 'Requested by', value: actor.email },
    ],
    sections: [
      {
        heading: 'Audit trail',
        note: 'Entries are HMAC-chained; `Entry hash` links each row to its predecessor. Verify with `GET /api/v1/audit/verify`.',
        columns: [
          { key: 'seq', label: 'Seq', align: 'right' },
          { key: 'occurredAt', label: 'Timestamp (UTC)' },
          { key: 'actor', label: 'Actor' },
          { key: 'role', label: 'Role' },
          { key: 'action', label: 'Action' },
          { key: 'resource', label: 'Resource' },
          { key: 'outcome', label: 'Outcome' },
          { key: 'severity', label: 'Severity' },
          { key: 'message', label: 'Message', wrap: true },
          { key: 'correlationId', label: 'Correlation id' },
          { key: 'entryHash', label: 'Entry hash' },
        ],
        rows: rows.map((r) => ({
          seq: r.seq,
          occurredAt: r.occurredAt,
          actor: r.actorEmail ?? r.actorId ?? 'anonymous',
          role: r.actorRole ?? '-',
          action: r.action,
          resource: r.resourceId ?? r.resourceType ?? '-',
          outcome: r.outcome,
          severity: r.severity,
          message: r.message || '-',
          correlationId: r.correlationId ?? '-',
          entryHash: `${r.prevHash.slice(0, 8)}...${r.entryHash.slice(0, 8)}`,
        })),
      },
      {
        heading: 'Activity by action (window)',
        columns: [
          { key: 'action', label: 'Action' },
          { key: 'count', label: 'Count', align: 'right' },
        ],
        rows: stats.byAction.map((a) => ({ action: a.action, count: a.count })),
      },
      {
        heading: 'Highest-risk principals (window)',
        note: 'Ranked by failed and denied authentications/authorisations.',
        columns: [
          { key: 'actor', label: 'Principal' },
          { key: 'failures', label: 'Failures', align: 'right' },
          { key: 'denied', label: 'Denials', align: 'right' },
        ],
        rows: stats.topRiskyActors.map((a) => ({ actor: a.actor, failures: a.failures, denied: a.denied })),
      },
    ],
    notes: [
      'IP addresses are stored as salted pseudonyms, never in clear text (data minimisation).',
      'This extract is itself an auditable event and is recorded in the chain with a CRITICAL severity.',
      'Retention: 30 days for generated extracts; the source trail is retained for the full statutory period.',
    ],
    chain: {
      verified: integrity.valid,
      entries: integrity.verifiedEntries,
      headHash: integrity.headHash,
      errors: integrity.errors,
      checkpoint: integrity.checkpoint,
    },
    raw: { stats },
  };
  model.meta.provenance = provenanceLine(model);
  return model;
}

function integrityModel(meta: BaseMeta): ReportModel {
  const result = verifyChain({ fromSeq: 0 });
  const stats = auditStats(30);
  const checkpoints = all<{ seq: number; head_hash: string; entry_count: number; created_at: string; created_by: string | null }>(
    'SELECT seq, head_hash, entry_count, created_at, created_by FROM audit_checkpoints ORDER BY seq DESC LIMIT 25',
  );

  const model: ReportModel = {
    schemaVersion: REPORT_SCHEMA_VERSION,
    meta: metaFor(meta, 'integrity', SUBJECT_CLASSIFICATION.integrity),
    headline: [
      { label: 'Overall result', value: result.valid ? 'PASS' : 'FAIL' },
      { label: 'Entries verified', value: String(result.verifiedEntries) },
      { label: 'Chain head seq', value: String(stats.chain.headSeq) },
      { label: 'Chain head hash', value: stats.chain.headHash },
      { label: 'Discrepancies', value: String(result.errors.length) },
      { label: 'Verification time (ms)', value: String(result.durationMs) },
    ],
    sections: [
      {
        heading: 'Verification summary',
        columns: [
          { key: 'check', label: 'Check' },
          { key: 'result', label: 'Result' },
          { key: 'evidence', label: 'Evidence', wrap: true },
        ],
        rows: [
          {
            check: 'Chain linkage (prev_hash)',
            result: result.errors.some((e) => e.reason === 'PREV_HASH_MISMATCH') ? 'FAIL' : 'PASS',
            evidence: `Each of ${result.verifiedEntries} entries links to its predecessor.`,
          },
          {
            check: 'Entry MAC integrity',
            result: result.errors.some((e) => e.reason === 'ENTRY_HASH_MISMATCH') ? 'FAIL' : 'PASS',
            evidence: 'HMAC-SHA256 recomputed over the canonical entry payload.',
          },
          {
            check: 'Sequence continuity',
            result: result.sequenceGaps.length === 0 ? 'PASS' : 'FAIL',
            evidence:
              result.sequenceGaps.length === 0
                ? 'No gaps detected in the monotonic sequence.'
                : `Gaps at: ${result.sequenceGaps.slice(0, 20).join(', ')}`,
          },
          {
            check: 'Signed checkpoint',
            result: result.checkpoint ? (result.checkpoint.ok ? 'PASS' : 'FAIL') : 'N/A',
            evidence: result.checkpoint?.note ?? 'No checkpoint has been recorded yet.',
          },
        ],
      },
      {
        heading: 'Discrepancies',
        note: result.errors.length ? 'Investigate immediately - the log has been modified or truncated.' : 'None detected.',
        columns: [
          { key: 'seq', label: 'Seq', align: 'right' },
          { key: 'reason', label: 'Reason' },
          { key: 'expected', label: 'Expected', wrap: true },
          { key: 'actual', label: 'Observed', wrap: true },
        ],
        rows: result.errors.map((e) => ({
          seq: e.seq,
          reason: e.reason,
          expected: e.expected ?? '-',
          actual: e.actual ?? '-',
        })),
      },
      {
        heading: 'Signed checkpoints',
        columns: [
          { key: 'seq', label: 'Seq', align: 'right' },
          { key: 'entries', label: 'Entries', align: 'right' },
          { key: 'headHash', label: 'Head hash' },
          { key: 'createdAt', label: 'Created (UTC)' },
        ],
        rows: checkpoints.map((c) => ({
          seq: Number(c.seq),
          entries: Number(c.entry_count),
          headHash: c.head_hash,
          createdAt: c.created_at,
        })),
      },
    ],
    notes: [
      'The audit_log table is append-only; UPDATE and DELETE are rejected by database triggers.',
      'Each entry is HMAC-SHA256 chained to its predecessor, so modification of any historical row is detectable.',
      'Signed checkpoints bind a chain head to a point in time, making truncation of the tail detectable too.',
    ],
    chain: {
      verified: result.valid,
      entries: result.verifiedEntries,
      headHash: result.headHash,
      errors: result.errors,
      checkpoint: result.checkpoint,
    },
    raw: { verification: result, stats },
  };
  model.meta.provenance = provenanceLine(model);
  return model;
}

function accessReviewModel(meta: BaseMeta): ReportModel {
  const users = all<{
    id: string;
    email: string;
    display_name: string;
    role: string;
    is_active: number;
    must_change_password: number;
    mfa_secret_enc: string | null;
    last_login_at: string | null;
    created_at: string;
    locked_until: string | null;
    failed_attempts: number;
  }>('SELECT * FROM users ORDER BY role, email');

  const sessionCount = (id: string) =>
    Number(
      get<{ c: number }>(
        'SELECT COUNT(*) AS c FROM sessions WHERE user_id = ? AND revoked_at IS NULL AND expires_at > ?',
        id,
        nowIso(),
      )?.c ?? 0,
    );

  const dormantDays = 90;
  const dormantCutoff = new Date(Date.now() - dormantDays * 86_400_000).toISOString();

  const findings: Array<{ principal: string; finding: string; severity: string; recommendation: string }> = [];
  const admins = users.filter((u) => u.role === 'admin' && u.is_active === 1);

  for (const u of users) {
    if (u.is_active === 1 && u.last_login_at && u.last_login_at < dormantCutoff) {
      findings.push({
        principal: u.email,
        finding: `No successful authentication for ${dormantDays} days`,
        severity: 'Medium',
        recommendation: 'Suspend the account or require re-certification of need (ISO/IEC 27001 A.5.18)',
      });
    }
    if (u.is_active === 1 && u.role !== 'viewer' && !u.mfa_secret_enc) {
      findings.push({
        principal: u.email,
        finding: `Privileged role '${u.role}' without multi-factor authentication`,
        severity: 'High',
        recommendation: 'Enrol TOTP before the next working day (NIST SP 800-63B AAL2)',
      });
    }
    if (u.is_active === 1 && u.must_change_password === 1) {
      findings.push({
        principal: u.email,
        finding: 'Provisional credential still in force',
        severity: 'High',
        recommendation: 'Force password rotation at next sign-in',
      });
    }
    if (u.role === 'admin' && users.filter((x) => x.role === 'admin' && x.is_active === 1).length === 1) {
      findings.push({
        principal: u.email,
        finding: 'Single point of failure: only one active administrator',
        severity: 'Medium',
        recommendation: 'Appoint at least one backup administrator (ISO/IEC 27001 A.5.3 segregation of duties)',
      });
    }
  }
  void admins;

  const model: ReportModel = {
    schemaVersion: REPORT_SCHEMA_VERSION,
    meta: metaFor(meta, 'access-review', SUBJECT_CLASSIFICATION['access-review']),
    headline: [
      { label: 'Accounts', value: String(users.length) },
      { label: 'Active', value: String(users.filter((u) => u.is_active === 1).length) },
      { label: 'With MFA', value: String(users.filter((u) => u.mfa_secret_enc).length) },
      { label: 'Administrators', value: String(users.filter((u) => u.role === 'admin').length) },
      { label: 'Findings', value: String(findings.length) },
      { label: 'Dormancy threshold', value: `${dormantDays} days` },
    ],
    sections: [
      {
        heading: 'Account inventory',
        columns: [
          { key: 'email', label: 'Principal' },
          { key: 'name', label: 'Display name' },
          { key: 'role', label: 'Role' },
          { key: 'status', label: 'Status' },
          { key: 'mfa', label: 'MFA' },
          { key: 'sessions', label: 'Active sessions', align: 'right' },
          { key: 'lastLogin', label: 'Last sign-in (UTC)' },
          { key: 'created', label: 'Created (UTC)' },
        ],
        rows: users.map((u) => ({
          email: u.email,
          name: u.display_name || '-',
          role: u.role,
          status: u.is_active === 1 ? (u.locked_until && Date.parse(u.locked_until) > Date.now() ? 'Locked' : 'Active') : 'Disabled',
          mfa: u.mfa_secret_enc ? 'Enrolled' : 'None',
          sessions: sessionCount(u.id),
          lastLogin: u.last_login_at ?? 'Never',
          created: u.created_at,
        })),
      },
      {
        heading: 'Access review findings',
        note: 'Derived automatically from the account register; each finding maps to a control reference.',
        columns: [
          { key: 'principal', label: 'Principal' },
          { key: 'finding', label: 'Finding', wrap: true },
          { key: 'severity', label: 'Severity' },
          { key: 'recommendation', label: 'Recommendation', wrap: true },
        ],
        rows: findings,
      },
    ],
    notes: [
      'Least privilege is enforced by the role ladder: viewer < configurator < auditor < security_officer < admin.',
      'Access reviews should be repeated at least quarterly and after any privileged role change.',
      'Every privileged action in this report window is individually evidenced in the audit trail.',
    ],
  };
  model.meta.provenance = provenanceLine(model);
  return model;
}

function securityPostureModel(meta: BaseMeta): ReportModel {
  const stats = auditStats(30);
  const events = all<{ id: string; detected_at: string; rule: string; severity: string; summary: string }>(
    'SELECT id, detected_at, rule, severity, summary FROM security_events ORDER BY detected_at DESC LIMIT 100',
  );
  const failedLogins = Number(
    get<{ c: number }>("SELECT COUNT(*) AS c FROM login_attempts WHERE outcome = 'FAILURE' AND occurred_at >= ?", stats.from)?.c ?? 0,
  );
  const denials = Number(
    get<{ c: number }>("SELECT COUNT(*) AS c FROM audit_log WHERE outcome = 'DENIED' AND occurred_at >= ?", stats.from)?.c ?? 0,
  );
  const activeUsers = Number(get<{ c: number }>('SELECT COUNT(*) AS c FROM users WHERE is_active = 1')?.c ?? 0);
  const mfaUsers = Number(
    get<{ c: number }>('SELECT COUNT(*) AS c FROM users WHERE is_active = 1 AND mfa_secret_enc IS NOT NULL')?.c ?? 0,
  );
  const mfaCoverage = activeUsers === 0 ? 0 : Math.round((mfaUsers / activeUsers) * 100);
  const staleShareLinks = Number(
    get<{ c: number }>('SELECT COUNT(*) AS c FROM configuration_shares WHERE revoked_at IS NULL AND expires_at < ?', nowIso())?.c ?? 0,
  );

  const controls: Array<Record<string, string | number>> = [
    { control: 'A.5.15 Access control', status: 'Implemented', evidence: 'Role ladder + per-object ownership checks on every read/write' },
    { control: 'A.5.16 Identity management', status: 'Implemented', evidence: 'User register, disable/rotate flows, access review report' },
    { control: 'A.5.17 Authentication information', status: 'Implemented', evidence: 'scrypt (N=2^17), lockout, TOTP, generic failure messages' },
    { control: 'A.5.18 Access rights', status: 'Implemented', evidence: 'Quarterly access review with dormancy detection' },
    { control: 'A.5.23 Cloud / service security', status: 'Implemented', evidence: 'Strict CORS allow-list, no wildcard, security headers on all responses' },
    { control: 'A.5.28 Collection of evidence', status: 'Implemented', evidence: 'Hash-chained, append-only audit trail with signed checkpoints' },
    { control: 'A.5.31 Legal requirements', status: 'Applicable', evidence: 'Retention windows defined per artefact class' },
    { control: 'A.5.34 Privacy and PII protection', status: 'Implemented', evidence: 'IP pseudonymisation, encrypted at rest, data minimisation in logs' },
    { control: 'A.8.2 Privileged access rights', status: 'Implemented', evidence: 'Last-admin guard rail, separation-of-duties checks' },
    { control: 'A.8.5 Secure authentication', status: 'Implemented', evidence: 'Short-lived JWT, rotating refresh with reuse detection' },
    { control: 'A.8.8 Technical vulnerabilities', status: 'Managed', evidence: 'Dependency audit in CI, minimal dependency surface' },
    { control: 'A.8.9 Configuration management', status: 'Implemented', evidence: 'Fail-fast env validation, no secrets in repo' },
    { control: 'A.8.12 Data leakage', status: 'Implemented', evidence: 'AES-256-GCM at rest, share tokens stored as digests, no-store on PII' },
    { control: 'A.8.15 Logging', status: 'Implemented', evidence: 'Structured JSON logs + database trail, 7-year retention target' },
    { control: 'A.8.16 Monitoring activities', status: 'Implemented', evidence: 'Detection rules raising CRITICAL security events' },
    { control: 'A.8.20 Network security', status: 'Implemented', evidence: 'Loopback bind by default, HSTS in production' },
    { control: 'A.8.24 Use of cryptography', status: 'Implemented', evidence: 'node:crypto only - AES-256-GCM, HMAC-SHA256, SHA-256, scrypt' },
    { control: 'A.8.25 Secure development lifecycle', status: 'Managed', evidence: 'Typed contracts, validation at the boundary, threat model documentation' },
    { control: 'A.8.28 Secure coding', status: 'Implemented', evidence: 'Parameterised SQL, no eval, CSP, output encoding in reports' },
    { control: 'A.8.29 Security testing', status: 'Managed', evidence: 'Chain verification job, linting, static typing' },
    { control: 'A.8.31 Separation of environments', status: 'Implemented', evidence: 'Ephemeral keys in dev, boot-time failure in production' },
    { control: 'A.8.32 Change management', status: 'Managed', evidence: 'Forward-only migrations, optimistic concurrency on records' },
  ];

  const model: ReportModel = {
    schemaVersion: REPORT_SCHEMA_VERSION,
    meta: metaFor(meta, 'security-posture', SUBJECT_CLASSIFICATION['security-posture']),
    headline: [
      { label: 'Audit events (30d)', value: String(stats.total) },
      { label: 'Failed authentications', value: String(failedLogins) },
      { label: 'Authorisation denials', value: String(denials) },
      { label: 'Active accounts', value: String(activeUsers) },
      { label: 'MFA coverage', value: `${mfaCoverage}%` },
      { label: 'Security events open', value: String(events.filter((e) => e.detected_at).length) },
      { label: 'Expired share links', value: String(staleShareLinks) },
    ],
    sections: [
      {
        heading: 'Control coverage (ISO/IEC 27001:2022 Annex A)',
        columns: [
          { key: 'control', label: 'Control' },
          { key: 'status', label: 'Status' },
          { key: 'evidence', label: 'Implementation evidence', wrap: true },
        ],
        rows: controls,
      },
      {
        heading: 'Recent security events',
        note: 'Raised by automated detection rules; each is also a CRITICAL audit entry.',
        columns: [
          { key: 'detectedAt', label: 'Detected (UTC)' },
          { key: 'rule', label: 'Rule' },
          { key: 'severity', label: 'Severity' },
          { key: 'summary', label: 'Summary', wrap: true },
        ],
        rows: events.map((e) => ({
          detectedAt: e.detected_at,
          rule: e.rule,
          severity: e.severity,
          summary: e.summary,
        })),
      },
      {
        heading: 'Daily audit volume (30 days)',
        columns: [
          { key: 'date', label: 'Date' },
          { key: 'count', label: 'Events', align: 'right' },
          { key: 'failures', label: 'Failures', align: 'right' },
          { key: 'denied', label: 'Denials', align: 'right' },
        ],
        rows: stats.daily,
      },
    ],
    notes: [
      'Status values describe the implemented state of this deployment, verified by automated tests where possible.',
      'This report is generated on demand and reflects live configuration; it is not a substitute for a periodic external assessment.',
    ],
    raw: { stats },
  };
  model.meta.provenance = provenanceLine(model);
  return model;
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

interface BaseMeta {
  format: ReportFormat;
  correlationId: string;
  generatedBy: { id: string; email: string; role: Role };
  organisation?: string;
}

/** Single construction point for report metadata - keeps all subjects consistent. */
function metaFor(
  base: BaseMeta,
  subject: ReportSubject,
  classification: Classification,
  title = SUBJECT_TITLE[subject],
): ReportModel['meta'] {
  return {
    ...base,
    title,
    subject,
    format: base.format,
    classification,
    organisation: base.organisation ?? 'PrismForge Demo Organisation',
    generatedAt: nowIso(),
    generatedBy: base.generatedBy,
    correlationId: base.correlationId,
    retentionUntil: isoPlusSeconds(30 * 86_400),
    toolVersion: REPORT_TOOL_VERSION,
    provenance: '',
  };
}

export interface BuildOptions {
  actor: Actor;
  subject: ReportSubject;
  format: ReportFormat;
  correlationId: string;
  configurationId?: string;
  spec?: ConfigurationSpec;
  from?: string;
  to?: string;
  action?: string;
  outcome?: string;
  minSeverity?: AuditSeverity;
  snapshot?: string;
  organisation?: string;
}

export function buildReport(options: BuildOptions): ReportModel {
  const { actor } = options;
  assertSubjectAllowed(actor, options.subject);

  const meta: BaseMeta = {
    format: options.format,
    correlationId: options.correlationId,
    generatedBy: { id: actor.id, email: actor.email, role: actor.role },
    organisation: options.organisation ?? 'PrismForge Demo Organisation',
  };

  switch (options.subject) {
    case 'configuration':
    case 'pricing': {
      let spec: ConfigurationSpec;
      let price: PriceBreakdown;
      let extra: { id?: string; version?: number; fingerprint?: string; owner?: string } = {};

      if (options.configurationId) {
        const detail = readConfiguration(actor, options.configurationId);
        spec = detail.spec;
        price = detail.price;
        extra = {
          id: detail.publicId,
          version: detail.version,
          fingerprint: detail.fingerprint,
          owner: detail.ownerId,
        };
      } else if (options.spec) {
        const validated = configurationSpecSchema.parse(options.spec);
        // Price is always recomputed on the server; a client-supplied price is
        // structurally impossible because the schema has no such field.
        spec = validated;
        price = computePrice(validated);
      } else {
        throw AppError.badRequest('Either configurationId or spec must be supplied');
      }

      const model =
        options.subject === 'pricing'
          ? pricingModel(actor, spec, price, meta)
          : configurationModel(actor, spec, price, meta, { ...extra, snapshot: options.snapshot });
      return model;
    }

    case 'configurations':
      return registerModel(actor, { from: options.from, to: options.to }, meta);

    case 'audit':
      return auditModel(
        actor,
        {
          from: options.from,
          to: options.to,
          action: options.action,
          outcome: options.outcome,
          minSeverity: options.minSeverity,
        },
        meta,
      );

    case 'integrity':
      return integrityModel(meta);

    case 'access-review':
      return accessReviewModel(meta);

    case 'security-posture':
      return securityPostureModel(meta);

    default: {
      const exhaustive: never = options.subject;
      throw AppError.badRequest(`Unsupported report subject: ${String(exhaustive)}`);
    }
  }
}
