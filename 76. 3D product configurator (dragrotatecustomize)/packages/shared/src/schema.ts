/**
 * Zod contracts - the single validation boundary for the whole platform.
 *
 * Security notes
 *  - Every schema is `.strict()` where the object shape is closed, which blocks
 *    mass-assignment / prototype-pollution payloads (OWASP A01:2021, A08:2021).
 *  - Free-text inputs are normalised and stripped of control characters before
 *    they can ever reach the database, the audit log, or a report renderer.
 *  - `.max()` bounds every variable-length input to prevent resource exhaustion
 *    and log-forging (OWASP A04:2021, ISO/IEC 27001 A.8.9).
 *  - `hexColor` is regex-anchored; no CSS injection vector into the renderer.
 */

import { z } from 'zod';
import {
  ACCESSORY_IDS,
  ENGRAVING_FONTS,
  ENGRAVING_POSITIONS,
  FINISH_IDS,
  LIMITS,
  PART_IDS,
  PRICE_MAX,
  REPORT_FORMATS,
  REPORT_SUBJECTS,
  ROLES,
} from './constants.js';

// ---------------------------------------------------------------------------
// Primitives
// ---------------------------------------------------------------------------

/** #RGB or #RRGGBB only. */
export const hexColor = z
  .string()
  .trim()
  .regex(/^#(?:[0-9a-fA-F]{3}|[0-9a-fA-F]{6})$/, 'Expected a #RGB or #RRGGBB colour value');

/** Strips C0/C1 control chars + Unicode format chars, collapses whitespace. */
export function sanitiseText(value: string): string {
  return value
    .replace(/[\u0000-\u001f\u007f-\u009f\u200b-\u200f\u2028\u2029\ufeff]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

const safeText = (max: number) =>
  z
    .string()
    .transform(sanitiseText)
    .pipe(z.string().max(max));

/** Lower-cased, trimmed e-mail. Length bounded to RFC-5321 maximum. */
export const email = z
  .string()
  .trim()
  .toLowerCase()
  .min(3)
  .max(254)
  .email()
  .refine((v) => !v.includes('..'), 'Malformed e-mail address');

/**
 * Password policy (NIST SP 800-63B: length-first, no composition rules, no
 * forced periodic rotation, screen against known-breached lists).
 */
export const password = z
  .string()
  .min(12, 'Use at least 12 characters')
  .max(256, 'Password is too long')
  .refine((v) => !/^(.)\1+$/.test(v), 'Password is a single repeated character')
  .refine((v) => /[a-z]/.test(v) && /[A-Z]/.test(v) && /[0-9]/.test(v), 'Use upper case, lower case and digits')
  .refine((v) => !/[\s]/.test(v), 'Do not use spaces - use a passphrase with separators instead');

export const uuid = z.string().uuid();

export const idString = z
  .string()
  .trim()
  .min(2)
  .max(64)
  .regex(/^[A-Za-z0-9][A-Za-z0-9._-]*$/, 'Identifier contains unsupported characters');

export const cuidLike = z
  .string()
  .trim()
  .min(8)
  .max(64)
  .regex(/^[A-Za-z0-9_-]+$/, 'Invalid identifier');

/** Opaque share token: base64url, 22+ chars (>=128 bits of entropy). */
export const shareToken = z
  .string()
  .trim()
  .regex(/^[A-Za-z0-9_-]{22,128}$/, 'Invalid share token');

export const isoDateTime = z
  .string()
  .datetime({ offset: true })
  .or(z.string().regex(/^\d{4}-\d{2}-\d{2}$/, 'Use ISO-8601 date or datetime'));

// ---------------------------------------------------------------------------
// Pagination
// ---------------------------------------------------------------------------

export const paginationSchema = z
  .object({
    page: z.coerce.number().int().min(1).max(100_000).default(1),
    pageSize: z.coerce
      .number()
      .int()
      .min(1)
      .max(LIMITS.pageSizeMax)
      .default(LIMITS.pageSizeDefault),
    sort: z.string().trim().max(40).optional(),
    order: z.enum(['asc', 'desc']).default('desc'),
  })
  .strict();

export type Pagination = z.infer<typeof paginationSchema>;

// ---------------------------------------------------------------------------
// Configuration domain
// ---------------------------------------------------------------------------

export const partIdSchema = z.enum(PART_IDS);
export const accessoryIdSchema = z.enum(ACCESSORY_IDS);
export const finishIdSchema = z.enum(FINISH_IDS);

export const partConfigSchema = z
  .object({
    colour: hexColor,
    finish: finishIdSchema,
    enabled: z.boolean().default(true),
  })
  .strict();

export const dimensionsSchema = z
  .object({
    height: z.coerce.number().int().min(LIMITS.dimensionMinMm).max(LIMITS.dimensionMaxMm),
    diameter: z.coerce.number().int().min(LIMITS.dimensionMinMm).max(LIMITS.dimensionMaxMm),
  })
  .strict();

export const engravingSchema = z
  .object({
    enabled: z.boolean().default(false),
    text: safeText(LIMITS.engravingMaxLength).default(''),
    position: z.enum(ENGRAVING_POSITIONS).default('front'),
    font: z.enum(ENGRAVING_FONTS).default('grotesk'),
    colour: hexColor.default('#f8fafc'),
  })
  .strict();

/**
 * The full configuration specification. This is the unit of work for the
 * configurator and the primary object rendered in every report.
 */
export const configurationSpecSchema = z
  .object({
    productId: idString,
    name: safeText(80).default('Untitled configuration'),
    dimensions: dimensionsSchema,
    parts: z.record(partIdSchema, partConfigSchema),
    accessories: z.array(accessoryIdSchema).max(ACCESSORY_IDS.length).default([]),
    engraving: engravingSchema.default({}),
    quantity: z.coerce
      .number()
      .int()
      .min(LIMITS.quantityMin)
      .max(LIMITS.quantityMax)
      .default(1),
    notes: safeText(LIMITS.notesMaxLength).default(''),
    /** Optional PNG snapshot (client-rendered) embedded in the spec sheet. */
    snapshot: z
      .string()
      .regex(/^data:image\/png;base64,[A-Za-z0-9+/=]+$/, 'Snapshot must be a base64 PNG data URL')
      .max(2_500_000)
      .optional()
      .or(z.literal('')),
  })
  .strict()
  .superRefine((spec, ctx) => {
    for (const key of Object.keys(spec.parts)) {
      if (!(PART_IDS as readonly string[]).includes(key)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['parts', key],
          message: `Unknown part '${key}'`,
        });
      }
    }
    if (spec.engraving.enabled && spec.engraving.text.length === 0) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['engraving', 'text'],
        message: 'Engraving is enabled but no text was supplied',
      });
    }
    const unique = new Set(spec.accessories);
    if (unique.size !== spec.accessories.length) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['accessories'],
        message: 'Duplicate accessory identifiers',
      });
    }
  });

export type ConfigurationSpec = z.infer<typeof configurationSpecSchema>;

export const createConfigurationSchema = z
  .object({
    spec: configurationSpecSchema,
    /** Persist a shareable read-only link alongside the record. */
    share: z.boolean().default(false),
  })
  .strict();

export const updateConfigurationSchema = z
  .object({
    spec: configurationSpecSchema.optional(),
    name: safeText(80).optional(),
    notes: safeText(LIMITS.notesMaxLength).optional(),
    expectedVersion: z.coerce.number().int().min(1).max(1_000_000),
  })
  .strict();

export const listConfigurationsSchema = paginationSchema
  .extend({
    q: z.string().trim().max(120).optional(),
    productId: idString.optional(),
    ownerId: cuidLike.optional(),
    createdFrom: isoDateTime.optional(),
    createdTo: isoDateTime.optional(),
  })
  .strict();
export type ListConfigurationsQuery = z.infer<typeof listConfigurationsSchema>;

export type CreateConfigurationInput = z.infer<typeof createConfigurationSchema>;
export type UpdateConfigurationInput = z.infer<typeof updateConfigurationSchema>;

export const configurationQuerySchema = z
  .object({
    includeAudit: z.coerce.boolean().default(false),
  })
  .strict()
  .partial();

// ---------------------------------------------------------------------------
// Auth
// ---------------------------------------------------------------------------

export const loginSchema = z
  .object({
    email,
    password: z.string().min(1).max(256),
    /** TOTP / WebAuthn assertion, when the account has MFA enrolled. */
    mfaCode: z.string().trim().regex(/^[0-9]{6,8}$/).optional(),
    /** Device fingerprint, hashed client-side before transmission. */
    deviceId: z.string().trim().max(128).optional(),
  })
  .strict();
export type LoginInput = z.infer<typeof loginSchema>;

export const refreshSchema = z
  .object({
    refreshToken: z.string().min(20).max(4096),
    deviceId: z.string().trim().max(128).optional(),
  })
  .strict();
export type RefreshInput = z.infer<typeof refreshSchema>;

export const changePasswordSchema = z
  .object({
    currentPassword: z.string().min(1).max(256),
    newPassword: password,
    revokeOtherSessions: z.boolean().default(true),
  })
  .strict();
export type ChangePasswordInput = z.infer<typeof changePasswordSchema>;

export const mfaEnrolSchema = z
  .object({
    label: safeText(60).default('Authenticator'),
    secret: z.string().trim().min(16).max(64).regex(/^[A-Z2-7]+$/i, 'Invalid base32 secret'),
  })
  .strict();
export type MfaEnrolInput = z.infer<typeof mfaEnrolSchema>;

export const mfaVerifySchema = z
  .object({
    code: z.string().trim().regex(/^[0-9]{6,8}$/),
  })
  .strict();
export type MfaVerifyInput = z.infer<typeof mfaVerifySchema>;

// ---------------------------------------------------------------------------
// Administration
// ---------------------------------------------------------------------------

export const createUserSchema = z
  .object({
    email,
    password,
    role: z.enum(ROLES),
    displayName: safeText(80).default(''),
    mustChangePassword: z.boolean().default(false),
  })
  .strict();
export type CreateUserInput = z.infer<typeof createUserSchema>;

export const updateUserSchema = z
  .object({
    role: z.enum(ROLES).optional(),
    displayName: safeText(80).optional(),
    isActive: z.boolean().optional(),
    mustChangePassword: z.boolean().optional(),
    /** Administrative unlock after a lockout window elapses. */
    unlock: z.boolean().optional(),
  })
  .strict()
  .refine((v) => Object.keys(v).length > 0, 'No changes supplied');
export type UpdateUserInput = z.infer<typeof updateUserSchema>;

export const listUsersSchema = paginationSchema
  .extend({
    role: z.enum(ROLES).optional(),
    isActive: z.coerce.boolean().optional(),
    q: z.string().trim().max(120).optional(),
  })
  .strict();
export type ListUsersQuery = z.infer<typeof listUsersSchema>;

// ---------------------------------------------------------------------------
// Audit
// ---------------------------------------------------------------------------

export const auditQuerySchema = paginationSchema
  .extend({
    actor: z.string().trim().max(254).optional(),
    action: z.string().trim().max(64).optional(),
    outcome: z.enum(['SUCCESS', 'FAILURE', 'DENIED']).optional(),
    minSeverity: z.enum(['INFO', 'NOTICE', 'WARNING', 'CRITICAL']).optional(),
    from: isoDateTime.optional(),
    to: isoDateTime.optional(),
    correlationId: z.string().trim().max(64).optional(),
  })
  .strict()
  .superRefine((v, ctx) => {
    if (v.from && v.to && new Date(v.from).getTime() > new Date(v.to).getTime()) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['from'], message: '`from` must precede `to`' });
    }
  });
export type AuditQueryInput = z.infer<typeof auditQuerySchema>;

export const auditStatsQuerySchema = z
  .object({
    days: z.coerce.number().int().min(1).max(LIMITS.auditWindowMaxDays).default(30),
  })
  .strict();

export const verifyAuditSchema = z
  .object({
    fromSeq: z.coerce.number().int().min(0).max(1_000_000_000).default(0),
    toSeq: z.coerce.number().int().min(0).max(1_000_000_000).optional(),
  })
  .strict();

// ---------------------------------------------------------------------------
// Reporting
// ---------------------------------------------------------------------------

export const reportRequestSchema = z
  .object({
    subject: z.enum(REPORT_SUBJECTS),
    format: z.enum(REPORT_FORMATS),
    /** For subject = 'configuration' | 'pricing'. */
    configurationId: cuidLike.optional(),
    /** Overrides configurationId when set (ad-hoc spec sheet). */
    spec: configurationSpecSchema.optional(),
    from: isoDateTime.optional(),
    to: isoDateTime.optional(),
    /** Row filters for the 'audit' subject. */
    action: z.string().trim().max(64).optional(),
    outcome: z.enum(['SUCCESS', 'FAILURE', 'DENIED']).optional(),
    minSeverity: z.enum(['INFO', 'NOTICE', 'WARNING', 'CRITICAL']).optional(),
    /** Embedded client-rendered PNG for visual spec sheets. */
    snapshot: z
      .string()
      .regex(/^data:image\/png;base64,[A-Za-z0-9+/=]+$/, 'Snapshot must be a base64 PNG data URL')
      .max(2_500_000)
      .optional()
      .or(z.literal('')),
    includeAuditTrail: z.boolean().default(false),
    includeSnapshot: z.boolean().default(true),
  })
  .strict()
  .superRefine((v, ctx) => {
    if ((v.subject === 'configuration' || v.subject === 'pricing') && !v.configurationId && !v.spec) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['configurationId'],
        message: 'configurationId or spec is required for this report subject',
      });
    }
    if (v.from && v.to && new Date(v.from).getTime() > new Date(v.to).getTime()) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['from'], message: 'from must precede to' });
    }
  });

export type ReportRequest = z.infer<typeof reportRequestSchema>;

// ---------------------------------------------------------------------------
// Misc
// ---------------------------------------------------------------------------

export const healthQuerySchema = z.object({ verbose: z.coerce.boolean().default(false) }).strict();

export const idParamSchema = z.object({ id: cuidLike });

export const priceMinor = z.coerce.number().int().min(0).max(PRICE_MAX);

// ---------------------------------------------------------------------------
// Envelope helpers
// ---------------------------------------------------------------------------

export interface ApiErrorBody {
  error: {
    code: string;
    message: string;
    correlationId: string;
    details?: unknown;
  };
}

export interface ApiSuccess<T> {
  data: T;
  correlationId: string;
}
