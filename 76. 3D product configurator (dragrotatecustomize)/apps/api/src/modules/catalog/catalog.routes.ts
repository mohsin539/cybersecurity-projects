/**
 * Catalogue routes - read-only product/option metadata.
 *
 * Public by design so a prospect can explore and build a configuration before
 * creating an account, but every read is still audited with the actor recorded
 * as `anonymous` where applicable. Catalogue data is not sensitive, but the
 * *access pattern* is: who looked at what, and when, matters for investigation.
 */

import { Router } from 'express';
import {
  ACCESSORY_LIST,
  configurationSpecSchema,
  DEFAULT_PRODUCT_ID,
  FINISH_LIST,
  LIMITS,
  PART_LIST,
  PRODUCTS,
  SWATCHES,
  computePrice,
  getProduct,
  type ConfigurationSpec,
} from '@prismforge/shared';
import { z } from 'zod';
import { asyncHandler } from '../../http/context.js';
import { requireAuth } from '../../http/auth.js';
import { validate } from '../../http/validate.js';
import { AppError } from '../../utils/errors.js';
import { record } from '../audit/audit.service.js';

export const catalogRouter = Router();

const productParam = z.object({ id: z.string().trim().min(2).max(64) }).strict();

catalogRouter.get(
  '/',
  asyncHandler(async (req, res) => {
    record({
      action: 'catalog.read',
      outcome: 'SUCCESS',
      severity: 'INFO',
      actorId: req.ctx.actor?.id ?? null,
      actorEmail: req.ctx.actor?.email ?? null,
      actorRole: req.ctx.actor?.role ?? null,
      ipFingerprint: req.ctx.ipFingerprint,
      userAgent: req.ctx.userAgent,
      sessionId: req.ctx.actor?.sessionId ?? null,
      correlationId: req.ctx.correlationId,
      resourceType: 'catalog',
      message: 'Catalogue metadata requested',
    });
    req.ctx.auditHandled = true;

    res.setHeader('Cache-Control', 'public, max-age=300, must-revalidate');
    res.json({
      data: {
        products: Object.values(PRODUCTS),
        defaultProductId: DEFAULT_PRODUCT_ID,
        parts: PART_LIST,
        finishes: FINISH_LIST,
        accessories: ACCESSORY_LIST,
        swatches: SWATCHES,
        limits: LIMITS,
      },
      correlationId: req.ctx.correlationId,
    });
  }),
);

catalogRouter.get(
  '/products/:id',
  validate(productParam, 'params'),
  asyncHandler(async (req, res) => {
    const id = (req.params as { id: string }).id;
    if (!PRODUCTS[id]) throw AppError.notFound('Product');
    res.setHeader('Cache-Control', 'public, max-age=300, must-revalidate');
    res.json({ data: getProduct(id), correlationId: req.ctx.correlationId });
  }),
);

/**
 * Server-authoritative price preview. The client also computes a price for
 * instant feedback, but only this endpoint's number is ever persisted, so a
 * tampered client cannot get a discounted quote written to the record.
 */
catalogRouter.post(
  '/price',
  requireAuth,
  validate(z.object({ spec: configurationSpecSchema }).strict()),
  asyncHandler(async (req, res) => {
    const { spec } = req.body as { spec: ConfigurationSpec };
    const price = computePrice(spec);
    req.ctx.auditHandled = true;
    res.json({
      data: { price, product: getProduct(spec.productId) },
      correlationId: req.ctx.correlationId,
    });
  }),
);
