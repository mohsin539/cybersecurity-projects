/**
 * Deterministic pricing engine.
 *
 * Runs identically on the client (live price feedback) and on the server
 * (authoritative quote generation). The server value is the one of record; the
 * client never submits a price, it is always recomputed here.
 */

import {
  ACCESSORIES,
  FINISHES,
  PARTS,
  getProduct,
} from './catalog.js';
import type { AccessoryId, PartId } from './constants.js';
import type { ConfigurationSpec } from './schema.js';

export interface PriceLine {
  code: string;
  label: string;
  detail: string;
  /** Minor units (cents) for the whole line at the ordered quantity. */
  amountMinor: number;
  /** Minor units per single unit. */
  unitMinor: number;
  category: 'base' | 'geometry' | 'finish' | 'accessory' | 'engraving' | 'discount' | 'tax';
}

export interface PriceBreakdown {
  currency: string;
  lines: PriceLine[];
  unitSubtotalMinor: number;
  quantityDiscountMinor: number;
  subtotalMinor: number;
  taxRate: number;
  taxMinor: number;
  totalMinor: number;
  totalPerUnitMinor: number;
  leadTimeDays: number;
  /** Stable fingerprint of the inputs, embedded into reports for traceability. */
  fingerprint: string;
}

export const TAX_RATE = 0.2;

/** Quantity break points: [minQty, discountRate]. */
const VOLUME_TIERS: ReadonlyArray<readonly [number, number]> = [
  [1, 0],
  [10, 0.03],
  [50, 0.06],
  [250, 0.1],
  [1000, 0.14],
  [5000, 0.18],
];

const ENGRAVING_UNIT_MINOR = 1200;
const ENGRAVING_SETUP_MINOR = 4500;

function tierRate(qty: number): number {
  let rate = 0;
  for (const [min, r] of VOLUME_TIERS) if (qty >= min) rate = r;
  return rate;
}

function roundMinor(n: number): number {
  return Math.round(n);
}

/** Stable, order-independent string hash (FNV-1a 64-bit as two 32-bit halves). */
export function fingerprint(input: string): string {
  let h1 = 0x811c9dc5;
  let h2 = 0x01000193;
  for (let i = 0; i < input.length; i++) {
    const c = input.charCodeAt(i);
    h1 ^= c;
    h1 = Math.imul(h1, 0x01000193) >>> 0;
    h2 = ((h2 << 5) + h2 + c) >>> 0;
  }
  return (h1 >>> 0).toString(16).padStart(8, '0') + (h2 >>> 0).toString(16).padStart(8, '0');
}

export function computePrice(spec: ConfigurationSpec): PriceBreakdown {
  const product = getProduct(spec.productId);
  const lines: PriceLine[] = [];
  const qty = Math.max(1, spec.quantity);

  // --- 1. Base chassis -------------------------------------------------
  lines.push({
    code: 'BASE',
    label: `${product.name} platform`,
    detail: `SKU ${product.sku} - base chassis`,
    unitMinor: product.basePriceMinor,
    amountMinor: product.basePriceMinor * qty,
    category: 'base',
  });

  // --- 2. Non-linear geometry scaling ----------------------------------
  const refVolume = product.defaultDimensions.height * product.defaultDimensions.diameter ** 2;
  const vol = spec.dimensions.height * spec.dimensions.diameter ** 2;
  const ratio = vol / refVolume;
  const geoFactor = Math.max(0.35, Math.min(3.2, ratio ** product.volumeExponent));
  const geoDelta = roundMinor(product.basePriceMinor * (geoFactor - 1));
  if (geoDelta !== 0) {
    lines.push({
      code: 'GEO',
      label: 'Custom geometry',
      detail: `${spec.dimensions.height}mm H x ${spec.dimensions.diameter}mm D - x${geoFactor.toFixed(3)} envelope factor`,
      unitMinor: geoDelta,
      amountMinor: geoDelta * qty,
      category: 'geometry',
    });
  }

  // --- 3. Per-part finishes -------------------------------------------
  const accessorySet = new Set<AccessoryId>(spec.accessories);
  for (const partId of Object.keys(PARTS) as PartId[]) {
    const def = PARTS[partId];
    const cfg = spec.parts[partId];
    if (!cfg) continue;
    if (def.requiresAccessory && !accessorySet.has(def.requiresAccessory)) continue;
    if (def.requiresAccessory && !cfg.enabled) continue;
    if (def.fixed) continue;

    const finish = FINISHES[cfg.finish];
    if (def.allowedFinishes.length && !def.allowedFinishes.includes(cfg.finish)) continue;

    const factor = finish.priceFactor;
    const unit = roundMinor(def.basePriceMinor * factor);
    lines.push({
      code: `PART-${partId.toUpperCase()}`,
      label: def.label,
      detail: `${finish.label} - ${def.description}`,
      unitMinor: unit,
      amountMinor: unit * qty,
      category: 'finish',
    });
  }

  // --- 4. Accessories ---------------------------------------------------
  for (const accId of spec.accessories) {
    const def = ACCESSORIES[accId];
    if (!def) continue;
    lines.push({
      code: `ACC-${accId.toUpperCase()}`,
      label: def.label,
      detail: def.description,
      unitMinor: def.priceMinor,
      amountMinor: def.priceMinor * qty,
      category: 'accessory',
    });
  }

  // --- 5. Engraving -----------------------------------------------------
  if (spec.engraving.enabled && spec.engraving.text.length > 0) {
    const setup = roundMinor(ENGRAVING_SETUP_MINOR * Math.sqrt(qty));
    lines.push({
      code: 'ENG-SETUP',
      label: 'Engraving setup',
      detail: `Digital tool path + first article approval (${spec.engraving.position}, ${spec.engraving.font})`,
      unitMinor: setup,
      amountMinor: setup,
      category: 'engraving',
    });
    lines.push({
      code: 'ENG-UNIT',
      label: 'Engraved units',
      detail: `"${spec.engraving.text.slice(0, 40)}" - laser mark, ${spec.engraving.position}`,
      unitMinor: ENGRAVING_UNIT_MINOR,
      amountMinor: ENGRAVING_UNIT_MINOR * qty,
      category: 'engraving',
    });
  }

  // --- 6. Volume discount ----------------------------------------------
  const unitSubtotalMinor = lines.reduce((acc, l) => acc + l.unitMinor, 0);
  const rate = tierRate(qty);
  const quantityDiscountMinor = -roundMinor(unitSubtotalMinor * qty * rate);
  if (quantityDiscountMinor !== 0) {
    lines.push({
      code: 'DISC-VOL',
      label: 'Volume discount',
      detail: `${(rate * 100).toFixed(0)}% off ${qty.toLocaleString('en-US')} unit${qty === 1 ? '' : 's'}`,
      unitMinor: roundMinor(quantityDiscountMinor / qty),
      amountMinor: quantityDiscountMinor,
      category: 'discount',
    });
  }

  const subtotalMinor = unitSubtotalMinor * qty + quantityDiscountMinor;
  const taxMinor = roundMinor(subtotalMinor * TAX_RATE);
  const totalMinor = subtotalMinor + taxMinor;

  const fingerprintSource = JSON.stringify({
    p: product.id,
    d: spec.dimensions,
    a: [...spec.accessories].sort(),
    f: Object.fromEntries(
      Object.entries(spec.parts)
        .map(([k, v]) => [k, `${v.colour}:${v.finish}:${v.enabled}`] as [string, string])
        .sort((x, y) => x[0].localeCompare(y[0])),
    ),
    e: spec.engraving,
    q: spec.quantity,
  });

  return {
    currency: product.currency,
    lines,
    unitSubtotalMinor,
    quantityDiscountMinor,
    subtotalMinor,
    taxRate: TAX_RATE,
    taxMinor,
    totalMinor,
    totalPerUnitMinor: roundMinor(totalMinor / qty),
    leadTimeDays: product.leadTimeDays + (spec.engraving.enabled ? 3 : 0),
    fingerprint: fingerprint(fingerprintSource),
  };
}

export function formatMoney(minor: number, currency = 'USD'): string {
  return new Intl.NumberFormat('en-US', {
    style: 'currency',
    currency,
  }).format(minor / 100);
}
