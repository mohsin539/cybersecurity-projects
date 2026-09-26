/**
 * Catalog metadata for the PrismForge configurable product.
 *
 * Finish definitions carry the physically-based rendering (PBR) parameters used
 * by the WebGL material so that the rendered preview is deterministic and
 * matches the generated spec sheet / report.
 */

import type { AccessoryId, FinishId, PartId } from './constants.js';

export interface PbrParams {
  roughness: number;
  metalness: number;
  /** 0 = opaque, 1 = fully transmissive (glass). */
  transmission: number;
  clearcoat: number;
  clearcoatRoughness: number;
  /** Emissive intensity, used for the LED ring. */
  emissiveIntensity: number;
  /** Emissive colour is taken from the part colour for luminous parts. */
}

export interface FinishDef {
  id: FinishId;
  label: string;
  description: string;
  /** Premium multiplier applied to the part base price. */
  priceFactor: number;
  pbr: PbrParams;
  /** Tailwind-ish hex used for the UI chip. */
  chip: string;
}

export const FINISHES: Record<FinishId, FinishDef> = {
  matte: {
    id: 'matte',
    label: 'Soft-touch Matte',
    description: 'Anti-fingerprint, low-glare coating. The everyday choice.',
    priceFactor: 1.0,
    chip: '#94a3b8',
    pbr: { roughness: 0.85, metalness: 0.02, transmission: 0, clearcoat: 0.05, clearcoatRoughness: 0.9, emissiveIntensity: 0 },
  },
  satin: {
    id: 'satin',
    label: 'Satin Sheen',
    description: 'Balanced soft highlight with a premium feel.',
    priceFactor: 1.08,
    chip: '#cbd5e1',
    pbr: { roughness: 0.45, metalness: 0.05, transmission: 0, clearcoat: 0.25, clearcoatRoughness: 0.5, emissiveIntensity: 0 },
  },
  gloss: {
    id: 'gloss',
    label: 'High Gloss Lacquer',
    description: 'Deep mirror-like lacquer, 4-coat polished.',
    priceFactor: 1.22,
    chip: '#e2e8f0',
    pbr: { roughness: 0.08, metalness: 0.08, transmission: 0, clearcoat: 1, clearcoatRoughness: 0.04, emissiveIntensity: 0 },
  },
  brushedMetal: {
    id: 'brushedMetal',
    label: 'Brushed Aluminium',
    description: 'Directional brushed grain, anodised clear coat.',
    priceFactor: 1.45,
    chip: '#a8b0bd',
    pbr: { roughness: 0.32, metalness: 0.92, transmission: 0, clearcoat: 0.1, clearcoatRoughness: 0.4, emissiveIntensity: 0 },
  },
  polishedMetal: {
    id: 'polishedMetal',
    label: 'Polished Chrome',
    description: 'Mirror-polished stainless steel trim.',
    priceFactor: 1.6,
    chip: '#e5e7eb',
    pbr: { roughness: 0.05, metalness: 1, transmission: 0, clearcoat: 0.6, clearcoatRoughness: 0.05, emissiveIntensity: 0 },
  },
  anodized: {
    id: 'anodized',
    label: 'Colour Anodised',
    description: 'Hard-anodised aluminium with rich, saturated dye.',
    priceFactor: 1.35,
    chip: '#7dd3fc',
    pbr: { roughness: 0.3, metalness: 0.75, transmission: 0, clearcoat: 0.3, clearcoatRoughness: 0.25, emissiveIntensity: 0 },
  },
  carbonWeave: {
    id: 'carbonWeave',
    label: 'Carbon Weave',
    description: '2x2 twill prepreg composite under clear lacquer.',
    priceFactor: 1.85,
    chip: '#334155',
    pbr: { roughness: 0.28, metalness: 0.35, transmission: 0, clearcoat: 0.9, clearcoatRoughness: 0.1, emissiveIntensity: 0 },
  },
  translucent: {
    id: 'translucent',
    label: 'Translucent Frost',
    description: 'Light-diffusing polycarbonate, RGB ready.',
    priceFactor: 1.5,
    chip: '#67e8f9',
    pbr: { roughness: 0.35, metalness: 0, transmission: 0.82, clearcoat: 0.4, clearcoatRoughness: 0.2, emissiveIntensity: 0.25 },
  },
  rubberized: {
    id: 'rubberized',
    label: 'Grip Rubber',
    description: 'TPE over-mould, high friction, outdoor rated.',
    priceFactor: 1.15,
    chip: '#475569',
    pbr: { roughness: 0.95, metalness: 0, transmission: 0, clearcoat: 0, clearcoatRoughness: 1, emissiveIntensity: 0 },
  },
};

export const FINISH_LIST: FinishDef[] = Object.values(FINISHES);

export interface PartDef {
  id: PartId;
  label: string;
  /** Human description used in reports. */
  description: string;
  /** Which accessory (if any) gates visibility. Null = always visible. */
  requiresAccessory: AccessoryId | null;
  /** Parts that emit light (their colour drives the emissive channel). */
  luminous: boolean;
  /** Default finish on a fresh configuration. */
  defaultFinish: FinishId;
  /** Allowed finishes; empty = all. */
  allowedFinishes: FinishId[];
  /** Unit price contribution in minor units (pence/cents). */
  basePriceMinor: number;
  /** Non-configurable reference part. */
  fixed: boolean;
}

export const PARTS: Record<PartId, PartDef> = {
  body: {
    id: 'body',
    label: 'Main Body',
    description: 'Primary monocoque shell.',
    requiresAccessory: null,
    luminous: false,
    defaultFinish: 'satin',
    allowedFinishes: [],
    basePriceMinor: 8900,
    fixed: false,
  },
  grille: {
    id: 'grille',
    label: 'Acoustic Grille',
    description: 'Perforated driver grille.',
    requiresAccessory: null,
    luminous: false,
    defaultFinish: 'matte',
    allowedFinishes: ['matte', 'brushedMetal', 'polishedMetal', 'carbonWeave'],
    basePriceMinor: 2400,
    fixed: false,
  },
  cap: {
    id: 'cap',
    label: 'Control Cap',
    description: 'Top control deck with sealed buttons.',
    requiresAccessory: 'cap',
    luminous: false,
    defaultFinish: 'brushedMetal',
    allowedFinishes: [],
    basePriceMinor: 3200,
    fixed: false,
  },
  ring: {
    id: 'ring',
    label: 'Light Ring',
    description: '360 degree RGB status ring.',
    requiresAccessory: 'ringLight',
    luminous: true,
    defaultFinish: 'gloss',
    allowedFinishes: ['gloss', 'matte', 'anodized', 'translucent'],
    basePriceMinor: 1800,
    fixed: false,
  },
  base: {
    id: 'base',
    label: 'Base Plate',
    description: 'Weighted, vibration-isolating base.',
    requiresAccessory: null,
    luminous: false,
    defaultFinish: 'rubberized',
    allowedFinishes: ['rubberized', 'brushedMetal', 'anodized', 'carbonWeave', 'matte'],
    basePriceMinor: 3100,
    fixed: false,
  },
  buttons: {
    id: 'buttons',
    label: 'Key Pad',
    description: 'Tactile silicone key set.',
    requiresAccessory: null,
    luminous: false,
    defaultFinish: 'rubberized',
    allowedFinishes: ['rubberized', 'matte', 'anodized', 'polishedMetal'],
    basePriceMinor: 900,
    fixed: false,
  },
  strap: {
    id: 'strap',
    label: 'Carry Strap',
    description: 'Braided shoulder strap.',
    requiresAccessory: 'strap',
    luminous: false,
    defaultFinish: 'rubberized',
    allowedFinishes: ['rubberized', 'matte', 'satin'],
    basePriceMinor: 1500,
    fixed: false,
  },
};

export const PART_LIST: PartDef[] = Object.values(PARTS);

export interface AccessoryDef {
  id: AccessoryId;
  label: string;
  description: string;
  priceMinor: number;
  defaultEnabled: boolean;
  icon: string;
}

export const ACCESSORIES: Record<AccessoryId, AccessoryDef> = {
  cap: {
    id: 'cap',
    label: 'Control Cap',
    description: 'Adds the sealed top control deck.',
    priceMinor: 1900,
    defaultEnabled: true,
    icon: 'disc',
  },
  ringLight: {
    id: 'ringLight',
    label: 'RGB Light Ring',
    description: 'Adds the 360 status ring with 16M colour.',
    priceMinor: 1500,
    defaultEnabled: true,
    icon: 'sparkles',
  },
  strap: {
    id: 'strap',
    label: 'Carry Strap',
    description: 'Adds a braided shoulder strap and lug.',
    priceMinor: 1200,
    defaultEnabled: false,
    icon: 'anchor',
  },
  handle: {
    id: 'handle',
    label: 'Top Handle',
    description: 'Adds a rigid carry handle.',
    priceMinor: 2100,
    defaultEnabled: false,
    icon: 'grip',
  },
  stand: {
    id: 'stand',
    label: 'Desk Stand',
    description: 'Adds a folding aluminium desk stand.',
    priceMinor: 1750,
    defaultEnabled: true,
    icon: 'layout',
  },
};

export const ACCESSORY_LIST: AccessoryDef[] = Object.values(ACCESSORIES);

export interface SwatchDef {
  name: string;
  hex: string;
  group: 'core' | 'vivid' | 'earth' | 'mono';
}

export const SWATCHES: SwatchDef[] = [
  { name: 'Obsidian', hex: '#0f172a', group: 'mono' },
  { name: 'Graphite', hex: '#334155', group: 'mono' },
  { name: 'Porcelain', hex: '#f1f5f9', group: 'mono' },
  { name: 'Platinum', hex: '#cbd5e1', group: 'mono' },
  { name: 'Solar Flare', hex: '#f97316', group: 'vivid' },
  { name: 'Ember', hex: '#ef4444', group: 'vivid' },
  { name: 'Rose Quartz', hex: '#fb7185', group: 'vivid' },
  { name: 'Fuchsia Storm', hex: '#d946ef', group: 'vivid' },
  { name: 'Ultraviolet', hex: '#8b5cf6', group: 'vivid' },
  { name: 'Electric Sky', hex: '#38bdf8', group: 'vivid' },
  { name: 'Cyber Lime', hex: '#a3e635', group: 'vivid' },
  { name: 'Aurora Teal', hex: '#2dd4bf', group: 'core' },
  { name: 'Pool', hex: '#06b6d4', group: 'core' },
  { name: 'Indigo Ink', hex: '#4f46e5', group: 'core' },
  { name: 'Deep Sea', hex: '#1e3a8a', group: 'core' },
  { name: 'Forest', hex: '#16a34a', group: 'earth' },
  { name: 'Moss', hex: '#65a30d', group: 'earth' },
  { name: 'Clay', hex: '#b45309', group: 'earth' },
  { name: 'Sand', hex: '#d6b98c', group: 'earth' },
  { name: 'Crimson Gold', hex: '#f59e0b', group: 'vivid' },
];

export interface ProductDef {
  id: string;
  sku: string;
  name: string;
  tagline: string;
  description: string;
  currency: string;
  /** Base chassis cost in minor units, before options. */
  basePriceMinor: number;
  /** Default bounding envelope in millimetres (height, diameter, depth). */
  defaultDimensions: { height: number; diameter: number };
  minDimensions: { height: number; diameter: number };
  maxDimensions: { height: number; diameter: number };
  /** Volume multiplier is deliberately non-linear: cost scales super-linearly. */
  volumeExponent: number;
  minOrderQty: number;
  leadTimeDays: number;
  /** Manufacturing/assembly site shown on the spec sheet. */
  origin: string;
}

export const PRODUCTS: Record<string, ProductDef> = {
  'prismforge-one': {
    id: 'prismforge-one',
    sku: 'PF-ONE-2024',
    name: 'PrismForge One',
    tagline: 'Modular spatial speaker',
    description:
      'A monocoque portable speaker engineered for modularity. Every visible surface, module and engraving is configurable, and every configuration is a signed, auditable record.',
    currency: 'USD',
    basePriceMinor: 19900,
    defaultDimensions: { height: 220, diameter: 96 },
    minDimensions: { height: 140, diameter: 70 },
    maxDimensions: { height: 400, diameter: 180 },
    volumeExponent: 1.35,
    minOrderQty: 1,
    leadTimeDays: 12,
    origin: 'Rotterdam, NL',
  },
};

export const DEFAULT_PRODUCT_ID = 'prismforge-one';

export function getProduct(id: string): ProductDef {
  return PRODUCTS[id] ?? PRODUCTS[DEFAULT_PRODUCT_ID]!;
}

/** Tailwind-safe hex -> linear RGB triple for three.js colour handling. */
export function hexToRgb(hex: string): { r: number; g: number; b: number } {
  const clean = hex.replace('#', '');
  const full =
    clean.length === 3
      ? clean
          .split('')
          .map((c) => c + c)
          .join('')
      : clean;
  const int = Number.parseInt(full, 16);
  return {
    r: ((int >> 16) & 255) / 255,
    g: ((int >> 8) & 255) / 255,
    b: (int & 255) / 255,
  };
}

/** Perceived luminance, used to auto-pick readable UI text colour over a swatch. */
export function luminance(hex: string): number {
  const { r, g, b } = hexToRgb(hex);
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}

export function contrastText(hex: string): string {
  return luminance(hex) > 0.55 ? '#0f172a' : '#f8fafc';
}
