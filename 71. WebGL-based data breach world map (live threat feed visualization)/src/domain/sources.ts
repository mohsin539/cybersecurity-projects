/**
 * AEGIS-SENTINEL — Threat feed source catalog (architecture.md §6.1)
 */
import type { Severity, ThreatCategory } from './types'

export type TrustTier = 'T1' | 'T2' | 'T3'

export interface FeedSource {
  id: string
  name: string
  trust_tier: TrustTier
  protocol: 'taxii' | 'misp' | 'webhook' | 'grpc' | 'osint'
  verified: boolean
}

export const FEED_SOURCES: FeedSource[] = [
  { id: 'src_cisa',     name: 'CISA AIS',       trust_tier: 'T1', protocol: 'taxii',   verified: true },
  { id: 'src_misp',     name: 'MISP Community', trust_tier: 'T1', protocol: 'misp',    verified: true },
  { id: 'src_abuse',    name: 'abuse.ch',       trust_tier: 'T2', protocol: 'taxii',   verified: true },
  { id: 'src_otx',      name: 'AlienVault OTX', trust_tier: 'T2', protocol: 'taxii',   verified: true },
  { id: 'src_shodan',   name: 'Shodan Stream',  trust_tier: 'T2', protocol: 'grpc',    verified: true },
  { id: 'src_isac',     name: 'ISAC Partners',  trust_tier: 'T2', protocol: 'webhook', verified: true },
  { id: 'src_honeypot', name: 'Honeypot Mesh',  trust_tier: 'T2', protocol: 'grpc',    verified: true },
  { id: 'src_osint',    name: 'OSINT Scrapers', trust_tier: 'T3', protocol: 'osint',   verified: false },
]

export const SOURCE_BY_ID = new Map(FEED_SOURCES.map((s) => [s.id, s]))

export const CATEGORY_LABELS: Record<ThreatCategory, string> = {
  breach: 'Data Breach',
  ransomware: 'Ransomware',
  malware: 'Malware',
  phishing: 'Phishing',
  ddos: 'DDoS',
  'credential-leak': 'Credential Leak',
  zeroday: 'Zero-Day',
  intrusion: 'Intrusion',
}

export const CATEGORY_COLORS: Record<ThreatCategory, string> = {
  breach: '#ff1e56',
  ransomware: '#ff7b54',
  malware: '#ffd32a',
  phishing: '#c084fc',
  ddos: '#00f0ff',
  'credential-leak': '#ff2d95',
  zeroday: '#7d5fff',
  intrusion: '#3ae374',
}

export const SEVERITY_ORDER: Severity[] = ['low', 'medium', 'high', 'critical', 'zero-day']

export const SEVERITY_COLORS: Record<Severity, string> = {
  low: '#3ae374',
  medium: '#ffd32a',
  high: '#ff7b54',
  critical: '#ff1e56',
  'zero-day': '#c084fc',
}

/** Shape coding so severity is never color-only (WCAG 2.2, §4.6). */
export const SEVERITY_SHAPES: Record<Severity, string> = {
  low: '▲',
  medium: '●',
  high: '◆',
  critical: '★',
  'zero-day': '⬣',
}
