/**
 * AEGIS-SENTINEL — Domain model (architecture.md §8.2)
 *
 * The canonical ThreatEvent wire format every stage of the pipeline
 * (ingest → normalize → enrich → score → publish) operates on.
 */

export type Severity = 'low' | 'medium' | 'high' | 'critical' | 'zero-day'

export type ThreatCategory =
  | 'breach'
  | 'ransomware'
  | 'malware'
  | 'phishing'
  | 'ddos'
  | 'credential-leak'
  | 'zeroday'
  | 'intrusion'

export type IocType = 'ip' | 'domain' | 'sha256' | 'url' | 'email'

export interface Indicator {
  type: IocType
  value: string
  confidence: 'low' | 'medium' | 'high'
}

export interface GeoPoint {
  lat: number
  lon: number
  country: string
  asn?: number
}

export interface ThreatEvent {
  event_id: string
  stix_id: string
  title: string
  category: ThreatCategory
  severity: Severity
  risk_score: number // 0-100
  geo: { src: GeoPoint; dst: GeoPoint }
  impact: { records: number; pii_classes: string[] }
  techniques: string[] // MITRE ATT&CK ids
  indicators: Indicator[]
  sources: { source_id: string; trust_tier: 'T1' | 'T2' | 'T3'; first_seen: string }[]
  occurred_at: string // ISO 8601
  ingested_at: string
  content_hash: string
  audit_seq?: number
}

/** A viewport/mutator applied to the live threat stream (client-side policy). */
export interface ThreatFilter {
  severities: Severity[]
  categories: ThreatCategory[]
  minRisk: number
  sources: string[]
  windowMinutes: number
}
