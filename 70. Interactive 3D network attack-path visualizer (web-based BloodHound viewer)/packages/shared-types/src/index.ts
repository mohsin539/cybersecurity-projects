export type NodeType =
  | 'User'
  | 'Group'
  | 'Computer'
  | 'Domain'
  | 'OU'
  | 'Container'
  | 'GPO'
  | 'AzureUser'
  | 'AzureGroup'
  | 'AzureDevice'
  | 'ServicePrincipal'
  | 'ForeignPrincipal';

/**
 * AoD node model. Mirrors BloodHound semantics with added risk metadata
 * used by the 3D renderer for color/glow calibration.
 */
export interface GraphNode {
  id: string;
  type: NodeType;
  name: string;
  tenantId: string;
  domainSid?: string;
  enabled?: boolean;
  tier0?: boolean;
  owner?: string;
  riskScore?: number;
  tier?: number;
  properties: Record<string, unknown>;
  props?: Record<string, unknown>;
}

export type EdgeType =
  | 'MemberOf'
  | 'HasSession'
  | 'AdminTo'
  | 'GenericAll'
  | 'GenericWrite'
  | 'WriteDacl'
  | 'WriteOwner'
  | 'ForceChangePassword'
  | 'AddMember'
  | 'AddSelf'
  | 'CanRDP'
  | 'CanPSRemote'
  | 'AllowedToDelegate'
  | 'Owns'
  | 'GPLink'
  | 'AddKeyCredentialLink'
  | 'Contains';

export interface GraphEdge {
  id: string;
  type: EdgeType;
  source: string;
  target: string;
  tenantId: string;
  weight?: number;
  techniqueIds?: string[];
  properties: Record<string, unknown>;
}

export interface GraphSnapshot {
  graphVersion: string;
  collectedAt: string;
  sourceSystem: 'sharp-hound' | 'azure-hound' | 'api';
  tenantId: string;
  nodes: GraphNode[];
  edges: GraphEdge[];
}

export type PathJobStatus = 'queued' | 'running' | 'complete' | 'failed' | 'cancelled';

export interface PathRequest {
  jobId: string;
  source: string;
  target: string;
  k?: number;
  maxDepth?: number;
  filters?: {
    edgeTypes?: EdgeType[];
    maxRiskWeight?: number;
    includeRemediated?: boolean;
  };
}

export interface PathStep {
  explainable: string;
  edgeId: string;
  from: string;
  to: string;
  edgeType: EdgeType;
  weight: number;
  techniqueIds: string[];
  remediation: string;
}

export interface AttackPath {
  pathId: string;
  steps: PathStep[];
  totalWeight: number;
  length: number;
  tier0Reached: boolean;
}

export interface PathJobResult {
  jobId: string;
  status: PathJobStatus;
  source: string;
  target: string;
  paths: AttackPath[];
  computedAt: string;
  graphVersion: string;
  executionMs: number;
}

/** Minimal canonical audit event (append-only, hash-chained). */
export interface AuditEvent {
  eventId: string;
  ts: string;
  actor: string;
  role: string;
  action: string;
  objectType: string;
  objectId: string;
  tenantId: string;
  ip: string;
  userAgent: string;
  mfa: boolean;
  prevHash: string;
  hash: string;
  meta: Record<string, unknown>;
}

export interface AuthContext {
  subject: string;
  role: 'Viewer' | 'Analyst' | 'Auditor' | 'Admin';
  tenantIds: string[];
  ous: string[];
  sensitivity: 'public' | 'internal' | 'confidential' | 'restricted';
}

export interface AbacDecisionRequest {
  subject: string;
  action: string;
  resource: string;
  resourceType: string;
  tenantId: string;
  sensitivity: string;
}

export interface AbacDecision {
  allowed: boolean;
  reason: string;
}

export interface ReportManifest {
  reportId: string;
  reportType: string;
  params: Record<string, unknown>;
  graphVersion: string;
  authorId: string;
  approverId?: string;
  classification: 'public' | 'internal' | 'confidential' | 'restricted';
  artifactUrl?: string;
  sha256?: string;
  retentionUntil?: string;
  auditRef?: string;
}