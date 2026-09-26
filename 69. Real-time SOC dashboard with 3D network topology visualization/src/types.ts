export type NodeKind = 'user' | 'computer' | 'group' | 'domain';

export type NodeHealth = 'healthy' | 'warning' | 'critical' | 'offline' | 'investigation' | 'quarantined';

export interface BHNode {
  id: string;
  name: string;
  label: string;
  kind: NodeKind;
  owned: boolean;
  highValue: boolean;
  enabled: boolean;
  domain: string;
  dept?: string;
  os?: string;
  description?: string;
  health?: NodeHealth;
}

export type EdgeType =
  | 'Owns'
  | 'MemberOf'
  | 'HasSession'
  | 'AdminTo'
  | 'GenericAll'
  | 'GenericWrite'
  | 'WriteDacl'
  | 'AllExtendedRights'
  | 'ForceChangePassword'
  | 'AddMember'
  | 'CanRDP';

export const EDGE_TYPES: EdgeType[] = [
  'Owns',
  'MemberOf',
  'HasSession',
  'AdminTo',
  'GenericAll',
  'GenericWrite',
  'WriteDacl',
  'AllExtendedRights',
  'ForceChangePassword',
  'AddMember',
  'CanRDP',
];

export interface BHEdge {
  id: string;
  source: string;
  target: string;
  type: EdgeType;
}

export interface Vec3 {
  x: number;
  y: number;
  z: number;
}

export interface GraphModel {
  nodes: BHNode[];
  edges: BHEdge[];
  positions: Record<string, Vec3>;
}

export interface PathHop {
  edge: BHEdge;
  from: BHNode;
  to: BHNode;
}

export interface AttackPath {
  hops: PathHop[];
  totalHops: number;
  fromOwned: boolean;
}

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type AlertStatus = 'new' | 'triaging' | 'escalated' | 'dismissed' | 'incident' | 'closed';

export interface SecurityAlert {
  id: string;
  ts: number;
  severity: Severity;
  title: string;
  description: string;
  source: string;
  mitreId: string;
  mitreName: string;
  assets: string[];
  technique: string;
  status: AlertStatus;
  assignee?: string;
  slaMinutes: number;
  raw?: string;
}

export type IncidentStatus = 'new' | 'investigating' | 'contained' | 'eradicated' | 'recovered' | 'closed';

export interface IncidentTask {
  id: string;
  title: string;
  done: boolean;
}

export interface IncidentEvent {
  ts: number;
  actor: string;
  action: string;
  note?: string;
}

export interface Incident {
  id: string;
  title: string;
  severity: Severity;
  status: IncidentStatus;
  description: string;
  createdAt: number;
  owner: string;
  alertIds: string[];
  assets: string[];
  tasks: IncidentTask[];
  events: IncidentEvent[];
  evidence: string[];
  notes: string;
}

export type IntelType = 'vulnerability' | 'malware' | 'actor' | 'campaign' | 'indicator';

export interface IntelItem {
  id: string;
  publishedAt: number;
  type: IntelType;
  title: string;
  description: string;
  confidence: number;
  source: string;
  sourceTrust: number;
  ttps: string[];
  iocs: string[];
  tags: string[];
  cve?: string;
}

export interface RegionState {
  id: string;
  label: string;
  sensors: number;
  online: number;
  status: NodeHealth;
  impact: number;
  x: number;
  y: number;
}

export interface StreamLine {
  id: string;
  ts: number;
  level: Severity;
  text: string;
  module: SocModule;
}

export type SocModule = 'topology' | 'blanket' | 'alerts' | 'incidents' | 'query' | 'intel' | 'compliance';

export interface SocMetrics {
  eps: number;
  alertRate: number;
  exposure: number;
  coverage: number;
  mtb?: number;
  mttr?: number;
}

export interface LogEntry {
  id: string;
  ts: number;
  source: string;
  host: string;
  user: string;
  eventId: string;
  message: string;
  severity: Severity;
  mitreId?: string;
}

export interface SocState {
  alerts: SecurityAlert[];
  incidents: Incident[];
  intel: IntelItem[];
  nodeHealth: Record<string, NodeHealth>;
  stream: StreamLine[];
  metrics: SocMetrics;
  epsHistory: number[];
  alertRateHistory: number[];
  regions: Record<string, RegionState>;
  trafficEdges: string[];
  logs: LogEntry[];
}