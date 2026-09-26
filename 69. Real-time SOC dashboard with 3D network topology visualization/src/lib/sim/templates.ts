import type { IncidentTask, IntelItem, NodeHealth, RegionState, Severity, SecurityAlert } from '../../types';

export const ANALYSTS = ['a.harper', 'm.yeung', 't.okafor', 'l.rossi', 's.vance', 'd.kruger'];

export const MITRE_CATALOG: Record<string, { name: string; tactic: string }> = {
  T1078: { name: 'Valid Accounts', tactic: 'Defense Evasion / Persistence / Privilege Escalation' },
  T1003: { name: 'OS Credential Dumping', tactic: 'Credential Access' },
  T1546: { name: 'Hijack Execution Flow', tactic: 'Persistence / Privilege Escalation' },
  T1098: { name: 'Account Manipulation', tactic: 'Persistence / Privilege Escalation' },
  'T1021.001': { name: 'Remote Services: RDP', tactic: 'Lateral Movement' },
  'T1059.001': { name: 'PowerShell', tactic: 'Execution' },
  T1110: { name: 'Brute Force', tactic: 'Credential Access' },
  T1566: { name: 'Phishing', tactic: 'Initial Access' },
  T1041: { name: 'Exfiltration Over C2', tactic: 'Exfiltration' },
  T1573: { name: 'Encrypted Channel', tactic: 'Command and Control' },
  T1190: { name: 'Exploit Public-Facing Application', tactic: 'Initial Access' },
  T1505: { name: 'Server Software Component', tactic: 'Persistence' },
  T1036: { name: 'Masquerading', tactic: 'Defense Evasion' },
  T1552: { name: 'Unsecured Credentials', tactic: 'Credential Access' },
  T1222: { name: 'File and Directory Permissions Modification', tactic: 'Defense Evasion / Privilege Escalation' },
  T1219: { name: 'Remote Access Software', tactic: 'Command and Control' },
  T1102: { name: 'Web Service', tactic: 'Command and Control' },
};

export interface AlertTemplate {
  title: string;
  description: string;
  source: string;
  mitreId: string;
  weight: number;
  baseSeg: Severity;
  assetsOf: ('user' | 'computer' | 'group' | 'domain')[];
}

export const ALERT_TEMPLATES: AlertTemplate[] = [
  {
    title: 'Suspicious New Local Admin',
    description: 'A user account was added to the local Administrators group on a workstation outside normal change windows.',
    source: 'EDR', mitreId: 'T1098', weight: 3, baseSeg: 'medium', assetsOf: ['user', 'computer'],
  },
  {
    title: 'Multiple Failed Logons (Brute Force)',
    description: 'More than 12 failed authentication attempts observed from a single source host within 5 minutes.',
    source: 'Domain Controller', mitreId: 'T1110', weight: 6, baseSeg: 'high', assetsOf: ['user'],
  },
  {
    title: 'LSASS Memory Dump Attempt',
    description: 'A process attempted to read lsass.exe memory — credential dump indicator. Requires immediate verification.',
    source: 'EDR', mitreId: 'T1003', weight: 4, baseSeg: 'critical', assetsOf: ['computer'],
  },
  {
    title: 'Oversized Egress Transfer',
    description: 'Outbound data volume from an internal host exceeded 500 MB in 10 minutes toward an unknown destination.',
    source: 'NetFlow', mitreId: 'T1041', weight: 4, baseSeg: 'high', assetsOf: ['computer', 'user'],
  },
  {
    title: 'PowerShell Encoded Command',
    description: 'Encoded PowerShell payload detected on endpoint. Review for download cradle and persistence hooks.',
    source: 'EDR', mitreId: 'T1059.001', weight: 5, baseSeg: 'high', assetsOf: ['computer'],
  },
  {
    title: 'RDP Inbound from Untrusted Geo',
    description: 'RDP connection permitted from a source country not present in the allow-list for this asset.',
    source: 'Firewall', mitreId: 'T1021.001', weight: 5, baseSeg: 'medium', assetsOf: ['computer'],
  },
  {
    title: 'Phishing URL Click Reported',
    description: 'User clicked a URL later tagged malicious by the threat-intel feed. Credential harvest template matches.',
    source: 'Mail Gateway', mitreId: 'T1566', weight: 4, baseSeg: 'high', assetsOf: ['user'],
  },
  {
    title: 'Suspicious Service Installed',
    description: 'A new Windows service was registered with an unapproved binary path on a server.',
    source: 'HIDS', mitreId: 'T1546', weight: 3, baseSeg: 'high', assetsOf: ['computer'],
  },
  {
    title: 'Pass-the-Hash Style Replay',
    description: 'NTLM authentication replayed from an anomalous relay target across trust boundary.',
    source: 'SIEM', mitreId: 'T1003', weight: 3, baseSeg: 'high', assetsOf: ['user', 'computer'],
  },
  {
    title: 'TOR Exit Node HTTPS Egress',
    description: 'Long-lived TLS channel to a known TOR exit node observed from an internal asset.',
    source: 'Firewall', mitreId: 'T1573', weight: 4, baseSeg: 'medium', assetsOf: ['computer'],
  },
  {
    title: 'Web Vulnerability Probe',
    description: 'Web application firewall flagged repetitive path traversal / SQLi signatures against the public tier.',
    source: 'WAF', mitreId: 'T1190', weight: 5, baseSeg: 'medium', assetsOf: ['computer'],
  },
  {
    title: 'Group Membership Change — Privileged Group',
    description: 'A member added to a highly privileged domain group outside change management.',
    source: 'Domain Controller', mitreId: 'T1098', weight: 3, baseSeg: 'critical', assetsOf: ['group', 'user'],
  },
  {
    title: 'Unknown Scheduled Task Persistence',
    description: 'A scheduled task was created with a payload hosted on a mismatch domain on an endpoint.',
    source: 'EDR', mitreId: 'T1505', weight: 3, baseSeg: 'medium', assetsOf: ['computer'],
  },
  {
    title: 'Shadow Credentials Added',
    description: 'Key credential-like attribute (msDS-KeyCredentialLink) modified on a user object.',
    source: 'Domain Controller', mitreId: 'T1098', weight: 3, baseSeg: 'high', assetsOf: ['user'],
  },
  {
    title: 'DNS Tunneling Anomaly',
    description: 'Subdomain query entropy and volume anomaly suggests data exfiltration over DNS.',
    source: 'NetFlow', mitreId: 'T1041', weight: 3, baseSeg: 'medium', assetsOf: ['computer'],
  },
];

export const SEVERITY_SLA_MIN: Record<Severity, number> = {
  critical: 5,
  high: 30,
  medium: 240,
  low: 1440,
  info: 1440,
};

export const INTEL_TEMPLATES: Omit<IntelItem, 'id' | 'publishedAt'>[] = [
  {
    type: 'vulnerability', title: 'CVE-2026-11842 — IIS 10 RCE Flaw Actively Exploited', description: 'Public-facing IIS servers vulnerable to an unauthenticated remote heap overflow. Chains with T1059 post-exploitation.', source: 'NVD + N-able Research', sourceTrust: 5, confidence: 0.92, ttps: ['T1190', 'T1059.001'], iocs: ['exploit#0x2af', 'shell.aspx', 'c2.noordgate[.]net'], tags: ['iis', 'rce', 'webshell'], cve: 'CVE-2026-11842',
  },
  {
    type: 'malware', title: 'Backdoor.QuietDawn — NHI Campaign Variant', description: 'Loader abuses signed drivers to disable EDR before deploying in-memory C2. Common in medium enterprises.', source: 'MISP feed #12', sourceTrust: 4, confidence: 0.81, ttps: ['T1546', 'T1219'], iocs: ['912e7c2b4d1a0f5b8c8d7e6f5a4b3c2d', 'quarantine.svc-updater.local', 'hxxps://cdn-sync[.]top'], tags: ['loader', 'edr-bypass', 'nhc'],
  },
  {
    type: 'actor', title: 'UNC-70K — Financial Theft Cluster', description: 'Borrowed from prior campaign tooling. Pivots to SQL servers. Active this quarter across banking verticals.', source: 'Mandiant SC', sourceTrust: 5, confidence: 0.88, ttps: ['T1110', 'T1003', 'T1505'], iocs: ['172.16.90.44', 'sqlupd.exe', 'mimikatz.ps1'], tags: ['financetarget', 'sql', 'ranch'],
  },
  {
    type: 'campaign', title: 'Overt-Push Phishing Wave (HR Lures)', description: 'HR-themed malicious .docx with CVE-2026-11842 attachment or OLE link out to decoy portal. Targets finance & HR.', source: 'SANS ISC', sourceTrust: 4, confidence: 0.74, ttps: ['T1566', 'T1190'], iocs: ['bonus-quotafin[.]com', 'benefits_2026.docm'], tags: ['phish', 'hr', 'mht'],
  },
  {
    type: 'indicator', title: 'Infrastructure Blocklist Update', description: 'Refresh of known C2 and banking trojan infrastructure. High confidence IP/domain blocklist for firewall enforcement.', source: 'AlienVault OTX', sourceTrust: 3, confidence: 0.95, ttps: ['T1573', 'T1102'], iocs: ['198.51.100.24', '198.51.100.77', 'update-sysmon[.]io'], tags: ['blocklist', 'c2'],
  },
  {
    type: 'vulnerability', title: 'CVE-2026-00821 — SQL Server Agent Privilege Bypass', description: 'Low-privilege authenticated user can execute agent jobs as service account on unpatched instances.', source: 'Tenable', sourceTrust: 4, confidence: 0.86, ttps: ['T1546', 'T1552'], iocs: ['sqagent_bin'], tags: ['sql', 'privesc'], cve: 'CVE-2026-00821',
  },
  {
    type: 'malware', title: 'RansomLib — Gaggle Variant with Cred Dump Stage', description: 'Drops credential dumpers pre-encryption. Uses scheduled task persistence and volume shadow copy deletion.', source: 'CrowdStrike Intel', sourceTrust: 5, confidence: 0.9, ttps: ['T1003', 'T1505', 'T1036'], iocs: ['ransomlib.exe', 'vssadmin.exe', 'gaggle_cerber.pdb'], tags: ['ransomware', 'scheduled-task'],
  },
  {
    type: 'actor', title: 'Midnight Cascade — OT-adjacent Access Broker', description: 'Sells access to firms preceding extortion. Favors VPN credential stuffing and RDP tunnel persistence.', source: 'Flashpoint', sourceTrust: 4, confidence: 0.78, ttps: ['T1110', 'T1021.001'], iocs: ['vpngate-x[.]net', '85.31.x.x block'], tags: ['broker', 'vpn', 'rdp'],
  },
];

export const INCIDENT_TITLES = [
  'Suspected Credential Dumping on Domain Tier',
  'Ransomware Precursor — Lateral Movement Spike',
  'Phishing Wave Targeting Finance Mailboxes',
  'Privileged Group Escalation — Account Ops',
  'Public Web Tier Probing / WAF Evasion',
  'Data Exfiltration Candidate — Bulk Egress',
];

export const INCIDENT_TASK_TEMPLATES = [
  'Identify patient-zero asset and time window',
  'Isolate affected endpoints from network',
  'Collect forensic evidence bundle (SHA-256)',
  'Reset credentials of impacted accounts',
  'Review permissions and remove unauthorized grants',
  'Block indicators on firewall / EDR / DNS',
  'Correlate with threat-intel feed indicators',
  'Patch/update detection rules to stop recurrence',
  'Postmortem write-up and SLA compliance check',
];

export const INCIDENT_EVIDENCE = [
  'capture-100293.pcap',
  'lsass_dump_triage.md',
  '4688-process-list.csv',
  'mailbox_export_0709.pst',
  'netflow_egress_0709.csv',
  'registry-persistence-export.json',
];

export const REGIONS: Omit<RegionState, 'status'>[] = [
  { id: 'na-east', label: 'NA · East', sensors: 42, online: 42, impact: 0, x: 26, y: 34 },
  { id: 'na-west', label: 'NA · West', sensors: 37, online: 37, impact: 0, x: 16, y: 42 },
  { id: 'eu-central', label: 'EU · Central', sensors: 31, online: 31, impact: 0, x: 50, y: 36 },
  { id: 'eu-west', label: 'EU · West', sensors: 26, online: 25, impact: 0, x: 44, y: 41 },
  { id: 'apac', label: 'APAC Hub', sensors: 44, online: 44, impact: 0, x: 76, y: 44 },
  { id: 'latam', label: 'LATAM', sensors: 18, online: 18, impact: 0, x: 30, y: 62 },
  { id: 'meaf', label: 'ME · Africa', sensors: 22, online: 22, impact: 0, x: 56, y: 55 },
  { id: 'cloud-aws', label: 'Cloud · AWS', sensors: 58, online: 58, impact: 0, x: 36, y: 22 },
  { id: 'cloud-azure', label: 'Cloud · Azure', sensors: 52, online: 52, impact: 0, x: 48, y: 20 },
  { id: 'cloud-gcp', label: 'Cloud · GCP', sensors: 30, online: 30, impact: 0, x: 64, y: 18 },
];

export const HEALTH_LABEL: Record<NodeHealth, string> = {
  healthy: 'Healthy',
  warning: 'Warning',
  critical: 'Critical',
  offline: 'Offline',
  investigation: 'Investigation',
  quarantined: 'Quarantined',
};

export function ticksFor(ts: number, count: number): number[] {
  const out: number[] = [];
  for (let i = 0; i < count; i++) out.push(ts - i * 60_000);
  return out;
}

export function makeTasks(ids: number[]): IncidentTask[] {
  return INCIDENT_TASK_TEMPLATES.slice(0, 4 + (ids[0] ?? 0) % 5).map((title, i) => ({
    id: `TK-${ids[0]}-${i}`,
    title,
    done: i < 2,
  }));
}

export function defaultAlertSummary(a: SecurityAlert): string {
  return `${a.title} — ${a.mitreId} · ${a.source}`;
}