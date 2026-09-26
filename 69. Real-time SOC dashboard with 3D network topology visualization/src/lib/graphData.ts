import type { BHEdge, BHNode, EdgeType, Vec3 } from '../types';
import { mulberry32, randInt } from './rng';

const DOMAIN = 'CORP.LOCAL';
const RNG_SEED = 0x5eed00d;

export const TARGET_NODE_ID = 'GROUP-DOMAIN ADMINS';

const FIRST = [
  'john', 'jane', 'mike', 'sarah', 'david', 'emily', 'chris', 'laura', 'james', 'amy',
  'robert', 'lisa', 'daniel', 'karen', 'matthew', 'nancy', 'kevin', 'sandra', 'brian', 'patricia',
  'jason', 'helen', 'eric', 'donna', 'scott', 'maria', 'mark', 'linda', 'steve', 'betty',
  'alex', 'olivia', 'nina', 'omar', 'priya', 'chen', 'rafael', 'ingrid', 'tom', 'grace',
];

const SURNAMES = [
  'cooper', 'mitchell', 'brooks', 'hayes', 'foster', 'coleman', 'bennett', 'sullivan',
  'parker', 'henderson', 'rogers', 'stewart', 'graham', 'walsh', 'quinn', 'madison',
  'keller', 'ramirez', 'gomez', 'navarro', 'liu', 'zhang', 'patel', 'singh', 'silva',
  'kumar', 'ahmed', 'novak', 'petrov', 'williams', 'brown', 'taylor', 'adams', 'nelson',
];

const WORKSTATIONS: string[] = [];
for (let i = 1; i <= 48; i++) {
  WORKSTATIONS.push(`CORP-WS-${String(i).padStart(3, '0')}`);
}

const SERVERS = [
  'CORP-DC01',
  'CORP-DC02',
  'CORP-SQL01',
  'CORP-WEB01',
  'CORP-FILE01',
  'CORP-APP01',
  'CORP-MAIL01',
  'CORP-BACKUP01',
  'CORP-ITSRV01',
  'CORP-VAULT01',
];

export const COMPUTERS: string[] = [...SERVERS, ...WORKSTATIONS];

const DEPT_GROUP: Record<string, string> = {
  finance: 'FINANCE',
  hr: 'HR',
  sales: 'SALES',
  eng: 'ENGINEERING',
  it: 'IT SUPPORT',
};

const GROUPS = [
  { id: 'DOMAIN ADMINS', dept: 'core' },
  { id: 'ENTERPRISE ADMINS', dept: 'core' },
  { id: 'SERVER ADMINS', dept: 'it' },
  { id: 'IT SUPPORT', dept: 'it' },
  { id: 'ACCOUNT OPERATORS', dept: 'it' },
  { id: 'FINANCE', dept: 'finance' },
  { id: 'HR', dept: 'hr' },
  { id: 'SALES', dept: 'sales' },
  { id: 'ENGINEERING', dept: 'eng' },
  { id: 'DOMAIN USERS', dept: 'all' },
];

let edgeSeq = 0;
const edgeId = (_s: string, _t: string, type: EdgeType) => `E-${edgeSeq++}-${type}`;

interface GenResult {
  nodes: BHNode[];
  edges: BHEdge[];
  positions: Record<string, Vec3>;
}

function nodeId(kind: string, name: string) {
  return `${kind.toUpperCase()}-${name}`;
}

export function generateBloodHoundGraph(): GenResult {
  const rng = mulberry32(RNG_SEED);
  edgeSeq = 0;

  const nodes: BHNode[] = [];
  const edges: BHEdge[] = [];

  const mkNode = (
    kind: BHNode['kind'],
    name: string,
    extra: Partial<BHNode> = {},
  ): BHNode => {
    const n: BHNode = {
      id: nodeId(kind, name),
      name,
      label: name,
      kind,
      owned: false,
      highValue: false,
      enabled: true,
      domain: DOMAIN,
      health: 'healthy',
      ...extra,
    } as BHNode;
    nodes.push(n);
    return n;
  };

  // ---- Domains ----
  mkNode('domain', DOMAIN, {
    description: 'Active Directory domain. Compromise of a Domain Controller yields the domain.',
  });

  // ---- Groups ----
  const groupNodes = new Map<string, BHNode>();
  for (const g of GROUPS) {
    groupNodes.set(
      g.id,
      mkNode('group', g.id, {
        highValue: g.id === 'DOMAIN ADMINS',
        dept: g.dept,
        description:
          g.id === 'DOMAIN ADMINS'
            ? 'HIGH VALUE TARGET. Full administrative control over the entire CORP.LOCAL domain. Reaching this group grants domain compromise.'
            : g.id === 'ENTERPRISE ADMINS'
              ? 'High value target. Enterprise-wide administrative control across all AD forests.'
              : 'Active Directory security group.',
      }),
    );
  }
  const DA = groupNodes.get('DOMAIN ADMINS')!;
  const EA = groupNodes.get('ENTERPRISE ADMINS')!;
  const SERVER_ADMINS = groupNodes.get('SERVER ADMINS')!;
  const IT_SUPPORT = groupNodes.get('IT SUPPORT')!;
  const ACCOUNT_OPS = groupNodes.get('ACCOUNT OPERATORS')!;
  const DOMAIN_USERS = groupNodes.get('DOMAIN USERS')!;

  // nested group membership
  edges.push({ id: edgeId(SERVER_ADMINS.id, groupNodes.get('DOMAIN USERS')!.id, 'MemberOf'), source: SERVER_ADMINS.id, target: DOMAIN_USERS.id, type: 'MemberOf' });
  edges.push({ id: edgeId(IT_SUPPORT.id, SERVER_ADMINS.id, 'MemberOf'), source: IT_SUPPORT.id, target: SERVER_ADMINS.id, type: 'MemberOf' });
  edges.push({ id: edgeId(ACCOUNT_OPS.id, IT_SUPPORT.id, 'MemberOf'), source: ACCOUNT_OPS.id, target: IT_SUPPORT.id, type: 'MemberOf' });
  edges.push({ id: edgeId(EA.id, DA.id, 'MemberOf'), source: EA.id, target: DA.id, type: 'MemberOf' });
  edges.push({ id: edgeId(DA.id, DOMAIN_USERS.id, 'MemberOf'), source: DA.id, target: DOMAIN_USERS.id, type: 'MemberOf' });

  // admin relationships on the domain + DCs
  edges.push({ id: edgeId(SERVER_ADMINS.id, nodeId('computer', 'CORP-DC01'), 'AdminTo'), source: SERVER_ADMINS.id, target: nodeId('computer', 'CORP-DC01'), type: 'AdminTo' });
  edges.push({ id: edgeId(SERVER_ADMINS.id, nodeId('computer', 'CORP-DC02'), 'AdminTo'), source: SERVER_ADMINS.id, target: nodeId('computer', 'CORP-DC02'), type: 'AdminTo' });

  // ---- Computers ----
  const serverMeta: Record<string, { os: string; desc: string }> = {
    'CORP-DC01': { os: 'Windows Server 2022 · Domain Controller', desc: 'Primary domain controller (PDC). Holds the KRBTGT keys and the full domain hash history.' },
    'CORP-DC02': { os: 'Windows Server 2022 · Domain Controller', desc: 'Secondary domain controller. Same restore power as DC01.' },
    'CORP-SQL01': { os: 'Windows Server 2019 · SQL Server 2019', desc: 'Production SQL cluster. Hosts finance, HR and identity databases.' },
    'CORP-WEB01': { os: 'Windows Server 2019 · IIS 10', desc: 'Public facing web tier. Sustains heavy inbound traffic.' },
    'CORP-FILE01': { os: 'Windows Server 2019 · File Server', desc: 'Departmental file shares. Contains accounting exports.' },
    'CORP-APP01': { os: 'Windows Server 2022 · App Tier', desc: 'Internal line-of-business application servers.' },
    'CORP-MAIL01': { os: 'Windows Server 2019 · Exchange', desc: 'Exchange mailbox servers.' },
    'CORP-BACKUP01': { os: 'Windows Server 2022 · Veeam', desc: 'Backup infrastructure. Wins the environment on restore.' },
    'CORP-ITSRV01': { os: 'Windows Server 2022 · Helpdesk / jump host', desc: 'IT jump-box used by helpdesk for remote administration.' },
    'CORP-VAULT01': { os: 'Windows Server 2022 · PAM/Vault', desc: 'Privileged access management vault.' },
  };

  const computerNodes = new Map<string, BHNode>();
  COMPUTERS.forEach((c) => {
    const meta = serverMeta[c] ?? {
      os: `Windows 11 Enterprise ${randInt(rng, 10, 24)}H2`,
      desc: 'Standard corporate endpoint.',
    };
    computerNodes.set(
      c,
      mkNode('computer', c, {
        os: meta.os,
        description: meta.desc,
        highValue: c === 'CORP-DC01' || c === 'CORP-DC02',
      }),
    );
  });

  // ---- Users ----
  const users: BHNode[] = [];
  const deptPool: Array<'finance' | 'hr' | 'sales' | 'eng' | 'it'> = ['finance', 'hr', 'sales', 'eng', 'eng', 'eng', 'it'];

  let k = 0;
  for (let i = 0; i < 96; i++) {
    k = (k + 7) % (FIRST.length * SURNAMES.length);
    const first = FIRST[Math.floor(k / SURNAMES.length) % FIRST.length];
    const last = SURNAMES[k % SURNAMES.length];
    const dept = deptPool[Math.floor(rng() * deptPool.length)];
    const uname = `${first}.${last}`;
    const n = mkNode('user', uname, {
      dept,
      description: `Standard ${dept.toUpperCase()} department user account.`,
      enabled: rng() > 0.04,
    });
    users.push(n);
  }

  const IT_USERS = users.filter((u) => u.dept === 'it');
  const boxIdx = (u: BHNode) => (u.id.charCodeAt(u.id.length - 1) + u.id.charCodeAt(5)) % 10;

  // ---- User memberships ----
  for (const u of users) {
    edges.push({ id: edgeId(u.id, DOMAIN_USERS.id, 'MemberOf'), source: u.id, target: DOMAIN_USERS.id, type: 'MemberOf' });
    const grp = groupNodes.get(DEPT_GROUP[u.dept ?? 'eng']);
    if (grp) edges.push({ id: edgeId(u.id, grp.id, 'MemberOf'), source: u.id, target: grp.id, type: 'MemberOf' });
  }

  // Service accounts + svc-sql (dangerous direct DA membership)
  const svcSql = mkNode('user', 'svc-sql', {
    dept: 'it',
    description: 'SQL service account. MISCONFIGURED: direct member of DOMAIN ADMINS.',
  });
  const svcHelpdesk = mkNode('user', 'svc-helpdesk', {
    dept: 'it',
    description: 'Shared helpdesk service account used by IT support.',
  });
  const svcBackup = mkNode('user', 'svc-backup', {
    dept: 'it',
    description: 'Backup service account with restore rights on servers.',
  });
  // The classic bloodhound misconfiguration:
  edges.push({ id: edgeId(svcSql.id, DA.id, 'MemberOf'), source: svcSql.id, target: DA.id, type: 'MemberOf' });
  edges.push({ id: edgeId(svcSql.id, SERVER_ADMINS.id, 'MemberOf'), source: svcSql.id, target: SERVER_ADMINS.id, type: 'MemberOf' });
  edges.push({ id: edgeId(svcHelpdesk.id, IT_SUPPORT.id, 'MemberOf'), source: svcHelpdesk.id, target: IT_SUPPORT.id, type: 'MemberOf' });
  edges.push({ id: edgeId(svcBackup.id, SERVER_ADMINS.id, 'MemberOf'), source: svcBackup.id, target: SERVER_ADMINS.id, type: 'MemberOf' });

  // svc-helpdesk local admin on IT jump server + sql server (abused)
  edges.push({ id: edgeId(svcHelpdesk.id, nodeId('computer', 'CORP-ITSRV01'), 'AdminTo'), source: svcHelpdesk.id, target: nodeId('computer', 'CORP-ITSRV01'), type: 'AdminTo' });
  edges.push({ id: edgeId(svcHelpdesk.id, nodeId('computer', 'CORP-SQL01'), 'AdminTo'), source: svcHelpdesk.id, target: nodeId('computer', 'CORP-SQL01'), type: 'AdminTo' });
  // IT support members have admin on jump server
  for (const u of IT_USERS.slice(0, 4)) {
    edges.push({ id: edgeId(u.id, nodeId('computer', 'CORP-ITSRV01'), 'AdminTo'), source: u.id, target: nodeId('computer', 'CORP-ITSRV01'), type: 'AdminTo' });
  }

  // ---- Sessions (HasSession) ----
  const sessions: BHEdge[] = [];
  const addSession = (user: BHNode, computer: string) => {
    sessions.push({
      id: edgeId(user.id, nodeId('computer', computer), 'HasSession'),
      source: user.id,
      target: nodeId('computer', computer),
      type: 'HasSession',
    });
  };

  // domain admins have sessions scattered on critical machines
  for (const c of ['CORP-DC01', 'CORP-DC02', 'CORP-SQL01', 'CORP-WEB01', 'CORP-ITSRV01']) {
    addSession(svcSql, c);
  }
  addSession(svcHelpdesk, 'CORP-ITSRV01');
  addSession(svcBackup, 'CORP-BACKUP01');
  addSession(svcBackup, 'CORP-FILE01');

  // every user has 1-3 sessions on workstations in their department proximity
  for (const u of users) {
    const base = boxIdx(u);
    const count = randInt(rng, 1, 3);
    for (let s = 0; s < count; s++) {
      const ws = WORKSTATIONS[(base + s * 5 + Math.floor(rng() * 5)) % WORKSTATIONS.length];
      addSession(u, ws);
    }
  }
  // IT users also on jump server
  for (const u of IT_USERS) if (rng() < 0.3) addSession(u, 'CORP-ITSRV01');
  edges.push(...sessions);

  // ---- Dangerous permission edges (misconfigurations) ----
  const allUsers = [...users, svcSql, svcHelpdesk, svcBackup];
  const someUser = () => allUsers[Math.floor(rng() * allUsers.length)];

  // ForceChangePassword on svc-sql (classic Kerberoast chain)
  edges.push({
    id: edgeId(someUser().id, svcSql.id, 'ForceChangePassword'),
    source: someUser().id,
    target: svcSql.id,
    type: 'ForceChangePassword',
  });

  // GenericAll on DA group from a corrupted IT account (AddMember equivalent)
  const corruptIT = IT_USERS[Math.floor(rng() * IT_USERS.length)];
  edges.push({ id: edgeId(corruptIT.id, DA.id, 'GenericAll'), source: corruptIT.id, target: DA.id, type: 'GenericAll' });
  edges.push({ id: edgeId(ACCOUNT_OPS.id, DA.id, 'AddMember'), source: ACCOUNT_OPS.id, target: DA.id, type: 'AddMember' });

  // WriteDacl on a server from finance lead
  edges.push({
    id: edgeId(someUser().id, nodeId('computer', 'CORP-SQL01'), 'WriteDacl'),
    source: someUser().id,
    target: nodeId('computer', 'CORP-SQL01'),
    type: 'WriteDacl',
  });

  // CanRDP sprinkles onto file/web server
  edges.push({
    id: edgeId(someUser().id, nodeId('computer', 'CORP-FILE01'), 'CanRDP'),
    source: someUser().id,
    target: nodeId('computer', 'CORP-FILE01'),
    type: 'CanRDP',
  });

  // AdminTo: some IT users admin on web + app servers
  for (const u of IT_USERS.slice(0, 6)) {
    edges.push({ id: edgeId(u.id, nodeId('computer', 'CORP-WEB01'), 'AdminTo'), source: u.id, target: nodeId('computer', 'CORP-WEB01'), type: 'AdminTo' });
    edges.push({ id: edgeId(u.id, nodeId('computer', 'CORP-APP01'), 'AdminTo'), source: u.id, target: nodeId('computer', 'CORP-APP01'), type: 'AdminTo' });
  }

  // GenericWrite: someone with write access to a server admin group
  edges.push({
    id: edgeId(someUser().id, SERVER_ADMINS.id, 'GenericWrite'),
    source: someUser().id,
    target: SERVER_ADMINS.id,
    type: 'GenericWrite',
  });
  edges.push({
    id: edgeId(someUser().id, ACCOUNT_OPS.id, 'GenericWrite'),
    source: someUser().id,
    target: ACCOUNT_OPS.id,
    type: 'GenericWrite',
  });
  // AllExtendedRights on file server from an engineering user
  edges.push({
    id: edgeId(someUser().id, nodeId('computer', 'CORP-FILE01'), 'AllExtendedRights'),
    source: someUser().id,
    target: nodeId('computer', 'CORP-FILE01'),
    type: 'AllExtendedRights',
  });

  // ---- Owned nodes (simulating attacker seed) ----
  const seedIdx = [3, 27, 51]; // picked by index for a stable demo
  const ownedSeeds = seedIdx.map((i) => users[i % users.length]);
  for (const u of ownedSeeds) {
    u.owned = true;
    u.description = `COMPROMISED / OWNED — simulated attacker foothold of a real beacon/C2 session on this account.`;
  }
  // Owns edges from attacker nodes
  for (const u of ownedSeeds) {
    const ws = WORKSTATIONS[(boxIdx(u) + 2) % WORKSTATIONS.length];
    edges.push({ id: edgeId(u.id, nodeId('computer', ws), 'Owns'), source: u.id, target: nodeId('computer', ws), type: 'Owns' });
  }

  // ---- Layout (deterministic) ----
  const positions = computeLayout(nodes, groupNodes, computerNodes);

  return { nodes, edges, positions };
}

function computeLayout(
  nodes: BHNode[],
  groupNodes: Map<string, BHNode>,
  computerNodes: Map<string, BHNode>,
): Record<string, Vec3> {
  const rng = mulberry32(0x1abe1);
  const pos: Record<string, Vec3> = {};

  const jitter = (r: number) => (rng() - 0.5) * r;
  const domain = nodes.find((n) => n.kind === 'domain')!;
  pos[domain.id] = { x: 0, y: 34, z: 0 };

  const gs = [...groupNodes.values()];
  gs.forEach((g, i) => {
    const t = (i / gs.length) * Math.PI * 2;
    pos[g.id] = { x: Math.cos(t) * 12, y: 27, z: Math.sin(t) * 12 };
  });

  const comps = [...computerNodes.values()];
  const servers = comps.filter((c) => /-(DC|SQL|WEB|FILE|APP|MAIL|BACKUP|ITSRV|VAULT)/.test(c.label));
  const workstations = comps.filter((c) => c.label.startsWith('CORP-WS'));
  // servers layered near the center
  servers.forEach((c, i) => {
    const t = (i / Math.max(1, servers.length)) * Math.PI * 2;
    const r = 9 + (i % 3) * 2.5;
    pos[c.id] = { x: Math.cos(t) * r + jitter(2), y: 16 + (i % 2) * 2, z: Math.sin(t) * r + jitter(2) };
  });
  // workstations in a distributed shell
  workstations.forEach((c, i) => {
    const col = i % 8;
    const row = Math.floor(i / 8);
    pos[c.id] = {
      x: -28 + col * 8 + jitter(3),
      y: 6 + (row % 3) * 2.5 + jitter(1.5),
      z: -20 + row * 6 + jitter(3),
    };
  });

  // users orbit their department group
  const deptAnchor: Record<string, string> = {
    finance: 'FINANCE',
    hr: 'HR',
    sales: 'SALES',
    eng: 'ENGINEERING',
    it: 'IT SUPPORT',
  };
  for (const n of nodes) {
    if (n.kind !== 'user') continue;
    const anchorId = groupNodes.get(deptAnchor[n.dept ?? 'eng'])?.id;
    const anchor = anchorId ? pos[anchorId] ?? { x: 0, y: 27, z: 0 } : { x: rng() * 40 - 20, y: 10, z: rng() * 40 - 20 };
    const a = rng() * Math.PI * 2;
    const rr = 5 + rng() * 5;
    pos[n.id] = {
      x: anchor.x + Math.cos(a) * rr + jitter(2),
      y: 3 + Math.abs(jitter(3)),
      z: anchor.z + Math.sin(a) * rr + jitter(2),
    };
  }
  return pos;
}