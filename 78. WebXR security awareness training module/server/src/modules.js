'use strict';
/**
 * modules.js — Training module catalog + scenario definitions.
 *
 * One entry per module in architecture.md §6 "TRAINING MODULE LIBRARY" (M1–M6).
 * Each module is a branching scenario consumed by the WebXR client
 * (public/js/xr.js) and carries the metadata the GUI renders:
 *
 *   scene        – immersive stage theme (drives the WebXR/canvas renderer)
 *   controls     – interaction affordances surfaced in the in-headset HUD
 *   telemetry    – allow-listed aggregate event types (GDPR Art.25 minimisation)
 *   standardRefs – ISO 27001 / NIST / OWASP anchors for the compliance view
 *
 * `isTrap` options are deliberate wrong answers scored against the learner.
 * Catalog is immutable at runtime; the only writer is the build/deploy process.
 */

const MODULES = [
  {
    id: 'phishing-triage',
    ref: 'M1',
    title: '📧 Phishing Email Triage',
    category: 'phishing',
    visual: '📨',
    scene: 'inbox',
    durationMin: 8,
    riskWeight: 1.0,
    xp: 120,
    description: 'Inspect a 3D inbox and identify malicious emails before damage occurs.',
    objectives: ['Recognize spoofed senders and lookalike domains', 'Spot urgency/authority lures', 'Use the report button instead of forwarding'],
    controls: ['reach', 'point', 'report'],
    telemetry: ['scene.enter', 'choice.make', 'feedback.view'],
    standardRefs: { iso: ['A.6.3', 'A.8.23'], nist: ['SI-4', 'AT-2'], owasp: ['A07'] },
    nodes: [
      {
        id: 'start',
        prompt: 'Your virtual inbox shows 3 unread emails. Which do you open first?',
        scene: 'inbox',
        options: [
          { id: 'a', text: '"URGENT: Payroll suspended — verify bank details NOW" from payroll-alerts@ext-portal.biz', isTrap: true },
          { id: 'b', text: '"Q3 security training reminder" from training@yourcompany.com' },
          { id: 'c', text: '"Invoice #4471" from accounting@known-vendor.com' },
        ],
        correct: 'b',
        isTrap: false,
        explain: 'Legitimate internal mail comes from the corporate domain. The "ext-portal.biz" lookalike combined with urgency and payroll authority is a classic lure.',
      },
      {
        id: 'inspect',
        prompt: 'You opened the payroll email. The link preview shows "payroll-portal.biz/verify?emp=you". What do you do?',
        scene: 'inbox',
        options: [
          { id: 'a', text: 'Click it — HR does use external portals sometimes', isTrap: true },
          { id: 'b', text: 'Hover to inspect the real domain, then report as phishing and delete' },
          { id: 'c', text: 'Forward it to a colleague to check', isTrap: true },
        ],
        correct: 'b',
        isTrap: false,
        explain: 'Never click. Verify the domain, report through the phishing button so the SOC can hunt for other recipients, then delete. Forwarding spreads the payload.',
      },
      {
        id: 'trap-callback',
        prompt: 'The email asks you to "confirm" by replying with your password. Replying is…',
        scene: 'inbox',
        options: [
          { id: 'a', text: 'Safe — it stays inside company email', isTrap: true },
          { id: 'b', text: 'Never acceptable — credentials are never shared by reply' },
        ],
        correct: 'b',
        isTrap: false,
        explain: 'Credential harvesting by reply is a common bypass of link-scanning filters, and it lands the credential straight in an attacker mailbox.',
      },
      {
        id: 'report',
        prompt: 'You reported it. What makes the report operationally useful?',
        scene: 'inbox',
        options: [
          { id: 'a', text: 'Adding the sender domain and the message headers so the SOC can block and hunt' },
          { id: 'b', text: 'Nothing — reporting is optional politeness' },
          { id: 'c', text: 'Deleting your own copy so nobody is tempted', isTrap: true },
        ],
        correct: 'a',
        isTrap: false,
        explain: 'Reporting is a security control: header and domain indicators let the SOC scope the campaign and warn other recipients (ISO A.6.3 effectiveness evidence).',
      },
    ],
  },
  {
    id: 'vishing-deepfake',
    ref: 'M2',
    title: '☎️ Vishing & Deepfake Call',
    category: 'social-engineering',
    visual: '☎️',
    scene: 'call',
    durationMin: 10,
    riskWeight: 1.2,
    xp: 160,
    description: 'A voice-cloned "CFO" calls asking for an urgent wire transfer. Verify identity under pressure.',
    objectives: ['Verify out-of-band on a trusted number', 'Resist manufactured urgency', 'Follow payment-change controls'],
    controls: ['listen', 'hangup', 'callback'],
    telemetry: ['scene.enter', 'choice.make', 'feedback.view'],
    standardRefs: { iso: ['A.6.3', 'A.5.15'], nist: ['AT-2', 'AC-3'], owasp: ['A07'] },
    nodes: [
      {
        id: 'start',
        prompt: 'Your phone rings: "This is the CFO. I need a €95,000 wire in the next 10 minutes — keep it between us." You…',
        scene: 'call',
        options: [
          { id: 'a', text: 'Process it — the voice sounds exactly right', isTrap: true },
          { id: 'b', text: 'Say you will call back on the number in the internal directory, then verify via a second channel' },
          { id: 'c', text: 'Ask them to email written approval', isTrap: true },
        ],
        correct: 'b',
        isTrap: false,
        explain: 'Voice cloning needs seconds of audio. Out-of-band verification on a known, internally published number defeats deepfake pressure and secrecy framing.',
      },
      {
        id: 'pressure',
        prompt: 'The caller gets angry: "This delay will cost the company millions!" Correct response?',
        scene: 'call',
        options: [
          { id: 'a', text: 'Apologize and start the transfer', isTrap: true },
          { id: 'b', text: 'Stay calm — urgency is the weapon; end the call and escalate per policy' },
        ],
        correct: 'b',
        isTrap: false,
        explain: 'Manufactured urgency and authority are manipulation markers. Policy exists precisely for this moment, and no verbal instruction overrides the payment controls.',
      },
      {
        id: 'verify',
        prompt: 'You call the CFO back on the directory number. She has no idea about the wire. Next step?',
        scene: 'call',
        options: [
          { id: 'a', text: 'Ask finance to reverse any transfer and report the attempted fraud to security' },
          { id: 'b', text: 'Assume it was a prank and tell nobody', isTrap: true },
          { id: 'c', text: 'Post about it in the team chat as a funny story', isTrap: true },
        ],
        correct: 'a',
        isTrap: false,
        explain: 'A failed deepfake attempt is a live indicator. Reporting it lets security block the attacker number, warn finance, and brief other executives.',
      },
    ],
  },
  {
    id: 'tailgating-lobby',
    ref: 'M3',
    title: '🚪 Tailgating & Badge Security',
    category: 'physical',
    visual: '🚪',
    scene: 'lobby',
    durationMin: 6,
    riskWeight: 0.8,
    xp: 90,
    description: 'Someone in the lobby asks you to hold the secure door. Practice polite refusal and reporting.',
    objectives: ['Enforce door discipline without confrontation', 'Route visitors to reception', 'Report reconnaissance behavior'],
    controls: ['reach', 'refuse', 'report'],
    telemetry: ['scene.enter', 'choice.make', 'feedback.view'],
    standardRefs: { iso: ['A.7.6', 'A.6.3'], nist: ['AC-3', 'PE-2'], owasp: ['A01'] },
    nodes: [
      {
        id: 'start',
        prompt: 'A person carrying two coffee cups asks you to badge them through the secure door. You…',
        scene: 'lobby',
        options: [
          { id: 'a', text: 'Badge them through — they look friendly', isTrap: true },
          { id: 'b', text: 'Politely decline and point them to reception for a visitor badge' },
          { id: 'c', text: 'Let them follow you through silently', isTrap: true },
        ],
        correct: 'b',
        isTrap: false,
        explain: 'Tailgating bypasses every technical control while looking harmless. Reception exists to verify identity and escort guests.',
      },
      {
        id: 'followup',
        prompt: 'Later, the same person is photographing the door readers. You…',
        scene: 'lobby',
        options: [
          { id: 'a', text: 'Ignore it — not my job', isTrap: true },
          { id: 'b', text: 'Report to security with time, location and what was photographed' },
        ],
        correct: 'b',
        isTrap: false,
        explain: 'Reconnaissance of badge readers precedes physical intrusion attempts. See something, say something — and give responders actionable detail.',
      },
      {
        id: 'escort',
        prompt: 'A genuine supplier needs a server room. Which handling is compliant?',
        scene: 'lobby',
        options: [
          { id: 'a', text: 'Let them in alone — suppliers know their way' },
          { id: 'b', text: 'Verify the work order, issue a time-boxed badge and escort them the whole time' },
          { id: 'c', text: 'Hold the door and wave them through from the stairs', isTrap: true },
        ],
        correct: 'b',
        isTrap: false,
        explain: 'Visitor access = identity verified + least privilege + time-boxed badge + continuous escort. That is the control that makes exceptions safe.',
      },
    ],
  },
  {
    id: 'data-handling',
    ref: 'M4',
    title: '💾 Data Handling & Clean Desk',
    category: 'data-protection',
    visual: '💾',
    scene: 'desk',
    durationMin: 7,
    riskWeight: 1.0,
    xp: 110,
    description: 'Classify documents correctly and keep sensitive data off unapproved channels.',
    objectives: ['Apply classification labels when sharing', 'Use only approved channels', 'Keep a clean desk and clean screen'],
    controls: ['reach', 'classify', 'shred'],
    telemetry: ['scene.enter', 'choice.make', 'feedback.view'],
    standardRefs: { iso: ['A.5.12', 'A.8.12', 'A.7.7'], nist: ['SC-28', 'AC-3'], owasp: ['A02'] },
    nodes: [
      {
        id: 'start',
        prompt: 'A file marked "Restricted — Customer PII" needs sharing with a partner under NDA. You use…',
        scene: 'desk',
        options: [
          { id: 'a', text: 'Your personal cloud drive for speed', isTrap: true },
          { id: 'b', text: 'The approved encrypted transfer portal with access expiry' },
          { id: 'c', text: 'A USB stick from the drawer', isTrap: true },
        ],
        correct: 'b',
        isTrap: false,
        explain: 'Approved channels enforce encryption, access control, expiry and audit trails for restricted data. Personal services and unencrypted media bypass all of them.',
      },
      {
        id: 'desks',
        prompt: 'End of day. Your desk has printed PII reports. You…',
        scene: 'desk',
        options: [
          { id: 'a', text: 'Lock them in the designated cabinet (clean desk policy)' },
          { id: 'b', text: 'Leave them — cleaning staff are trustworthy', isTrap: true },
        ],
        correct: 'a',
        isTrap: false,
        explain: 'Clean desk policy prevents shoulder-surfing, janitor attacks and compliance findings. Lockable storage is the cheapest control in this list.',
      },
      {
        id: 'disposal',
        prompt: 'The drafts are obsolete. Correct disposal?',
        scene: 'desk',
        options: [
          { id: 'a', text: 'Cross-cut shred in the console / approved confidential bin' },
          { id: 'b', text: 'Recycle bin — the label says it is paper', isTrap: true },
          { id: 'c', text: 'Tape the pages shut and put them back in the drawer', isTrap: true },
        ],
        correct: 'a',
        isTrap: false,
        explain: 'Confidential waste only leaves the desk through shredding or locked confidential bins. "It is in a bin" is not destruction evidence.',
      },
    ],
  },
  {
    id: 'ransomware-drill',
    ref: 'M5',
    title: '🦠 Ransomware Response Drill',
    category: 'malware',
    visual: '🦠',
    scene: 'ransomware',
    durationMin: 12,
    riskWeight: 1.5,
    xp: 200,
    description: 'Files start encrypting on your virtual desktop. Execute the isolate-report-recover drill.',
    objectives: ['Disconnect first to stop lateral movement', 'Report within minutes', 'Never pay or negotiate'],
    controls: ['reach', 'disconnect', 'report'],
    telemetry: ['scene.enter', 'choice.make', 'feedback.view'],
    standardRefs: { iso: ['A.5.24', 'A.5.28', 'A.5.29'], nist: ['IR-4', 'IR-6', 'CP-9'], owasp: ['A08'] },
    nodes: [
      {
        id: 'start',
        prompt: 'Files rename to .locked and a ransom note appears. First action?',
        scene: 'ransomware',
        options: [
          { id: 'a', text: 'Disconnect the device from the network (Wi-Fi off / cable out)' },
          { id: 'b', text: 'Keep working and hope it stops', isTrap: true },
          { id: 'c', text: 'Restart to "clean" it', isTrap: true },
        ],
        correct: 'a',
        isTrap: false,
        explain: 'Network isolation halts lateral movement. Restarting can trigger further encryption stages and destroys volatile evidence responders need.',
      },
      {
        id: 'report',
        prompt: 'Device is isolated. Next?',
        scene: 'ransomware',
        options: [
          { id: 'a', text: 'Report to the security team within minutes — every minute counts' },
          { id: 'b', text: 'Pay the ransom quietly', isTrap: true },
          { id: 'c', text: 'Email the ransom note to colleagues for advice', isTrap: true },
        ],
        correct: 'a',
        isTrap: false,
        explain: 'Fast reporting activates the incident response plan and backup strategy. Payment funds crime, is illegal in many jurisdictions and is no guarantee of decryption.',
      },
      {
        id: 'preserve',
        prompt: 'Before you hand the device over, what must you do?',
        scene: 'ransomware',
        options: [
          { id: 'a', text: 'Leave it powered on and untouched so responders can preserve evidence' },
          { id: 'b', text: 'Wipe it yourself so the attacker gets nothing', isTrap: true },
          { id: 'c', text: 'Unplug it and forget about it', isTrap: true },
        ],
        correct: 'a',
        isTrap: false,
        explain: 'Containment must not destroy evidence. Do not power down, wipe or reimage until the incident commander says so (NIST IR-4 evidence handling).',
      },
      {
        id: 'recover',
        prompt: 'Recovery resumes. Which source do you restore from?',
        scene: 'ransomware',
        options: [
          { id: 'a', text: 'The last known-good, integrity-verified offline/immutable backup' },
          { id: 'b', text: 'The network share — the files are still there', isTrap: true },
          { id: 'c', text: 'Whatever the vendor provides after payment', isTrap: true },
        ],
        correct: 'a',
        isTrap: false,
        explain: 'Ransomware operators encrypt reachable backups first. Immutable/offline copies plus a rehearsed restore test are what make recovery real (A.5.30 ICT readiness).',
      },
    ],
  },
  {
    id: 'insider-pretexting',
    ref: 'M6',
    title: '👤 Insider Pretexting & Social Engineering',
    category: 'social-engineering',
    visual: '🎭',
    scene: 'office',
    durationMin: 9,
    riskWeight: 1.3,
    xp: 180,
    description: 'A new "contractor" uses authority, urgency and rapport to extract access and data. Practise refusal and verification.',
    objectives: ['Recognise pretexting and rapport weapons', 'Verify identity through HR/IT channels', 'Escalate insider-risk indicators, not gossip'],
    controls: ['reach', 'verify', 'escalate'],
    telemetry: ['scene.enter', 'choice.make', 'feedback.view'],
    standardRefs: { iso: ['A.6.3', 'A.6.8'], nist: ['AT-2', 'IR-4'], owasp: ['A07'] },
    nodes: [
      {
        id: 'start',
        prompt: 'A "contractor from HQ" asks for a shared export of the sales workbook "before the 15:00 board pack". You…',
        scene: 'office',
        options: [
          { id: 'a', text: 'Share it — they are "internal" and it is urgent', isTrap: true },
          { id: 'b', text: 'Verify the person and request through the IT ticket / HR process, no side-channel data' },
          { id: 'c', text: 'Send it to their personal email so they are not blocked', isTrap: true },
        ],
        correct: 'b',
        isTrap: false,
        explain: 'Authority + urgency + a side channel is the classic pretext triad. Data leaves only through the approved request process, never "just this once".',
      },
      {
        id: 'rapport',
        prompt: 'They are friendly, share personal details, and name-drop the CFO. What is the tell?',
        scene: 'office',
        options: [
          { id: 'a', text: 'Affinity and authority claims are pressure, not proof of identity' },
          { id: 'b', text: 'Being friendly means they are legitimate', isTrap: true },
        ],
        correct: 'a',
        isTrap: false,
        explain: 'Pretexting manipulates trust, not credentials. Identity is established by an independent channel you already trust, not by how credible the story sounds.',
      },
      {
        id: 'escalate',
        prompt: 'You later learn this person has no contractor record and asked three teams for data. You…',
        scene: 'office',
        options: [
          { id: 'a', text: 'Report it to security through the confidential channel with what you observed' },
          { id: 'b', text: 'Mention it in the team chat as a warning', isTrap: true },
          { id: 'c', text: 'Confront them alone in the kitchen', isTrap: true },
        ],
        correct: 'a',
        isTrap: false,
        explain: 'Use the reporting channel. Personal confrontation is unsafe, and public warnings tip off a potential insider and start rumour cycles.',
      },
    ],
  },
];

/** Categories in display order (used by the catalog filter chips). */
const CATEGORIES = [
  { id: 'all', label: 'All modules', visual: '🗂️' },
  { id: 'phishing', label: 'Phishing', visual: '📧' },
  { id: 'social-engineering', label: 'Social engineering', visual: '🎭' },
  { id: 'physical', label: 'Physical', visual: '🚪' },
  { id: 'data-protection', label: 'Data protection', visual: '💾' },
  { id: 'malware', label: 'Malware & IR', visual: '🦠' },
];

/** Get a module by id (validated upstream). */
function getModule(id) {
  return MODULES.find((m) => m.id === id) || null;
}

/** Catalog projection — never leaks `correct` / `explain` to the catalog list. */
function catalogEntry(m) {
  return {
    id: m.id,
    ref: m.ref,
    title: m.title,
    category: m.category,
    visual: m.visual,
    scene: m.scene,
    durationMin: m.durationMin,
    riskWeight: m.riskWeight,
    xp: m.xp,
    description: m.description,
    objectives: m.objectives,
    controls: m.controls,
    telemetry: m.telemetry,
    standardRefs: m.standardRefs,
    nodeCount: m.nodes.length,
    trapCount: m.nodes.reduce((n, node) => n + node.options.filter((o) => o.isTrap).length, 0),
  };
}

/** Scenario bundle projection — includes nodes, plus a SHA-256 integrity hash (SI-7). */
function bundleEntry(m) {
  return { ...catalogEntry(m), nodes: m.nodes, integrity: sha256Hex(JSON.stringify(m.nodes)) };
}

function sha256Hex(input) {
  return require('node:crypto').createHash('sha256').update(input).digest('hex');
}

/** Score a completed session: correct ratio − trap penalty → 0..100. */
function scoreSession(module, results) {
  if (!module || !Array.isArray(results) || results.length === 0) return null;
  const byNode = new Map(results.map((r) => [r.nodeId, r.choice]));
  let correct = 0;
  let trapHits = 0;
  for (const node of module.nodes) {
    const choice = byNode.get(node.id);
    if (!choice) continue;
    if (choice === node.correct) correct += 1;
    const chosen = node.options.find((o) => o.id === choice);
    if (chosen && chosen.isTrap) trapHits += 1;
  }
  const ratio = correct / module.nodes.length;
  const penalty = trapHits * 0.15;
  return {
    riskScore: Math.max(0, Math.round((ratio - penalty) * 100)),
    correct,
    total: module.nodes.length,
    trapHits,
  };
}

module.exports = { MODULES, CATEGORIES, getModule, catalogEntry, bundleEntry, scoreSession };
