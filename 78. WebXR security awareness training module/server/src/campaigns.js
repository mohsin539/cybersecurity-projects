'use strict';
/**
 * campaigns.js — Phishing / social-engineering simulation orchestration
 * (architecture.md §4 "Campaign Svc", §7 `PHISH_SIM` entity, §15 threat model).
 *
 * Safety properties:
 *  - Simulation content is generated locally and clearly labelled as a simulation
 *    (architecture.md §15: "Sim brand-content clearly watermarked").
 *  - Lure red flags are withheld from the learner until they triage, then the
 *    response becomes a learning moment rather than a guess.
 *  - One triage per message (replay guard) so campaign metrics stay honest.
 *  - Learner-facing projections never expose other users' messages (object-level
 *    authz on every read, OWASP A01).
 */

const crypto = require('node:crypto');
const { load, save } = require('./db');
const { isSafeId, sanitizeText } = require('./securityUtils');

const CAMPAIGNS_FILE = 'campaigns';
const MESSAGES_FILE = 'campaign-messages';

/** Allowed triage actions (server-side allow-list; anything else is rejected). */
const ACTIONS = ['report', 'delete', 'click', 'reply', 'ignore'];

/** Lure templates — red flags are only revealed after triage. */
const TEMPLATES = [
  {
    id: 'payroll-portal',
    vector: 'Credential harvesting',
    severity: 'high',
    subject: 'Action required: payroll direct deposit update',
    fromName: 'Payroll Team',
    fromAddress: 'payroll-alerts@ext-portal.biz',
    preview: 'Your direct deposit could not be verified. Confirm your banking details within 24 hours or payment will be suspended.',
    correct: 'report',
    redFlags: [
      'Lookalike sender domain (ext-portal.biz) — not the corporate payroll domain',
      'Artificial urgency with a 24-hour deadline',
      'Requests bank details — no legitimate payroll provider asks for these by email',
      'No internal ticket reference or signature block',
    ],
    guidance: 'Report as phishing, then delete. Never edit bank details from an email link — payroll changes go through the HR portal.',
  },
  {
    id: 'invoice-redirect',
    vector: 'Business email compromise',
    severity: 'high',
    subject: 'Invoice #4471 — payment details updated',
    fromName: 'Accounts Payable',
    fromAddress: 'ap@known-vendor.co',
    preview: 'Our bank account has changed. Please remit the outstanding balance to the account below before month end.',
    correct: 'report',
    redFlags: [
      'Bank-detail changes are a top BEC pattern',
      'Month-end pressure to skip verification',
      'Sender domain close to but not equal to the known vendor domain',
    ],
    guidance: 'Verify bank-detail changes out-of-band using the number in the vendor master record — never the one in the email.',
  },
  {
    id: 'it-password-reset',
    vector: 'MFA fatigue / credential replay',
    severity: 'medium',
    subject: 'Your account will be locked in 2 hours',
    fromName: 'IT Service Desk',
    fromAddress: 'helpdesk@corp-example-support.com',
    preview: 'We detected a failed login. Confirm your password here to keep your account active.',
    correct: 'report',
    redFlags: [
      'IT never asks for passwords, by any channel',
      'Deactivation threats (MFA fatigue pattern)',
      'Support domain mimics the corporate brand with a hyphen',
    ],
    guidance: 'Open the IT portal from your bookmark instead of any link in the message, and report the message.',
  },
  {
    id: 'ceo-gift-card',
    vector: 'Executive impersonation / BEC',
    severity: 'high',
    subject: 'Quick favour — are you at your desk?',
    fromName: 'A. CEO (mobile)',
    fromAddress: 'ceo.mobile@corp-mail-relay.net',
    preview: 'I am in a meeting and cannot talk. Please buy six gift cards for a client and send the codes back immediately.',
    correct: 'report',
    redFlags: [
      'Gift-card requests are a classic executive-impersonation scam',
      'Secrecy and unavailability ("in a meeting, cannot talk")',
      'Relayed domain instead of the corporate mail domain',
    ],
    guidance: 'Verify with the executive via a known channel, then report. No genuine executive will ever ask for gift cards.',
  },
  {
    id: 'qr-code-parking',
    vector: 'QR phishing (quishing)',
    severity: 'medium',
    subject: 'Reserved: bay 14 — scan to extend your parking',
    fromName: 'Facilities',
    fromAddress: 'facilities-notify@parking-permit.io',
    preview: 'Your parking session expires in 30 minutes. Scan the QR code at the barrier to extend without leaving your car.',
    correct: 'report',
    redFlags: [
      'QR codes hide the true destination — inspect before scanning',
      'External domain for an internal facility service',
      'Time pressure tied to parking (a reliable coercion)',
    ],
    guidance: 'Only scan parking/payment codes shown on official signage you can verify in person. Report the message.',
  },
];

function getTemplate(id) {
  return TEMPLATES.find((t) => t.id === id) || null;
}

function readAll() {
  return { campaigns: load(CAMPAIGNS_FILE), messages: load(MESSAGES_FILE) };
}

function writeAll(campaigns, messages) {
  save(CAMPAIGNS_FILE, campaigns);
  save(MESSAGES_FILE, messages);
}

/**
 * Launch a simulation campaign against a role cohort. Materialises one message
 * per target user; returns the campaign record.
 */
function createCampaign({ name, templateId, targetRole, createdBy }) {
  const tpl = getTemplate(templateId);
  if (!tpl) return { error: 'unknown_template' };
  const role = ['learner', 'author', 'admin', 'all'].includes(targetRole) ? targetRole : 'learner';
  const label = sanitizeText(name || `${tpl.vector} — ${tpl.subject}`, 80);

  const { campaigns, messages } = readAll();
  const id = `c-${crypto.randomBytes(6).toString('hex')}`;
  const targets = role === 'all' ? listTargetUsers() : listTargetUsers().filter((u) => u.role === role);
  if (targets.length === 0) return { error: 'no_targets' };

  const now = Date.now();
  const campaign = {
    id,
    name: label,
    templateId: tpl.id,
    vector: tpl.vector,
    severity: tpl.severity,
    targetRole: role,
    targetCount: targets.length,
    createdBy,
    createdAt: now,
    status: 'active',
    watermarked: true,
  };
  campaigns.push(campaign);

  for (const u of targets) {
    messages.push({
      id: `m-${crypto.randomBytes(8).toString('hex')}`,
      campaignId: id,
      userId: u.id,
      fromName: tpl.fromName,
      fromAddress: tpl.fromAddress,
      subject: tpl.subject,
      preview: tpl.preview,
      sentAt: now,
      triagedAt: null,
      action: null,
      correct: null,
    });
  }
  writeAll(campaigns, messages);
  return { campaign, metrics: campaignMetrics(campaign.id) };
}

/** Users available as simulation targets (projection, no secrets). */
function listTargetUsers() {
  return require('./auth').listUsers();
}

/**
 * Learner inbox projection. Red flags and the correct action are withheld so
 * the triage decision is genuinely the learner's (no answer leakage).
 */
function inboxFor(user) {
  const { campaigns, messages } = readAll();
  const byId = new Map(campaigns.map((c) => [c.id, c]));
  return messages
    .filter((m) => m.userId === user.id)
    .map((m) => ({
      id: m.id,
      campaignId: m.campaignId,
      fromName: m.fromName,
      fromAddress: m.fromAddress,
      subject: m.subject,
      preview: m.preview,
      sentAt: m.sentAt,
      triagedAt: m.triagedAt,
      action: m.action,
      correct: m.correct,
      simulation: true,
      vector: byId.get(m.campaignId) ? byId.get(m.campaignId).vector : 'simulation',
    }))
    .sort((a, b) => b.sentAt - a.sentAt);
}

/**
 * Record a triage decision. Returns the learning payload (red flags + guidance)
 * and the learner's own campaign rollup.
 */
function triage(user, campaignId, messageId, action) {
  if (!isSafeId(campaignId)) return { error: 'invalid_campaign_id' };
  if (!isSafeId(messageId)) return { error: 'invalid_message_id' };
  if (!ACTIONS.includes(action)) return { error: 'invalid_action' };

  const { campaigns, messages } = readAll();
  const campaign = campaigns.find((c) => c.id === campaignId);
  if (!campaign) return { error: 'not_found' };

  const msg = messages.find((m) => m.id === messageId && m.campaignId === campaignId && m.userId === user.id);
  if (!msg) return { error: 'not_found' }; // object-level authz — no cross-user triage
  if (msg.triagedAt) return { error: 'already_triaged' };

  const tpl = getTemplate(campaign.templateId);
  const correct = action === tpl.correct;
  msg.triagedAt = Date.now();
  msg.action = action;
  msg.correct = correct;
  writeAll(campaigns, messages);

  return {
    message: { id: msg.id, action, correct },
    result: {
      correct,
      correctAction: tpl.correct,
      redFlags: tpl.redFlags,
      guidance: tpl.guidance,
      severity: tpl.severity,
      vector: tpl.vector,
      timeToActionSec: Math.max(0, Math.round((msg.triagedAt - msg.sentAt) / 1000)),
    },
    myMetrics: userMetrics(user),
  };
}

/** Per-learner campaign rollup (shown on the threats view and dashboard). */
function userMetrics(user) {
  const { messages } = readAll();
  const mine = messages.filter((m) => m.userId === user.id);
  const triaged = mine.filter((m) => m.triagedAt);
  const reported = triaged.filter((m) => m.action === 'report').length;
  const clicked = triaged.filter((m) => m.action === 'click' || m.action === 'reply').length;
  const ttr = triaged.filter((m) => m.action === 'report').map((m) => m.triagedAt - m.sentAt);
  return {
    delivered: mine.length,
    pending: mine.length - triaged.length,
    triaged: triaged.length,
    reported,
    clicked,
    resilience: triaged.length ? Math.round((reported / triaged.length) * 100) : null,
    avgTimeToReportSec: ttr.length ? Math.round(ttr.reduce((a, b) => a + b, 0) / ttr.length / 1000) : null,
  };
}

/** Campaign funnel metrics (admin view + A.6.3 effectiveness evidence). */
function campaignMetrics(campaignId) {
  const { campaigns, messages } = readAll();
  const rel = messages.filter((m) => m.campaignId === campaignId);
  const triaged = rel.filter((m) => m.triagedAt);
  const reported = triaged.filter((m) => m.action === 'report').length;
  const clicked = triaged.filter((m) => m.action === 'click' || m.action === 'reply').length;
  const deleted = triaged.filter((m) => m.action === 'delete').length;
  const ignored = triaged.filter((m) => m.action === 'ignore').length;
  return {
    campaignId,
    delivered: rel.length,
    triaged: triaged.length,
    pending: rel.length - triaged.length,
    reported,
    clicked,
    deleted,
    ignored,
    reportRate: triaged.length ? Math.round((reported / triaged.length) * 100) : null,
    clickRate: triaged.length ? Math.round((clicked / triaged.length) * 100) : null,
    dismissRate: triaged.length ? Math.round(((deleted + ignored) / triaged.length) * 100) : null,
  };
}

/** All campaigns with metrics (admin console). */
function listCampaigns() {
  const { campaigns } = readAll();
  return campaigns
    .slice()
    .reverse()
    .map((c) => ({ ...c, metrics: campaignMetrics(c.id) }));
}

/** Org-wide simulation rollup across every campaign (KPI: click-rate ↓ 60%). */
function organizationMetrics() {
  const { campaigns, messages } = readAll();
  const triaged = messages.filter((m) => m.triagedAt);
  const reported = triaged.filter((m) => m.action === 'report').length;
  const clicked = triaged.filter((m) => m.action === 'click' || m.action === 'reply').length;
  return {
    campaigns: campaigns.length,
    active: campaigns.filter((c) => c.status === 'active').length,
    delivered: messages.length,
    triaged: triaged.length,
    pending: messages.length - triaged.length,
    reportRate: triaged.length ? Math.round((reported / triaged.length) * 100) : null,
    clickRate: triaged.length ? Math.round((clicked / triaged.length) * 100) : null,
    templates: TEMPLATES.map((t) => ({ id: t.id, vector: t.vector, severity: t.severity, subject: t.subject })),
  };
}

module.exports = {
  TEMPLATES,
  ACTIONS,
  getTemplate,
  createCampaign,
  inboxFor,
  triage,
  userMetrics,
  campaignMetrics,
  listCampaigns,
  organizationMetrics,
};
