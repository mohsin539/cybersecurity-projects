import { jsonServer, health, isMain } from '@pathsphere/server-kit';
import { generateKeyPairSync, sign, verify } from 'node:crypto';
import { sha256Hex } from '@pathsphere/security-utils';
import type { ReportManifest } from '@pathsphere/shared-types';

/** Report engine — signs canonical report bodies with Ed25519.
 *  /verify recomputes sha256 over the body and checks the detached signature
 *  against /public-key (key integrity: ISO A.8.13 / NIST SP 800-53).
 *  In production keys come from KMS; here a process-local Ed25519 keypair. */

export interface SignedReport {
  reportId: string;
  manifest: ReportManifest;
  body: Record<string, unknown>;
  bodyBytes: string; // hex sha256 of canonical body
  signature: string; // hex Ed25519 sig
  signerKid: string;
  producedAt: string;
}

function sha256HexOf(obj: Record<string, unknown>): string {
  return sha256Hex(JSON.stringify(obj));
}

export function createReportEngine() {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' }).toString();
  const privateKeyPem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
  const kid = 'ps3d-signer-1';
  const reports = new Map<string, SignedReport>();

  function buildReport(manifest: ReportManifest): SignedReport {
    const body = {
      reportId: manifest.reportId,
      reportType: manifest.reportType,
      params: manifest.params,
      graphVersion: manifest.graphVersion,
      classification: manifest.classification,
      generatedBy: 'pathsphere-report-engine',
      generatedAt: new Date().toISOString(),
    };
    const bodyBytes = sha256HexOf(body);
    const signature = sign(null, Buffer.from(bodyBytes, 'hex'), privateKey).toString('hex');
    return {
      reportId: manifest.reportId,
      manifest,
      body,
      bodyBytes,
      signature,
      signerKid: kid,
      producedAt: body.generatedAt,
    };
  }

  function verifyReport(report: SignedReport): boolean {
    if (sha256HexOf(report.body) !== report.bodyBytes) return false;
    try {
      return verify(null, Buffer.from(report.bodyBytes, 'hex'), publicKey, Buffer.from(report.signature, 'hex'));
    } catch {
      return false;
    }
  }

  const server = jsonServer([
    { method: 'GET', path: /^\/service$/, handler: health('report-engine') },
    { method: 'GET', path: /^\/public-key$/, handler: (ctx) => ctx.jsonOk({ publicKey: publicKeyPem, kid }) },
    {
      method: 'POST',
      path: /^\/reports$/,
      handler: async (ctx) => {
        const body = await ctx.json<Partial<ReportManifest>>();
        if (!body || typeof body.reportType !== 'string') throw new Error('bad_request');
        const manifest: ReportManifest = {
          reportId: `r-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 6)}`,
          reportType: body.reportType,
          params: body.params ?? {},
          graphVersion: body.graphVersion ?? 'g-demo-1',
          authorId: body.authorId ?? 'system',
          approverId: body.approverId,
          classification: body.classification ?? 'internal',
        };
        const signed = buildReport(manifest);
        reports.set(signed.reportId, signed);
        console.log(JSON.stringify({
          service: 'report-engine', action: 'report.signed', reportId: signed.reportId,
          bodyBytes: signed.bodyBytes, ts: new Date().toISOString(),
        }));
        return ctx.send(201, signed);
      },
    },
    {
      method: 'GET',
      path: /^\/reports\/(.+)$/,
      handler: (ctx) => {
        const report = reports.get(decodeURIComponent(ctx.seg[1] ?? ''));
        if (!report) throw new Error('not_found');
        return ctx.jsonOk(report);
      },
    },
    {
      method: 'POST',
      path: /^\/verify$/,
      handler: async (ctx) => {
        const body = await ctx.json<SignedReport>();
        if (!body || !body.bodyBytes || !body.signature || !body.body) throw new Error('bad_request');
        return ctx.jsonOk({ reportId: body.reportId, valid: verifyReport(body) });
      },
    },
  ]);

  return { server, buildReport, verifyReport, publicKeyPem };
}

export async function main(): Promise<void> {
  const port = Number(process.env.REPORT_PORT) || 8085;
  const { server } = createReportEngine();
  server.listen(port, '0.0.0.0', () => console.log(`[report-engine] listening on :${port}`));
}

if (isMain(import.meta.url)) {
  void main();
}