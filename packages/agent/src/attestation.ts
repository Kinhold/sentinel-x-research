import { createHmac, createHash } from 'node:crypto';
import type { Vulnerability } from '@sentinel-x/contracts';

export interface ScanAttestation {
  version: 1;
  scanId: number;
  targetId: number;
  generatedAt: string;
  sourceMode?: string | null;
  sourceCommit?: string | null;
  rulePackHash: string;
  findingFingerprints: string[];
  verifiedFingerprints: string[];
  bugsFound: number;
  bugsVerified: number;
  contentHash: string;
  signature: string | null;
}

export function hashRulePackPayload(payload: unknown): string {
  return createHash('sha256').update(JSON.stringify(payload)).digest('hex');
}

export function buildScanAttestation(input: {
  scanId: number;
  targetId: number;
  sourceMode?: string | null;
  sourceCommit?: string | null;
  rulePackHash: string;
  vulnerabilities: Vulnerability[];
  secret?: string | null;
}): ScanAttestation {
  const findingFingerprints = input.vulnerabilities
    .map((v) => v.fingerprint)
    .filter((fp): fp is string => Boolean(fp))
    .sort();
  const verifiedFingerprints = input.vulnerabilities
    .filter((v) => v.status === 'verified' || v.status === 'reported')
    .map((v) => v.fingerprint)
    .filter((fp): fp is string => Boolean(fp))
    .sort();

  const body = {
    version: 1 as const,
    scanId: input.scanId,
    targetId: input.targetId,
    generatedAt: new Date().toISOString(),
    sourceMode: input.sourceMode ?? null,
    sourceCommit: input.sourceCommit ?? null,
    rulePackHash: input.rulePackHash,
    findingFingerprints,
    verifiedFingerprints,
    bugsFound: input.vulnerabilities.length,
    bugsVerified: verifiedFingerprints.length,
  };

  const contentHash = createHash('sha256').update(stableStringify(body)).digest('hex');
  const secret = input.secret ?? process.env.ATTESTATION_SECRET ?? null;
  const signature = secret
    ? createHmac('sha256', secret).update(`${contentHash}.${stableStringify(body)}`).digest('hex')
    : null;

  return { ...body, contentHash, signature };
}

export function verifyScanAttestation(
  attestation: ScanAttestation,
  secret?: string | null,
): { ok: boolean; reason?: string } {
  const { contentHash, signature, ...body } = attestation;
  const expectedHash = createHash('sha256').update(stableStringify(body)).digest('hex');
  if (expectedHash !== contentHash) {
    return { ok: false, reason: 'content hash mismatch' };
  }
  const key = secret ?? process.env.ATTESTATION_SECRET ?? null;
  if (!key) {
    return signature ? { ok: false, reason: 'signature present but no secret configured' } : { ok: true };
  }
  if (!signature) return { ok: false, reason: 'missing signature' };
  const expectedSig = createHmac('sha256', key).update(`${contentHash}.${stableStringify(body)}`).digest('hex');
  if (expectedSig !== signature) return { ok: false, reason: 'signature mismatch' };
  return { ok: true };
}

function stableStringify(value: unknown): string {
  return JSON.stringify(sortValue(value));
}

function sortValue(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortValue);
  if (value && typeof value === 'object') {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .sort(([a], [b]) => a.localeCompare(b))
        .map(([k, v]) => [k, sortValue(v)]),
    );
  }
  return value;
}
