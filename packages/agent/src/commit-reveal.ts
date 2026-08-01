import { createHash, randomBytes } from 'node:crypto';
import type { Vulnerability } from '@sentinel-x/contracts';

export interface ReviewCommitment {
  commitmentId: string;
  vulnerabilityId: number;
  /** SHA-256(secret || canonical review payload) */
  commitment: string;
  issuedAt: string;
  expiresAt: string;
}

export interface ReviewReveal {
  commitmentId: string;
  vulnerabilityId: number;
  secret: string;
  notes: string;
  decision: 'approve_report' | 'reject_false_positive' | 'defer';
}

interface PendingCommitment {
  commitment: ReviewCommitment;
  expectedHash: string;
  payload: { notes: string; decision: ReviewReveal['decision'] };
}

const pending = new Map<string, PendingCommitment>();

/**
 * Commit-reveal envelope for operator review.
 * Commit first (blinds the decision), reveal later — prevents retroactive editing of review notes.
 */
export function commitReview(input: {
  vulnerabilityId: number;
  notes: string;
  decision: ReviewReveal['decision'];
  ttlMs?: number;
}): { commitment: ReviewCommitment; secret: string } {
  const secret = randomBytes(16).toString('hex');
  const payload = { notes: input.notes.trim(), decision: input.decision };
  const expectedHash = hashCommit(secret, input.vulnerabilityId, payload);
  const commitmentId = createHash('sha256').update(randomBytes(12)).digest('hex').slice(0, 16);
  const commitment: ReviewCommitment = {
    commitmentId,
    vulnerabilityId: input.vulnerabilityId,
    commitment: expectedHash,
    issuedAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + (input.ttlMs ?? 30 * 60_000)).toISOString(),
  };
  pending.set(commitmentId, { commitment, expectedHash, payload });
  return { commitment, secret };
}

export function revealReview(reveal: ReviewReveal): {
  ok: boolean;
  reason?: string;
  decision?: ReviewReveal['decision'];
  notes?: string;
} {
  const entry = pending.get(reveal.commitmentId);
  if (!entry) return { ok: false, reason: 'unknown commitment' };
  if (Date.parse(entry.commitment.expiresAt) < Date.now()) {
    pending.delete(reveal.commitmentId);
    return { ok: false, reason: 'commitment expired' };
  }
  if (reveal.vulnerabilityId !== entry.commitment.vulnerabilityId) {
    return { ok: false, reason: 'vulnerability mismatch' };
  }
  const actual = hashCommit(reveal.secret, reveal.vulnerabilityId, {
    notes: reveal.notes.trim(),
    decision: reveal.decision,
  });
  if (actual !== entry.expectedHash) {
    return { ok: false, reason: 'commitment mismatch' };
  }
  pending.delete(reveal.commitmentId);
  return { ok: true, decision: reveal.decision, notes: reveal.notes.trim() };
}

export function merkleRoot(leaves: string[]): string {
  if (leaves.length === 0) return createHash('sha256').update('empty').digest('hex');
  let layer = leaves.map((leaf) => createHash('sha256').update(leaf).digest('hex'));
  while (layer.length > 1) {
    const next: string[] = [];
    for (let i = 0; i < layer.length; i += 2) {
      const left = layer[i]!;
      const right = layer[i + 1] ?? left;
      next.push(createHash('sha256').update(left + right).digest('hex'));
    }
    layer = next;
  }
  return layer[0]!;
}

export function campaignLineageRoot(attestations: Array<{ contentHash: string; scanId: number }>): string {
  const leaves = [...attestations]
    .sort((a, b) => a.scanId - b.scanId)
    .map((a) => `${a.scanId}:${a.contentHash}`);
  return merkleRoot(leaves);
}

export function vulnerabilityLeaf(v: Pick<Vulnerability, 'id' | 'fingerprint' | 'status' | 'ruleId'>): string {
  return `${v.id}|${v.ruleId ?? ''}|${v.fingerprint ?? ''}|${v.status}`;
}

function hashCommit(
  secret: string,
  vulnerabilityId: number,
  payload: { notes: string; decision: string },
): string {
  return createHash('sha256')
    .update(`${secret}|${vulnerabilityId}|${payload.decision}|${payload.notes}`)
    .digest('hex');
}

export function clearCommitments(): void {
  pending.clear();
}
