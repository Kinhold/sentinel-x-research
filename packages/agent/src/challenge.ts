import { createHash, randomBytes } from 'node:crypto';

export interface OperatorChallenge {
  challengeId: string;
  vulnerabilityId: number;
  prompt: string;
  /** Fields the operator must echo back correctly. */
  requiredEcho: {
    ruleId: string;
    fingerprint: string;
    affectedFile: string;
    lineNumber: number;
  };
  nonce: string;
  expiresAt: string;
  issuedAt: string;
}

export interface ChallengeAnswer {
  challengeId: string;
  vulnerabilityId: number;
  ruleId: string;
  fingerprint: string;
  affectedFile: string;
  lineNumber: number;
  nonce: string;
}

const store = new Map<string, OperatorChallenge>();

/**
 * Dual-control style gate before marking a finding `reported`.
 * Operator must prove they inspected the binding fields — not a CAPTCHA,
 * an accountability challenge.
 */
export function issueOperatorChallenge(input: {
  vulnerabilityId: number;
  ruleId?: string | null;
  fingerprint?: string | null;
  affectedFile?: string | null;
  lineNumber?: number | null;
  ttlMs?: number;
}): OperatorChallenge {
  const challengeId = createHash('sha256').update(randomBytes(16)).digest('hex').slice(0, 16);
  const nonce = randomBytes(8).toString('hex');
  const challenge: OperatorChallenge = {
    challengeId,
    vulnerabilityId: input.vulnerabilityId,
    prompt:
      'Echo ruleId, fingerprint, affectedFile, lineNumber, and nonce exactly to confirm live-scope review before marking reported.',
    requiredEcho: {
      ruleId: input.ruleId ?? '',
      fingerprint: input.fingerprint ?? '',
      affectedFile: input.affectedFile ?? '',
      lineNumber: input.lineNumber ?? 0,
    },
    nonce,
    issuedAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + (input.ttlMs ?? 15 * 60_000)).toISOString(),
  };
  store.set(challengeId, challenge);
  return challenge;
}

export function verifyOperatorChallenge(answer: ChallengeAnswer): { ok: boolean; reason?: string } {
  const challenge = store.get(answer.challengeId);
  if (!challenge) return { ok: false, reason: 'unknown challenge' };
  if (Date.parse(challenge.expiresAt) < Date.now()) {
    store.delete(answer.challengeId);
    return { ok: false, reason: 'challenge expired' };
  }
  if (answer.vulnerabilityId !== challenge.vulnerabilityId) return { ok: false, reason: 'vulnerability mismatch' };
  if (answer.nonce !== challenge.nonce) return { ok: false, reason: 'nonce mismatch' };
  const echo = challenge.requiredEcho;
  if (answer.ruleId !== echo.ruleId) return { ok: false, reason: 'ruleId mismatch' };
  if (answer.fingerprint !== echo.fingerprint) return { ok: false, reason: 'fingerprint mismatch' };
  if (answer.affectedFile !== echo.affectedFile) return { ok: false, reason: 'affectedFile mismatch' };
  if (answer.lineNumber !== echo.lineNumber) return { ok: false, reason: 'lineNumber mismatch' };
  store.delete(answer.challengeId);
  return { ok: true };
}

export function clearChallenges(): void {
  store.clear();
}
