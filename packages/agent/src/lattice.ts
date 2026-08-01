import type { DiscoveryFinding } from '@sentinel-x/contracts';
import type { ToolAdapterResult } from './verify-adapters.js';

export interface LatticeInput {
  finding: DiscoveryFinding;
  structuralScore: number;
  adapterBoost: number;
  adapters?: ToolAdapterResult[];
  /** Historical false-positive rate for this ruleId in [0,1], if known. */
  historicalFpRate?: number;
  priorVerifiedSameFingerprint?: boolean;
}

export interface LatticeResult {
  confidence: number;
  components: {
    base: number;
    structural: number;
    adapters: number;
    history: number;
    prior: number;
  };
  rationale: string;
}

/**
 * Confidence lattice: fuse independent evidence channels into a bounded score.
 * Channels are intentionally simple, auditable weights — not a black-box model.
 */
export function fuseConfidence(input: LatticeInput): LatticeResult {
  const base = clamp(input.finding.confidenceScore, 0, 1);
  const structural = clamp(input.structuralScore / 3, 0, 1) * 0.18;
  const adapters = clamp(input.adapterBoost, 0, 0.15);
  const history =
    input.historicalFpRate == null ? 0 : clamp(0.12 - input.historicalFpRate * 0.2, -0.12, 0.12);
  const prior = input.priorVerifiedSameFingerprint ? 0.08 : 0;
  const confidence = clamp(base + structural + adapters + history + prior, 0.05, 0.99);

  const rationale = [
    `base=${base.toFixed(2)}`,
    `structural=+${structural.toFixed(2)}`,
    `adapters=+${adapters.toFixed(2)}`,
    `history=${history >= 0 ? '+' : ''}${history.toFixed(2)}`,
    `prior=+${prior.toFixed(2)}`,
    `=> ${confidence.toFixed(2)}`,
  ].join(' ');

  return {
    confidence,
    components: { base, structural, adapters, history, prior },
    rationale,
  };
}

export function structuralEvidenceScore(finding: DiscoveryFinding): number {
  const hasSnippet = Boolean(finding.pocCode && finding.pocCode.trim().length >= 8);
  const hasLocation = Boolean(finding.affectedFile && finding.lineNumber);
  const hasRule = Boolean(finding.ruleId || finding.fingerprint);
  return [hasSnippet, hasLocation, hasRule].filter(Boolean).length;
}

function clamp(value: number, min: number, max: number): number {
  return Math.min(max, Math.max(min, value));
}
