/**
 * Proof Algebra — composable evidence stages.
 *
 * Each stage is a pure Kleisli-style arrow: Evidence -> Evidence.
 * Stages never invent ground truth; they only transform audited scores
 * and append an explanation trail. This is the "equation of equations"
 * for Sentinel-X verification: honest, inspectable, reorder-safe when
 * stages commute on independent channels.
 */

export interface Evidence {
  confidence: number;
  structural: number;
  trail: string[];
  tags: Record<string, number | string | boolean | null>;
}

export type EvidenceStage = (evidence: Evidence) => Evidence;

export function evidenceOf(confidence: number, structural = 0): Evidence {
  return {
    confidence: clamp(confidence),
    structural: clamp(structural, 0, 3),
    trail: [`seed confidence=${confidence.toFixed(3)} structural=${structural}`],
    tags: {},
  };
}

export function compose(...stages: EvidenceStage[]): EvidenceStage {
  return (input) => stages.reduce((acc, stage) => stage(acc), input);
}

export function stageLift(
  name: string,
  fn: (evidence: Evidence) => { confidence?: number; structural?: number; tag?: Record<string, number | string | boolean | null>; note?: string },
): EvidenceStage {
  return (evidence) => {
    const patch = fn(evidence);
    const next: Evidence = {
      confidence: clamp(patch.confidence ?? evidence.confidence),
      structural: clamp(patch.structural ?? evidence.structural, 0, 3),
      trail: [...evidence.trail, patch.note ?? `${name}`],
      tags: { ...evidence.tags, ...(patch.tag ?? {}), stage: name },
    };
    return next;
  };
}

export function collapse(evidence: Evidence, floor = 0.62): {
  verified: boolean;
  confidence: number;
  rationale: string;
} {
  const verified = evidence.confidence >= floor && evidence.structural >= 2;
  return {
    verified,
    confidence: evidence.confidence,
    rationale: `${verified ? 'ACCEPT' : 'REJECT'} :: ${evidence.trail.join(' → ')}`,
  };
}

function clamp(value: number, min = 0, max = 1): number {
  return Math.min(max, Math.max(min, value));
}
