import type { DiscoveryFinding, TargetLanguage, Vulnerability } from '@sentinel-x/contracts';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

export type HypothesisStatus = 'proposed' | 'supported' | 'refuted' | 'inconclusive';

export interface Hypothesis {
  id: string;
  findingFingerprint?: string;
  ruleId?: string;
  claim: string;
  status: HypothesisStatus;
  evidence: string[];
  confidenceDelta: number;
}

export interface HypothesisEngineOptions {
  workspacePath: string;
  language: TargetLanguage;
  signal?: AbortSignal;
}

/**
 * Constrained defensive hypothesis loop.
 * Allowlisted tools only: read file slice, count pattern hits, check nearby guards.
 * Never executes target code, never network, never writes.
 */
export function runHypothesisEngine(
  findings: DiscoveryFinding[],
  options: HypothesisEngineOptions,
): Hypothesis[] {
  const hypotheses: Hypothesis[] = [];
  for (const finding of findings) {
    if (options.signal?.aborted) break;
    hypotheses.push(...evaluateFinding(finding, findings, options));
  }
  return hypotheses;
}

function evaluateFinding(
  finding: DiscoveryFinding,
  allFindings: DiscoveryFinding[],
  options: HypothesisEngineOptions,
): Hypothesis[] {
  const out: Hypothesis[] = [];
  const baseId = `${finding.fingerprint ?? finding.ruleId ?? 'anon'}`;

  const h1: Hypothesis = {
    id: `${baseId}:loc`,
    findingFingerprint: finding.fingerprint,
    ruleId: finding.ruleId,
    claim: `Location ${finding.affectedFile ?? 'unknown'}:${finding.lineNumber ?? '?'} reproduces the static signal`,
    status: 'proposed',
    evidence: [],
    confidenceDelta: 0,
  };

  if (!finding.affectedFile || !finding.lineNumber) {
    h1.status = 'inconclusive';
    h1.evidence.push('Missing file/line anchors');
    out.push(h1);
    return out;
  }

  const absolute = join(options.workspacePath, finding.affectedFile);
  if (!existsSync(absolute)) {
    h1.status = 'refuted';
    h1.evidence.push('Affected file missing from workspace');
    h1.confidenceDelta = -0.12;
    out.push(h1);
    return out;
  }

  const content = readFileSync(absolute, 'utf8');
  const lines = content.split('\n');
  const idx = finding.lineNumber - 1;
  const slice = lines.slice(Math.max(0, idx - 2), Math.min(lines.length, idx + 3)).join('\n');
  h1.evidence.push(`slice:\n${slice}`);

  if (finding.pocCode && slice.includes(finding.pocCode.split('\n')[0]!.trim().slice(0, 24))) {
    h1.status = 'supported';
    h1.confidenceDelta = 0.05;
    h1.evidence.push('PoC first line appears in local slice');
  } else if (finding.ruleId?.includes('wrapping') && /wrapping_(?:add|sub|mul)/.test(slice)) {
    h1.status = 'supported';
    h1.confidenceDelta = 0.05;
  } else if (finding.ruleId?.includes('underconstrained') || finding.vulnType === 'under_constrained_circuit') {
    const hasAssert = /\bassert(?:_eq)?\s*\(/.test(content);
    h1.status = hasAssert ? 'inconclusive' : 'supported';
    h1.confidenceDelta = hasAssert ? 0 : 0.04;
    h1.evidence.push(hasAssert ? 'File contains asserts; need witness binding review' : 'No asserts in file');
  } else if (finding.vulnType === 'cpi_vulnerability') {
    const nearby = lines.slice(Math.max(0, idx - 8), Math.min(lines.length, idx + 12)).join('\n');
    const guarded = /is_signer|has_one|owner/.test(nearby);
    h1.status = guarded ? 'refuted' : 'supported';
    h1.confidenceDelta = guarded ? -0.08 : 0.05;
    h1.evidence.push(guarded ? 'Nearby signer/owner guard detected' : 'No nearby signer/owner guard');
  } else {
    h1.status = 'supported';
    h1.confidenceDelta = 0.02;
  }

  out.push(h1);

  // Second hypothesis: blast radius / correlation risk in same function
  if (finding.affectedFunction) {
    const h2: Hypothesis = {
      id: `${baseId}:fn-blast`,
      findingFingerprint: finding.fingerprint,
      ruleId: finding.ruleId,
      claim: `Function ${finding.affectedFunction} may concentrate multiple weakness classes`,
      status: 'proposed',
      evidence: [],
      confidenceDelta: 0,
    };
    const fnHits = allFindings.filter(
      (f) => f.affectedFile === finding.affectedFile && f.affectedFunction === finding.affectedFunction,
    );
    if (fnHits.length >= 2) {
      h2.status = 'supported';
      h2.confidenceDelta = 0.03;
      h2.evidence.push(`${fnHits.length} findings share function ${finding.affectedFunction}`);
    } else {
      h2.status = 'inconclusive';
      h2.evidence.push('Single finding in function');
    }
    out.push(h2);
  }

  return out;
}

export function applyHypothesisDeltas(
  finding: DiscoveryFinding,
  hypotheses: Hypothesis[],
): DiscoveryFinding {
  const related = hypotheses.filter(
    (h) => h.findingFingerprint === finding.fingerprint || h.ruleId === finding.ruleId,
  );
  const delta = related.reduce((sum, h) => sum + h.confidenceDelta, 0);
  return {
    ...finding,
    confidenceScore: Math.min(0.99, Math.max(0.05, finding.confidenceScore + delta)),
  };
}

export function summarizeHypotheses(hypotheses: Hypothesis[]): {
  proposed: number;
  supported: number;
  refuted: number;
  inconclusive: number;
} {
  return {
    proposed: hypotheses.filter((h) => h.status === 'proposed').length,
    supported: hypotheses.filter((h) => h.status === 'supported').length,
    refuted: hypotheses.filter((h) => h.status === 'refuted').length,
    inconclusive: hypotheses.filter((h) => h.status === 'inconclusive').length,
  };
}

export function portfolioRiskScore(vulnerabilities: Vulnerability[]): {
  score: number;
  band: 'low' | 'moderate' | 'elevated' | 'critical';
  nodes: number;
  edges: number;
  clusters: Array<{ key: string; size: number; severities: string[] }>;
} {
  const weights: Record<string, number> = {
    critical: 10,
    high: 6,
    medium: 3,
    low: 1,
    informational: 0.25,
  };
  const active = vulnerabilities.filter((v) => v.status === 'verified' || v.status === 'reported' || v.status === 'discovered');
  const raw = active.reduce((sum, v) => sum + (weights[v.severity] ?? 1) * (v.confidenceScore ?? 0.5), 0);

  const graph = new Map<string, Set<string>>();
  for (const v of active) {
    const fileKey = `file:${v.affectedFile ?? 'unknown'}`;
    const fnKey = `fn:${v.affectedFile ?? 'unknown'}:${v.affectedFunction ?? 'unknown'}`;
    const typeKey = `type:${v.vulnType}`;
    for (const key of [fileKey, fnKey, typeKey]) {
      if (!graph.has(key)) graph.set(key, new Set());
      graph.get(key)!.add(String(v.id));
    }
  }

  const clusters = [...graph.entries()]
    .map(([key, ids]) => ({
      key,
      size: ids.size,
      severities: active.filter((v) => ids.has(String(v.id))).map((v) => v.severity),
    }))
    .filter((c) => c.size >= 2)
    .sort((a, b) => b.size - a.size)
    .slice(0, 12);

  const clusterBoost = clusters.reduce((sum, c) => sum + (c.size - 1) * 0.75, 0);
  const score = Math.round((raw + clusterBoost) * 10) / 10;
  const band = score >= 40 ? 'critical' : score >= 20 ? 'elevated' : score >= 8 ? 'moderate' : 'low';
  const edges = clusters.reduce((sum, c) => sum + c.size, 0);

  return { score, band, nodes: active.length, edges, clusters };
}
