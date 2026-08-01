import type { DiscoveryFinding, Vulnerability, VulnerabilitySeverity } from '@sentinel-x/contracts';

const SEVERITY_BITS: Record<VulnerabilitySeverity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  informational: 0.5,
};

/**
 * Information-gain style ranking for operator attention.
 * Surprise = binary entropy of confidence + severity bits + causal fan-in.
 * Higher score => review first. Honest: ranking, not truth.
 */
export function rankFindingsForAttention(
  findings: DiscoveryFinding[],
  options: { causalFanIn?: Record<string, number> } = {},
): Array<DiscoveryFinding & { attentionScore: number; surprise: number }> {
  return findings
    .map((finding) => {
      const p = clamp(finding.confidenceScore, 0.001, 0.999);
      const surprise = binaryEntropy(p);
      const severity = SEVERITY_BITS[finding.severity] ?? 1;
      const fanIn = options.causalFanIn?.[finding.fingerprint ?? ''] ?? 0;
      const attentionScore = Math.round((surprise * 2.2 + severity * 0.55 + fanIn * 0.35) * 1000) / 1000;
      return { ...finding, attentionScore, surprise: Math.round(surprise * 1000) / 1000 };
    })
    .sort((a, b) => b.attentionScore - a.attentionScore);
}

export function binaryEntropy(p: number): number {
  const q = 1 - p;
  return -(p * Math.log2(p) + q * Math.log2(q));
}

/**
 * Bayesian-ish rule prior update from operator outcomes.
 * reported => success evidence; false_positive => failure evidence.
 */
export function updateRulePrior(
  prior: { alpha: number; beta: number },
  outcome: 'reported' | 'false_positive',
): { alpha: number; beta: number; mean: number } {
  const next =
    outcome === 'reported'
      ? { alpha: prior.alpha + 1, beta: prior.beta }
      : { alpha: prior.alpha, beta: prior.beta + 1 };
  return { ...next, mean: next.alpha / (next.alpha + next.beta) };
}

export function priorBoostFromMean(mean: number): number {
  // mean 0.5 => 0; mean 0.9 => +0.06; mean 0.1 => -0.06
  return clamp((mean - 0.5) * 0.15, -0.08, 0.08);
}

export function defaultPrior(): { alpha: number; beta: number } {
  return { alpha: 2, beta: 2 };
}

export function learnPriorsFromHistory(
  vulns: Array<Pick<Vulnerability, 'ruleId' | 'status'>>,
): Record<string, { alpha: number; beta: number; mean: number }> {
  const priors: Record<string, { alpha: number; beta: number; mean: number }> = {};
  for (const vuln of vulns) {
    if (!vuln.ruleId) continue;
    if (vuln.status !== 'reported' && vuln.status !== 'false_positive') continue;
    const current = priors[vuln.ruleId] ?? { ...defaultPrior(), mean: 0.5 };
    priors[vuln.ruleId] = updateRulePrior(current, vuln.status);
  }
  return priors;
}

function clamp(value: number, min: number, max: number): number {
  return Math.min(max, Math.max(min, value));
}
