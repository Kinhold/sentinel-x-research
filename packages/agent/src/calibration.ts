import { join } from 'node:path';
import type { DiscoveryFinding, TargetLanguage } from '@sentinel-x/contracts';
import { analyzeFixtureDirectory } from './discovery.js';

export interface CalibrationPoint {
  language: TargetLanguage;
  ruleId: string;
  predicted: number;
  label: 0 | 1;
}

export interface CalibrationModel {
  /** Piecewise isotonic-ish map: raw confidence -> calibrated confidence */
  bins: Array<{ lo: number; hi: number; calibrated: number; n: number }>;
  brierScore: number;
  samples: number;
  builtAt: string;
}

/**
 * Fit a simple reliability diagram from labeled fixture pairs.
 * Vuln fixtures label discoveries as 1; safe fixtures label as 0 when a rule fires
 * (false positive), and contribute no points when quiet.
 */
export function fitCalibration(points: CalibrationPoint[]): CalibrationModel {
  const edges = [0, 0.2, 0.4, 0.6, 0.8, 1.0001];
  const bins = edges.slice(0, -1).map((lo, i) => {
    const hi = edges[i + 1]!;
    const inBin = points.filter((p) => p.predicted >= lo && p.predicted < hi);
    const rate = inBin.length ? inBin.reduce((s, p) => s + p.label, 0) / inBin.length : (lo + hi) / 2;
    return { lo, hi, calibrated: rate, n: inBin.length };
  });

  const brier =
    points.length === 0
      ? 0
      : points.reduce((sum, p) => {
          const cal = applyCalibration({ bins, brierScore: 0, samples: 0, builtAt: '' }, p.predicted);
          return sum + (cal - p.label) ** 2;
        }, 0) / Math.max(1, points.length);

  return {
    bins,
    brierScore: Math.round(brier * 10_000) / 10_000,
    samples: points.length,
    builtAt: new Date().toISOString(),
  };
}

export function applyCalibration(model: CalibrationModel, raw: number): number {
  const bin = model.bins.find((b) => raw >= b.lo && raw < b.hi) ?? model.bins.at(-1);
  if (!bin || bin.n === 0) return raw;
  // Blend toward empirical rate; never fully discard the raw score.
  return Math.min(0.99, Math.max(0.01, 0.45 * raw + 0.55 * bin.calibrated));
}

export function collectFixtureCalibrationPoints(fixturesDir: string): CalibrationPoint[] {
  const pairs: Array<{ language: TargetLanguage; vuln: string; safe: string }> = [
    { language: 'rust', vuln: 'rust-sample', safe: 'rust-safe' },
    { language: 'noir', vuln: 'noir-sample', safe: 'noir-safe' },
    { language: 'solana', vuln: 'solana-sample', safe: 'solana-safe' },
  ];
  const points: CalibrationPoint[] = [];
  for (const pair of pairs) {
    const vulnFindings = analyzeFixtureDirectory(join(fixturesDir, pair.vuln), pair.language);
    for (const finding of vulnFindings) {
      points.push({
        language: pair.language,
        ruleId: finding.ruleId ?? 'unknown',
        predicted: finding.confidenceScore,
        label: 1,
      });
    }
    const safeFindings = analyzeFixtureDirectory(join(fixturesDir, pair.safe), pair.language);
    for (const finding of safeFindings) {
      points.push({
        language: pair.language,
        ruleId: finding.ruleId ?? 'unknown',
        predicted: finding.confidenceScore,
        label: 0,
      });
    }
  }
  return points;
}

export function calibrateFinding(finding: DiscoveryFinding, model: CalibrationModel): DiscoveryFinding {
  return {
    ...finding,
    confidenceScore: applyCalibration(model, finding.confidenceScore),
  };
}
