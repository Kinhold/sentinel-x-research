import type { DiscoveryFinding, TargetLanguage, VulnerabilitySeverity, VulnerabilityType } from '@sentinel-x/contracts';
import { FindingCollector, type SourceFile, windowAround } from '../ir.js';

export interface DeclarativeRule {
  id: string;
  language: TargetLanguage | 'any';
  title: string;
  description: string;
  severity: VulnerabilitySeverity;
  vulnType: VulnerabilityType;
  pattern: string;
  flags?: string;
  /** If this regex matches the local window, suppress the hit. */
  unless?: string;
  confidence: number;
  windowBefore?: number;
  windowAfter?: number;
  cwe?: string;
}

export interface RulePack {
  id: string;
  version: string;
  rules: DeclarativeRule[];
}

export function loadRulePack(pack: RulePack): RulePack {
  if (!pack.id || !Array.isArray(pack.rules)) {
    throw new Error('Invalid rule pack');
  }
  for (const rule of pack.rules) {
    // Compile once to fail fast on bad patterns
    new RegExp(rule.pattern, rule.flags ?? 'g');
    if (rule.unless) new RegExp(rule.unless, 'm');
  }
  return pack;
}

export function applyRulePack(
  pack: RulePack,
  language: TargetLanguage,
  files: SourceFile[],
): DiscoveryFinding[] {
  const collector = new FindingCollector();
  const rules = pack.rules.filter((rule) => rule.language === language || rule.language === 'any');

  for (const file of files) {
    for (const rule of rules) {
      const regex = new RegExp(rule.pattern, rule.flags ?? 'g');
      let match: RegExpExecArray | null;
      while ((match = regex.exec(file.content)) !== null) {
        const before = rule.windowBefore ?? 100;
        const after = rule.windowAfter ?? 180;
        const local = windowAround(file.content, match.index, before, after);
        if (rule.unless && new RegExp(rule.unless, 'm').test(local)) continue;
        collector.push(file, match.index, {
          ruleId: `${pack.id}.${rule.id}`,
          title: rule.title.includes('$1') && match[1] ? rule.title.replace('$1', match[1]) : rule.title,
          description: rule.cwe ? `${rule.description} (CWE-${rule.cwe})` : rule.description,
          severity: rule.severity,
          vulnType: rule.vulnType,
          confidenceScore: rule.confidence,
        });
        if (!regex.global) break;
      }
    }
  }

  return collector.all();
}

export function mergeFindings(...groups: DiscoveryFinding[][]): DiscoveryFinding[] {
  const seen = new Set<string>();
  const out: DiscoveryFinding[] = [];
  for (const group of groups) {
    for (const finding of group) {
      const key = finding.fingerprint ?? `${finding.ruleId}:${finding.affectedFile}:${finding.lineNumber}:${finding.title}`;
      if (seen.has(key)) continue;
      seen.add(key);
      out.push(finding);
    }
  }
  return out;
}
