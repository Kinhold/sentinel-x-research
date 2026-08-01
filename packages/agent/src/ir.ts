import { createHash } from 'node:crypto';
import type { DiscoveryFinding, VulnerabilitySeverity, VulnerabilityType } from '@sentinel-x/contracts';

export type SourceFile = { path: string; content: string };

export function lineNumberAt(content: string, index: number): number {
  return content.slice(0, index).split('\n').length;
}

export function snippet(content: string, index: number, radius = 1): string {
  const lines = content.slice(0).split('\n');
  const line = lineNumberAt(content, index) - 1;
  const start = Math.max(0, line - radius);
  const end = Math.min(lines.length, line + radius + 1);
  return lines.slice(start, end).join('\n');
}

export function windowAround(content: string, index: number, before = 80, after = 180): string {
  return content.slice(Math.max(0, index - before), Math.min(content.length, index + after));
}

export function fingerprintFinding(parts: {
  ruleId: string;
  file: string;
  line?: number;
  title: string;
}): string {
  return createHash('sha256')
    .update([parts.ruleId, parts.file, String(parts.line ?? 0), parts.title].join('|'))
    .digest('hex')
    .slice(0, 24);
}

export class FindingCollector {
  private readonly findings: DiscoveryFinding[] = [];
  private readonly seen = new Set<string>();

  push(
    file: SourceFile,
    matchIndex: number,
    draft: {
      ruleId: string;
      title: string;
      description: string;
      severity: VulnerabilitySeverity;
      vulnType: VulnerabilityType;
      affectedFunction?: string;
      confidenceScore: number;
      pocCode?: string;
    },
  ): void {
    const lineNumber = lineNumberAt(file.content, matchIndex);
    const fingerprint = fingerprintFinding({
      ruleId: draft.ruleId,
      file: file.path,
      line: lineNumber,
      title: draft.title,
    });
    if (this.seen.has(fingerprint)) return;
    this.seen.add(fingerprint);
    this.findings.push({
      title: draft.title,
      description: draft.description,
      severity: draft.severity,
      vulnType: draft.vulnType,
      affectedFile: file.path,
      affectedFunction: draft.affectedFunction,
      lineNumber,
      pocCode: draft.pocCode ?? snippet(file.content, matchIndex),
      confidenceScore: draft.confidenceScore,
      ruleId: draft.ruleId,
      fingerprint,
    });
  }

  all(): DiscoveryFinding[] {
    return this.findings;
  }
}

export function enclosingRustFn(content: string, index: number): string | undefined {
  const prefix = content.slice(0, index);
  const match = [...prefix.matchAll(/\bfn\s+([A-Za-z0-9_]+)/g)].at(-1);
  return match?.[1];
}

export function matchUsesLocalToken(content: string, matchIndex: number, token: string, radius = 120): boolean {
  const local = windowAround(content, matchIndex, radius, radius);
  return local.includes(token);
}
