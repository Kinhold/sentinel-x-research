import type { DiscoveryFinding } from '@sentinel-x/contracts';

type SourceFile = { path: string; content: string };

function lineNumberAt(content: string, index: number): number {
  return content.slice(0, index).split('\n').length;
}

function pushFinding(
  findings: DiscoveryFinding[],
  seen: Set<string>,
  file: SourceFile,
  matchIndex: number,
  finding: Omit<DiscoveryFinding, 'lineNumber'> & { lineNumber?: number },
): void {
  const key = `${file.path}:${finding.title}:${finding.affectedFunction ?? ''}`;
  if (seen.has(key)) return;
  seen.add(key);
  findings.push({
    ...finding,
    affectedFile: file.path,
    lineNumber: finding.lineNumber ?? lineNumberAt(file.content, matchIndex),
  });
}

export function analyzeRustSources(files: SourceFile[]): DiscoveryFinding[] {
  const findings: DiscoveryFinding[] = [];
  const seen = new Set<string>();

  for (const file of files) {
    const overflowPattern = /\bchecked_add\b|\bwrapping_add\b|\bas\s+u(32|64|128)\b/g;
    let match: RegExpExecArray | null;
    while ((match = overflowPattern.exec(file.content)) !== null) {
      const usesWrapping = file.content.includes('wrapping_add');
      pushFinding(findings, seen, file, match.index, {
        title: usesWrapping ? 'Unchecked integer wrapping path' : 'Integer boundary conversion',
        description:
          'Arithmetic uses wrapping or narrowing conversions without an explicit domain check. Review for overflow-driven balance or index corruption.',
        severity: usesWrapping ? 'high' : 'medium',
        vulnType: 'integer_overflow',
        affectedFunction: extractRustFn(file.content, match.index),
        confidenceScore: usesWrapping ? 0.74 : 0.58,
        pocCode: snippet(file.content, match.index),
      });
    }

    const unsafePattern = /\bunsafe\s*\{/g;
    while ((match = unsafePattern.exec(file.content)) !== null) {
      pushFinding(findings, seen, file, match.index, {
        title: 'Unsafe block without documented invariant',
        description:
          'Unsafe Rust block detected. Defensive review should confirm lifetime, aliasing, and bounds invariants before trusting downstream attestations.',
        severity: 'medium',
        vulnType: 'access_control',
        affectedFunction: extractRustFn(file.content, match.index),
        confidenceScore: 0.52,
        pocCode: snippet(file.content, match.index),
      });
    }
  }

  return findings;
}

function extractRustFn(content: string, index: number): string | undefined {
  const prefix = content.slice(0, index);
  const fnMatch = [...prefix.matchAll(/\bfn\s+([A-Za-z0-9_]+)/g)].at(-1);
  return fnMatch?.[1];
}

function snippet(content: string, index: number): string {
  const lines = content.split('\n');
  const line = lineNumberAt(content, index) - 1;
  const start = Math.max(0, line - 1);
  const end = Math.min(lines.length, line + 2);
  return lines.slice(start, end).join('\n');
}
