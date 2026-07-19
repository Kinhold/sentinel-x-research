import type { DiscoveryFinding } from '@sentinel-x/contracts';

type SourceFile = { path: string; content: string };

export function analyzeNoirSources(files: SourceFile[]): DiscoveryFinding[] {
  const findings: DiscoveryFinding[] = [];
  const seen = new Set<string>();

  for (const file of files) {
    const privateInputs = [
      ...file.content.matchAll(/\b(?:let|pub)?\s*([A-Za-z0-9_]+)\s*:\s*Field\b/g),
    ]
      .map((m) => m[1])
      .filter((name) => name !== 'pub');
    const asserts = new Set([...file.content.matchAll(/\bassert\s*\(\s*([A-Za-z0-9_]+)/g)].map((m) => m[1]));
    const publicInputs = new Set(
      [...file.content.matchAll(/\b([A-Za-z0-9_]+)\s*:\s*pub\s+Field\b/g)].map((m) => m[1]),
    );

    for (const input of privateInputs) {
      if (publicInputs.has(input)) continue;
      if (asserts.has(input)) continue;
      const index = file.content.indexOf(input);
      const key = `${file.path}:unconstrained:${input}`;
      if (seen.has(key)) continue;
      seen.add(key);
      findings.push({
        title: `Private field ${input} lacks explicit constraint`,
        description:
          'A private Field input is never referenced in an assertion. This is a classic under-constrained witness lane in Noir circuits.',
        severity: 'high',
        vulnType: 'under_constrained_circuit',
        affectedFile: file.path,
        affectedFunction: 'main',
        lineNumber: lineNumberAt(file.content, index),
        confidenceScore: 0.81,
        pocCode: snippet(file.content, index),
      });
    }

    const divPattern = /\b\/\b/g;
    let match: RegExpExecArray | null;
    while ((match = divPattern.exec(file.content)) !== null) {
      const context = file.content.slice(Math.max(0, match.index - 40), match.index + 40);
      if (!/assert|!=\s*0|is_zero/.test(context)) {
        const key = `${file.path}:division:${match.index}`;
        if (seen.has(key)) continue;
        seen.add(key);
        findings.push({
          title: 'Division without zero guard',
          description: 'Field division appears without an adjacent zero-check assertion. Review for unconstrained denominator witnesses.',
          severity: 'medium',
          vulnType: 'arithmetic_error',
          affectedFile: file.path,
          lineNumber: lineNumberAt(file.content, match.index),
          confidenceScore: 0.63,
          pocCode: snippet(file.content, match.index),
        });
      }
    }
  }

  return findings;
}

function lineNumberAt(content: string, index: number): number {
  return content.slice(0, index).split('\n').length;
}

function snippet(content: string, index: number): string {
  const lines = content.split('\n');
  const line = lineNumberAt(content, index) - 1;
  return lines.slice(Math.max(0, line - 1), Math.min(lines.length, line + 2)).join('\n');
}
