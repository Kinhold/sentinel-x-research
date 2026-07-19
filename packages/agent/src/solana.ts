import type { DiscoveryFinding } from '@sentinel-x/contracts';

type SourceFile = { path: string; content: string };

export function analyzeSolanaSources(files: SourceFile[]): DiscoveryFinding[] {
  const findings: DiscoveryFinding[] = [];
  const seen = new Set<string>();

  for (const file of files) {
    const cpiPattern = /invoke(?:_signed)?\s*\(/g;
    let match: RegExpExecArray | null;
    while ((match = cpiPattern.exec(file.content)) !== null) {
      const context = file.content.slice(match.index, match.index + 220);
      if (!/owner|signer|is_signer|has_one/.test(context)) {
        const key = `${file.path}:cpi:${match.index}`;
        if (seen.has(key)) continue;
        seen.add(key);
        findings.push({
          title: 'CPI without signer or owner guard',
          description:
            'Cross-program invocation detected without an obvious signer, owner, or has_one constraint in the immediate context.',
          severity: 'high',
          vulnType: 'cpi_vulnerability',
          affectedFile: file.path,
          lineNumber: lineNumberAt(file.content, match.index),
          confidenceScore: 0.7,
          pocCode: snippet(file.content, match.index),
        });
      }
    }

  const initPattern = /#\[account\(init\b/g;
    while ((match = initPattern.exec(file.content)) !== null) {
      const context = file.content.slice(match.index, match.index + 180);
      if (!/payer|space|seeds/.test(context)) {
        const key = `${file.path}:init:${match.index}`;
        if (seen.has(key)) continue;
        seen.add(key);
        findings.push({
          title: 'Account init missing payer or space binding',
          description: 'Anchor init constraint appears incomplete. Uninitialized or payer-less account lanes are a common Solana bug class.',
          severity: 'medium',
          vulnType: 'uninitialized_account',
          affectedFile: file.path,
          lineNumber: lineNumberAt(file.content, match.index),
          confidenceScore: 0.6,
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
