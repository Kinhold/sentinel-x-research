import { FindingCollector, type SourceFile, windowAround } from './ir.js';
import type { DiscoveryFinding } from '@sentinel-x/contracts';

export function analyzeNoirSources(files: SourceFile[]): DiscoveryFinding[] {
  const collector = new FindingCollector();

  for (const file of files) {
    const fnBodies = extractNoirFunctions(file.content);
    for (const fn of fnBodies) {
      const privateInputs = [
        ...fn.body.matchAll(/\b([A-Za-z_][A-Za-z0-9_]*)\s*:\s*Field\b/g),
      ]
        .map((m) => m[1])
        .filter((name) => name !== 'pub');
      const publicInputs = new Set(
        [...fn.body.matchAll(/\b([A-Za-z_][A-Za-z0-9_]*)\s*:\s*pub\s+Field\b/g)].map((m) => m[1]),
      );
      const asserted = new Set(
        [...fn.body.matchAll(/\bassert(?:_eq)?\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)/g)].map((m) => m[1]),
      );
      // Also treat appearance inside assert expressions as constrained
      for (const name of privateInputs) {
        if (publicInputs.has(name)) continue;
        const constrained =
          asserted.has(name) ||
          new RegExp(`\\bassert(?:_eq)?\\s*\\([^;]*\\b${name}\\b`, 'm').test(fn.body);
        if (constrained) continue;
        const relative = fn.body.indexOf(name);
        const absolute = relative >= 0 ? fn.start + relative : fn.start;
        collector.push(file, absolute, {
          ruleId: 'noir.underconstrained-witness',
          title: `Private field ${name} lacks explicit constraint`,
          description:
            'A private Field input is never referenced in an assertion inside its function. Classic under-constrained witness lane in Noir circuits.',
          severity: 'high',
          vulnType: 'under_constrained_circuit',
          affectedFunction: fn.name,
          confidenceScore: 0.84,
        });
      }
    }

    const divPattern = /\b\/\b/g;
    let match: RegExpExecArray | null;
    while ((match = divPattern.exec(file.content)) !== null) {
      const context = windowAround(file.content, match.index, 48, 48);
      if (/assert|!=\s*0|is_zero|assert_eq/.test(context)) continue;
      // skip comment lines
      const lineStart = file.content.lastIndexOf('\n', match.index) + 1;
      if (file.content.slice(lineStart, match.index).includes('//')) continue;
      collector.push(file, match.index, {
        ruleId: 'noir.div-no-zero-guard',
        title: 'Division without zero guard',
        description:
          'Field division appears without an adjacent zero-check assertion. Review for unconstrained denominator witnesses.',
        severity: 'medium',
        vulnType: 'arithmetic_error',
        confidenceScore: 0.66,
      });
    }

    const unconstrainedPattern = /\bunconstrained\s+fn\s+([A-Za-z_][A-Za-z0-9_]*)/g;
    while ((match = unconstrainedPattern.exec(file.content)) !== null) {
      collector.push(file, match.index, {
        ruleId: 'noir.unconstrained-fn',
        title: `Unconstrained function ${match[1]}`,
        description:
          'Unconstrained Noir functions skip circuit constraints. Ensure every trusted claim is re-asserted in a constrained path.',
        severity: 'medium',
        vulnType: 'under_constrained_circuit',
        affectedFunction: match[1],
        confidenceScore: 0.7,
      });
    }
  }

  return collector.all();
}

function extractNoirFunctions(content: string): Array<{ name: string; start: number; body: string }> {
  const results: Array<{ name: string; start: number; body: string }> = [];
  const pattern = /\bfn\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(/g;
  let match: RegExpExecArray | null;
  while ((match = pattern.exec(content)) !== null) {
    const brace = content.indexOf('{', match.index);
    if (brace < 0) continue;
    let depth = 0;
    let end = brace;
    for (let i = brace; i < content.length; i += 1) {
      if (content[i] === '{') depth += 1;
      if (content[i] === '}') {
        depth -= 1;
        if (depth === 0) {
          end = i + 1;
          break;
        }
      }
    }
    results.push({
      name: match[1],
      start: match.index,
      body: content.slice(match.index, end),
    });
  }
  return results;
}
