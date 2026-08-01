import {
  FindingCollector,
  enclosingRustFn,
  matchUsesLocalToken,
  type SourceFile,
  windowAround,
} from './ir.js';
import type { DiscoveryFinding } from '@sentinel-x/contracts';

export function analyzeRustSources(files: SourceFile[]): DiscoveryFinding[] {
  const collector = new FindingCollector();

  for (const file of files) {
    const wrappingPattern = /\bwrapping_(?:add|sub|mul)\s*\(/g;
    let match: RegExpExecArray | null;
    while ((match = wrappingPattern.exec(file.content)) !== null) {
      collector.push(file, match.index, {
        ruleId: 'rust.wrapping-arithmetic',
        title: 'Unchecked integer wrapping path',
        description:
          'Wrapping arithmetic absorbs overflow instead of failing closed. In balance, index, or authority math this can corrupt state without a panic.',
        severity: 'high',
        vulnType: 'integer_overflow',
        affectedFunction: enclosingRustFn(file.content, match.index),
        confidenceScore: 0.82,
      });
    }

    const castPattern = /\bas\s+u(8|16|32|64|128)\b/g;
    while ((match = castPattern.exec(file.content)) !== null) {
      const local = windowAround(file.content, match.index, 40, 40);
      if (/\bchecked_|saturating_|try_from|TryFrom|try_into/i.test(local)) continue;
      collector.push(file, match.index, {
        ruleId: 'rust.narrowing-cast',
        title: 'Integer boundary conversion',
        description:
          'Narrowing cast without an adjacent checked conversion. Truncation can collapse distinct values onto the same slot or authority id.',
        severity: 'medium',
        vulnType: 'integer_overflow',
        affectedFunction: enclosingRustFn(file.content, match.index),
        confidenceScore: 0.64,
      });
    }

    // checked_add alone is safe — do not flag it as overflow.
    const unsafePattern = /\bunsafe\s*\{/g;
    while ((match = unsafePattern.exec(file.content)) !== null) {
      collector.push(file, match.index, {
        ruleId: 'rust.unsafe-block',
        title: 'Unsafe block without documented invariant',
        description:
          'Unsafe Rust block detected. Confirm lifetime, aliasing, and bounds invariants before trusting downstream attestations.',
        severity: 'medium',
        vulnType: 'access_control',
        affectedFunction: enclosingRustFn(file.content, match.index),
        confidenceScore: 0.55,
      });
    }

    const unwrapPattern = /\.unwrap\s*\(\s*\)/g;
    while ((match = unwrapPattern.exec(file.content)) !== null) {
      if (matchUsesLocalToken(file.content, match.index, 'test', 200)) continue;
      collector.push(file, match.index, {
        ruleId: 'rust.unwrap-panic',
        title: 'Panic path via unwrap in production lane',
        description:
          '`.unwrap()` converts recoverable failure into an abort. In protocol code this can DoS validators or freeze fund movement.',
        severity: 'low',
        vulnType: 'other',
        affectedFunction: enclosingRustFn(file.content, match.index),
        confidenceScore: 0.48,
      });
    }

    const transmutePattern = /\b(?:mem::)?transmute(?:_copy)?\s*[::<(]/g;
    while ((match = transmutePattern.exec(file.content)) !== null) {
      collector.push(file, match.index, {
        ruleId: 'rust.transmute',
        title: 'Transmute bypasses type invariants',
        description:
          'Transmute can invent invalid bit patterns for typed values. Require an audited safety comment and property tests.',
        severity: 'high',
        vulnType: 'access_control',
        affectedFunction: enclosingRustFn(file.content, match.index),
        confidenceScore: 0.72,
      });
    }
  }

  return collector.all();
}
