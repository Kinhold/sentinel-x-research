import { FindingCollector, enclosingRustFn, type SourceFile, windowAround } from './ir.js';
import type { DiscoveryFinding } from '@sentinel-x/contracts';

export function analyzeSolanaSources(files: SourceFile[]): DiscoveryFinding[] {
  const collector = new FindingCollector();

  for (const file of files) {
    const cpiPattern = /invoke(?:_signed)?\s*\(/g;
    let match: RegExpExecArray | null;
    while ((match = cpiPattern.exec(file.content)) !== null) {
      const context = windowAround(file.content, match.index, 120, 260);
      if (/owner|is_signer|has_one|signer::|AccountInfo.*is_signer|constraint\s*=/.test(context)) {
        continue;
      }
      collector.push(file, match.index, {
        ruleId: 'solana.cpi-unguarded',
        title: 'CPI without signer or owner guard',
        description:
          'Cross-program invocation detected without an obvious signer, owner, or has_one constraint in the surrounding context.',
        severity: 'high',
        vulnType: 'cpi_vulnerability',
        affectedFunction: enclosingRustFn(file.content, match.index),
        confidenceScore: 0.74,
      });
    }

    const initPattern = /#\[account\(\s*init\b/g;
    while ((match = initPattern.exec(file.content)) !== null) {
      const context = windowAround(file.content, match.index, 20, 220);
      const missing = !/payer\s*=/.test(context) || !/space\s*=/.test(context);
      if (!missing && /seeds\s*=/.test(context)) continue;
      if (!missing) continue;
      collector.push(file, match.index, {
        ruleId: 'solana.init-incomplete',
        title: 'Account init missing payer or space binding',
        description:
          'Anchor init constraint appears incomplete. Uninitialized or payer-less account lanes are a common Solana bug class.',
        severity: 'medium',
        vulnType: 'uninitialized_account',
        affectedFunction: enclosingRustFn(file.content, match.index),
        confidenceScore: 0.68,
      });
    }

    const closePattern = /#\[account\([^)]*\bclose\s*=/g;
    while ((match = closePattern.exec(file.content)) !== null) {
      const context = windowAround(file.content, match.index, 40, 200);
      if (!/has_one|constraint\s*=|signer/.test(context)) {
        collector.push(file, match.index, {
          ruleId: 'solana.close-unguarded',
          title: 'Account close without ownership binding',
          description:
            'Closing an account without a tight ownership/signer constraint can enable lamport theft or reinitialization attacks.',
          severity: 'high',
          vulnType: 'access_control',
          confidenceScore: 0.71,
        });
      }
    }

    const remainingPattern = /\bremaining_accounts\b/g;
    while ((match = remainingPattern.exec(file.content)) !== null) {
      collector.push(file, match.index, {
        ruleId: 'solana.remaining-accounts',
        title: 'remaining_accounts privilege surface',
        description:
          'remaining_accounts expands the attack surface. Ensure every consumed account is type-checked and authorized.',
        severity: 'medium',
        vulnType: 'access_control',
        affectedFunction: enclosingRustFn(file.content, match.index),
        confidenceScore: 0.58,
      });
    }

    // Simple reentrancy heuristic: invoke after state mutation without reload
    const mutateThenCpi =
      /\.(?:lamports|data)\.borrow_mut\(\)[\s\S]{0,240}invoke(?:_signed)?\s*\(/g;
    while ((match = mutateThenCpi.exec(file.content)) !== null) {
      collector.push(file, match.index, {
        ruleId: 'solana.reentrancy-cpi',
        title: 'State mutation before CPI (reentrancy lane)',
        description:
          'Mutable account state is borrowed before a CPI. If the callee re-enters, invariants may be observed mid-update.',
        severity: 'high',
        vulnType: 'reentrancy',
        affectedFunction: enclosingRustFn(file.content, match.index),
        confidenceScore: 0.62,
      });
    }
  }

  return collector.all();
}
