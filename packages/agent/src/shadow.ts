import type { DiscoveryFinding, TargetLanguage } from '@sentinel-x/contracts';
import { analyzeRustSources } from './rust.js';
import { analyzeNoirSources } from './noir.js';
import { analyzeSolanaSources } from './solana.js';
import { applyRulePack, loadRulePack, mergeFindings } from './rules/engine.js';
import corePack from './rules/sentinel-core.json' with { type: 'json' };
import type { SourceFile } from './ir.js';

export interface ShadowDiff {
  onlySpecialized: DiscoveryFinding[];
  onlyDeclarative: DiscoveryFinding[];
  both: DiscoveryFinding[];
  agreementRate: number;
}

const pack = loadRulePack(corePack as Parameters<typeof loadRulePack>[0]);

/**
 * Shadow dual-run: specialized analyzers vs declarative pack, side-by-side.
 * Used for operator visibility into pack drift — never silently drops either set.
 */
export function shadowDualRun(language: TargetLanguage, files: SourceFile[]): ShadowDiff {
  const specialized =
    language === 'rust'
      ? analyzeRustSources(files)
      : language === 'noir'
        ? analyzeNoirSources(files)
        : analyzeSolanaSources(files);
  const declarative = applyRulePack(pack, language, files);

  const specKeys = new Set(specialized.map(keyOf));
  const declKeys = new Set(declarative.map(keyOf));

  const onlySpecialized = specialized.filter((f) => !declKeys.has(keyOf(f)));
  const onlyDeclarative = declarative.filter((f) => !specKeys.has(keyOf(f)));
  const both = specialized.filter((f) => declKeys.has(keyOf(f)));
  const union = mergeFindings(specialized, declarative).length;
  const agreementRate = union === 0 ? 1 : Math.round((both.length / union) * 1000) / 1000;

  return { onlySpecialized, onlyDeclarative, both, agreementRate };
}

function keyOf(finding: DiscoveryFinding): string {
  return finding.fingerprint ?? `${finding.ruleId}:${finding.affectedFile}:${finding.lineNumber}:${finding.title}`;
}
