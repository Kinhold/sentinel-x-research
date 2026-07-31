import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import type { DiscoveryFinding, TargetLanguage } from '@sentinel-x/contracts';
import { analyzeNoirSources } from './noir.js';
import { analyzeRustSources } from './rust.js';
import { analyzeSolanaSources } from './solana.js';
import { applyRulePack, loadRulePack, mergeFindings } from './rules/engine.js';
import corePack from './rules/sentinel-core.json' with { type: 'json' };
import {
  applyScopeFirewall,
  filterToChanged,
  listChangedFiles,
  type ScopePolicy,
} from './scope.js';
import type { SourceFile } from './ir.js';

const SOURCE_EXTENSIONS: Record<TargetLanguage, string[]> = {
  rust: ['.rs'],
  noir: ['.nr'],
  solana: ['.rs', '.ts', '.js'],
};

const loadedCorePack = loadRulePack(corePack as Parameters<typeof loadRulePack>[0]);

export interface AnalyzeOptions {
  scope?: ScopePolicy;
  differentialSinceCommit?: string | null;
  includeDeclarativePacks?: boolean;
}

export function collectSourceFiles(rootDir: string, language: TargetLanguage): SourceFile[] {
  const extensions = new Set(SOURCE_EXTENSIONS[language]);
  const files: SourceFile[] = [];

  function walk(current: string, relative = ''): void {
    for (const entry of readdirSync(current)) {
      const fullPath = join(current, entry);
      const relPath = relative ? `${relative}/${entry}` : entry;
      const stats = statSync(fullPath);
      if (stats.isDirectory()) {
        if (entry === 'node_modules' || entry === 'target' || entry === '.git' || entry === 'dist') continue;
        walk(fullPath, relPath);
        continue;
      }
      if ([...extensions].some((ext) => entry.endsWith(ext))) {
        files.push({ path: relPath, content: readFileSync(fullPath, 'utf8') });
      }
    }
  }

  walk(rootDir);
  return files;
}

export function analyzeSources(
  language: TargetLanguage,
  files: SourceFile[],
  options: AnalyzeOptions = {},
): DiscoveryFinding[] {
  const scoped = applyScopeFirewall(files, options.scope);
  const specialized =
    language === 'rust'
      ? analyzeRustSources(scoped)
      : language === 'noir'
        ? analyzeNoirSources(scoped)
        : language === 'solana'
          ? analyzeSolanaSources(scoped)
          : [];

  if (options.includeDeclarativePacks === false) return specialized;
  const declarative = applyRulePack(loadedCorePack, language, scoped);
  return mergeFindings(specialized, declarative);
}

export function analyzeFixtureDirectory(
  rootDir: string,
  language: TargetLanguage,
  options: AnalyzeOptions = {},
): DiscoveryFinding[] {
  let files = collectSourceFiles(rootDir, language);
  if (options.differentialSinceCommit) {
    const changed = listChangedFiles(rootDir, options.differentialSinceCommit);
    files = filterToChanged(files, changed);
  }
  return analyzeSources(language, files, options);
}
