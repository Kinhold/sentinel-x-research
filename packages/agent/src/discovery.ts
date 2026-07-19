import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import type { DiscoveryFinding, TargetLanguage } from '@sentinel-x/contracts';
import { analyzeNoirSources } from './noir.js';
import { analyzeRustSources } from './rust.js';
import { analyzeSolanaSources } from './solana.js';

const SOURCE_EXTENSIONS: Record<TargetLanguage, string[]> = {
  rust: ['.rs'],
  noir: ['.nr'],
  solana: ['.rs', '.ts', '.js'],
};

export function collectSourceFiles(rootDir: string, language: TargetLanguage): Array<{ path: string; content: string }> {
  const extensions = new Set(SOURCE_EXTENSIONS[language]);
  const files: Array<{ path: string; content: string }> = [];

  function walk(current: string, relative = ''): void {
    for (const entry of readdirSync(current)) {
      const fullPath = join(current, entry);
      const relPath = relative ? `${relative}/${entry}` : entry;
      const stats = statSync(fullPath);
      if (stats.isDirectory()) {
        if (entry === 'node_modules' || entry === 'target' || entry === '.git') continue;
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

export function analyzeSources(language: TargetLanguage, files: Array<{ path: string; content: string }>): DiscoveryFinding[] {
  switch (language) {
    case 'rust':
      return analyzeRustSources(files);
    case 'noir':
      return analyzeNoirSources(files);
    case 'solana':
      return analyzeSolanaSources(files);
    default:
      return [];
  }
}

export function analyzeFixtureDirectory(rootDir: string, language: TargetLanguage): DiscoveryFinding[] {
  const files = collectSourceFiles(rootDir, language);
  return analyzeSources(language, files);
}
