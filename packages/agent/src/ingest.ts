import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import type { Target, TargetLanguage } from '@sentinel-x/contracts';

export interface WorkspaceResolution {
  mode: 'fixture' | 'clone' | 'workspace';
  path: string;
  commit: string | null;
}

export interface IngestOptions {
  fixturesDir?: string;
  workspaceCacheDir?: string;
  allowClone?: boolean;
  signal?: AbortSignal;
}

const ALLOWED_HOSTS = new Set(['github.com', 'gitlab.com', 'bitbucket.org', 'codeberg.org']);

export function resolveScanWorkspace(target: Target, options: IngestOptions = {}): WorkspaceResolution {
  throwIfAborted(options.signal);

  const fixture = resolveFixtureDir(target.name, target.language, options.fixturesDir);
  if (fixture) {
    return { mode: 'fixture', path: fixture, commit: null };
  }

  if (options.allowClone !== false && isAllowedRepoUrl(target.repoUrl)) {
    const cacheRoot = options.workspaceCacheDir ?? join(process.cwd(), 'data', 'workspaces');
    mkdirSync(cacheRoot, { recursive: true });
    const slug = createHash('sha256').update(target.repoUrl).digest('hex').slice(0, 16);
    const dest = join(cacheRoot, `${target.language}-${slug}`);
    throwIfAborted(options.signal);
    const commit = shallowClone(target.repoUrl, dest, options.signal);
    return { mode: 'clone', path: dest, commit };
  }

  throw new Error(
    `No ingestible workspace for target ${target.name}. Provide fixtures under SCAN_FIXTURES_DIR or an allowlisted repoUrl.`,
  );
}

export function resolveFixtureDir(
  name: string,
  language: TargetLanguage | string,
  fixturesDir?: string,
): string | null {
  if (!fixturesDir) return null;
  const slug = name.toLowerCase().replace(/[^a-z0-9]+/g, '-');
  const candidates = [
    join(fixturesDir, slug),
    join(fixturesDir, language),
    join(fixturesDir, `${language}-sample`),
    join(fixturesDir, 'default'),
  ];
  return candidates.find((candidate) => existsSync(candidate)) ?? null;
}

export function isAllowedRepoUrl(repoUrl: string): boolean {
  try {
    const url = new URL(repoUrl);
    if (url.protocol !== 'https:') return false;
    if (!ALLOWED_HOSTS.has(url.hostname)) return false;
    if (!/^\/[\w.-]+\/[\w.-]+\/?$/.test(url.pathname.replace(/\.git$/, ''))) {
      // allow org/repo and org/repo.git
      const parts = url.pathname.replace(/\.git$/, '').split('/').filter(Boolean);
      return parts.length === 2;
    }
    return true;
  } catch {
    return false;
  }
}

function shallowClone(repoUrl: string, dest: string, signal?: AbortSignal): string | null {
  throwIfAborted(signal);
  if (existsSync(dest)) {
    rmSync(dest, { recursive: true, force: true });
  }
  const clone = spawnSync(
    'git',
    ['clone', '--depth', '1', '--single-branch', repoUrl, dest],
    { encoding: 'utf8', timeout: 120_000 },
  );
  if (clone.status !== 0) {
    throw new Error(`git clone failed for ${repoUrl}: ${clone.stderr || clone.stdout || 'unknown error'}`);
  }
  const rev = spawnSync('git', ['-C', dest, 'rev-parse', 'HEAD'], { encoding: 'utf8' });
  return rev.status === 0 ? rev.stdout.trim() : null;
}

function throwIfAborted(signal?: AbortSignal): void {
  if (signal?.aborted) {
    const error = new Error('Scan cancelled by operator');
    error.name = 'AbortError';
    throw error;
  }
}
