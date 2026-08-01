import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import type { SourceFile } from './ir.js';

export interface ScopePolicy {
  allowGlobs?: string[];
  denyGlobs?: string[];
}

export function applyScopeFirewall(files: SourceFile[], policy: ScopePolicy = {}): SourceFile[] {
  const deny = policy.denyGlobs ?? ['**/node_modules/**', '**/target/**', '**/.git/**', '**/dist/**'];
  const allow = policy.allowGlobs;
  return files.filter((file) => {
    if (deny.some((glob) => matchGlob(file.path, glob))) return false;
    if (allow && allow.length > 0) return allow.some((glob) => matchGlob(file.path, glob));
    return true;
  });
}

export function listChangedFiles(workspacePath: string, sinceCommit?: string | null): string[] | null {
  if (!sinceCommit || !existsSync(join(workspacePath, '.git'))) return null;
  const result = spawnSync(
    'git',
    ['-C', workspacePath, 'diff', '--name-only', `${sinceCommit}...HEAD`],
    { encoding: 'utf8' },
  );
  if (result.status !== 0) return null;
  return result.stdout
    .split('\n')
    .map((line) => line.trim())
    .filter(Boolean);
}

export function filterToChanged(files: SourceFile[], changed: string[] | null): SourceFile[] {
  if (!changed || changed.length === 0) return files;
  const set = new Set(changed.map(normalizePath));
  const filtered = files.filter((file) => set.has(normalizePath(file.path)));
  return filtered.length > 0 ? filtered : files;
}

export function matchGlob(path: string, glob: string): boolean {
  const normalized = normalizePath(path);
  let pattern = normalizePath(glob);
  const optionalPrefix = pattern.startsWith('**/');
  if (optionalPrefix) pattern = pattern.slice(3);
  const escaped = pattern
    .replace(/[.+^${}()|[\]\\]/g, '\\$&')
    .replace(/\*\*/g, '::DOUBLE::')
    .replace(/\*/g, '[^/]*')
    .replace(/::DOUBLE::/g, '.*');
  const regex = optionalPrefix ? `^(?:.*/)?${escaped}$` : `^${escaped}$`;
  return new RegExp(regex, 'i').test(normalized);
}

export function hashPayload(payload: unknown): string {
  return createHash('sha256').update(JSON.stringify(payload)).digest('hex');
}

function normalizePath(path: string): string {
  return path.replace(/\\/g, '/').replace(/^\.\//, '');
}
