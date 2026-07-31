import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import type { DiscoveryFinding, TargetLanguage } from '@sentinel-x/contracts';

export interface ToolAdapterResult {
  tool: string;
  available: boolean;
  ran: boolean;
  exitCode: number | null;
  summary: string;
  boost: number;
}

/**
 * Opt-in defensive tool adapters. Never invents tool output — only runs when
 * binaries exist on PATH and ENABLE_TOOL_ADAPTERS=1 (or options.enableToolAdapters).
 */
export function runVerificationAdapters(
  language: TargetLanguage,
  workspacePath: string,
  finding: DiscoveryFinding,
  options: { enableToolAdapters?: boolean; signal?: AbortSignal } = {},
): ToolAdapterResult[] {
  if (options.enableToolAdapters === false) return [];
  if (options.enableToolAdapters !== true && process.env.ENABLE_TOOL_ADAPTERS !== '1') {
    return [];
  }
  if (options.signal?.aborted) return [];

  switch (language) {
    case 'rust':
      return [maybeCargoCheck(workspacePath), maybeRustcSyntax(workspacePath, finding)].filter(Boolean) as ToolAdapterResult[];
    case 'noir':
      return [maybeNargoCheck(workspacePath)].filter(Boolean) as ToolAdapterResult[];
    case 'solana':
      return [maybeCargoCheck(workspacePath), maybeAnchorTestDry(workspacePath)].filter(Boolean) as ToolAdapterResult[];
    default:
      return [];
  }
}

export function aggregateAdapterBoost(results: ToolAdapterResult[]): number {
  return results.reduce((sum, item) => sum + item.boost, 0);
}

function maybeCargoCheck(workspacePath: string): ToolAdapterResult | null {
  if (!commandExists('cargo')) {
    return { tool: 'cargo', available: false, ran: false, exitCode: null, summary: 'cargo not on PATH', boost: 0 };
  }
  if (!existsSync(join(workspacePath, 'Cargo.toml'))) {
    return { tool: 'cargo', available: true, ran: false, exitCode: null, summary: 'No Cargo.toml in workspace', boost: 0 };
  }
  const result = spawnSync('cargo', ['check', '--message-format=short'], {
    cwd: workspacePath,
    encoding: 'utf8',
    timeout: 90_000,
  });
  const ok = result.status === 0;
  return {
    tool: 'cargo-check',
    available: true,
    ran: true,
    exitCode: result.status,
    summary: ok ? 'cargo check passed' : truncate(result.stderr || result.stdout || 'cargo check failed'),
    boost: ok ? 0.02 : 0.04,
  };
}

function maybeRustcSyntax(workspacePath: string, finding: DiscoveryFinding): ToolAdapterResult | null {
  if (!finding.affectedFile || !commandExists('rustc')) {
    return null;
  }
  const filePath = join(workspacePath, finding.affectedFile);
  if (!existsSync(filePath)) return null;
  // Syntax-only parse when the file is a free-standing sample (no crate).
  if (existsSync(join(workspacePath, 'Cargo.toml'))) return null;
  const result = spawnSync('rustc', ['--edition', '2021', '--crate-type', 'lib', '-o', '/tmp/sentinel-x-rustc.rlib', filePath], {
    encoding: 'utf8',
    timeout: 30_000,
  });
  return {
    tool: 'rustc-syntax',
    available: true,
    ran: true,
    exitCode: result.status,
    summary: result.status === 0 ? 'rustc accepted snippet crate-type=lib' : truncate(result.stderr || 'rustc failed'),
    boost: 0.03,
  };
}

function maybeNargoCheck(workspacePath: string): ToolAdapterResult | null {
  if (!commandExists('nargo')) {
    return { tool: 'nargo', available: false, ran: false, exitCode: null, summary: 'nargo not on PATH', boost: 0 };
  }
  if (!existsSync(join(workspacePath, 'Nargo.toml'))) {
    return { tool: 'nargo', available: true, ran: false, exitCode: null, summary: 'No Nargo.toml in workspace', boost: 0 };
  }
  const result = spawnSync('nargo', ['check'], {
    cwd: workspacePath,
    encoding: 'utf8',
    timeout: 90_000,
  });
  return {
    tool: 'nargo-check',
    available: true,
    ran: true,
    exitCode: result.status,
    summary: result.status === 0 ? 'nargo check passed' : truncate(result.stderr || result.stdout || 'nargo check failed'),
    boost: result.status === 0 ? 0.02 : 0.04,
  };
}

function maybeAnchorTestDry(workspacePath: string): ToolAdapterResult | null {
  if (!commandExists('anchor')) {
    return { tool: 'anchor', available: false, ran: false, exitCode: null, summary: 'anchor not on PATH', boost: 0 };
  }
  if (!existsSync(join(workspacePath, 'Anchor.toml'))) {
    return { tool: 'anchor', available: true, ran: false, exitCode: null, summary: 'No Anchor.toml in workspace', boost: 0 };
  }
  const result = spawnSync('anchor', ['build', '--no-idl'], {
    cwd: workspacePath,
    encoding: 'utf8',
    timeout: 120_000,
  });
  return {
    tool: 'anchor-build',
    available: true,
    ran: true,
    exitCode: result.status,
    summary: result.status === 0 ? 'anchor build passed' : truncate(result.stderr || result.stdout || 'anchor build failed'),
    boost: result.status === 0 ? 0.02 : 0.05,
  };
}

function commandExists(bin: string): boolean {
  const result = spawnSync('sh', ['-c', `command -v ${bin}`], { encoding: 'utf8' });
  return result.status === 0;
}

function truncate(text: string, max = 280): string {
  const cleaned = text.replace(/\s+/g, ' ').trim();
  return cleaned.length <= max ? cleaned : `${cleaned.slice(0, max)}…`;
}
