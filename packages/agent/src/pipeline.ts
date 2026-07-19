import { existsSync } from 'node:fs';
import { join } from 'node:path';
import type { ScanPhase } from '@sentinel-x/contracts';
import type { SentinelStore } from '@sentinel-x/storage';
import { analyzeFixtureDirectory } from './discovery.js';
import { buildImmunefiReport, verifyFinding } from './report.js';

export interface ScanRunnerOptions {
  fixturesDir?: string;
  onLog?: (scanId: number, phase: ScanPhase, level: 'info' | 'warn' | 'error', message: string) => void;
}

export class ScanRunner {
  constructor(
    private readonly store: SentinelStore,
    private readonly options: ScanRunnerOptions = {},
  ) {}

  async run(scanId: number): Promise<void> {
    const scan = this.store.getScan(scanId);
    if (!scan?.target) throw new Error('Scan or target not found');
    const target = scan.target;
    const log = (phase: ScanPhase, level: 'info' | 'warn' | 'error', message: string) => {
      this.store.appendScanLog(scanId, level, phase, message);
      this.options.onLog?.(scanId, phase, level, message);
    };

    try {
      this.store.updateScan(scanId, {
        status: 'running',
        phase: 'discovery',
        startedAt: new Date().toISOString(),
        errorMessage: null,
      });
      this.store.appendActivity('scan_started', `Scan ${scanId} started for ${target.name}`, null, scanId);
      log('discovery', 'info', `Loading fixture sources for ${target.language} target ${target.name}`);

      const fixtureDir = this.resolveFixtureDir(target.name, target.language);
      if (!fixtureDir) {
        throw new Error(`No fixture directory found for target ${target.name}`);
      }

      const findings = analyzeFixtureDirectory(fixtureDir, target.language);
      log('discovery', 'info', `Discovery complete: ${findings.length} candidate findings`);

      let bugsFound = 0;
      let bugsVerified = 0;
      this.store.updateScan(scanId, { phase: 'verification' });

      for (const finding of findings) {
        const vulnerability = this.store.insertVulnerability(scanId, target.id, finding, target.language);
        bugsFound += 1;
        this.store.appendActivity('bug_found', vulnerability.title, vulnerability.severity, scanId, vulnerability.id);
        log('verification', 'info', `Verifying ${vulnerability.title}`);

        const verification = verifyFinding(finding);
        const updated = this.store.updateVulnerabilityVerification(vulnerability.id, {
          status: verification.status,
          fvHarness: verification.fvHarness,
          fvLog: verification.fvLog,
          counterExample: verification.counterExample ?? null,
          confidenceScore: verification.confidenceScore,
        });
        if (updated?.status === 'verified') {
          bugsVerified += 1;
          this.store.appendActivity('bug_verified', updated.title, updated.severity, scanId, updated.id);
          log('verification', 'info', `Verified ${updated.title}`);
        } else {
          log('verification', 'warn', `Downgraded ${finding.title} to false positive`);
        }
      }

      this.store.updateScan(scanId, {
        phase: 'reporting',
        bugsFound,
        bugsVerified,
      });
      log('reporting', 'info', 'Generating Immunefi-ready report shells for verified findings');

      const verified = this.store
        .listVulnerabilities({ scanId })
        .filter((item) => item.status === 'verified');
      for (const vulnerability of verified) {
        buildImmunefiReport(vulnerability);
      }

      this.store.updateScan(scanId, {
        status: 'completed',
        phase: 'idle',
        completedAt: new Date().toISOString(),
        bugsFound,
        bugsVerified,
      });
      this.store.appendActivity(
        'scan_completed',
        `Scan ${scanId} completed with ${bugsVerified}/${bugsFound} verified findings`,
        null,
        scanId,
      );
      log('idle', 'info', `Scan ${scanId} completed`);
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Unknown scan failure';
      this.store.updateScan(scanId, {
        status: 'failed',
        phase: 'idle',
        completedAt: new Date().toISOString(),
        errorMessage: message,
      });
      log('idle', 'error', message);
      throw error;
    }
  }

  cancel(scanId: number): void {
    const scan = this.store.getScan(scanId);
    if (!scan) throw new Error('Scan not found');
    if (scan.status !== 'running' && scan.status !== 'pending') return;
    this.store.updateScan(scanId, {
      status: 'failed',
      phase: 'idle',
      completedAt: new Date().toISOString(),
      errorMessage: 'Cancelled by operator',
    });
    this.store.appendScanLog(scanId, 'warn', 'idle', 'Scan cancelled by operator');
  }

  private resolveFixtureDir(name: string, language: string): string | null {
    const root = this.options.fixturesDir;
    if (!root) return null;
    const slug = name.toLowerCase().replace(/[^a-z0-9]+/g, '-');
    const candidates = [
      join(root, slug),
      join(root, language),
      join(root, `${language}-sample`),
      join(root, 'default'),
    ];
    return candidates.find((candidate) => existsSync(candidate)) ?? null;
  }
}

export { buildImmunefiReport, verifyFinding } from './report.js';
export { analyzeFixtureDirectory, analyzeSources, collectSourceFiles } from './discovery.js';
