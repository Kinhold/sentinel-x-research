import type { ScanPhase } from '@sentinel-x/contracts';
import type { SentinelStore } from '@sentinel-x/storage';
import { analyzeFixtureDirectory } from './discovery.js';
import { resolveScanWorkspace, type IngestOptions } from './ingest.js';
import { buildImmunefiReport, verifyFinding } from './report.js';

export class ScanCancelledError extends Error {
  constructor(message = 'Scan cancelled by operator') {
    super(message);
    this.name = 'AbortError';
  }
}

export interface ScanRunnerOptions extends IngestOptions {
  onLog?: (scanId: number, phase: ScanPhase, level: 'info' | 'warn' | 'error', message: string) => void;
  /** Test-only cooperative pause after entering running state. */
  injectPauseMs?: number;
}

export class ScanRunner {
  private readonly controllers = new Map<number, AbortController>();

  constructor(
    private readonly store: SentinelStore,
    private readonly options: ScanRunnerOptions = {},
  ) {}

  async run(scanId: number): Promise<void> {
    const existing = this.controllers.get(scanId);
    if (existing) existing.abort();
    const controller = new AbortController();
    this.controllers.set(scanId, controller);

    const scan = this.store.getScan(scanId);
    if (!scan?.target) throw new Error('Scan or target not found');
    const target = scan.target;
    const log = (phase: ScanPhase, level: 'info' | 'warn' | 'error', message: string) => {
      this.store.appendScanLog(scanId, level, phase, message);
      this.options.onLog?.(scanId, phase, level, message);
    };

    const checkpoint = () => {
      if (controller.signal.aborted) throw new ScanCancelledError();
      const current = this.store.getScan(scanId);
      if (current?.status === 'failed' && current.errorMessage === 'Cancelled by operator') {
        throw new ScanCancelledError();
      }
    };

    try {
      this.store.updateScan(scanId, {
        status: 'running',
        phase: 'discovery',
        startedAt: new Date().toISOString(),
        errorMessage: null,
      });
      this.store.appendActivity('scan_started', `Scan ${scanId} started for ${target.name}`, null, scanId);
      log('discovery', 'info', `Resolving workspace for ${target.language} target ${target.name}`);

      if (this.options.injectPauseMs && this.options.injectPauseMs > 0) {
        await sleep(this.options.injectPauseMs, controller.signal);
      }
      checkpoint();
      const workspace = resolveScanWorkspace(target, {
        fixturesDir: this.options.fixturesDir,
        workspaceCacheDir: this.options.workspaceCacheDir,
        allowClone: this.options.allowClone,
        signal: controller.signal,
      });
      this.store.updateScan(scanId, {
        sourceMode: workspace.mode,
        sourcePath: workspace.path,
        sourceCommit: workspace.commit,
      });
      log(
        'discovery',
        'info',
        `Workspace ready via ${workspace.mode}${workspace.commit ? ` @ ${workspace.commit.slice(0, 8)}` : ''}`,
      );

      checkpoint();
      const findings = analyzeFixtureDirectory(workspace.path, target.language);
      log('discovery', 'info', `Discovery complete: ${findings.length} candidate findings`);

      let bugsFound = 0;
      let bugsVerified = 0;
      this.store.updateScan(scanId, { phase: 'verification' });

      for (const finding of findings) {
        checkpoint();
        const vulnerability = this.store.insertVulnerability(scanId, target.id, finding, target.language);
        bugsFound += 1;
        this.store.appendActivity('bug_found', vulnerability.title, vulnerability.severity, scanId, vulnerability.id);
        log('verification', 'info', `Verifying ${vulnerability.title} [${finding.ruleId ?? 'legacy'}]`);

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

      checkpoint();
      this.store.updateScan(scanId, {
        phase: 'reporting',
        bugsFound,
        bugsVerified,
      });
      log('reporting', 'info', 'Persisting Immunefi-ready report shells for verified findings');

      const verified = this.store
        .listVulnerabilities({ scanId })
        .filter((item) => item.status === 'verified');
      for (const vulnerability of verified) {
        checkpoint();
        const report = buildImmunefiReport(vulnerability);
        this.store.upsertReport(report);
        this.store.appendActivity(
          'report_generated',
          `Report ready for ${vulnerability.title}`,
          vulnerability.severity,
          scanId,
          vulnerability.id,
        );
      }

      checkpoint();
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
      const cancelled = error instanceof ScanCancelledError || (error instanceof Error && error.name === 'AbortError');
      const message = cancelled
        ? 'Cancelled by operator'
        : error instanceof Error
          ? error.message
          : 'Unknown scan failure';
      this.store.updateScan(scanId, {
        status: 'failed',
        phase: 'idle',
        completedAt: new Date().toISOString(),
        errorMessage: message,
      });
      if (cancelled) {
        this.store.appendActivity('scan_cancelled', `Scan ${scanId} cancelled`, null, scanId);
        log('idle', 'warn', message);
      } else {
        log('idle', 'error', message);
        throw error;
      }
    } finally {
      this.controllers.delete(scanId);
    }
  }

  cancel(scanId: number): void {
    const scan = this.store.getScan(scanId);
    if (!scan) throw new Error('Scan not found');
    if (scan.status !== 'running' && scan.status !== 'pending') return;
    this.controllers.get(scanId)?.abort();
    this.store.updateScan(scanId, {
      status: 'failed',
      phase: 'idle',
      completedAt: new Date().toISOString(),
      errorMessage: 'Cancelled by operator',
    });
    this.store.appendScanLog(scanId, 'warn', 'idle', 'Scan cancelled by operator');
  }
}

export { buildImmunefiReport, verifyFinding } from './report.js';
export { analyzeFixtureDirectory, analyzeSources, collectSourceFiles } from './discovery.js';
export { resolveScanWorkspace, resolveFixtureDir, isAllowedRepoUrl } from './ingest.js';

function sleep(ms: number, signal: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal.aborted) {
      reject(new ScanCancelledError());
      return;
    }
    const timer = setTimeout(() => {
      signal.removeEventListener('abort', onAbort);
      resolve();
    }, ms);
    const onAbort = () => {
      clearTimeout(timer);
      reject(new ScanCancelledError());
    };
    signal.addEventListener('abort', onAbort, { once: true });
  });
}
