import type { ScanPhase } from '@sentinel-x/contracts';
import type { SentinelStore } from '@sentinel-x/storage';
import { analyzeFixtureDirectory } from './discovery.js';
import { resolveScanWorkspace, type IngestOptions } from './ingest.js';
import { buildImmunefiReport, verifyFinding } from './report.js';
import { aggregateAdapterBoost, runVerificationAdapters } from './verify-adapters.js';
import {
  applyHypothesisDeltas,
  portfolioRiskScore,
  runHypothesisEngine,
  summarizeHypotheses,
} from './hypothesis.js';
import { dispatchWebhooks } from './notify.js';
import { applySuppressions } from './campaign.js';
import { buildScanAttestation, hashRulePackPayload } from './attestation.js';
import corePack from './rules/sentinel-core.json' with { type: 'json' };

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
  enableToolAdapters?: boolean;
  dedupeFingerprints?: boolean;
  includeDeclarativePacks?: boolean;
  scope?: import('./scope.js').ScopePolicy;
}

export class ScanRunner {
  private readonly controllers = new Map<number, AbortController>();
  private readonly cancelReasons = new Map<number, string>();

  constructor(
    private readonly store: SentinelStore,
    private readonly options: ScanRunnerOptions = {},
  ) {}

  async run(scanId: number): Promise<void> {
    const existing = this.controllers.get(scanId);
    if (existing) existing.abort();
    const controller = new AbortController();
    this.controllers.set(scanId, controller);
    this.cancelReasons.delete(scanId);

    const scan = this.store.getScan(scanId);
    if (!scan?.target) throw new Error('Scan or target not found');
    const target = scan.target;
    const log = (phase: ScanPhase, level: 'info' | 'warn' | 'error', message: string) => {
      this.store.appendScanLog(scanId, level, phase, message);
      this.options.onLog?.(scanId, phase, level, message);
    };

    const checkpoint = () => {
      if (controller.signal.aborted) {
        throw new ScanCancelledError(this.cancelReasons.get(scanId) ?? 'Cancelled by operator');
      }
      const current = this.store.getScan(scanId);
      if (current?.status === 'failed' && current.errorMessage) {
        const msg = current.errorMessage;
        if (msg === 'Cancelled by operator' || msg.startsWith('Timed out')) {
          throw new ScanCancelledError(msg);
        }
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
        await sleep(this.options.injectPauseMs, controller.signal, () => this.cancelReasons.get(scanId));
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
      const previousCommit = this.store.getLastCompletedCommit(target.id);
      const findings = analyzeFixtureDirectory(workspace.path, target.language, {
        differentialSinceCommit: previousCommit && workspace.commit ? previousCommit : null,
        scope: this.options.scope,
        includeDeclarativePacks: this.options.includeDeclarativePacks,
      });
      this.store.appendProvenance(scanId, 'discovery.complete', {
        findingCount: findings.length,
        mode: workspace.mode,
        commit: workspace.commit,
        differentialSince: previousCommit,
      });
      log(
        'discovery',
        'info',
        `Discovery complete: ${findings.length} candidate findings${previousCommit ? ` (diff since ${previousCommit.slice(0, 8)})` : ''}`,
      );

      checkpoint();
      const hypotheses = runHypothesisEngine(findings, {
        workspacePath: workspace.path,
        language: target.language,
        signal: controller.signal,
      });
      const hypoSummary = summarizeHypotheses(hypotheses);
      this.store.appendProvenance(scanId, 'hypothesis.complete', {
        ...hypoSummary,
        total: hypotheses.length,
      });
      log(
        'discovery',
        'info',
        `Hypothesis engine: ${hypotheses.length} claims (${hypoSummary.supported} supported / ${hypoSummary.refuted} refuted)`,
      );
      const refinedFindings = findings.map((finding) => applyHypothesisDeltas(finding, hypotheses));
      const suppressions = this.store.listActiveSuppressions();
      const { kept: actionableFindings, suppressed } = applySuppressions(refinedFindings, suppressions);
      if (suppressed.length) {
        this.store.appendProvenance(scanId, 'suppression.applied', {
          suppressed: suppressed.length,
          fingerprints: suppressed.map((f) => f.fingerprint).filter(Boolean),
        });
        log('verification', 'info', `Suppressed ${suppressed.length} findings via operator registry`);
      }

      let bugsFound = 0;
      let bugsVerified = 0;
      let duplicatesSkipped = 0;
      this.store.updateScan(scanId, { phase: 'verification' });

      for (const finding of actionableFindings) {
        checkpoint();
        if (this.options.dedupeFingerprints !== false && finding.fingerprint) {
          const prior = this.store.findVerifiedByFingerprint(finding.fingerprint, target.id);
          if (prior && prior.scanId !== scanId) {
            duplicatesSkipped += 1;
            log(
              'verification',
              'info',
              `Deduped ${finding.title} against prior finding #${prior.id} (${finding.fingerprint})`,
            );
            continue;
          }
        }

        const vulnerability = this.store.insertVulnerability(scanId, target.id, finding, target.language);
        bugsFound += 1;
        this.store.appendActivity('bug_found', vulnerability.title, vulnerability.severity, scanId, vulnerability.id);
        log('verification', 'info', `Verifying ${vulnerability.title} [${finding.ruleId ?? 'legacy'}]`);

        const adapters = runVerificationAdapters(target.language, workspace.path, finding, {
          enableToolAdapters: this.options.enableToolAdapters,
          signal: controller.signal,
        });
        for (const adapter of adapters.filter((item) => item.ran || !item.available)) {
          log('verification', 'info', `Adapter ${adapter.tool}: ${adapter.summary}`);
        }
        const adapterBoost = aggregateAdapterBoost(adapters);
        const adapterLog = adapters.length
          ? adapters.map((item) => `${item.tool}=${item.ran ? item.exitCode ?? 'ran' : 'skip'}`).join(', ')
          : undefined;
        const historicalFpRate = finding.ruleId
          ? this.store.getRuleFalsePositiveRate(finding.ruleId) ?? undefined
          : undefined;
        const priorVerifiedSameFingerprint = Boolean(
          finding.fingerprint && this.store.findVerifiedByFingerprint(finding.fingerprint, target.id),
        );

        const verification = verifyFinding(finding, {
          adapterBoost,
          adapterLog,
          adapters,
          historicalFpRate,
          priorVerifiedSameFingerprint,
        });
        this.store.appendProvenance(scanId, 'verification.result', {
          vulnerabilityId: vulnerability.id,
          ruleId: finding.ruleId,
          status: verification.status,
          confidence: verification.confidenceScore,
          lattice: verification.latticeRationale,
        });
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

      if (duplicatesSkipped > 0) {
        log('verification', 'info', `Skipped ${duplicatesSkipped} fingerprint duplicates`);
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
      this.store.appendProvenance(scanId, 'scan.completed', {
        bugsFound,
        bugsVerified,
        duplicatesSkipped,
        suppressed: suppressed.length,
        hypotheses: hypoSummary,
        risk: portfolioRiskScore(this.store.listVulnerabilities({ scanId })),
        chainValid: this.store.verifyProvenanceChain(scanId),
      });
      const attestation = buildScanAttestation({
        scanId,
        targetId: target.id,
        sourceMode: workspace.mode,
        sourceCommit: workspace.commit,
        rulePackHash: hashRulePackPayload(corePack),
        vulnerabilities: this.store.listVulnerabilities({ scanId }),
      });
      this.store.upsertAttestation(scanId, attestation.contentHash, attestation.signature, attestation);
      this.store.appendProvenance(scanId, 'attestation.issued', {
        contentHash: attestation.contentHash,
        signed: Boolean(attestation.signature),
      });
      this.store.appendActivity(
        'scan_completed',
        `Scan ${scanId} completed with ${bugsVerified}/${bugsFound} verified findings`,
        null,
        scanId,
      );
      log('idle', 'info', `Scan ${scanId} completed`);
      void dispatchWebhooks({
        type: 'scan.completed',
        scanId,
        timestamp: new Date().toISOString(),
        payload: {
          bugsFound,
          bugsVerified,
          targetId: target.id,
          targetName: target.name,
          hypotheses: hypoSummary,
          attestationHash: attestation.contentHash,
        },
      }).then((results) => {
        if (results.length) {
          this.store.appendProvenance(scanId, 'webhook.dispatch', { results });
        }
      });
    } catch (error) {
      const cancelled = error instanceof ScanCancelledError || (error instanceof Error && error.name === 'AbortError');
      const message = cancelled
        ? error instanceof Error
          ? error.message
          : 'Cancelled by operator'
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
        this.store.appendActivity('scan_cancelled', `Scan ${scanId}: ${message}`, null, scanId);
        log('idle', 'warn', message);
      } else {
        log('idle', 'error', message);
        void dispatchWebhooks({
          type: 'scan.failed',
          scanId,
          timestamp: new Date().toISOString(),
          payload: { error: message, targetId: target.id },
        });
        throw error;
      }
    } finally {
      this.controllers.delete(scanId);
      this.cancelReasons.delete(scanId);
    }
  }

  cancel(scanId: number, reason = 'Cancelled by operator'): void {
    const scan = this.store.getScan(scanId);
    if (!scan) throw new Error('Scan not found');
    if (scan.status !== 'running' && scan.status !== 'pending') return;
    this.cancelReasons.set(scanId, reason);
    this.controllers.get(scanId)?.abort();
    this.store.updateScan(scanId, {
      status: 'failed',
      phase: 'idle',
      completedAt: new Date().toISOString(),
      errorMessage: reason,
    });
    this.store.appendScanLog(scanId, 'warn', 'idle', reason);
  }
}

export { buildImmunefiReport, verifyFinding } from './report.js';
export { analyzeFixtureDirectory, analyzeSources, collectSourceFiles } from './discovery.js';
export { resolveScanWorkspace, resolveFixtureDir, isAllowedRepoUrl } from './ingest.js';
export { buildSarifReport } from './sarif.js';
export { ScanQueue } from './queue.js';
export type { ScanQueueOptions } from './queue.js';
export { runVerificationAdapters, aggregateAdapterBoost } from './verify-adapters.js';
export { fuseConfidence, structuralEvidenceScore } from './lattice.js';
export { applyRulePack, loadRulePack, mergeFindings } from './rules/engine.js';
export { applyScopeFirewall, matchGlob, filterToChanged } from './scope.js';
export {
  runHypothesisEngine,
  applyHypothesisDeltas,
  summarizeHypotheses,
  portfolioRiskScore,
} from './hypothesis.js';
export { dispatchWebhooks, parseWebhookUrls, RateLimiter } from './notify.js';
export { buildScanAttestation, verifyScanAttestation, hashRulePackPayload } from './attestation.js';
export { createAndEnqueueCampaign, getCampaignStatus, applySuppressions } from './campaign.js';

function sleep(ms: number, signal: AbortSignal, reason?: () => string | undefined): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal.aborted) {
      reject(new ScanCancelledError(reason?.() ?? 'Cancelled by operator'));
      return;
    }
    const timer = setTimeout(() => {
      signal.removeEventListener('abort', onAbort);
      resolve();
    }, ms);
    const onAbort = () => {
      clearTimeout(timer);
      reject(new ScanCancelledError(reason?.() ?? 'Cancelled by operator'));
    };
    signal.addEventListener('abort', onAbort, { once: true });
  });
}
