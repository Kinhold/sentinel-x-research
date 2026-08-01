import { mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { randomUUID } from 'node:crypto';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { config } from 'dotenv';
import express, { type Express, type NextFunction, type Request, type Response } from 'express';
import {
  ScanQueue,
  ScanRunner,
  RateLimiter,
  buildImmunefiReport,
  buildSarifReport,
  portfolioRiskScore,
  createAndEnqueueCampaign,
  getCampaignStatus,
  verifyScanAttestation,
  issueOperatorChallenge,
  verifyOperatorChallenge,
  collectFixtureCalibrationPoints,
  fitCalibration,
  buildCausalGraph,
  analyzeFixtureDirectory,
} from '@sentinel-x/agent';
import {
  isTargetLanguage,
  isVulnerabilitySeverity,
  isVulnerabilityStatus,
  parseCreateCampaignBody,
  parseCreateScanBody,
  parseCreateSuppressionBody,
  parseCreateTargetBody,
  parseUpdateVulnerabilityBody,
} from '@sentinel-x/contracts';
import { createDatabase, SentinelStore } from '@sentinel-x/storage';

config();

export interface AppOptions {
  store?: SentinelStore;
  runner?: ScanRunner;
  queue?: ScanQueue;
  fixturesDir?: string;
  workspaceCacheDir?: string;
  corsOrigin?: string;
  apiKey?: string | null;
  scanConcurrency?: number;
  scanTimeoutMs?: number;
  rateLimitPerMinute?: number;
}

const rootDir = join(dirname(fileURLToPath(import.meta.url)), '../../..');

declare global {
  namespace Express {
    interface Request {
      requestId?: string;
    }
  }
}

export function createApp(options: AppOptions = {}): Express {
  const store =
    options.store ??
    (() => {
      const databasePath = process.env.DATABASE_PATH ?? join(rootDir, 'data/sentinel-x.db');
      mkdirSync(dirname(databasePath), { recursive: true });
      return new SentinelStore(createDatabase(databasePath));
    })();

  const fixturesDir = options.fixturesDir ?? process.env.SCAN_FIXTURES_DIR ?? join(rootDir, 'fixtures/repos');
  const workspaceCacheDir =
    options.workspaceCacheDir ?? process.env.WORKSPACE_CACHE_DIR ?? join(rootDir, 'data/workspaces');
  const runner =
    options.runner ??
    new ScanRunner(store, {
      fixturesDir,
      workspaceCacheDir,
      allowClone: process.env.ALLOW_CLONE !== '0',
      enableToolAdapters: process.env.ENABLE_TOOL_ADAPTERS === '1',
      dedupeFingerprints: process.env.DEDUPE_FINGERPRINTS !== '0',
    });
  const queue =
    options.queue ??
    new ScanQueue(runner, {
      concurrency: options.scanConcurrency ?? Number(process.env.SCAN_CONCURRENCY ?? 2),
      timeoutMs: options.scanTimeoutMs ?? Number(process.env.SCAN_TIMEOUT_MS ?? 600_000),
      onError: (scanId, error) => {
        console.error(`Scan ${scanId} failed`, error);
      },
    });
  const corsOrigin = options.corsOrigin ?? process.env.CORS_ORIGIN ?? 'http://localhost:5174';
  const apiKey = options.apiKey === undefined ? process.env.API_KEY ?? null : options.apiKey;
  const rateLimitPerMinute =
    options.rateLimitPerMinute ?? Number(process.env.RATE_LIMIT_PER_MINUTE ?? 120);
  const limiter = new RateLimiter(rateLimitPerMinute, rateLimitPerMinute / 60);

  const app = express();

  app.use((req, res, next) => {
    const requestId = req.header('x-request-id') || randomUUID();
    req.requestId = requestId;
    res.setHeader('X-Request-Id', requestId);
    res.setHeader('Access-Control-Allow-Origin', corsOrigin);
    res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PATCH,DELETE,OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-API-Key, X-Request-Id');
    res.setHeader('Access-Control-Expose-Headers', 'X-Request-Id');
    if (req.method === 'OPTIONS') {
      res.status(204).end();
      return;
    }
    next();
  });
  app.use(express.json({ limit: '1mb' }));

  app.use((req, res, next) => {
    if (req.path === '/api/healthz' || req.path === '/api/metrics') {
      next();
      return;
    }
    const key = req.header('x-api-key') || req.ip || 'anon';
    if (!limiter.allow(key)) {
      res.status(429).json({ error: 'Rate limit exceeded', requestId: req.requestId, code: 'rate_limited' });
      return;
    }
    next();
  });

  app.use((req, res, next) => {
    if (!apiKey) {
      next();
      return;
    }
    if (req.path === '/api/healthz') {
      next();
      return;
    }
    const provided = req.header('x-api-key') ?? bearer(req.header('authorization'));
    if (provided !== apiKey) {
      res.status(401).json({ error: 'Unauthorized', requestId: req.requestId, code: 'unauthorized' });
      return;
    }
    next();
  });

  app.get('/api/healthz', (req, res) => {
    res.json({ status: 'ok', requestId: req.requestId });
  });

  app.get('/api/queue', (_req, res) => {
    res.json(queue.size());
  });

  app.get('/api/targets', (_req, res) => {
    res.json(store.listTargets());
  });

  app.post('/api/targets', (req, res, next) => {
    try {
      const body = parseCreateTargetBody(req.body);
      res.status(201).json(store.createTarget(body));
    } catch (error) {
      next(error);
    }
  });

  app.get('/api/targets/:id', (req, res) => {
    const target = store.getTarget(Number(req.params.id));
    if (!target) {
      res.status(404).json({ error: 'Target not found', requestId: req.requestId, code: 'not_found' });
      return;
    }
    res.json(target);
  });

  app.delete('/api/targets/:id', (req, res) => {
    const deleted = store.deleteTarget(Number(req.params.id));
    res.status(deleted ? 204 : 404).end();
  });

  app.get('/api/scans', (req, res) => {
    const scanStatus = typeof req.query.status === 'string' ? req.query.status : undefined;
    const allowed = new Set(['pending', 'running', 'completed', 'failed']);
    const targetId = req.query.targetId ? Number(req.query.targetId) : undefined;
    res.json(
      store.listScans({
        status: scanStatus && allowed.has(scanStatus) ? (scanStatus as 'pending' | 'running' | 'completed' | 'failed') : undefined,
        targetId: Number.isInteger(targetId) ? targetId : undefined,
      }),
    );
  });

  app.post('/api/scans', (req, res, next) => {
    try {
      const body = parseCreateScanBody(req.body);
      const scan = store.createScan(body.targetId);
      store.appendAudit({
        action: 'scan.create',
        resourceType: 'scan',
        resourceId: String(scan.id),
        requestId: req.requestId,
      });
      queue.enqueue(scan.id);
      res.status(201).json(scan);
    } catch (error) {
      next(error);
    }
  });

  app.get('/api/scans/:id', (req, res) => {
    const scan = store.getScan(Number(req.params.id));
    if (!scan) {
      res.status(404).json({ error: 'Scan not found', requestId: req.requestId, code: 'not_found' });
      return;
    }
    res.json(scan);
  });

  app.post('/api/scans/:id/cancel', (req, res, next) => {
    try {
      runner.cancel(Number(req.params.id));
      const scan = store.getScan(Number(req.params.id));
      if (!scan) {
        res.status(404).json({ error: 'Scan not found', requestId: req.requestId, code: 'not_found' });
        return;
      }
      res.json(scan);
    } catch (error) {
      next(error);
    }
  });

  app.get('/api/vulnerabilities', (req, res) => {
    const status = typeof req.query.status === 'string' && isVulnerabilityStatus(req.query.status) ? req.query.status : undefined;
    const severity =
      typeof req.query.severity === 'string' && isVulnerabilitySeverity(req.query.severity) ? req.query.severity : undefined;
    const targetLanguage =
      typeof req.query.targetLanguage === 'string' && isTargetLanguage(req.query.targetLanguage)
        ? req.query.targetLanguage
        : undefined;
    const scanId = req.query.scanId ? Number(req.query.scanId) : undefined;
    res.json(
      store.listVulnerabilities({
        status,
        severity,
        targetLanguage,
        scanId: Number.isInteger(scanId) ? scanId : undefined,
      }),
    );
  });

  app.get('/api/vulnerabilities/:id', (req, res) => {
    const vulnerability = store.getVulnerability(Number(req.params.id));
    if (!vulnerability) {
      res.status(404).json({ error: 'Vulnerability not found', requestId: req.requestId, code: 'not_found' });
      return;
    }
    res.json(vulnerability);
  });

  app.patch('/api/vulnerabilities/:id', (req, res, next) => {
    try {
      const body = parseUpdateVulnerabilityBody(req.body);
      const current = store.getVulnerability(Number(req.params.id));
      if (!current) {
        res.status(404).json({ error: 'Vulnerability not found', requestId: req.requestId, code: 'not_found' });
        return;
      }
      if (body.status === 'reported') {
        const check = verifyOperatorChallenge({
          challengeId: body.challengeId!,
          vulnerabilityId: current.id,
          ruleId: body.ruleId ?? '',
          fingerprint: body.fingerprint ?? '',
          affectedFile: body.affectedFile ?? '',
          lineNumber: body.lineNumber ?? 0,
          nonce: body.nonce!,
        });
        if (!check.ok) {
          res.status(400).json({ error: check.reason ?? 'challenge failed', requestId: req.requestId, code: 'challenge_failed' });
          return;
        }
      }
      const vulnerability = store.updateVulnerabilityStatus(current.id, body.status);
      store.appendAudit({
        action: 'vulnerability.status',
        resourceType: 'vulnerability',
        resourceId: String(vulnerability!.id),
        detail: body.status,
        requestId: req.requestId,
      });
      res.json(vulnerability);
    } catch (error) {
      next(error);
    }
  });

  app.post('/api/vulnerabilities/:id/challenge', (req, res) => {
    const vulnerability = store.getVulnerability(Number(req.params.id));
    if (!vulnerability) {
      res.status(404).json({ error: 'Vulnerability not found', requestId: req.requestId, code: 'not_found' });
      return;
    }
    const challenge = issueOperatorChallenge({
      vulnerabilityId: vulnerability.id,
      ruleId: vulnerability.ruleId,
      fingerprint: vulnerability.fingerprint,
      affectedFile: vulnerability.affectedFile,
      lineNumber: vulnerability.lineNumber,
    });
    store.appendAudit({
      action: 'vulnerability.challenge',
      resourceType: 'vulnerability',
      resourceId: String(vulnerability.id),
      requestId: req.requestId,
    });
    res.status(201).json(challenge);
  });

  app.get('/api/reports/:vulnerabilityId', (req, res) => {
    const vulnerabilityId = Number(req.params.vulnerabilityId);
    const persisted = store.getReport(vulnerabilityId);
    if (persisted) {
      res.json(persisted);
      return;
    }
    const vulnerability = store.getVulnerability(vulnerabilityId);
    if (!vulnerability) {
      res.status(404).json({ error: 'Vulnerability not found', requestId: req.requestId, code: 'not_found' });
      return;
    }
    res.json(buildImmunefiReport(vulnerability));
  });

  app.get('/api/exports/sarif', (req, res) => {
    const scanId = req.query.scanId ? Number(req.query.scanId) : undefined;
    const vulnerabilities = store.listVulnerabilities({
      scanId: Number.isInteger(scanId) ? scanId : undefined,
    });
    res.json(buildSarifReport({ vulnerabilities }));
  });

  app.get('/api/metrics', (req, res) => {
    const snap = store.getMetricsSnapshot();
    const queueSize = queue.size();
    if (req.query.format === 'prometheus') {
      const lines = [
        `# HELP sentinel_scans_total Total scans`,
        `# TYPE sentinel_scans_total counter`,
        `sentinel_scans_total ${snap.scansTotal}`,
        `# HELP sentinel_scans_active Active scans`,
        `# TYPE sentinel_scans_active gauge`,
        `sentinel_scans_active ${snap.scansActive}`,
        `# HELP sentinel_scans_failed Failed scans`,
        `# TYPE sentinel_scans_failed counter`,
        `sentinel_scans_failed ${snap.scansFailed}`,
        `# HELP sentinel_vulns_total Total vulnerabilities`,
        `# TYPE sentinel_vulns_total counter`,
        `sentinel_vulns_total ${snap.vulnsTotal}`,
        `# HELP sentinel_vulns_verified Verified vulnerabilities`,
        `# TYPE sentinel_vulns_verified counter`,
        `sentinel_vulns_verified ${snap.vulnsVerified}`,
        `# HELP sentinel_queue_pending Pending queue depth`,
        `# TYPE sentinel_queue_pending gauge`,
        `sentinel_queue_pending ${queueSize.pending}`,
        `# HELP sentinel_queue_active Active queue workers`,
        `# TYPE sentinel_queue_active gauge`,
        `sentinel_queue_active ${queueSize.active}`,
      ];
      res.type('text/plain').send(lines.join('\n') + '\n');
      return;
    }
    res.json({ ...snap, queue: queueSize });
  });

  app.get('/api/provenance/:scanId', (req, res) => {
    const scanId = Number(req.params.scanId);
    if (!store.getScan(scanId)) {
      res.status(404).json({ error: 'Scan not found', requestId: req.requestId, code: 'not_found' });
      return;
    }
    res.json({
      scanId,
      chainValid: store.verifyProvenanceChain(scanId),
      entries: store.listProvenance(scanId),
    });
  });

  app.get('/api/audit', (req, res) => {
    const limit = req.query.limit ? Number(req.query.limit) : 50;
    res.json(store.listAuditEvents(Number.isFinite(limit) ? limit : 50));
  });

  app.get('/api/risk', (req, res) => {
    const scanId = req.query.scanId ? Number(req.query.scanId) : undefined;
    const vulnerabilities = store.listVulnerabilities({
      scanId: Number.isInteger(scanId) ? scanId : undefined,
    });
    res.json(portfolioRiskScore(vulnerabilities));
  });

  app.get('/api/suppressions', (_req, res) => {
    res.json(store.listActiveSuppressions());
  });

  app.post('/api/suppressions', (req, res, next) => {
    try {
      const body = parseCreateSuppressionBody(req.body);
      const suppression = store.createSuppression(body);
      store.appendAudit({
        action: 'suppression.create',
        resourceType: 'suppression',
        resourceId: String(suppression.id),
        detail: body.reason,
        requestId: req.requestId,
      });
      res.status(201).json(suppression);
    } catch (error) {
      next(error);
    }
  });

  app.delete('/api/suppressions/:id', (req, res) => {
    const deleted = store.deleteSuppression(Number(req.params.id));
    if (deleted) {
      store.appendAudit({
        action: 'suppression.delete',
        resourceType: 'suppression',
        resourceId: String(req.params.id),
        requestId: req.requestId,
      });
    }
    res.status(deleted ? 204 : 404).end();
  });

  app.get('/api/campaigns', (_req, res) => {
    res.json(store.listCampaigns());
  });

  app.post('/api/campaigns', (req, res, next) => {
    try {
      const body = parseCreateCampaignBody(req.body);
      const plan = createAndEnqueueCampaign(store, queue, body);
      store.appendAudit({
        action: 'campaign.create',
        resourceType: 'campaign',
        resourceId: String(plan.id),
        detail: body.name,
        requestId: req.requestId,
      });
      res.status(201).json(plan);
    } catch (error) {
      next(error);
    }
  });

  app.get('/api/campaigns/:id', (req, res) => {
    const status = getCampaignStatus(store, Number(req.params.id));
    if (!status) {
      res.status(404).json({ error: 'Campaign not found', requestId: req.requestId, code: 'not_found' });
      return;
    }
    res.json(status);
  });

  app.get('/api/attestations/:scanId', (req, res) => {
    const scanId = Number(req.params.scanId);
    const attestation = store.getAttestation(scanId);
    if (!attestation) {
      res.status(404).json({ error: 'Attestation not found', requestId: req.requestId, code: 'not_found' });
      return;
    }
    const verification = verifyScanAttestation(attestation.manifest as Parameters<typeof verifyScanAttestation>[0]);
    res.json({ ...attestation, verification });
  });

  app.get('/api/calibration', (_req, res) => {
    const points = collectFixtureCalibrationPoints(fixturesDir);
    res.json(fitCalibration(points));
  });

  app.get('/api/causality/:language', (req, res) => {
    const language = req.params.language;
    if (!isTargetLanguage(language)) {
      res.status(400).json({ error: 'Unsupported language', requestId: req.requestId, code: 'bad_request' });
      return;
    }
    const sample = `${language}-sample`;
    const findings = analyzeFixtureDirectory(join(fixturesDir, sample), language);
    res.json(buildCausalGraph(findings));
  });

  app.get('/api/stats/dashboard', (_req, res) => {
    res.json(store.getDashboardStats());
  });

  app.get('/api/stats/payout-potential', (_req, res) => {
    res.json(store.getPayoutPotential());
  });

  app.get('/api/logs/:scanId', (req, res) => {
    const scanId = Number(req.params.scanId);
    const scan = store.getScan(scanId);
    if (!scan) {
      res.status(404).json({ error: 'Scan not found', requestId: req.requestId, code: 'not_found' });
      return;
    }

    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    res.flushHeaders?.();

    let cursor = 0;
    const existing = store.listScanLogs(scanId);
    for (const entry of existing) {
      res.write(`data: ${JSON.stringify(entry)}\n\n`);
      cursor += 1;
    }

    const interval = setInterval(() => {
      const logs = store.listScanLogs(scanId);
      for (const entry of logs.slice(cursor)) {
        res.write(`data: ${JSON.stringify(entry)}\n\n`);
        cursor += 1;
      }
      const current = store.getScan(scanId);
      if (current && (current.status === 'completed' || current.status === 'failed')) {
        res.write(`event: complete\ndata: ${JSON.stringify({ status: current.status })}\n\n`);
        clearInterval(interval);
        res.end();
      }
    }, 400);

    req.on('close', () => clearInterval(interval));
  });

  app.use((error: unknown, req: Request, res: Response, _next: NextFunction) => {
    const message = error instanceof Error ? error.message : 'Unexpected error';
    res.status(400).json({ error: message, requestId: req.requestId, code: 'bad_request' });
  });

  return app;
}

function bearer(header: string | undefined): string | null {
  if (!header) return null;
  const match = header.match(/^Bearer\s+(.+)$/i);
  return match?.[1] ?? null;
}

const isDirectRun = process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;
if (isDirectRun) {
  const port = Number(process.env.PORT ?? 8788);
  createApp().listen(port, () => {
    console.log(`Sentinel-X API listening on http://localhost:${port}`);
  });
}
