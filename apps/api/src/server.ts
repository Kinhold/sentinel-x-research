import { mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { config } from 'dotenv';
import express, { type Express, type NextFunction, type Request, type Response } from 'express';
import { ScanRunner, buildImmunefiReport } from '@sentinel-x/agent';
import {
  isTargetLanguage,
  isVulnerabilitySeverity,
  isVulnerabilityStatus,
  parseCreateScanBody,
  parseCreateTargetBody,
  parseUpdateVulnerabilityBody,
} from '@sentinel-x/contracts';
import { createDatabase, SentinelStore } from '@sentinel-x/storage';

config();

const rootDir = join(dirname(fileURLToPath(import.meta.url)), '../../..');
const databasePath = process.env.DATABASE_PATH ?? join(rootDir, 'data/sentinel-x.db');
mkdirSync(dirname(databasePath), { recursive: true });

const db = createDatabase(databasePath);
const store = new SentinelStore(db);
const fixturesDir = process.env.SCAN_FIXTURES_DIR ?? join(rootDir, 'fixtures/repos');
const runner = new ScanRunner(store, { fixturesDir });
const activeScans = new Set<number>();

export function createApp(): Express {
  const app = express();
  const corsOrigin = process.env.CORS_ORIGIN ?? 'http://localhost:5174';

  app.use((req, res, next) => {
    res.setHeader('Access-Control-Allow-Origin', corsOrigin);
    res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PATCH,DELETE,OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    if (req.method === 'OPTIONS') {
      res.status(204).end();
      return;
    }
    next();
  });
  app.use(express.json({ limit: '1mb' }));

  app.get('/api/healthz', (_req, res) => {
    res.json({ status: 'ok' });
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
      res.status(404).json({ error: 'Target not found' });
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
      queueScan(scan.id);
      res.status(201).json(scan);
    } catch (error) {
      next(error);
    }
  });

  app.get('/api/scans/:id', (req, res) => {
    const scan = store.getScan(Number(req.params.id));
    if (!scan) {
      res.status(404).json({ error: 'Scan not found' });
      return;
    }
    res.json(scan);
  });

  app.post('/api/scans/:id/cancel', (req, res, next) => {
    try {
      runner.cancel(Number(req.params.id));
      const scan = store.getScan(Number(req.params.id));
      if (!scan) {
        res.status(404).json({ error: 'Scan not found' });
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
      res.status(404).json({ error: 'Vulnerability not found' });
      return;
    }
    res.json(vulnerability);
  });

  app.patch('/api/vulnerabilities/:id', (req, res, next) => {
    try {
      const body = parseUpdateVulnerabilityBody(req.body);
      const vulnerability = store.updateVulnerabilityStatus(Number(req.params.id), body.status);
      if (!vulnerability) {
        res.status(404).json({ error: 'Vulnerability not found' });
        return;
      }
      res.json(vulnerability);
    } catch (error) {
      next(error);
    }
  });

  app.get('/api/reports/:vulnerabilityId', (req, res) => {
    const vulnerability = store.getVulnerability(Number(req.params.vulnerabilityId));
    if (!vulnerability) {
      res.status(404).json({ error: 'Vulnerability not found' });
      return;
    }
    res.json(buildImmunefiReport(vulnerability));
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
      res.status(404).json({ error: 'Scan not found' });
      return;
    }

    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    res.flushHeaders?.();

    const existing = store.listScanLogs(scanId);
    for (const entry of existing) {
      res.write(`data: ${JSON.stringify(entry)}\n\n`);
    }

    const interval = setInterval(() => {
      const latest = store.listScanLogs(scanId).slice(existing.length);
      for (const entry of latest) {
        res.write(`data: ${JSON.stringify(entry)}\n\n`);
        existing.push(entry);
      }
      const current = store.getScan(scanId);
      if (current && (current.status === 'completed' || current.status === 'failed')) {
        res.write(`event: complete\ndata: ${JSON.stringify({ status: current.status })}\n\n`);
        clearInterval(interval);
        res.end();
      }
    }, 500);

    req.on('close', () => clearInterval(interval));
  });

  app.use((error: unknown, _req: Request, res: Response, _next: NextFunction) => {
    const message = error instanceof Error ? error.message : 'Unexpected error';
    res.status(400).json({ error: message });
  });

  return app;
}

function queueScan(scanId: number): void {
  if (activeScans.has(scanId)) return;
  activeScans.add(scanId);
  setImmediate(() => {
    runner
      .run(scanId)
      .catch(() => undefined)
      .finally(() => activeScans.delete(scanId));
  });
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const port = Number(process.env.PORT ?? 8788);
  createApp().listen(port, () => {
    console.log(`Sentinel-X API listening on http://localhost:${port}`);
  });
}
