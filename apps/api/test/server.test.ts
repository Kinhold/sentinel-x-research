import assert from 'node:assert/strict';
import { join } from 'node:path';
import test from 'node:test';
import { ScanRunner } from '@sentinel-x/agent';
import { createDatabase, SentinelStore } from '@sentinel-x/storage';
import { request } from './request.js';
import { createApp } from '../src/server.js';

const fixturesDir = join(import.meta.dirname, '../../../fixtures/repos');

function testApp() {
  const store = new SentinelStore(createDatabase());
  const runner = new ScanRunner(store, { fixturesDir, allowClone: false });
  return createApp({ store, runner, fixturesDir, apiKey: null });
}

test('health check responds ok', async () => {
  const app = testApp();
  const response = await request(app, '/api/healthz');
  assert.equal(response.status, 200);
  const body = (await response.json()) as { status: string; requestId?: string };
  assert.equal(body.status, 'ok');
  assert.ok(body.requestId);
});

test('target and scan lifecycle', async () => {
  const app = testApp();
  const targetResponse = await request(app, '/api/targets', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      repoUrl: 'https://github.com/example/noir-sample',
      name: 'noir-sample',
      language: 'noir',
      maxPayout: 8000,
    }),
  });
  assert.equal(targetResponse.status, 201);
  const target = (await targetResponse.json()) as { id: number };
  const scanResponse = await request(app, '/api/scans', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ targetId: target.id }),
  });
  assert.equal(scanResponse.status, 201);
  const scan = (await scanResponse.json()) as { id: number };
  await waitFor(async () => {
    const current = await request(app, `/api/scans/${scan.id}`);
    const body = (await current.json()) as { status: string };
    return body.status === 'completed' || body.status === 'failed';
  }, 8000);
  const completed = await request(app, `/api/scans/${scan.id}`);
  const completedBody = (await completed.json()) as { status: string; sourceMode?: string };
  assert.equal(completedBody.status, 'completed');
  assert.equal(completedBody.sourceMode, 'fixture');
  const statsResponse = await request(app, '/api/stats/dashboard');
  assert.equal(statsResponse.status, 200);
  const stats = (await statsResponse.json()) as { totalScans: number; verifiedVulnerabilities: number };
  assert.ok(stats.totalScans >= 1);
  assert.ok(stats.verifiedVulnerabilities >= 1);
});

test('API key auth rejects missing credentials', async () => {
  const store = new SentinelStore(createDatabase());
  const runner = new ScanRunner(store, { fixturesDir, allowClone: false });
  const app = createApp({ store, runner, fixturesDir, apiKey: 'secret' });
  const denied = await request(app, '/api/targets');
  assert.equal(denied.status, 401);
  const allowed = await request(app, '/api/targets', {
    headers: { 'x-api-key': 'secret' },
  });
  assert.equal(allowed.status, 200);
});

test('SARIF export returns tool driver and results', async () => {
  const app = testApp();
  const targetResponse = await request(app, '/api/targets', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      repoUrl: 'https://github.com/example/rust-sample',
      name: 'rust-sample',
      language: 'rust',
      maxPayout: 1000,
    }),
  });
  const target = (await targetResponse.json()) as { id: number };
  const scanResponse = await request(app, '/api/scans', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ targetId: target.id }),
  });
  const scan = (await scanResponse.json()) as { id: number };
  await waitFor(async () => {
    const current = await request(app, `/api/scans/${scan.id}`);
    const body = (await current.json()) as { status: string };
    return body.status === 'completed' || body.status === 'failed';
  }, 8000);
  const sarifResponse = await request(app, `/api/exports/sarif?scanId=${scan.id}`);
  assert.equal(sarifResponse.status, 200);
  const sarif = (await sarifResponse.json()) as {
    version: string;
    runs: Array<{ tool: { driver: { name: string } }; results: unknown[] }>;
  };
  assert.equal(sarif.version, '2.1.0');
  assert.equal(sarif.runs[0]?.tool.driver.name, 'Sentinel-X');
  assert.ok((sarif.runs[0]?.results.length ?? 0) >= 1);

  const metrics = await request(app, '/api/metrics');
  assert.equal(metrics.status, 200);
  const metricsBody = (await metrics.json()) as { scansTotal: number; queue: { pending: number } };
  assert.ok(metricsBody.scansTotal >= 1);

  const provenance = await request(app, `/api/provenance/${scan.id}`);
  assert.equal(provenance.status, 200);
  const provBody = (await provenance.json()) as { chainValid: boolean; entries: unknown[] };
  assert.equal(provBody.chainValid, true);
  assert.ok(provBody.entries.length >= 1);

  const risk = await request(app, `/api/risk?scanId=${scan.id}`);
  assert.equal(risk.status, 200);
  const riskBody = (await risk.json()) as { score: number; band: string };
  assert.ok(typeof riskBody.score === 'number');
  assert.ok(riskBody.band);
});

async function waitFor(predicate: () => Promise<boolean>, timeoutMs: number): Promise<void> {
  const started = Date.now();
  while (Date.now() - started < timeoutMs) {
    if (await predicate()) return;
    await new Promise((resolve) => setTimeout(resolve, 200));
  }
  throw new Error('Timed out waiting for condition');
}
