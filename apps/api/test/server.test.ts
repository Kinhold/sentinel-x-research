import assert from 'node:assert/strict';
import test from 'node:test';
import { request } from './request.js';
import { createApp } from '../src/server.js';

test('health check responds ok', async () => {
  const app = createApp();
  const response = await request(app, '/api/healthz');
  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), { status: 'ok' });
});

test('target and scan lifecycle', async () => {
  const app = createApp();
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
  const statsResponse = await request(app, '/api/stats/dashboard');
  assert.equal(statsResponse.status, 200);
  const stats = (await statsResponse.json()) as { totalScans: number };
  assert.ok(stats.totalScans >= 1);
});

async function waitFor(predicate: () => Promise<boolean>, timeoutMs: number): Promise<void> {
  const started = Date.now();
  while (Date.now() - started < timeoutMs) {
    if (await predicate()) return;
    await new Promise((resolve) => setTimeout(resolve, 200));
  }
  throw new Error('Timed out waiting for condition');
}
