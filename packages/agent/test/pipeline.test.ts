import assert from 'node:assert/strict';
import { join } from 'node:path';
import test from 'node:test';
import { createDatabase, SentinelStore } from '@sentinel-x/storage';
import { ScanRunner } from '../src/index.js';

const fixturesDir = join(import.meta.dirname, '../../../fixtures/repos');

test('ScanRunner completes an end-to-end noir scan', async () => {
  const store = new SentinelStore(createDatabase());
  const target = store.createTarget({
    repoUrl: 'https://github.com/example/noir-sample',
    name: 'noir-sample',
    language: 'noir',
    maxPayout: 12000,
  });
  const scan = store.createScan(target.id);
  const runner = new ScanRunner(store, { fixturesDir });
  await runner.run(scan.id);
  const completed = store.getScan(scan.id);
  assert.equal(completed?.status, 'completed');
  assert.ok((completed?.bugsFound ?? 0) > 0);
  const verified = store.listVulnerabilities({ scanId: scan.id, status: 'verified' });
  assert.ok(verified.length > 0);
});
