import assert from 'node:assert/strict';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import test from 'node:test';
import { createDatabase, SentinelStore } from '@sentinel-x/storage';
import { ScanRunner } from '../src/index.js';

const fixturesDir = join(import.meta.dirname, '../../../fixtures/repos');

test('ScanRunner completes an end-to-end noir scan and persists reports', async () => {
  const store = new SentinelStore(createDatabase());
  const target = store.createTarget({
    repoUrl: 'https://github.com/example/noir-sample',
    name: 'noir-sample',
    language: 'noir',
    maxPayout: 12000,
  });
  const scan = store.createScan(target.id);
  const runner = new ScanRunner(store, { fixturesDir, allowClone: false });
  await runner.run(scan.id);
  const completed = store.getScan(scan.id);
  assert.equal(completed?.status, 'completed');
  assert.equal(completed?.sourceMode, 'fixture');
  assert.ok((completed?.bugsFound ?? 0) > 0);
  const verified = store.listVulnerabilities({ scanId: scan.id, status: 'verified' });
  assert.ok(verified.length > 0);
  assert.ok(verified[0]?.ruleId);
  assert.ok(store.getReport(verified[0]!.id));
  assert.equal(store.verifyProvenanceChain(scan.id), true);
  assert.ok(store.listProvenance(scan.id).length >= 2);
});

test('ScanRunner cancel aborts an in-flight scan', async () => {
  const store = new SentinelStore(createDatabase());
  const target = store.createTarget({
    repoUrl: 'https://github.com/example/rust-sample',
    name: 'rust-sample',
    language: 'rust',
    maxPayout: 5000,
  });
  const scan = store.createScan(target.id);
  const runner = new ScanRunner(store, {
    fixturesDir,
    allowClone: false,
    injectPauseMs: 250,
  });

  const running = runner.run(scan.id);
  await delay(40);
  runner.cancel(scan.id);
  await running;
  const final = store.getScan(scan.id);
  assert.equal(final?.status, 'failed');
  assert.equal(final?.errorMessage, 'Cancelled by operator');
});
