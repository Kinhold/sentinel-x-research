import assert from 'node:assert/strict';
import test from 'node:test';
import { createDatabase, SentinelStore } from '../src/index.js';

test('SentinelStore creates targets and scans', () => {
  const db = createDatabase();
  const store = new SentinelStore(db);
  const target = store.createTarget({
    repoUrl: 'https://github.com/example/vuln',
    name: 'Example',
    language: 'rust',
    maxPayout: 10000,
  });
  const scan = store.createScan(target.id);
  assert.equal(scan.status, 'pending');
  assert.equal(store.listTargets().length, 1);
});

test('SentinelStore records vulnerabilities and dashboard stats', () => {
  const db = createDatabase();
  const store = new SentinelStore(db);
  const target = store.createTarget({
    repoUrl: 'https://github.com/example/vuln',
    name: 'Example',
    language: 'noir',
    maxPayout: 5000,
  });
  const scan = store.createScan(target.id);
  store.insertVulnerability(scan.id, target.id, {
    title: 'Under-constrained witness',
    description: 'Private input never constrained against public claim.',
    severity: 'high',
    vulnType: 'under_constrained_circuit',
    confidenceScore: 0.82,
    affectedFile: 'src/main.nr',
    lineNumber: 14,
  }, 'noir');
  const stats = store.getDashboardStats();
  assert.equal(stats.totalVulnerabilities, 1);
  assert.equal(stats.highCount, 1);
});
