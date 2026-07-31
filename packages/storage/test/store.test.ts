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

test('SentinelStore records vulnerabilities, reports, and dashboard stats', () => {
  const db = createDatabase();
  const store = new SentinelStore(db);
  const target = store.createTarget({
    repoUrl: 'https://github.com/example/vuln',
    name: 'Example',
    language: 'noir',
    maxPayout: 5000,
  });
  const scan = store.createScan(target.id);
  const vuln = store.insertVulnerability(
    scan.id,
    target.id,
    {
      title: 'Under-constrained witness',
      description: 'Private input never constrained against public claim.',
      severity: 'high',
      vulnType: 'under_constrained_circuit',
      confidenceScore: 0.82,
      affectedFile: 'src/main.nr',
      lineNumber: 14,
      ruleId: 'noir.underconstrained-witness',
      fingerprint: 'fp-test-1',
    },
    'noir',
  );
  store.updateVulnerabilityVerification(vuln.id, {
    status: 'verified',
    fvHarness: 'harness',
    fvLog: 'ok',
    confidenceScore: 0.9,
  });
  store.upsertReport({
    vulnerabilityId: vuln.id,
    title: vuln.title,
    severity: vuln.severity,
    markdown: '# report',
    generatedAt: new Date().toISOString(),
  });
  assert.ok(store.getReport(vuln.id));
  const stats = store.getDashboardStats();
  assert.equal(stats.totalVulnerabilities, 1);
  assert.equal(stats.highCount, 1);
  assert.equal(stats.verifiedVulnerabilities, 1);
});

test('false_positive clears verified_at', () => {
  const store = new SentinelStore(createDatabase());
  const target = store.createTarget({
    repoUrl: 'https://github.com/example/vuln',
    name: 'Example',
    language: 'rust',
  });
  const scan = store.createScan(target.id);
  const vuln = store.insertVulnerability(
    scan.id,
    target.id,
    {
      title: 'x',
      description: 'y',
      severity: 'low',
      vulnType: 'other',
      confidenceScore: 0.5,
    },
    'rust',
  );
  store.updateVulnerabilityStatus(vuln.id, 'verified');
  assert.ok(store.getVulnerability(vuln.id)?.verifiedAt);
  store.updateVulnerabilityStatus(vuln.id, 'false_positive');
  assert.equal(store.getVulnerability(vuln.id)?.verifiedAt, null);
});
