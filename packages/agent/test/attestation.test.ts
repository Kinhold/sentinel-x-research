import assert from 'node:assert/strict';
import { join } from 'node:path';
import test from 'node:test';
import { createDatabase, SentinelStore } from '@sentinel-x/storage';
import {
  ScanRunner,
  analyzeFixtureDirectory,
  applySuppressions,
  buildScanAttestation,
  hashRulePackPayload,
  verifyScanAttestation,
} from '../src/index.js';
import corePack from '../src/rules/sentinel-core.json' with { type: 'json' };

const fixturesDir = join(import.meta.dirname, '../../../fixtures/repos');

test('attestation signs and verifies with secret', () => {
  process.env.ATTESTATION_SECRET = 'test-secret';
  const attestation = buildScanAttestation({
    scanId: 1,
    targetId: 2,
    sourceMode: 'fixture',
    sourceCommit: null,
    rulePackHash: hashRulePackPayload(corePack),
    vulnerabilities: [],
    secret: 'test-secret',
  });
  assert.ok(attestation.contentHash);
  assert.ok(attestation.signature);
  assert.equal(verifyScanAttestation(attestation, 'test-secret').ok, true);
  assert.equal(verifyScanAttestation(attestation, 'wrong').ok, false);
});

test('suppressions filter matching fingerprints', () => {
  const findings = analyzeFixtureDirectory(join(fixturesDir, 'rust-sample'), 'rust');
  assert.ok(findings.length > 0);
  const fp = findings[0]!.fingerprint!;
  const { kept, suppressed } = applySuppressions(findings, [{ fingerprint: fp, reason: 'accepted risk' }]);
  assert.equal(suppressed.length, 1);
  assert.equal(kept.length, findings.length - 1);
});

test('deterministic replay yields identical fingerprints', () => {
  const a = analyzeFixtureDirectory(join(fixturesDir, 'noir-sample'), 'noir');
  const b = analyzeFixtureDirectory(join(fixturesDir, 'noir-sample'), 'noir');
  assert.deepEqual(
    a.map((f) => f.fingerprint).sort(),
    b.map((f) => f.fingerprint).sort(),
  );
});

test('scan issues attestation artifact', async () => {
  const store = new SentinelStore(createDatabase());
  const target = store.createTarget({
    repoUrl: 'https://github.com/example/noir-sample',
    name: 'noir-sample',
    language: 'noir',
    maxPayout: 1000,
  });
  const scan = store.createScan(target.id);
  const runner = new ScanRunner(store, { fixturesDir, allowClone: false });
  await runner.run(scan.id);
  const attestation = store.getAttestation(scan.id);
  assert.ok(attestation);
  assert.ok(attestation!.contentHash);
});
