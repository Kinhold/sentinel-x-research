import assert from 'node:assert/strict';
import test from 'node:test';
import {
  parseCreateScanBody,
  parseCreateTargetBody,
  parseUpdateVulnerabilityBody,
  SEVERITY_PAYOUT_WEIGHT,
} from '../src/index.js';

test('parseCreateTargetBody accepts valid payload', () => {
  const body = parseCreateTargetBody({
    repoUrl: 'https://github.com/example/repo',
    name: 'Example',
    language: 'rust',
    maxPayout: 25000,
  });
  assert.equal(body.language, 'rust');
  assert.equal(body.maxPayout, 25000);
});

test('parseCreateTargetBody rejects unknown language', () => {
  assert.throws(() => parseCreateTargetBody({ repoUrl: 'x', name: 'x', language: 'go' }));
});

test('parseCreateScanBody requires positive integer targetId', () => {
  assert.throws(() => parseCreateScanBody({ targetId: 0 }));
  assert.equal(parseCreateScanBody({ targetId: 3 }).targetId, 3);
});

test('parseUpdateVulnerabilityBody validates status enum', () => {
  assert.throws(() => parseUpdateVulnerabilityBody({ status: 'maybe' }));
  assert.equal(parseUpdateVulnerabilityBody({ status: 'verified' }).status, 'verified');
});

test('severity payout weights are ordered', () => {
  assert.ok(SEVERITY_PAYOUT_WEIGHT.critical > SEVERITY_PAYOUT_WEIGHT.high);
  assert.ok(SEVERITY_PAYOUT_WEIGHT.high > SEVERITY_PAYOUT_WEIGHT.medium);
});
