import assert from 'node:assert/strict';
import { join } from 'node:path';
import test from 'node:test';
import {
  applyCalibration,
  buildCausalGraph,
  collapse,
  collectFixtureCalibrationPoints,
  compose,
  evidenceOf,
  fitCalibration,
  issueOperatorChallenge,
  stageLift,
  verifyOperatorChallenge,
} from '../src/index.js';
import { clearChallenges } from '../src/challenge.js';

const fixturesDir = join(import.meta.dirname, '../../../fixtures/repos');

test('proof algebra compose is auditable', () => {
  const proof = compose(
    stageLift('a', (e) => ({ confidence: e.confidence + 0.1, note: 'a+0.1' })),
    stageLift('b', (e) => ({ confidence: e.confidence + 0.05, note: 'b+0.05' })),
  )(evidenceOf(0.5, 2));
  const decision = collapse(proof, 0.62);
  assert.equal(decision.verified, true);
  assert.match(decision.rationale, /a\+0\.1/);
});

test('calibration reduces brier on labeled fixtures', () => {
  const points = collectFixtureCalibrationPoints(fixturesDir);
  assert.ok(points.length > 0);
  const model = fitCalibration(points);
  assert.ok(model.samples === points.length);
  assert.ok(model.brierScore >= 0 && model.brierScore <= 1);
  const cal = applyCalibration(model, 0.8);
  assert.ok(cal > 0 && cal < 1);
});

test('causal graph links co-located findings', () => {
  const graph = buildCausalGraph([
    {
      title: 'a',
      description: 'd',
      severity: 'high',
      vulnType: 'access_control',
      confidenceScore: 0.7,
      affectedFile: 'x.rs',
      affectedFunction: 'f',
      fingerprint: 'a',
      ruleId: 'r1',
    },
    {
      title: 'b',
      description: 'd',
      severity: 'high',
      vulnType: 'cpi_vulnerability',
      confidenceScore: 0.7,
      affectedFile: 'x.rs',
      affectedFunction: 'f',
      fingerprint: 'b',
      ruleId: 'r2',
    },
  ]);
  assert.ok(graph.edges.some((e) => e.relation === 'same-function'));
  assert.ok(graph.edges.some((e) => e.relation === 'type-enables'));
});

test('operator challenge gates reported status', () => {
  clearChallenges();
  const challenge = issueOperatorChallenge({
    vulnerabilityId: 9,
    ruleId: 'rust.wrapping-arithmetic',
    fingerprint: 'fp',
    affectedFile: 'src/lib.rs',
    lineNumber: 2,
  });
  assert.equal(
    verifyOperatorChallenge({
      challengeId: challenge.challengeId,
      vulnerabilityId: 9,
      ruleId: 'wrong',
      fingerprint: 'fp',
      affectedFile: 'src/lib.rs',
      lineNumber: 2,
      nonce: challenge.nonce,
    }).ok,
    false,
  );
  const ok = verifyOperatorChallenge({
    challengeId: challenge.challengeId,
    vulnerabilityId: 9,
    ruleId: 'rust.wrapping-arithmetic',
    fingerprint: 'fp',
    affectedFile: 'src/lib.rs',
    lineNumber: 2,
    nonce: challenge.nonce,
  });
  assert.equal(ok.ok, true);
});
