import assert from 'node:assert/strict';
import { join } from 'node:path';
import test from 'node:test';
import {
  binaryEntropy,
  campaignLineageRoot,
  clearCommitments,
  commitReview,
  learnPriorsFromHistory,
  merkleRoot,
  priorBoostFromMean,
  rankFindingsForAttention,
  revealReview,
  shadowDualRun,
  updateRulePrior,
  collectSourceFiles,
} from '../src/index.js';

const fixtures = join(import.meta.dirname, '../../../fixtures/repos');

test('binary entropy peaks near 0.5', () => {
  assert.ok(binaryEntropy(0.5) > binaryEntropy(0.9));
  assert.ok(binaryEntropy(0.5) > binaryEntropy(0.1));
});

test('attention ranking prefers uncertain high-severity findings', () => {
  const ranked = rankFindingsForAttention([
    {
      title: 'low-conf high',
      description: 'd',
      severity: 'high',
      vulnType: 'integer_overflow',
      confidenceScore: 0.55,
      fingerprint: 'a',
    },
    {
      title: 'certain low',
      description: 'd',
      severity: 'low',
      vulnType: 'other',
      confidenceScore: 0.95,
      fingerprint: 'b',
    },
  ]);
  assert.equal(ranked[0]?.fingerprint, 'a');
});

test('rule prior updates from operator feedback', () => {
  const prior = updateRulePrior({ alpha: 2, beta: 2 }, 'reported');
  assert.ok(prior.mean > 0.5);
  const down = updateRulePrior(prior, 'false_positive');
  assert.ok(down.mean < prior.mean);
  assert.ok(priorBoostFromMean(0.9) > 0);
  assert.ok(priorBoostFromMean(0.1) < 0);
  const learned = learnPriorsFromHistory([
    { ruleId: 'r1', status: 'reported' },
    { ruleId: 'r1', status: 'false_positive' },
    { ruleId: 'r1', status: 'reported' },
  ]);
  assert.ok(learned.r1);
});

test('commit-reveal rejects tampered notes', () => {
  clearCommitments();
  const { commitment, secret } = commitReview({
    vulnerabilityId: 1,
    notes: 'looks real',
    decision: 'approve_report',
  });
  const bad = revealReview({
    commitmentId: commitment.commitmentId,
    vulnerabilityId: 1,
    secret,
    notes: 'tampered',
    decision: 'approve_report',
  });
  assert.equal(bad.ok, false);
  const { commitment: c2, secret: s2 } = commitReview({
    vulnerabilityId: 2,
    notes: 'fp',
    decision: 'reject_false_positive',
  });
  const good = revealReview({
    commitmentId: c2.commitmentId,
    vulnerabilityId: 2,
    secret: s2,
    notes: 'fp',
    decision: 'reject_false_positive',
  });
  assert.equal(good.ok, true);
});

test('merkle lineage is order-sensitive by scanId sort', () => {
  const root = campaignLineageRoot([
    { scanId: 2, contentHash: 'bbb' },
    { scanId: 1, contentHash: 'aaa' },
  ]);
  const root2 = campaignLineageRoot([
    { scanId: 1, contentHash: 'aaa' },
    { scanId: 2, contentHash: 'bbb' },
  ]);
  assert.equal(root, root2);
  assert.notEqual(merkleRoot(['a', 'b']), merkleRoot(['b', 'a']));
});

test('shadow dual-run reports agreement for rust fixture', () => {
  const files = collectSourceFiles(join(fixtures, 'rust-sample'), 'rust');
  const shadow = shadowDualRun('rust', files);
  assert.ok(shadow.agreementRate >= 0 && shadow.agreementRate <= 1);
  assert.ok(shadow.both.length + shadow.onlySpecialized.length + shadow.onlyDeclarative.length >= 1);
});
