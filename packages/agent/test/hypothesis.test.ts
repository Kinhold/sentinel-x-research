import assert from 'node:assert/strict';
import { join } from 'node:path';
import test from 'node:test';
import {
  applyHypothesisDeltas,
  portfolioRiskScore,
  runHypothesisEngine,
  summarizeHypotheses,
} from '../src/hypothesis.js';
import { RateLimiter, parseWebhookUrls } from '../src/notify.js';

const fixtures = join(import.meta.dirname, '../../../fixtures/repos');

test('hypothesis engine supports wrapping findings in rust fixture', () => {
  const findings = [
    {
      title: 'Unchecked integer wrapping path',
      description: 'wrap',
      severity: 'high' as const,
      vulnType: 'integer_overflow' as const,
      confidenceScore: 0.8,
      affectedFile: 'src/lib.rs',
      lineNumber: 2,
      ruleId: 'rust.wrapping-arithmetic',
      fingerprint: 'wrap-1',
      pocCode: 'balance.wrapping_add(amount)',
      affectedFunction: 'mint',
    },
  ];
  const hypotheses = runHypothesisEngine(findings, {
    workspacePath: join(fixtures, 'rust-sample'),
    language: 'rust',
  });
  assert.ok(hypotheses.some((h) => h.status === 'supported'));
  const refined = applyHypothesisDeltas(findings[0]!, hypotheses);
  assert.ok(refined.confidenceScore >= findings[0]!.confidenceScore);
  const summary = summarizeHypotheses(hypotheses);
  assert.ok(summary.supported >= 1);
});

test('portfolio risk score clusters correlated findings', () => {
  const risk = portfolioRiskScore([
    {
      id: 1,
      scanId: 1,
      targetId: 1,
      title: 'a',
      description: 'd',
      severity: 'high',
      vulnType: 'integer_overflow',
      targetLanguage: 'rust',
      status: 'verified',
      affectedFile: 'src/lib.rs',
      affectedFunction: 'mint',
      confidenceScore: 0.9,
      createdAt: new Date().toISOString(),
    },
    {
      id: 2,
      scanId: 1,
      targetId: 1,
      title: 'b',
      description: 'd',
      severity: 'medium',
      vulnType: 'access_control',
      targetLanguage: 'rust',
      status: 'verified',
      affectedFile: 'src/lib.rs',
      affectedFunction: 'mint',
      confidenceScore: 0.7,
      createdAt: new Date().toISOString(),
    },
  ]);
  assert.ok(risk.score > 0);
  assert.ok(risk.clusters.some((c) => c.key.includes('fn:src/lib.rs:mint')));
});

test('rate limiter eventually blocks burst traffic', () => {
  const limiter = new RateLimiter(2, 0);
  assert.equal(limiter.allow('a'), true);
  assert.equal(limiter.allow('a'), true);
  assert.equal(limiter.allow('a'), false);
});

test('parseWebhookUrls filters non-http entries', () => {
  assert.deepEqual(parseWebhookUrls('https://example.com/hook, ftp://bad, http://localhost:9/x'), [
    'https://example.com/hook',
    'http://localhost:9/x',
  ]);
});
