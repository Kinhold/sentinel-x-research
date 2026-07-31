import assert from 'node:assert/strict';
import { join } from 'node:path';
import test from 'node:test';
import { analyzeFixtureDirectory, analyzeRustSources, verifyFinding } from '../src/index.js';

const fixtures = join(import.meta.dirname, '../../../fixtures/repos');

test('rust analyzer finds wrapping arithmetic and ignores checked_add', () => {
  const findings = analyzeFixtureDirectory(join(fixtures, 'rust-sample'), 'rust');
  assert.ok(findings.some((finding) => finding.vulnType === 'integer_overflow' && finding.ruleId === 'rust.wrapping-arithmetic'));
  assert.ok(findings.some((finding) => finding.ruleId === 'rust.narrowing-cast'));
  assert.ok(findings.every((finding) => finding.fingerprint && finding.ruleId));
});

test('rust analyzer does not flag checked_add as overflow', () => {
  const findings = analyzeRustSources([
    {
      path: 'safe.rs',
      content: 'fn add(a: u64, b: u64) -> Option<u64> { a.checked_add(b) }\n',
    },
  ]);
  assert.equal(findings.filter((f) => f.vulnType === 'integer_overflow').length, 0);
});

test('noir analyzer finds under-constrained witness', () => {
  const findings = analyzeFixtureDirectory(join(fixtures, 'noir-sample'), 'noir');
  assert.ok(findings.some((finding) => finding.vulnType === 'under_constrained_circuit'));
  assert.ok(findings.some((finding) => finding.title.includes('age')));
});

test('solana analyzer finds CPI and init issues', () => {
  const findings = analyzeFixtureDirectory(join(fixtures, 'solana-sample'), 'solana');
  assert.ok(findings.some((finding) => finding.vulnType === 'cpi_vulnerability'));
  assert.ok(findings.some((finding) => finding.vulnType === 'uninitialized_account'));
});

test('verifyFinding requires structural evidence', () => {
  const weak = verifyFinding({
    title: 'weak',
    description: 'd',
    severity: 'low',
    vulnType: 'other',
    confidenceScore: 0.9,
  });
  assert.equal(weak.status, 'false_positive');

  const strong = verifyFinding({
    title: 'strong',
    description: 'd',
    severity: 'high',
    vulnType: 'integer_overflow',
    confidenceScore: 0.8,
    affectedFile: 'a.rs',
    lineNumber: 3,
    ruleId: 'rust.wrapping-arithmetic',
    fingerprint: 'abc',
    pocCode: 'wrapping_add(1)',
  });
  assert.equal(strong.status, 'verified');
});
