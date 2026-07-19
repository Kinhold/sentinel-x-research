import assert from 'node:assert/strict';
import { join } from 'node:path';
import test from 'node:test';
import { analyzeFixtureDirectory } from '../src/index.js';

const fixtures = join(import.meta.dirname, '../../../fixtures/repos');

test('rust analyzer finds wrapping arithmetic', () => {
  const findings = analyzeFixtureDirectory(join(fixtures, 'rust-sample'), 'rust');
  assert.ok(findings.some((finding) => finding.vulnType === 'integer_overflow'));
});

test('noir analyzer finds under-constrained witness', () => {
  const findings = analyzeFixtureDirectory(join(fixtures, 'noir-sample'), 'noir');
  assert.ok(findings.some((finding) => finding.vulnType === 'under_constrained_circuit'));
});

test('solana analyzer finds CPI and init issues', () => {
  const findings = analyzeFixtureDirectory(join(fixtures, 'solana-sample'), 'solana');
  assert.ok(findings.some((finding) => finding.vulnType === 'cpi_vulnerability'));
  assert.ok(findings.some((finding) => finding.vulnType === 'uninitialized_account'));
});
