import assert from 'node:assert/strict';
import test from 'node:test';
import { buildSarifReport } from '../src/sarif.js';
import type { Vulnerability } from '@sentinel-x/contracts';

test('buildSarifReport emits SARIF 2.1 with fingerprints', () => {
  const vulns: Vulnerability[] = [
    {
      id: 1,
      scanId: 9,
      targetId: 3,
      title: 'Unchecked integer wrapping path',
      description: 'wrapping_add absorbs overflow',
      severity: 'high',
      vulnType: 'integer_overflow',
      targetLanguage: 'rust',
      status: 'verified',
      affectedFile: 'src/lib.rs',
      lineNumber: 2,
      ruleId: 'rust.wrapping-arithmetic',
      fingerprint: 'deadbeefcafebabe',
      confidenceScore: 0.9,
      createdAt: new Date().toISOString(),
    },
  ];
  const sarif = buildSarifReport({ vulnerabilities: vulns });
  assert.equal(sarif.version, '2.1.0');
  assert.equal(sarif.runs[0]?.results[0]?.fingerprints?.['sentinel/v1'], 'deadbeefcafebabe');
  assert.equal(sarif.runs[0]?.tool.driver.rules[0]?.id, 'rust.wrapping-arithmetic');
});
