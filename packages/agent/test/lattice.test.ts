import assert from 'node:assert/strict';
import test from 'node:test';
import { fuseConfidence, structuralEvidenceScore } from '../src/lattice.js';
import { applyRulePack, loadRulePack } from '../src/rules/engine.js';
import { applyScopeFirewall, matchGlob } from '../src/scope.js';
import corePack from '../src/rules/sentinel-core.json' with { type: 'json' };

test('confidence lattice fuses channels audibly', () => {
  const result = fuseConfidence({
    finding: {
      title: 't',
      description: 'd',
      severity: 'high',
      vulnType: 'integer_overflow',
      confidenceScore: 0.7,
      affectedFile: 'a.rs',
      lineNumber: 1,
      ruleId: 'rust.wrapping-arithmetic',
      fingerprint: 'x',
      pocCode: 'wrapping_add(1)',
    },
    structuralScore: structuralEvidenceScore({
      title: 't',
      description: 'd',
      severity: 'high',
      vulnType: 'integer_overflow',
      confidenceScore: 0.7,
      affectedFile: 'a.rs',
      lineNumber: 1,
      ruleId: 'rust.wrapping-arithmetic',
      fingerprint: 'x',
      pocCode: 'wrapping_add(1)',
    }),
    adapterBoost: 0.04,
    historicalFpRate: 0.1,
    priorVerifiedSameFingerprint: true,
  });
  assert.ok(result.confidence > 0.7);
  assert.match(result.rationale, /base=/);
});

test('declarative rule pack loads and matches', () => {
  const pack = loadRulePack(corePack as Parameters<typeof loadRulePack>[0]);
  const findings = applyRulePack(pack, 'rust', [
    {
      path: 'src/lib.rs',
      content: 'fn x() { todo!("finish"); }\n',
    },
  ]);
  assert.ok(findings.some((f) => f.ruleId === 'sentinel-core.rust.todo-macro'));
});

test('scope firewall denies target directories', () => {
  assert.equal(matchGlob('src/lib.rs', 'src/*'), true);
  const filtered = applyScopeFirewall(
    [
      { path: 'src/lib.rs', content: '' },
      { path: 'target/debug/foo.rs', content: '' },
    ],
    {},
  );
  assert.equal(filtered.length, 1);
  assert.equal(filtered[0]?.path, 'src/lib.rs');
});
