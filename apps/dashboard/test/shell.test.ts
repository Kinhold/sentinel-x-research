import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

test('dashboard ships operator shell assets', () => {
  const css = readFileSync(join(import.meta.dirname, '../src/styles.css'), 'utf8');
  const app = readFileSync(join(import.meta.dirname, '../src/App.tsx'), 'utf8');
  assert.match(css, /--display:\s*'Syne'/);
  assert.match(app, /Sentinel-X/);
  assert.match(app, /streamScanLogs|EventSource|\/api\/logs/);
});
