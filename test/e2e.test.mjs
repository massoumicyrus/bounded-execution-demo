import test from 'node:test';
import assert from 'node:assert/strict';
import { scenarios } from '../scenarios.mjs';
test('end-to-end enforcement scenarios', {timeout:120000}, async () => {
  const r=await scenarios(); assert.equal(r.cases.length,26); assert.ok(r.cases.every(c=>c.passed));
});
