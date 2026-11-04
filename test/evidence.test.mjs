import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { verifyRun } from '../verify.mjs';
import { hash } from '../store.mjs';
// These run against the published demonstration, not assertions copied from its runtime.
test('recorded evidence and APS signatures verify offline',()=>assert.ok(verifyRun(JSON.parse(readFileSync('evidence/run.json'))).valid));
test('missing effect cannot be masked by an asserted success',()=>{
  const run=JSON.parse(readFileSync('evidence/run.json'));run.snapshot.effects.pop();assert.throws(()=>verifyRun(run));
});
test('rewriting and rehashing a forbidden effect still fails semantic verification',()=>{
  const run=JSON.parse(readFileSync('evidence/run.json'));
  const effect=run.snapshot.events.find(e=>e.type==='effect_committed');
  effect.detail.value='forged';
  const {effectHash,...body}=effect.detail;effect.detail.effectHash=hash(body);
  let previous='0'.repeat(64);
  for(const e of run.snapshot.events){e.previous=previous;const {hash:old,...event}=e;e.hash=hash(event);previous=e.hash;}
  assert.throws(()=>verifyRun(run));
});
test('changed APS request signatures are rejected',()=>{
  const run=JSON.parse(readFileSync('evidence/run.json'));
  const e=run.snapshot.events.find(e=>e.type==='gateway_decided'&&e.detail.record.raw.approved);
  e.detail.record.request.signature='00'.repeat(64);
  let previous='0'.repeat(64);for(const e of run.snapshot.events){e.previous=previous;const {hash:old,...event}=e;e.hash=hash(event);previous=e.hash;}
  assert.throws(()=>verifyRun(run),/signature/);
});
