// Offline checker: intentionally does not import the runtime or APS implementation.
import assert from 'node:assert/strict';
import { createHash, createPublicKey, verify as ed25519Verify } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
const json = (v, aps=false) => v === null || typeof v !== 'object' ? JSON.stringify(v)
  : Array.isArray(v) ? '['+v.map(x=>json(x,aps)).join(',')+']'
  : '{'+Object.keys(v).sort().filter(k=>!aps || v[k]!=null).map(k=>JSON.stringify(k)+':'+json(v[k],aps)).join(',')+'}';
const digest = v => createHash('sha256').update(typeof v==='string'?v:json(v)).digest('hex');
function signature(body, sig, publicKey) {
  const key=createPublicKey({key:Buffer.from('302a300506032b6570032100'+publicKey,'hex'),format:'der',type:'spki'});
  assert.ok(ed25519Verify(null,Buffer.from(json(body,true)),key,Buffer.from(sig,'hex')),'Invalid APS signature');
}
function signed(record,key) { const {signature:sig,...body}=record; signature(body,sig,key); }
function gateway(record, time) {
  if (!record.raw) { assert.equal(record.effective,'unknown'); return; }
  const req=record.request;
  const {requestId,agentId,tool,params,scopeRequired}=req;
  signature({requestId,agentId,tool,params,scopeRequired},req.signature,req.agentPublicKey);
  const [first,second]=record.chain;
  assert.equal(first.delegatedBy,record.rootPublicKey); signed(first,record.rootPublicKey);
  assert.equal(second.delegatedBy,first.delegatedTo); signed(second,first.delegatedTo);
  assert.equal(second.delegatedTo,req.agentPublicKey);
  assert.ok(second.scope.every(x=>first.scope.includes(x)),'APS child expanded scope');
  if (record.raw.approved) {
    const {decision,intent}=record.raw;
    signed(intent,record.gatewayPublicKey); signed(decision,record.gatewayPublicKey);
    assert.equal(decision.intentId,intent.intentId); assert.equal(decision.verdict,'permit');
    assert.equal(intent.delegationId,second.delegationId); assert.equal(req.delegationId,second.delegationId);
    assert.equal(intent.action.scopeRequired,req.scopeRequired); assert.deepEqual(JSON.parse(intent.action.target),req.params);
    assert.ok(second.scope.includes(req.scopeRequired));
    assert.ok(Date.parse(second.notBefore)<=time && time<Date.parse(second.expiresAt),'APS delegation outside validity window');
    assert.ok(time<Date.parse(decision.expiresAt),'APS decision expired at observation');
  }
  if (record.effective==='permit') { assert.equal(record.raw.approved,true); assert.equal(record.source,'connected'); assert.equal(record.observedAuthority,'active'); }
  if (record.source==='partitioned') assert.equal(record.effective,'unknown');
}
export function verifyRun(run, {checkSources=false,sourceRoot=process.cwd()}={}) {
  assert.equal(run.schema,'bounded-execution-evidence/1');
  if(checkSources) for(const [path,expected] of Object.entries(run.sourceHashes)) assert.equal(digest(readFileSync(resolve(sourceRoot,path),'utf8')),expected,`Source changed: ${path}`);
  const tasks=new Map(),objects=new Map(),conditions=new Map(),sessions=new Map(),approvals=new Map(),attempts=new Map(),effects=new Map();
  let previous='0'.repeat(64), seq=0, signatureRecords=0;const exchanges=new Map();
  for(const full of run.snapshot.events) {
    const {hash:stored,...event}=full;
    assert.equal(event.seq,++seq,'Event sequence gap'); assert.equal(event.previous,previous,'Broken event link');
    assert.equal(digest(event),stored,'Event bytes changed'); previous=stored;
    assert.ok(event.causes.every(c=>Number.isInteger(c)&&c>0&&c<seq),'Invalid causal reference');
    const d=event.detail, time=Date.parse(event.at);
    if(event.type==='http_exchange') { assert.ok(!exchanges.has(d.callId));exchanges.set(d.callId,d); }
    if(event.type==='task_created'||event.type==='task_changed') tasks.set(d.id,d);
    if(event.type==='object_created') objects.set(d.id,{...d});
    if(event.type==='condition_created'||event.type==='condition_changed') conditions.set(d.id,d);
    if(event.type==='delegated') {
      if(d.parentId){const parent=sessions.get(d.parentId);assert.ok(parent);assert.equal(parent.objectId,d.objectId);assert.ok(d.tools.every(t=>parent.tools.includes(t)));assert.ok(d.expiresAt<=parent.expiresAt);}
      sessions.set(d.id,{...d,revoked:false});
    }
    if(event.type==='session_revoked') { assert.ok(sessions.has(d.id)); sessions.get(d.id).revoked=true; }
    if(event.type==='approval_requested'||event.type==='approval_presented'||event.type==='approval_decided') approvals.set(d.objectId,d);
    if(event.type==='prepared') attempts.set(d.attemptId,{...d});
    if(event.type==='gateway_decided'||event.type==='gateway_probe') { gateway(d.record,time); signatureRecords++; }
    if(event.type==='gateway_decided'){assert.ok(attempts.has(d.attemptId));attempts.get(d.attemptId).gateway=d.record;attempts.get(d.attemptId).gatewayCause=seq;}
    if(event.type==='turn_locked'){assert.ok(objects.has(d.objectId));objects.get(d.objectId).latch=d;}
    if(event.type==='effect_committed') {
      assert.ok(!effects.has(d.objectId),'Duplicate effect');
      const o=objects.get(d.objectId),t=tasks.get(o?.taskId),a=attempts.get(d.attemptId);
      assert.ok(o&&t&&a,'Missing object/task/attempt');
      assert.equal(t.authority,'active','Effect executed after revocation or unknown authority');
      assert.notEqual(o.latch?.turn,t.turn,'Effect bypassed a turn lock');
      assert.equal(a.epoch,t.epoch);assert.equal(a.turn,t.turn);assert.equal(d.turn,t.turn);assert.equal(d.authorityEpoch,t.epoch);
      assert.equal(a.gateway?.effective,'permit');assert.ok(event.causes.includes(a.gatewayCause));
      assert.ok(time-a.gateway.checkedAt<=5000,'Stale gateway decision');
      assert.equal(a.gateway.request.params.objectId,o.id);assert.equal(a.gateway.request.params.value,o.value);
      assert.equal(d.value,o.value);assert.equal(d.target,o.target);assert.equal(d.actionHash,o.actionHash);
      assert.equal(o.actionHash,digest({verb:o.verb,target:o.target,value:o.value,revision:o.revision}));
      let session=sessions.get(a.sessionId);assert.ok(session);
      while(session){assert.equal(session.objectId,o.id);assert.ok(!session.revoked&&session.expiresAt>time);assert.ok(session.tools.includes(a.tool));session=session.parentId?sessions.get(session.parentId):null;}
      const dependencyVersions={};
      function walk(key){if(key in dependencyVersions)return;const c=conditions.get(key);assert.ok(c);assert.equal(c.state,'valid','Invalid prerequisite at effect');assert.ok(time-c.checkedAt<=c.ttlMs,'Stale prerequisite');dependencyVersions[key]=c.revision;c.parents.forEach(walk);}
      o.dependencies.forEach(walk);assert.deepEqual(d.dependencies,dependencyVersions);assert.deepEqual(a.deps,dependencyVersions);
      if(o.requiresApproval){const p=approvals.get(o.id);assert.ok(p);assert.equal(p.state,'approved');assert.equal(p.delivery,'presented');assert.equal(p.actionHash,o.actionHash);assert.ok(p.expiresAt>time);assert.equal(d.approvalId,p.id);}
      const {effectHash,...body}=d;assert.equal(effectHash,digest(body));effects.set(d.objectId,{...d,cause:seq});
    }
    if(event.type==='verified'||event.type==='effect_reused') { const e=effects.get(d.objectId);assert.ok(e,'Completion without an effect');assert.equal(e.effectHash,d.effectHash);assert.ok(event.causes.includes(e.cause)); }
  }
  assert.equal(effects.size,run.snapshot.effects.length);
  for(const effect of run.snapshot.effects)assert.deepEqual(effect,effects.get(effect.objectId),'Stored effect differs from committed effect');
  for(const exchange of run.exchanges){const recorded=exchanges.get(exchange.callId);assert.ok(recorded,'Missing runtime call receipt');
    assert.equal(recorded.path,exchange.path);assert.deepEqual(recorded.request,exchange.request);assert.deepEqual(recorded.response,exchange.response);
    const r=exchange.response?.result?.structuredContent||exchange.response;if(r?.status==='verified'){const e=effects.get(r.objectId);assert.ok(e,'Verified response without effect');assert.deepEqual(r.effect,e);}}
  assert.ok(run.cases.length>=26&&run.cases.every(c=>c.passed));
  return {valid:true,scenarios:run.cases.length,events:seq,effects:effects.size,signedGatewayRecords:signatureRecords,journalHead:previous};
}
if(process.argv[1]===fileURLToPath(import.meta.url)) {
  const folder=resolve(process.argv[2]||'evidence');
  const run=JSON.parse(readFileSync(resolve(folder,'run.json'),'utf8'));
  console.log(JSON.stringify(verifyRun(run,{checkSources:true}),null,2));
}
