import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { start } from './server.mjs';

const clean = v => Array.isArray(v) ? v.map(clean) : v && typeof v === 'object'
  ? Object.fromEntries(Object.entries(v).map(([k,x]) => [k, /^(token|admin|human|privateKey|tokenHash)$/.test(k) ? '[REDACTED]' : clean(x)])) : v;

export async function scenarios() {
  const directory = mkdtempSync(join(tmpdir(), 'bounded-execution-'));
  let hook = null, app = await start(directory, { beforeCommit: a => hook?.(a) });
  const exchanges = [], cases = [];
  async function call(path, body, credential = app.secrets.admin) {
    const r = await fetch(app.url + path, { method: 'POST', headers: { 'content-type':'application/json', authorization:`Bearer ${credential}` }, body: JSON.stringify(body) });
    const result = await r.json();
    if (path !== '/admin/export') exchanges.push({ sequence: exchanges.length + 1, callId:r.headers.get('x-call-id'), path, request: clean(body), status: r.status, response: clean(result) });
    return result;
  }
  async function setup(name, overrides = {}) {
    const task = await call('/admin/task', { name });
    const object = await call('/admin/object', { taskId: task.id, target: name, value: `record:${name}`, ...overrides });
    assert.ok(object.id, JSON.stringify(object));
    const grant = await call('/admin/mint', { objectId: object.id });
    return { task, object, grant };
  }
  const run = (c, extra = {}) => call('/run', { objectId: c.object.id, tool:'APPEND', value:c.object.value, ...extra }, c.grant.token);
  const status = c => call('/status', { objectId:c.object.id }, c.grant.token);
  const count = c => app.store.effect(c.object.id) ? 1 : 0;
  async function scenario(name, fn) {
    const first = exchanges.length + 1;
    await fn(); cases.push({ name, passed:true, exchangeStart:first, exchangeEnd:exchanges.length });
    console.log(`PASS ${name}`);
  }
  try {
    await scenario('authorized action is appended and independently read back', async () => {
      const c = await setup('authorized'); const r = await run(c); assert.equal(r.status,'verified',JSON.stringify(r)); assert.equal(count(c),1);
    });
    await scenario('APS scope denial locks alternate REST and MCP routes', async () => {
      const c = await setup('denial', { scope:'records:delete' });
      const first = await run(c); assert.equal(first.status,'blocked'); assert.match(first.reason,/scope/);
      assert.equal((await run(c, { tool:'write_record' })).reason,'turn_locked');
      assert.equal((await call('/api/run',{tool:'APPEND',args:{objectId:c.object.id,value:c.object.value}},c.grant.token)).reason,'turn_locked');
      const m = await call('/mcp', { jsonrpc:'2.0', id:7, method:'tools/call', params:{ name:'APPEND', arguments:{ objectId:c.object.id, value:c.object.value } } }, c.grant.token);
      assert.equal(m.result.structuredContent.reason,'turn_locked'); assert.equal(count(c),0);
    });
    await scenario('new request, object alias, child, and caller-selected turn cannot clear denial', async () => {
      const c = await setup('child-denial', { scope:'records:delete' }); await run(c);
      const duplicate = await call('/admin/object', { taskId:c.task.id, target:c.object.target, value:c.object.value }); assert.equal(duplicate.id,c.object.id);
      assert.equal((await run(c,{ turn:99 })).error,'unsupported_arguments');
      const child = await call('/agent', { objectId:c.object.id, value:c.object.value }, c.grant.token);
      assert.ok(child.results,JSON.stringify(child));
      assert.ok(child.results.filter(x => x.probe === 'filesystem' || x.probe === 'subprocess').every(x => x.blocked));
      assert.equal(child.results.find(x=>x.route==='/run').body.reason,'turn_locked');
      assert.equal(child.results.find(x=>x.route==='/mcp').body.result.structuredContent.reason,'turn_locked');
      assert.equal(child.results.find(x=>x.probe==='admin_access').status,403); assert.equal(count(c),0);
    });
    await scenario('next turn reevaluates a continuing denial', async () => {
      const c = await setup('next-turn', { scope:'records:delete' }); await run(c);
      await call('/admin/task-change',{taskId:c.task.id,change:'next_turn'});
      const second = await run(c); assert.equal(second.status,'blocked'); assert.match(second.reason,/scope/); assert.equal(count(c),0);
    });
    await scenario('approval survives child handoff and complete service restart', async () => {
      const c = await setup('approval-restart',{approval:true}); assert.equal((await run(c)).reason,'approval_pending');
      const child = await call('/agent',{objectId:c.object.id,value:c.object.value},c.grant.token);
      assert.equal(child.results.find(x=>x.route==='/run').body.reason,'approval_pending');
      await app.close(); app = await start(directory,{beforeCommit:a=>hook?.(a)});
      const inbox = await call('/human/inbox',{presented:true},app.secrets.human); const a = inbox.find(x=>x.objectId===c.object.id);
      assert.ok(a); assert.equal(a.delivery,'presented'); assert.equal(count(c),0);
      await call('/human/decide',{objectId:c.object.id,actionHash:a.actionHash,decision:'approved'},app.secrets.human);
      assert.equal((await run(c)).status,'verified'); assert.equal(count(c),1);
    });
    await scenario('agent cannot approve; altered arguments and wrong approval hashes fail', async () => {
      const c = await setup('approval-binding',{approval:true});
      assert.equal((await call('/human/decide',{objectId:c.object.id,actionHash:c.object.actionHash,decision:'approved'},c.grant.token)).error,'human_required');
      await call('/human/inbox',{presented:true},app.secrets.human);
      assert.equal((await call('/human/decide',{objectId:c.object.id,actionHash:'changed',decision:'approved'},app.secrets.human)).error,'approval_mismatch');
      await call('/human/decide',{objectId:c.object.id,actionHash:c.object.actionHash,decision:'approved'},app.secrets.human);
      assert.equal((await run(c,{value:'changed'})).reason,'arguments_changed'); assert.equal(count(c),0);
    });
    await scenario('undelivered and expired approvals cannot authorize execution', async () => {
      const c = await setup('approval-expired',{approval:true,approvalTtlMs:2000});
      assert.equal((await call('/human/decide',{objectId:c.object.id,actionHash:c.object.actionHash,decision:'approved'},app.secrets.human)).error,'approval_not_presented');
      await call('/human/inbox',{presented:true},app.secrets.human);
      const approval=await call('/human/decide',{objectId:c.object.id,actionHash:c.object.actionHash,decision:'approved'},app.secrets.human);
      await new Promise(r=>setTimeout(r,Math.max(0,approval.expiresAt-Date.now()+10))); assert.equal((await run(c)).reason,'approval_expired'); assert.equal(count(c),0);
    });
    await scenario('human denial stays blocked and delivered requests remain durable', async () => {
      const c = await setup('approval-denied',{approval:true});
      await call('/human/inbox',{presented:true},app.secrets.human);
      await call('/human/decide',{objectId:c.object.id,actionHash:c.object.actionHash,decision:'denied'},app.secrets.human);
      assert.equal((await run(c)).reason,'approval_denied'); assert.equal(count(c),0);
    });
    await scenario('transitive invalidation blocks a whole declared action family', async () => {
      const source = await call('/admin/condition',{name:'source credential'});
      const derived = await call('/admin/condition',{name:'script readiness',parents:[source.id]});
      const a = await setup('causal-a',{dependencies:[derived.id]}), b = await setup('causal-b',{dependencies:[derived.id]});
      const unrelated = await setup('causal-unrelated');
      await call('/admin/condition-change',{id:source.id,state:'invalid'});
      assert.equal((await run(a)).reason,'dependency_invalid'); assert.equal((await run(b)).reason,'dependency_invalid');
      assert.equal((await run(unrelated)).status,'verified'); assert.equal(count(a)+count(b),0);
    });
    await scenario('unknown and stale prerequisite observations fail closed', async () => {
      const dep = await call('/admin/condition',{name:'unknown-input'}), c = await setup('unknown-input',{dependencies:[dep.id]});
      await call('/admin/condition-change',{id:dep.id,state:'unknown'}); assert.equal((await run(c)).reason,'dependency_unknown');
      const stale = await call('/admin/condition',{name:'stale-input',ttlMs:20}), d = await setup('stale-input',{dependencies:[stale.id]});
      await new Promise(r=>setTimeout(r,30)); assert.equal((await run(d)).reason,'dependency_stale'); assert.equal(count(c)+count(d),0);
    });
    await scenario('repairing a prerequisite cannot clear its lock within the same turn', async () => {
      const dep=await call('/admin/condition',{name:'turn-toggle'}), c=await setup('turn-toggle',{dependencies:[dep.id]});
      await call('/admin/condition-change',{id:dep.id,state:'invalid'}); assert.equal((await run(c)).reason,'dependency_invalid');
      await call('/admin/condition-change',{id:dep.id,state:'valid'}); assert.equal((await run(c)).reason,'turn_locked');
      await call('/admin/task-change',{taskId:c.task.id,change:'next_turn'}); assert.equal((await run(c)).status,'verified'); assert.equal(count(c),1);
    });
    await scenario('child scope cannot expand and ancestor session revocation propagates', async () => {
      const c = await setup('scope');
      const narrowed = await call('/admin/mint',{objectId:c.object.id,parentId:c.grant.id,tools:['APPEND']});
      assert.equal((await call('/admin/mint',{objectId:c.object.id,parentId:narrowed.id,tools:['RUN_CHILD']})).error,'scope_expansion');
      await call('/admin/revoke-session',{id:c.grant.id});
      assert.equal((await call('/run',{objectId:c.object.id,tool:'APPEND',value:c.object.value},narrowed.token)).error,'session_revoked_or_expired'); assert.equal(count(c),0);
    });
    await scenario('a permitted bounded child executes only the assigned effect', async () => {
      const c = await setup('child-permitted');
      const child = await call('/agent',{objectId:c.object.id,value:c.object.value},c.grant.token);
      assert.equal(child.results.find(x=>x.route==='/run').body.status,'verified');
      assert.equal(child.results.find(x=>x.route==='/mcp').body.result.structuredContent.reused,true); assert.equal(count(c),1);
    });
    await scenario('an MCP tool call invokes the bounded child and inherits its action lock', async()=>{
      const c=await setup('mcp-agent',{scope:'records:delete'});await run(c);
      const r=await call('/mcp',{jsonrpc:'2.0',id:9,method:'tools/call',params:{name:'RUN_CHILD',arguments:{objectId:c.object.id,value:c.object.value}}},c.grant.token);
      assert.equal(r.result.structuredContent.status,'delegated');assert.equal(r.result.isError,false);
      assert.equal(r.result.structuredContent.results.find(x=>x.route==='/run').body.reason,'turn_locked');assert.equal(count(c),0);
    });
    await scenario('success-looking executor return without effect is unverified', async () => {
      const c = await setup('false-success',{mode:'no_effect'}); assert.equal((await run(c)).status,'unverified');
      assert.equal((await status(c)).status,'unverified'); assert.equal(count(c),0);
    });
    await scenario('lost response reconciles the effect without duplicate execution', async () => {
      const c = await setup('lost-response',{mode:'drop_response'}); assert.equal((await run(c)).status,'unknown'); assert.equal(count(c),1);
      assert.equal((await status(c)).status,'verified'); assert.equal((await run(c)).reused,true); assert.equal(count(c),1);
    });
    await scenario('executor failure before commit produces neither effect nor success', async () => {
      const c = await setup('executor-failure',{mode:'crash_before_commit'}); assert.equal((await run(c)).status,'unknown');
      assert.equal((await status(c)).status,'unknown'); assert.equal(count(c),0);
    });
    await scenario('concurrent retries produce exactly one controlled effect', async () => {
      const c = await setup('concurrent'); const results = await Promise.all(Array.from({length:12},()=>run(c)));
      assert.ok(results.every(r=>r.status==='verified')); assert.equal(results.filter(r=>!r.reused).length,1); assert.equal(count(c),1);
    });
    async function race(name, change, expected) {
      const dep = await call('/admin/condition',{name:`${name}-dependency`});
      const c = await setup(name,{dependencies:[dep.id]});
      let release, ready; const waiting = new Promise(r=>ready=r), barrier = new Promise(r=>release=r);
      hook = a => a.objectId === c.object.id ? (ready(),barrier) : undefined;
      const pending = run(c); await waiting; await change(c,dep); release();
      const result = await pending; hook=null; assert.equal(result.reason,expected); assert.equal(count(c),0);
    }
    await scenario('revocation between preauthorization and commit blocks the effect',()=>race('revocation-race', c=>call('/admin/task-change',{taskId:c.task.id,change:'revoke'}),'authority_revoked'));
    await scenario('dependency change between preauthorization and commit blocks the effect',()=>race('dependency-race', (c,d)=>call('/admin/condition-change',{id:d.id,state:'invalid'}),'dependency_invalid'));
    await scenario('new turn fences a previously authorized in-flight call',()=>race('turn-race', c=>call('/admin/task-change',{taskId:c.task.id,change:'next_turn'}),'stale_authorization'));
    await scenario('two isolated APS gateways distinguish revocation and unknown freshness', async () => {
      const c = await setup('partition');
      const beforeA = await call('/admin/observe',{objectId:c.object.id,gateway:'A'}), beforeB = await call('/admin/observe',{objectId:c.object.id,gateway:'B'});
      assert.equal(beforeA.raw.approved,true); assert.equal(beforeB.raw.approved,true);
      assert.deepEqual(beforeA.chain,beforeB.chain);
      await call('/admin/partition',{gateway:'B',connected:false});
      await call('/admin/task-change',{taskId:c.task.id,change:'revoke'});
      const a = await call('/admin/observe',{objectId:c.object.id,gateway:'A'}), b = await call('/admin/observe',{objectId:c.object.id,gateway:'B'});
      assert.equal(a.raw.approved,false); assert.equal(a.effective,'deny');
      assert.equal(b.raw.approved,true); assert.equal(b.effective,'unknown');
      assert.equal((await run(c,{gateway:'A'})).reason,'authority_revoked');
      assert.equal((await run(c,{gateway:'B'})).reason,'authority_revoked'); assert.equal(count(c),0);
      await call('/admin/partition',{gateway:'B',connected:true});
    });
    await scenario('a partition alone cannot turn a cached APS permit into authorization', async () => {
      const c = await setup('partition-active'); await call('/admin/partition',{gateway:'B',connected:false});
      const r = await run(c,{gateway:'B'}); assert.equal(r.reason,'current_authority_unavailable'); assert.equal(count(c),0);
      await call('/admin/partition',{gateway:'B',connected:true});
    });
    await scenario('revocation cannot be cleared by a new turn or refresh', async () => {
      const c = await setup('revocation-persistent'); await call('/admin/task-change',{taskId:c.task.id,change:'revoke'});
      await call('/admin/task-change',{taskId:c.task.id,change:'next_turn'});
      assert.equal((await call('/admin/task-change',{taskId:c.task.id,change:'refresh'})).error,'revocation_final');
      assert.equal((await run(c)).reason,'authority_revoked'); assert.equal(count(c),0);
    });
    await scenario('cross-object tokens, unknown tools and fabricated success fields are rejected', async () => {
      const a = await setup('isolation-a'), b = await setup('isolation-b');
      assert.equal((await call('/run',{objectId:b.object.id,tool:'APPEND',value:b.object.value},a.grant.token)).reason,'scope_denied');
      assert.equal((await run(a,{tool:'SHELL'})).reason,'unsupported_effect_tool');
      assert.equal((await run(a,{success:true})).error,'unsupported_arguments'); assert.equal(count(a)+count(b),0);
    });
    await scenario('past verified effects remain historical facts after revocation', async () => {
      const c = await setup('historical'); assert.equal((await run(c)).status,'verified');
      await call('/admin/task-change',{taskId:c.task.id,change:'revoke'});
      assert.equal((await status(c)).status,'verified'); assert.equal((await run(c)).reason,'authority_revoked'); assert.equal(count(c),1);
    });
    return { cases, exchanges, snapshot: await call('/admin/export',{}) };
  } finally { await app.close(); rmSync(directory,{recursive:true,force:true}); }
}
