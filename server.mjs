import { createServer } from 'node:http';
import { spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { mkdirSync, writeFileSync, readFileSync, existsSync, chmodSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Store, Refusal } from './store.mjs';
import { fixture } from './aps.mjs';
import { worker } from './workers.mjs';
const redact = v => Array.isArray(v) ? v.map(redact) : v && typeof v === 'object'
  ? Object.fromEntries(Object.entries(v).map(([k,x])=>[k,/token|secret|authorization|cookie|privatekey/i.test(k)?'[REDACTED]':redact(x)])) : v;

export async function start(directory, options = {}) {
  mkdirSync(directory, { recursive: true, mode: 0o700 }); chmodSync(directory, 0o700);
  const secretsPath = resolve(directory, 'secrets.json');
  const secrets = existsSync(secretsPath) ? JSON.parse(readFileSync(secretsPath, 'utf8'))
    : { admin: randomBytes(32).toString('hex'), human: randomBytes(32).toString('hex'), fixtures: {} };
  const save = () => writeFileSync(secretsPath, JSON.stringify(secrets), { mode: 0o600 }); save();
  const dbPath = resolve(directory, 'state.db'); const store = new Store(dbPath); chmodSync(dbPath, 0o600);
  const gateways = { A: worker('./aps-worker.mjs'), B: worker('./aps-worker.mjs') };
  let executor = worker('./executor-worker.mjs', [dbPath]);
  const observations = Object.fromEntries(['A','B'].map(g=>[g, store.get('gateway', g)?.connected ?? true])); let url;
  function fixtureFor(taskId) { if (!secrets.fixtures[taskId]) { secrets.fixtures[taskId] = fixture(taskId); save(); } return secrets.fixtures[taskId]; }
  async function policy(attempt, gateway = 'A') {
    if (!gateways[gateway]) throw new Refusal('unknown_gateway');
    const o = store.get('object', attempt.objectId), t = store.get('task', o.taskId);
    const online = observations[gateway];
    const observedAuthority = online ? t.authority : 'active';
    const raw = await gateways[gateway].call({ fixture: fixtureFor(t.id), gateway, attempt, observedAuthority });
    const effective = !online || observedAuthority === 'unknown' ? 'unknown' : raw.raw.approved ? 'permit' : 'deny';
    return { gateway, checkedAt: Date.now(), source: online ? 'connected' : 'partitioned', observedAuthority: online ? observedAuthority : 'unknown',
      cachedObservation: online ? null : 'active', effective, reason: !online ? 'current_authority_unavailable' : raw.raw.denial?.reason || effective, ...raw };
  }
  async function run(session, p, route) {
    if (Object.keys(p).some(k => !['objectId','tool','value','gateway'].includes(k))) throw new Refusal('unsupported_arguments');
    if (p.tool === 'RUN_CHILD') return { status:'delegated', ...await runChild(session,{objectId:p.objectId,value:p.value}) };
    const attempt = store.prepare(session.id, p.objectId, p.tool, p.value, route);
    if (attempt.denied) return { status: 'blocked', ...attempt };
    let record;
    try { record = await policy(attempt, p.gateway || 'A'); }
    catch { record = { gateway: p.gateway || 'A', checkedAt: Date.now(), effective: 'unknown', reason: 'gateway_unavailable' }; }
    store.recordGateway(attempt, record);
    if (record.effective !== 'permit') return { status: 'blocked', reason: record.reason, attemptId: attempt.attemptId };
    await options.beforeCommit?.(attempt);
    try {
      const result = await executor.call({ attemptId: attempt.attemptId });
      if (!result.accepted) return { status: 'blocked', reason: result.reason, attemptId: attempt.attemptId };
      const verified = store.reconcile(p.objectId, session.id);
      if (!verified.effect) { store.outcome(p.objectId, 'unverified', attempt.attemptId); return { status: 'unverified', reason: 'effect_missing', attemptId: attempt.attemptId }; }
      return { ...verified, reused: result.reused === true, attemptId: attempt.attemptId };
    } catch {
      if(executor.dead) executor=worker('./executor-worker.mjs',[dbPath]);
      store.outcome(p.objectId, 'unknown', attempt.attemptId); return { status: 'unknown', reason: 'executor_unavailable', attemptId: attempt.attemptId };
    }
  }
  async function runChild(session, p) {
    if (Object.keys(p).some(k => !['objectId','value','tools'].includes(k))) throw new Refusal('unsupported_arguments');
    if (session.objectId !== p.objectId || !session.tools.includes('RUN_CHILD')) throw new Refusal('scope_denied');
    const grant = store.mint(p.objectId, session.id, p.tools || ['APPEND','write_record']);
    const path = fileURLToPath(new URL('./child.mjs', import.meta.url));
    const args = ['--permission', `--allow-fs-read=${path}`, '--disallow-code-generation-from-strings', path];
    if (process.allowedNodeEnvironmentFlags.has('--allow-net')) args.splice(1, 0, '--allow-net');
    const result = await new Promise((resolveResult, reject) => {
      const proc = spawn(process.execPath, args, { stdio: ['pipe','pipe','pipe'], env: {}, cwd: directory });
      let out = ''; const timer = setTimeout(() => { proc.kill(); reject(new Error('child_timeout')); }, 10000);
      proc.stdout.on('data', b => { out += b; if (out.length > 100000) proc.kill(); }); proc.stderr.on('data', () => {});
      proc.on('error', reject); proc.on('exit', code => { clearTimeout(timer); code === 0 ? resolveResult(JSON.parse(out)) : reject(new Error('child_failed')); });
      proc.stdin.end(JSON.stringify({ url, token: grant.token, objectId: p.objectId, value: p.value, forbiddenPath: dbPath }));
    });
    store.tx(() => store.event('child_returned', { sessionId: grant.id, parentId: session.id, objectId: p.objectId, results: result }));
    return { sessionId: grant.id, results: result };
  }
  const server = createServer(async (req, res) => {
    const callId=randomBytes(16).toString('hex'); let input=null, path='', role='unauthenticated';
    const send = (status, body) => {
      if (!['/health','/admin/export'].includes(path)) store.tx(()=>store.event('http_exchange',{
        callId, method:req.method, path, role, request:redact(input), status, response:redact(body) }));
      res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store', 'x-call-id':callId }); res.end(JSON.stringify(body));
    };
    try {
      path = new URL(req.url, 'http://localhost').pathname;
      if (req.method === 'GET' && path === '/health') return send(200, { ok: true });
      if (req.method === 'GET' && path === '/review') {
        res.writeHead(200, { 'content-type':'text/html; charset=utf-8', 'cache-control':'no-store', 'content-security-policy':"default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; frame-ancestors 'none'" });
        return res.end(readFileSync(new URL('./review.html', import.meta.url)));
      }
      const token = req.headers.authorization?.replace(/^Bearer /, '') || '';
      role=token===secrets.admin?'administrator':token===secrets.human?'reviewer':'caller';
      let text = ''; for await (const b of req) { text += b; if (text.length > 16384) throw new Refusal('body_too_large'); }
      const p = text ? JSON.parse(text) : {}; input=p;
      if (path.startsWith('/admin/')) {
        if (token !== secrets.admin) throw new Refusal('admin_required');
        if (path === '/admin/task') return send(200, store.createTask(p.name));
        if (path === '/admin/task-change') return send(200, store.changeTask(p.taskId, p.change));
        if (path === '/admin/object') return send(200, store.createObject(p));
        if (path === '/admin/condition') return send(200, store.createCondition(p));
        if (path === '/admin/condition-change') return send(200, store.changeCondition(p.id, p.state));
        if (path === '/admin/mint') return send(200, store.mint(p.objectId, p.parentId, p.tools));
        if (path === '/admin/revoke-session') return send(200, store.revokeSession(p.id));
        if (path === '/admin/partition') { if (!(p.gateway in observations)) throw new Refusal('unknown_gateway'); observations[p.gateway] = p.connected === true;
          store.tx(()=>{ store.put('gateway',p.gateway,{connected:observations[p.gateway]}); store.event('gateway_connectivity',{gateway:p.gateway,connected:observations[p.gateway]}); });
          return send(200, { gateway: p.gateway, connected: observations[p.gateway] }); }
        if (path === '/admin/observe') {
          // Diagnostic policy-only probe; never executes an effect.
          const o = store.get('object', p.objectId); if (!o) throw new Refusal('unknown_object');
          const a = { attemptId: randomBytes(16).toString('hex'), objectId: o.id, value: o.value, scope: o.scope };
          const record = await policy(a, p.gateway); store.tx(() => store.event('gateway_probe', { objectId: o.id, record })); return send(200, record);
        }
        if (path === '/admin/export') return send(200, store.export());
      } else if (path.startsWith('/human/')) {
        if (token !== secrets.human) throw new Refusal('human_required');
        if (path === '/human/inbox') return send(200, store.inbox(p.presented === true));
        if (path === '/human/decide') return send(200, store.decideApproval(p.objectId, p.actionHash, p.decision));
      } else {
        const session = store.authenticate(token);
        if (path === '/run') return send(200, await run(session, p, 'rest'));
        if (path === '/api/run') {
          if (!p.args||typeof p.args!=='object'||Object.keys(p).some(k=>!['tool','args'].includes(k))) throw new Refusal('invalid_dispatch_envelope');
          return send(200,await run(session,{...p.args,tool:p.tool},'api-run'));
        }
        if (path === '/mcp') {
          if (p.jsonrpc !== '2.0' || p.method !== 'tools/call' || !p.params) throw new Refusal('unsupported_mcp');
          const value = await run(session, { ...p.params.arguments, tool: p.params.name }, 'mcp-tools-call');
          return send(200, { jsonrpc: '2.0', id: p.id, result: { content: [{ type: 'text', text: JSON.stringify(value) }], structuredContent: value, isError: !['verified','delegated'].includes(value.status) } });
        }
        if (path === '/agent') return send(200, await runChild(session, p));
        if (path === '/status') return send(200, store.reconcile(p.objectId, session.id));
      }
      send(404, { error: 'unknown_route' });
    } catch (e) { send(e instanceof Refusal ? 403 : 400, { error: e instanceof Refusal ? e.code : 'invalid_request_or_internal_failure' }); }
  });
  await new Promise(resolveReady => server.listen(0, '127.0.0.1', resolveReady)); url = `http://127.0.0.1:${server.address().port}`;
  return { url, secrets, store, async close() { server.closeAllConnections(); await new Promise(r => server.close(r)); await Promise.all([gateways.A.close(), gateways.B.close(), executor.close()]); store.close(); } };
}
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const app = await start(resolve('.runtime'));
  console.log(JSON.stringify({ url: app.url, credentials: 'Private .runtime/secrets.json; never publish this file.' }));
  process.on('SIGINT', async () => { await app.close(); process.exit(0); });
}
