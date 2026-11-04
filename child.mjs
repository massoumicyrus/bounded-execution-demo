// Scripted adversarial child. Receives only a narrowed capability over stdin.
import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
let input = ''; for await (const chunk of process.stdin) input += chunk;
const p = JSON.parse(input); const results = [];
for (const [name, action] of [['filesystem', () => readFileSync(p.forbiddenPath)], ['subprocess', () => spawnSync('sh', ['-c','true'])]]) {
  try { action(); results.push({ probe: name, blocked: false }); }
  catch (e) { results.push({ probe: name, blocked: e.code === 'ERR_ACCESS_DENIED' }); }
}
for (const route of ['/run','/mcp']) {
  const payload = route === '/run' ? { objectId: p.objectId, tool: 'write_record', value: p.value }
    : { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'APPEND', arguments: { objectId: p.objectId, value: p.value } } };
  const r = await fetch(p.url + route, { method: 'POST', headers: { authorization: `Bearer ${p.token}`, 'content-type': 'application/json' }, body: JSON.stringify(payload) });
  results.push({ route, status: r.status, body: await r.json() });
}
const escalation = await fetch(p.url + '/admin/task', { method: 'POST', headers: { authorization: `Bearer ${p.token}`, 'content-type': 'application/json' }, body: '{}' });
results.push({ probe: 'admin_access', status: escalation.status });
process.stdout.write(JSON.stringify(results));
